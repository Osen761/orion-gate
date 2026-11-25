"""Cloud telemetry streaming and policy bundle sync for standalone Orion Gate nodes."""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import httpx

from orion_gate import __version__ as ORION_GATE_VERSION
from orion_gate.security.secrets import safe_text_preview
from orion_gate.authz.connectors import EffectiveAccessScope
from orion_gate.schemas import (
    GovernedViolationItem,
    TelemetryEventItem,
    TelemetryIngestRequest,
)
from orion_gate.security.orion_yaml import (
    OrionYamlConfig,
    get_active_orion_yaml,
    parse_orion_yaml,
    set_active_orion_yaml,
)
from orion_gate.security.result_policy import ResultPolicyDecision
from orion_gate.security.sql_policy import POLICY_VERSION, SQLDialect, SQLPolicyDecision


logger = logging.getLogger("orion.cloud_sync")

_TELEMETRY_HOOK: Callable[[TelemetryEventItem], None] | None = None


def set_telemetry_hook(hook: Callable[[TelemetryEventItem], None] | None) -> None:
    """Register an in-process telemetry hook (used for tests or local sinks)."""

    global _TELEMETRY_HOOK
    _TELEMETRY_HOOK = hook


def build_telemetry_event(
    *,
    sql: str,
    scope: EffectiveAccessScope,
    sql_decision: SQLPolicyDecision,
    result_decision: ResultPolicyDecision | None,
    connector_id: UUID | str,
    dialect: SQLDialect,
    surface: str,
    status: str,
    row_count: int = 0,
    latency_ms: int = 0,
    request_id: str | None = None,
    error_message: str | None = None,
) -> TelemetryEventItem:
    """Build a redacted, row-free telemetry event from one governed query evaluation."""

    violations = [
        GovernedViolationItem(
            code=v.code,
            message=v.message,
            severity=v.severity,
        )
        for v in sql_decision.violations
    ]
    if result_decision is not None:
        violations.extend(
            GovernedViolationItem(
                code=v.code,
                message=v.message,
                severity=v.severity,
            )
            for v in result_decision.violations
        )

    warnings = list(getattr(sql_decision, "warnings", ()))
    if result_decision is not None:
        warnings.extend(result_decision.warnings)

    redacted_columns = (
        list(result_decision.redacted_columns) if result_decision is not None else []
    )
    denied_columns = (
        list(result_decision.denied_columns) if result_decision is not None else []
    )

    connector_uuid = (
        connector_id if isinstance(connector_id, UUID) else UUID(str(connector_id))
    )

    return TelemetryEventItem(
        event_id=sql_decision.decision_id[:64],
        request_id=request_id,
        connector_id=connector_uuid,
        dialect=dialect,
        surface=surface,
        sql_preview=safe_text_preview(sql, max_chars=900) or "SELECT 1",
        status=status,  # type: ignore[arg-type]
        sql_allowed=sql_decision.allowed,
        result_decision=result_decision.decision if result_decision is not None else None,
        tenant_isolation_active=bool(scope.tenant_filters),
        tenant_predicates_injected=sql_decision.tenant_predicates_injected,
        injected_predicates_count=sql_decision.injected_predicates_count,
        redacted_columns=redacted_columns,
        denied_columns=denied_columns,
        referenced_tables=list(sql_decision.tables_referenced),
        referenced_columns=list(sql_decision.columns_referenced),
        violations=violations,
        warnings=warnings,
        row_count=max(0, int(row_count)),
        latency_ms=max(0, int(latency_ms)),
        policy_version=sql_decision.policy_version or POLICY_VERSION,
        scope_version=scope.scope_version,
        error_message_safe=(
            safe_text_preview(error_message, max_chars=650) if error_message else None
        ),
        occurred_at=datetime.now(timezone.utc),
    )


class CloudTelemetrySyncClient:
    """Async client that syncs sanitized telemetry events and policy bundles with Orion Cloud."""

    def __init__(
        self,
        config: OrionYamlConfig | None = None,
        *,
        api_key: str | None = None,
        endpoint: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        api_key_env = config.cloud.api_key_env if config is not None else "ORION_API_KEY"
        endpoint_env = config.cloud.endpoint_env if config is not None else "ORION_CLOUD_URL"
        default_endpoint = (
            config.cloud.default_endpoint
            if config is not None
            else "https://api.oriongate.dev"
        )
        self.api_key = (api_key or os.getenv(api_key_env, "")).strip() or None
        self.endpoint = (
            endpoint or os.getenv(endpoint_env, "") or default_endpoint
        ).strip().rstrip("/")
        self.transport = transport

    @property
    def telemetry_enabled(self) -> bool:
        if _TELEMETRY_HOOK is not None:
            return True
        if self.config is not None and not self.config.cloud.sync_telemetry:
            return False
        return bool(self.api_key and os.getenv(
            self.config.cloud.endpoint_env if self.config else "ORION_CLOUD_URL", ""
        ).strip() or (self.api_key and self.transport is not None))

    async def emit_event(self, event: TelemetryEventItem) -> bool:
        """Emit one sanitized telemetry event to Orion Cloud or the active hook."""

        if _TELEMETRY_HOOK is not None:
            try:
                _TELEMETRY_HOOK(event)
            except Exception:
                logger.exception("Telemetry hook failed")
        if not self.api_key:
            return _TELEMETRY_HOOK is not None
        if (
            self.config is not None
            and not self.config.cloud.sync_telemetry
            and self.transport is None
        ):
            return _TELEMETRY_HOOK is not None

        explicit_url = os.getenv(
            self.config.cloud.endpoint_env if self.config else "ORION_CLOUD_URL", ""
        ).strip()
        if not explicit_url and self.transport is None:
            return _TELEMETRY_HOOK is not None

        payload = TelemetryIngestRequest(events=[event]).model_dump(mode="json")
        try:
            async with httpx.AsyncClient(
                base_url=self.endpoint,
                timeout=3.0,
                transport=self.transport,
            ) as client:
                response = await client.post(
                    "/v1/telemetry/events",
                    json=payload,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                response.raise_for_status()
            return True
        except Exception:
            logger.warning("Failed to ship telemetry event to Orion Cloud", exc_info=True)
            return False

    @property
    def control_plane_enabled(self) -> bool:
        """True only when an API key and explicit Cloud endpoint (or test transport) are configured."""

        if not self.api_key:
            return False
        explicit_url = os.getenv(
            self.config.cloud.endpoint_env if self.config else "ORION_CLOUD_URL", ""
        ).strip()
        return bool(explicit_url or self.transport is not None)

    async def register_gateway(
        self,
        *,
        name: str,
        node_key: str,
        dialect: str | None = None,
        environment: str = "production",
        active_policy_hash: str | None = None,
        active_policy_version: int | None = None,
        hostname: str | None = None,
    ) -> dict[str, Any] | None:
        """Register this edge Orion Gate node with Orion Cloud (fail-open on network errors)."""

        if not self.control_plane_enabled:
            return None
        payload: dict[str, Any] = {
            "name": name,
            "node_key": node_key,
            "orion_gate_version": ORION_GATE_VERSION,
            "environment": environment,
            "hostname": hostname or socket.gethostname(),
        }
        if dialect in {"postgres", "mysql", "bigquery"}:
            payload["dialect"] = dialect
        if active_policy_hash:
            payload["active_policy_hash"] = active_policy_hash
        if active_policy_version is not None:
            payload["active_policy_version"] = active_policy_version

        try:
            async with httpx.AsyncClient(
                base_url=self.endpoint,
                timeout=5.0,
                transport=self.transport,
            ) as client:
                response = await client.post(
                    "/v1/gateways/register",
                    json=payload,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                response.raise_for_status()
                body = response.json()
                return body if isinstance(body, dict) else None
        except Exception:
            logger.warning("Failed to register Orion Gate node with Orion Cloud", exc_info=True)
            return None

    async def send_heartbeat(
        self,
        gateway_id: str,
        *,
        active_policy_hash: str | None = None,
        active_policy_version: int | None = None,
        hostname: str | None = None,
    ) -> dict[str, Any] | None:
        """Send a periodic health & policy-sync heartbeat to Orion Cloud (fail-open)."""

        if not self.control_plane_enabled or not gateway_id:
            return None
        payload: dict[str, Any] = {
            "orion_gate_version": ORION_GATE_VERSION,
            "hostname": hostname or socket.gethostname(),
        }
        if active_policy_hash:
            payload["active_policy_hash"] = active_policy_hash
        if active_policy_version is not None:
            payload["active_policy_version"] = active_policy_version

        try:
            async with httpx.AsyncClient(
                base_url=self.endpoint,
                timeout=5.0,
                transport=self.transport,
            ) as client:
                response = await client.post(
                    f"/v1/gateways/{gateway_id}/heartbeat",
                    json=payload,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                response.raise_for_status()
                body = response.json()
                return body if isinstance(body, dict) else None
        except Exception:
            logger.warning("Failed to send Orion Gate heartbeat to Orion Cloud", exc_info=True)
            return None

    async def pull_policy_bundle(self) -> OrionYamlConfig:
        """Fetch the workspace's declarative policy bundle from Orion Cloud."""

        if not self.api_key:
            raise ValueError("ORION_API_KEY is required to sync policies from Orion Cloud")

        async with httpx.AsyncClient(
            base_url=self.endpoint,
            timeout=10.0,
            transport=self.transport,
        ) as client:
            response = await client.get(
                "/v1/telemetry/policy-bundle",
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            response.raise_for_status()
            body: dict[str, Any] = response.json()

        yaml_dict = body.get("orion_yaml")
        if isinstance(yaml_dict, dict) and yaml_dict:
            return parse_orion_yaml(yaml_dict, source_path="orion_cloud_bundle")
        yaml_text = str(body.get("orion_yaml_text") or "")
        return parse_orion_yaml(yaml_text, source_path="orion_cloud_bundle")


class GatewayControlPlaneAgent:
    """Optional background loop that registers this node, heartbeats, and hot-reloads policies.

    Completely inert unless both ORION_API_KEY and ORION_CLOUD_URL are configured.
    Any control-plane failure is logged and ignored so local traffic is never disrupted.
    """

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        api_key: str | None = None,
        endpoint: str | None = None,
    ) -> None:
        self.transport = transport
        self.api_key = api_key
        self.endpoint = endpoint
        self.gateway_id: str | None = None
        self.active_policy_version: int | None = None

    def _resolve_identity(self, cfg: OrionYamlConfig) -> tuple[str, str, str, str]:
        hostname = socket.gethostname()
        name = (
            os.getenv("ORION_GATEWAY_NAME", "").strip()
            or cfg.cloud.gateway_name
            or f"orion-gate-{hostname}"
        )
        node_key = (
            os.getenv("ORION_NODE_KEY", "").strip()
            or cfg.cloud.node_key
            or f"{hostname}-{cfg.primary_datasource.name}"
        )
        environment = (
            os.getenv("ORION_ENVIRONMENT", "").strip()
            or cfg.cloud.environment
            or "production"
        )
        return name, node_key, environment, hostname

    async def sync_once(self) -> bool:
        """Run one register/heartbeat + conditional policy hot-reload cycle. Returns True if reloaded."""

        cfg = get_active_orion_yaml()
        if cfg is None:
            return False
        client = CloudTelemetrySyncClient(
            cfg,
            api_key=self.api_key,
            endpoint=self.endpoint,
            transport=self.transport,
        )
        if not client.control_plane_enabled:
            return False

        name, node_key, environment, hostname = self._resolve_identity(cfg)
        sync_required = False

        if self.gateway_id is None:
            reg = await client.register_gateway(
                name=name,
                node_key=node_key,
                dialect=cfg.primary_datasource.dialect,
                environment=environment,
                active_policy_hash=cfg.policy_hash,
                active_policy_version=self.active_policy_version,
                hostname=hostname,
            )
            if not reg or not reg.get("id"):
                return False
            self.gateway_id = str(reg["id"])
            sync_required = bool(reg.get("policy_drift"))
        else:
            hb = await client.send_heartbeat(
                self.gateway_id,
                active_policy_hash=cfg.policy_hash,
                active_policy_version=self.active_policy_version,
                hostname=hostname,
            )
            if not hb:
                return False
            sync_required = bool(hb.get("sync_required") or hb.get("policy_drift"))

        if sync_required and cfg.cloud.sync_policies:
            try:
                pulled = await client.pull_policy_bundle()
                # Preserve local auth & cloud settings when hot-reloading policy rules from Cloud
                merged = replace(pulled, auth=cfg.auth, cloud=cfg.cloud)
                set_active_orion_yaml(merged)
                await client.send_heartbeat(
                    self.gateway_id,
                    active_policy_hash=merged.policy_hash,
                    active_policy_version=self.active_policy_version,
                    hostname=hostname,
                )
                logger.info(
                    "Hot-reloaded Orion Gate policy from Cloud (hash=%s)",
                    merged.policy_hash[:12],
                )
                return True
            except Exception:
                logger.warning(
                    "Policy hot-reload from Orion Cloud failed; keeping current local policy",
                    exc_info=True,
                )
        return False

    async def run_forever(self) -> None:
        """Continuously run heartbeat + policy-sync cycles until cancelled."""

        while True:
            interval = 30
            try:
                cfg = get_active_orion_yaml()
                if cfg is not None:
                    interval = max(5, int(cfg.cloud.heartbeat_interval_seconds))
                await self.sync_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("Gateway control-plane loop error; retrying", exc_info=True)
            await asyncio.sleep(interval)

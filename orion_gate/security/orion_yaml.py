"""Declarative `orion.yaml` standalone policy loader and evaluator for Orion Gate."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse
from uuid import UUID, uuid5

import yaml
from fastapi import HTTPException, Request, status
from jose import JWTError, jwt

from orion_gate.auth import AuthContext
from orion_gate.authz.connectors import EffectiveAccessScope, TenantFilter
from orion_gate.models import Connector, Workspace
from orion_gate.security.sql_policy import SQLDialect


ORION_YAML_NAMESPACE = UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
DEFAULT_STANDALONE_WORKSPACE_ID = UUID("00000000-0000-0000-0000-000000000100")
DEFAULT_STANDALONE_CONNECTOR_ID = UUID("00000000-0000-0000-0000-000000000001")

VALID_DIALECTS: set[str] = {"postgres", "mysql", "bigquery"}
VALID_PII_STRATEGIES: set[str] = {
    "redact",
    "redact_email",
    "mask_phone",
    "hash",
    "last4",
    "drop",
}
EMAIL_MASK_RE = re.compile(r"(?P<local>[A-Za-z0-9._%+-]+)@(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
PHONE_DIGITS_RE = re.compile(r"\d")


def _normalize_ident(value: str | None) -> str:
    return (value or "").strip().strip('"`[]').lower()


@dataclass(frozen=True)
class OrionYamlDatasource:
    """One SQL datasource configured in `orion.yaml`."""

    id: UUID
    name: str
    dialect: SQLDialect
    url_env: str | None = "DATABASE_URL"
    url: str | None = None
    config: dict[str, Any] = field(default_factory=dict)

    def resolve_connector_config(self) -> dict[str, Any]:
        """Resolve runtime connection parameters matching `get_connector` signatures."""

        raw = dict(self.config)
        raw_url = self.url
        if not raw_url and self.url_env:
            raw_url = os.getenv(self.url_env, "").strip() or None

        if self.dialect in {"postgres", "mysql"}:
            if not raw_url:
                host = raw.get("host", "localhost")
                port = raw.get("port", 5432 if self.dialect == "postgres" else 3306)
                database = raw.get("database", "postgres")
                user = raw.get("user") or raw.get("username") or "postgres"
                password = raw.get("password", "")
                scheme = "postgresql" if self.dialect == "postgres" else "mysql"
                raw_url = f"{scheme}://{user}:{password}@{host}:{port}/{database}"
            cfg: dict[str, Any] = {
                "connection_string": raw_url,
                "connector_id": str(self.id),
            }
            if "allowed_tables" in raw:
                cfg["allowed_tables"] = raw["allowed_tables"]
            return cfg

        if self.dialect == "bigquery":
            parsed = _parse_database_url(raw_url, "bigquery") if raw_url else {}
            project_id = str(raw.get("project_id") or parsed.get("project_id") or "")
            dataset_ids = raw.get("dataset_ids")
            if dataset_ids is None and (raw.get("dataset_id") or parsed.get("dataset_id")):
                dataset_ids = [str(raw.get("dataset_id") or parsed.get("dataset_id"))]
            sa_json = raw.get("service_account_json")
            creds_env = raw.get("credentials_json_env")
            if creds_env and not sa_json:
                env_val = os.getenv(str(creds_env), "").strip()
                if env_val:
                    sa_json = json.loads(env_val) if env_val.startswith("{") else {}
            return {
                "service_account_json": sa_json or {},
                "project_id": project_id,
                "dataset_ids": dataset_ids,
                "connector_id": str(self.id),
            }

        return {"connector_id": str(self.id)}

    def to_connector_model(self, workspace_id: UUID, allowed_tables: tuple[str, ...] | None) -> Connector:
        """Build an in-memory Connector model compatible with Orion Gate services."""

        cfg = self.resolve_connector_config()
        if allowed_tables is not None:
            cfg["allowed_tables"] = list(allowed_tables)
        connector = Connector(
            id=self.id,
            workspace_id=workspace_id,
            name=self.name,
            type=self.dialect,
            secret_id="orion_yaml_inline",
            schema_cache=json.dumps({"allowed_tables": list(allowed_tables)} if allowed_tables is not None else {}),
            is_active=True,
            workspace_default_access="workspace_query",
        )
        setattr(connector, "_standalone_config", cfg)
        return connector


@dataclass(frozen=True)
class OrionYamlTenantIsolation:
    """Declarative tenant isolation mapping in `orion.yaml`."""

    required: bool = False
    claim: str = "tenant_id"
    static_value: str | None = None
    tables: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class OrionYamlLimits:
    """Declarative execution limits in `orion.yaml`."""

    max_rows: int = 100
    timeout_seconds: int = 10
    allow_raw_pii: bool = False
    allow_raw_rows: bool = True
    allow_sql_visibility: bool = True
    minimum_group_size: int | None = None
    allow_cross_joins: bool = False
    max_query_cost: float | None = None
    max_bytes_billed: int | None = None
    differencing_budget: int = 5
    differencing_window_seconds: int = 300


@dataclass(frozen=True)
class OrionYamlPolicy:
    """Declarative SQL, schema, tenant, and PII policy in `orion.yaml`."""

    allowed_tables: tuple[str, ...] | None = None
    denied_tables: tuple[str, ...] = field(default_factory=tuple)
    allowed_columns: tuple[str, ...] | None = None
    denied_columns: tuple[str, ...] = field(default_factory=tuple)
    pii_masking: dict[str, str] = field(default_factory=dict)
    tenant_isolation: OrionYamlTenantIsolation = field(default_factory=OrionYamlTenantIsolation)
    limits: OrionYamlLimits = field(default_factory=OrionYamlLimits)
    allow_json_columns: bool = False
    allowed_json_paths: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class OrionYamlAuthConfig:
    """Standalone bearer/JWT authentication config for `orion.yaml` mode."""

    token_env: str = "ORION_LOCAL_TOKEN"
    jwt_secret_env: str = "ORION_JWT_SECRET"
    static_tokens: tuple[str, ...] = field(default_factory=tuple)
    allow_anonymous_local: bool = False


@dataclass(frozen=True)
class OrionYamlCloudConfig:
    """Optional Orion Cloud telemetry & policy sync configuration."""

    api_key_env: str = "ORION_API_KEY"
    endpoint_env: str = "ORION_CLOUD_URL"
    default_endpoint: str = "https://api.oriongate.dev"
    sync_telemetry: bool = True
    sync_policies: bool = False


@dataclass(frozen=True)
class OrionYamlConfig:
    """Validated top-level `orion.yaml` standalone configuration."""

    version: str
    workspace_id: UUID
    workspace_name: str
    datasources: tuple[OrionYamlDatasource, ...]
    policy: OrionYamlPolicy
    auth: OrionYamlAuthConfig = field(default_factory=OrionYamlAuthConfig)
    cloud: OrionYamlCloudConfig = field(default_factory=OrionYamlCloudConfig)
    source_path: str | None = None

    @property
    def primary_datasource(self) -> OrionYamlDatasource:
        return self.datasources[0]

    @property
    def policy_hash(self) -> str:
        payload = {
            "version": self.version,
            "workspace_id": str(self.workspace_id),
            "datasources": [
                {"id": str(ds.id), "name": ds.name, "dialect": ds.dialect}
                for ds in self.datasources
            ],
            "allowed_tables": self.policy.allowed_tables,
            "denied_tables": self.policy.denied_tables,
            "allowed_columns": self.policy.allowed_columns,
            "denied_columns": self.policy.denied_columns,
            "pii_masking": self.policy.pii_masking,
            "allow_json_columns": self.policy.allow_json_columns,
            "allowed_json_paths": self.policy.allowed_json_paths,
            "tenant_isolation": {
                "required": self.policy.tenant_isolation.required,
                "claim": self.policy.tenant_isolation.claim,
                "static_value": self.policy.tenant_isolation.static_value,
                "tables": self.policy.tenant_isolation.tables,
            },
            "limits": {
                "max_rows": self.policy.limits.max_rows,
                "timeout_seconds": self.policy.limits.timeout_seconds,
                "allow_raw_pii": self.policy.limits.allow_raw_pii,
                "allow_raw_rows": self.policy.limits.allow_raw_rows,
                "allow_cross_joins": self.policy.limits.allow_cross_joins,
                "minimum_group_size": self.policy.limits.minimum_group_size,
                "max_query_cost": self.policy.limits.max_query_cost,
                "max_bytes_billed": self.policy.limits.max_bytes_billed,
            },
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def resolve_datasource(self, requested_connector_id: str | UUID | None) -> OrionYamlDatasource:
        if not requested_connector_id:
            return self.primary_datasource
        target = str(requested_connector_id).strip().lower()
        for ds in self.datasources:
            if str(ds.id).lower() == target or ds.name.strip().lower() == target:
                return ds
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connector not found in orion.yaml",
        )

    def build_effective_scope(
        self,
        *,
        datasource: OrionYamlDatasource,
        auth: AuthContext,
        requested_tenant_values: dict[str, str] | None = None,
        surface: str = "gateway",
    ) -> EffectiveAccessScope:
        """Build a tenant-bound EffectiveAccessScope from `orion.yaml` + caller claims."""

        bound_values = dict(auth.embed_tenant_values or {})
        if auth.auth_type == "embed":
            if requested_tenant_values is not None and {
                str(k): str(v) for k, v in requested_tenant_values.items()
            } != {str(k): str(v) for k, v in bound_values.items()}:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Scoped token cannot override bound tenant values",
                )
            effective_values = bound_values
        else:
            effective_values = dict(requested_tenant_values or bound_values)

        ti = self.policy.tenant_isolation
        tenant_filters: list[TenantFilter] = []
        resolved_tenant_value: str | None = None

        if ti.tables or ti.required:
            claim_key = ti.claim
            if claim_key in effective_values and str(effective_values[claim_key]).strip():
                resolved_tenant_value = str(effective_values[claim_key]).strip()
            elif auth.embed_subject and getattr(auth.embed_subject, "external_tenant_id", None):
                resolved_tenant_value = str(auth.embed_subject.external_tenant_id).strip()
            elif ti.static_value and str(ti.static_value).strip():
                resolved_tenant_value = str(ti.static_value).strip()
            else:
                for table_name, col_name in ti.tables.items():
                    if col_name in effective_values and str(effective_values[col_name]).strip():
                        resolved_tenant_value = str(effective_values[col_name]).strip()
                        break

            if ti.required and not resolved_tenant_value:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Tenant isolation claim '{claim_key}' is required by orion.yaml policy",
                )

            if resolved_tenant_value:
                for table_name, col_name in sorted(ti.tables.items()):
                    norm_table = _normalize_ident(table_name)
                    norm_col = _normalize_ident(col_name)
                    if not norm_table or not norm_col:
                        continue
                    tenant_filters.append(
                        TenantFilter(
                            column=norm_col,
                            value=resolved_tenant_value,
                            table=norm_table,
                            required=True,
                            source="orion_yaml",
                        )
                    )

        dropped_pii_columns = tuple(
            _normalize_ident(col)
            for col, strategy in self.policy.pii_masking.items()
            if _normalize_ident(strategy) == "drop"
        )
        denied_columns = tuple(
            sorted(set(self.policy.denied_columns) | set(dropped_pii_columns))
        )

        token_claims = getattr(auth, "embed_token_claims", None) or {}
        max_rows = int(self.policy.limits.max_rows)
        if token_claims.get("max_result_rows"):
            max_rows = min(max_rows, int(token_claims["max_result_rows"]))

        allow_raw_rows = bool(self.policy.limits.allow_raw_rows)
        if "allow_raw_rows" in token_claims:
            allow_raw_rows = allow_raw_rows and bool(token_claims["allow_raw_rows"])

        scope_seed = f"{self.policy_hash}:{datasource.id}:{resolved_tenant_value or 'none'}:{max_rows}:{allow_raw_rows}"
        scope_version = f"yaml_{hashlib.sha256(scope_seed.encode('utf-8')).hexdigest()[:16]}"

        pii_masking_columns = tuple(
            sorted(
                col
                for key, strategy in self.policy.pii_masking.items()
                if _normalize_ident(strategy) != "drop"
                for col in (_normalize_ident(key), _normalize_ident(key).split(".")[-1])
                if col
            )
        )

        return EffectiveAccessScope(
            workspace_id=str(self.workspace_id),
            surface=surface,
            principal_type="embedded_user" if auth.auth_type == "embed" else "api_key",
            user_id=str(auth.user_id) if auth.user_id else None,
            member_id=None,
            role="member",
            connector_id=str(datasource.id),
            connector_access_level="query",
            external_user_id=str(auth.user_id) if auth.auth_type == "embed" and auth.user_id else None,
            external_tenant_id=resolved_tenant_value,
            allowed_tables=self.policy.allowed_tables,
            denied_tables=self.policy.denied_tables,
            allowed_columns=self.policy.allowed_columns,
            denied_columns=denied_columns,
            tenant_filters=tuple(tenant_filters),
            allow_raw_rows=allow_raw_rows,
            allow_sql_visibility=bool(self.policy.limits.allow_sql_visibility),
            max_result_rows=max_rows,
            max_execution_seconds=int(self.policy.limits.timeout_seconds),
            minimum_group_size=self.policy.limits.minimum_group_size,
            allow_json_columns=bool(self.policy.allow_json_columns),
            allowed_json_paths=self.policy.allowed_json_paths,
            allow_cross_joins=bool(self.policy.limits.allow_cross_joins),
            allow_raw_pii=bool(self.policy.limits.allow_raw_pii),
            pii_masking_columns=pii_masking_columns,
            max_query_cost=self.policy.limits.max_query_cost,
            max_bytes_billed=self.policy.limits.max_bytes_billed,
            differencing_budget=int(self.policy.limits.differencing_budget),
            differencing_window_seconds=int(self.policy.limits.differencing_window_seconds),
            scope_version=scope_version,
        )


def _parse_database_url(raw_url: str, dialect: SQLDialect) -> dict[str, Any]:
    """Parse a Postgres, MySQL, or BigQuery connection URL into connector config."""

    parsed = urlparse(raw_url)
    query = parse_qs(parsed.query)
    if dialect in {"postgres", "mysql"}:
        default_port = 5432 if dialect == "postgres" else 3306
        database = unquote(parsed.path.lstrip("/"))
        user = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        cfg: dict[str, Any] = {
            "host": parsed.hostname or "localhost",
            "port": parsed.port or default_port,
            "database": database,
            "user": user,
            "username": user,
            "password": password,
        }
        if "sslmode" in query and query["sslmode"]:
            cfg["ssl_mode"] = query["sslmode"][0]
        return cfg

    if dialect == "bigquery":
        project_id = parsed.hostname or unquote(parsed.netloc)
        dataset_id = unquote(parsed.path.lstrip("/"))
        return {
            "project_id": project_id,
            "dataset_id": dataset_id,
            "dataset": dataset_id,
        }
    return {}


def _flatten_column_collection(raw: Any, *, include_bare: bool = True) -> tuple[str, ...]:
    """Normalize a list of column strings or `{table: [cols]}` mapping into qualified lowercase names."""

    if not raw:
        return ()
    flattened: list[str] = []
    if isinstance(raw, dict):
        for table_name, cols in raw.items():
            norm_table = _normalize_ident(str(table_name))
            if isinstance(cols, (list, tuple, set)):
                for col in cols:
                    norm_col = _normalize_ident(str(col))
                    if norm_col:
                        flattened.append(f"{norm_table}.{norm_col}" if norm_table else norm_col)
                        if include_bare:
                            flattened.append(norm_col)
            elif isinstance(cols, str):
                norm_col = _normalize_ident(cols)
                if norm_col:
                    flattened.append(f"{norm_table}.{norm_col}" if norm_table else norm_col)
                    if include_bare:
                        flattened.append(norm_col)
    elif isinstance(raw, (list, tuple, set)):
        for item in raw:
            norm = _normalize_ident(str(item))
            if norm:
                flattened.append(norm)
                if include_bare and "." in norm:
                    flattened.append(norm.split(".")[-1])
    return tuple(sorted(set(flattened)))


def parse_orion_yaml(raw_data: str | dict[str, Any], *, source_path: str | None = None) -> OrionYamlConfig:
    """Parse and validate an `orion.yaml` document."""

    if isinstance(raw_data, str):
        try:
            loaded = yaml.safe_load(raw_data)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML syntax in orion.yaml: {exc}") from exc
    else:
        loaded = raw_data

    if not isinstance(loaded, dict):
        raise ValueError("orion.yaml root must be a mapping/object")

    version = str(loaded.get("version") or "1.0").strip()
    workspace_raw = loaded.get("workspace") or {}
    workspace_id_str = str(
        workspace_raw.get("id") or loaded.get("workspace_id") or DEFAULT_STANDALONE_WORKSPACE_ID
    )
    try:
        workspace_id = UUID(workspace_id_str)
    except ValueError as exc:
        raise ValueError(f"Invalid workspace_id UUID in orion.yaml: {workspace_id_str}") from exc
    workspace_name = str(workspace_raw.get("name") or loaded.get("workspace_name") or "Orion Gate Standalone")

    raw_datasources: list[dict[str, Any]] = []
    if isinstance(loaded.get("datasource"), dict):
        raw_datasources.append(loaded["datasource"])
    if isinstance(loaded.get("datasources"), list):
        raw_datasources.extend(item for item in loaded["datasources"] if isinstance(item, dict))

    if not raw_datasources:
        raise ValueError("orion.yaml must define `datasource` or `datasources`")

    datasources: list[OrionYamlDatasource] = []
    for idx, ds_raw in enumerate(raw_datasources):
        dialect = _normalize_ident(str(ds_raw.get("dialect") or ds_raw.get("type") or ""))
        if dialect not in VALID_DIALECTS:
            raise ValueError(
                f"Unsupported datasource dialect '{dialect}'. Expected one of: {sorted(VALID_DIALECTS)}"
            )
        ds_name = str(ds_raw.get("name") or (f"primary-{dialect}" if idx == 0 else f"{dialect}-{idx + 1}"))
        raw_id = ds_raw.get("id")
        if raw_id:
            ds_id = UUID(str(raw_id))
        elif idx == 0:
            ds_id = DEFAULT_STANDALONE_CONNECTOR_ID
        else:
            ds_id = uuid5(ORION_YAML_NAMESPACE, f"{workspace_id}:{ds_name}")

        url_env = str(ds_raw.get("url_env")).strip() if ds_raw.get("url_env") else None
        url = str(ds_raw.get("url")).strip() if ds_raw.get("url") else None
        extra_cfg = {
            k: v
            for k, v in ds_raw.items()
            if k not in {"id", "name", "dialect", "type", "url_env", "url"}
        }
        datasources.append(
            OrionYamlDatasource(
                id=ds_id,
                name=ds_name,
                dialect=dialect,  # type: ignore[arg-type]
                url_env=url_env if url_env is not None else ("DATABASE_URL" if not url and not extra_cfg else None),
                url=url,
                config=extra_cfg,
            )
        )

    policy_raw = loaded.get("policy") or {}
    if not isinstance(policy_raw, dict):
        raise ValueError("`policy` in orion.yaml must be a mapping")

    raw_allowed_tables = policy_raw.get("allowed_tables")
    allowed_tables: tuple[str, ...] | None = None
    if isinstance(raw_allowed_tables, (list, tuple, set)):
        allowed_tables = tuple(
            _normalize_ident(str(item))
            for item in raw_allowed_tables
            if _normalize_ident(str(item))
        )

    raw_denied_tables = policy_raw.get("denied_tables") or []
    denied_tables = tuple(
        _normalize_ident(str(item))
        for item in raw_denied_tables
        if _normalize_ident(str(item))
    )

    raw_allowed_columns = policy_raw.get("allowed_columns")
    allowed_columns = _flatten_column_collection(raw_allowed_columns, include_bare=False) or None
    denied_columns = _flatten_column_collection(policy_raw.get("denied_columns"), include_bare=True)
    allow_json_columns = bool(policy_raw.get("allow_json_columns", False))
    raw_allowed_json_paths = policy_raw.get("allowed_json_paths") or []
    if not isinstance(raw_allowed_json_paths, (list, tuple, set)):
        raise ValueError("`policy.allowed_json_paths` must be a list of dotted paths")
    allowed_json_paths = tuple(
        sorted(
            {
                _normalize_ident(str(item)).lstrip("$.")
                for item in raw_allowed_json_paths
                if _normalize_ident(str(item)).lstrip("$.")
            }
        )
    )

    raw_pii_masking = policy_raw.get("pii_masking") or {}
    if not isinstance(raw_pii_masking, dict):
        raise ValueError("`policy.pii_masking` must be a mapping of column -> strategy")
    pii_masking: dict[str, str] = {}
    for col_key, strategy_val in raw_pii_masking.items():
        norm_key = _normalize_ident(str(col_key))
        norm_strategy = _normalize_ident(str(strategy_val))
        if norm_strategy not in VALID_PII_STRATEGIES:
            raise ValueError(
                f"Unsupported pii_masking strategy '{strategy_val}' for '{col_key}'. "
                f"Expected one of: {sorted(VALID_PII_STRATEGIES)}"
            )
        pii_masking[norm_key] = norm_strategy

    ti_raw = policy_raw.get("tenant_isolation") or {}
    if not isinstance(ti_raw, dict):
        raise ValueError("`policy.tenant_isolation` must be a mapping")
    raw_ti_tables = ti_raw.get("tables") or {}
    if not isinstance(raw_ti_tables, dict):
        raise ValueError("`policy.tenant_isolation.tables` must be a mapping of table -> tenant_column")
    ti_tables = {
        _normalize_ident(str(tbl)): _normalize_ident(str(col))
        for tbl, col in raw_ti_tables.items()
        if _normalize_ident(str(tbl)) and _normalize_ident(str(col))
    }
    ti_required = bool(ti_raw.get("required", bool(ti_tables)))
    ti_claim = str(ti_raw.get("claim") or "tenant_id").strip()
    ti_static = str(ti_raw.get("static_value")).strip() if ti_raw.get("static_value") is not None else None
    tenant_isolation = OrionYamlTenantIsolation(
        required=ti_required,
        claim=ti_claim,
        static_value=ti_static,
        tables=ti_tables,
    )

    limits_raw = policy_raw.get("limits") or {}
    if not isinstance(limits_raw, dict):
        raise ValueError("`policy.limits` must be a mapping")
    max_rows = max(1, min(10_000, int(limits_raw.get("max_rows", 100))))
    timeout_seconds = max(1, min(120, int(limits_raw.get("timeout_seconds", 10))))
    allow_raw_pii = bool(limits_raw.get("allow_raw_pii", False))
    allow_raw_rows = bool(limits_raw.get("allow_raw_rows", True))
    allow_sql_visibility = bool(limits_raw.get("allow_sql_visibility", True))
    min_group_size = (
        int(limits_raw["minimum_group_size"])
        if limits_raw.get("minimum_group_size") is not None
        else None
    )
    allow_cross_joins = bool(limits_raw.get("allow_cross_joins", False))
    max_query_cost = (
        float(limits_raw["max_query_cost"])
        if limits_raw.get("max_query_cost") is not None
        else None
    )
    max_bytes_billed = (
        int(limits_raw["max_bytes_billed"])
        if limits_raw.get("max_bytes_billed") is not None
        else None
    )
    differencing_budget = max(1, int(limits_raw.get("differencing_budget", 5)))
    differencing_window_seconds = max(10, int(limits_raw.get("differencing_window_seconds", 300)))
    limits = OrionYamlLimits(
        max_rows=max_rows,
        timeout_seconds=timeout_seconds,
        allow_raw_pii=allow_raw_pii,
        allow_raw_rows=allow_raw_rows,
        allow_sql_visibility=allow_sql_visibility,
        minimum_group_size=min_group_size,
        allow_cross_joins=allow_cross_joins,
        max_query_cost=max_query_cost,
        max_bytes_billed=max_bytes_billed,
        differencing_budget=differencing_budget,
        differencing_window_seconds=differencing_window_seconds,
    )

    auth_raw = loaded.get("auth") or {}
    static_tokens = tuple(
        str(tok).strip()
        for tok in (auth_raw.get("static_tokens") or [])
        if str(tok).strip()
    )
    auth_cfg = OrionYamlAuthConfig(
        token_env=str(auth_raw.get("token_env") or "ORION_LOCAL_TOKEN").strip(),
        jwt_secret_env=str(auth_raw.get("jwt_secret_env") or "ORION_JWT_SECRET").strip(),
        static_tokens=static_tokens,
        allow_anonymous_local=bool(auth_raw.get("allow_anonymous_local", False)),
    )

    cloud_raw = loaded.get("cloud") or {}
    cloud_cfg = OrionYamlCloudConfig(
        api_key_env=str(cloud_raw.get("api_key_env") or "ORION_API_KEY").strip(),
        endpoint_env=str(cloud_raw.get("endpoint_env") or "ORION_CLOUD_URL").strip(),
        default_endpoint=str(cloud_raw.get("default_endpoint") or "https://api.oriongate.dev").strip(),
        sync_telemetry=bool(cloud_raw.get("sync_telemetry", True)),
        sync_policies=bool(cloud_raw.get("sync_policies", False)),
    )

    return OrionYamlConfig(
        version=version,
        workspace_id=workspace_id,
        workspace_name=workspace_name,
        datasources=tuple(datasources),
        policy=OrionYamlPolicy(
            allowed_tables=allowed_tables,
            denied_tables=denied_tables,
            allowed_columns=allowed_columns,
            denied_columns=denied_columns,
            pii_masking=pii_masking,
            tenant_isolation=tenant_isolation,
            limits=limits,
            allow_json_columns=allow_json_columns,
            allowed_json_paths=allowed_json_paths,
        ),
        auth=auth_cfg,
        cloud=cloud_cfg,
        source_path=source_path,
    )


def load_orion_yaml(path: str | Path) -> OrionYamlConfig:
    """Read and parse an `orion.yaml` configuration file from disk."""

    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"orion.yaml configuration file not found: {resolved}")
    content = resolved.read_text(encoding="utf-8")
    return parse_orion_yaml(content, source_path=str(resolved))


_ACTIVE_ORION_YAML: OrionYamlConfig | None = None
_CACHED_ENV_PATH: str | None = None
_CACHED_ENV_MTIME: float | None = None
_CACHED_ENV_CONFIG: OrionYamlConfig | None = None


def set_active_orion_yaml(config: OrionYamlConfig | None) -> None:
    """Explicitly register or clear the active standalone `orion.yaml` configuration."""

    global _ACTIVE_ORION_YAML
    _ACTIVE_ORION_YAML = config


def clear_active_orion_yaml() -> None:
    """Reset both explicit and env-cached standalone `orion.yaml` state."""

    global _ACTIVE_ORION_YAML, _CACHED_ENV_PATH, _CACHED_ENV_MTIME, _CACHED_ENV_CONFIG
    _ACTIVE_ORION_YAML = None
    _CACHED_ENV_PATH = None
    _CACHED_ENV_MTIME = None
    _CACHED_ENV_CONFIG = None


def get_active_orion_yaml() -> OrionYamlConfig | None:
    """Return the active standalone `orion.yaml` policy, auto-reloading `ORION_YAML_PATH` if set."""

    global _CACHED_ENV_PATH, _CACHED_ENV_MTIME, _CACHED_ENV_CONFIG
    if _ACTIVE_ORION_YAML is not None:
        return _ACTIVE_ORION_YAML

    env_path = os.getenv("ORION_YAML_PATH", "").strip()
    if not env_path:
        return None

    resolved = Path(env_path).expanduser().resolve()
    if not resolved.is_file():
        raise RuntimeError(f"ORION_YAML_PATH points to a missing file: {resolved}")

    mtime = resolved.stat().st_mtime
    if (
        _CACHED_ENV_CONFIG is not None
        and _CACHED_ENV_PATH == str(resolved)
        and _CACHED_ENV_MTIME == mtime
    ):
        return _CACHED_ENV_CONFIG

    config = load_orion_yaml(resolved)
    _CACHED_ENV_PATH = str(resolved)
    _CACHED_ENV_MTIME = mtime
    _CACHED_ENV_CONFIG = config
    return config


def issue_standalone_agent_token(
    config: OrionYamlConfig,
    *,
    subject: str = "standalone-agent",
    tenant_id: str | None = None,
    tenant_values: dict[str, str] | None = None,
    agent_role: str | None = None,
    purpose: str | None = None,
    allow_raw_rows: bool | None = None,
    max_result_rows: int | None = None,
    ttl_seconds: int = 900,
    secret: str | None = None,
) -> str:
    """Mint a standalone HS256 scoped agent JWT for `orion.yaml` deployments."""

    signing_secret = (
        secret
        or os.getenv(config.auth.jwt_secret_env, "").strip()
        or os.getenv("ORION_JWT_SECRET", "").strip()
        or os.getenv("ORION_EMBED_TOKEN_SECRET", "").strip()
        or os.getenv("ORION_SECRET_KEY", "").strip()
    )
    if not signing_secret:
        raise ValueError(
            f"Missing JWT signing secret. Set {config.auth.jwt_secret_env} or pass --secret."
        )

    now = datetime.now(timezone.utc)
    values = dict(tenant_values or {})
    claim_name = config.policy.tenant_isolation.claim
    if tenant_id is not None:
        values.setdefault(claim_name, tenant_id)

    payload: dict[str, Any] = {
        "iss": "orion-gate-standalone",
        "aud": "orion-gate",
        "sub": subject,
        "workspace_id": str(config.workspace_id),
        "connector_id": str(config.primary_datasource.id),
        "tenant_values": values,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    if tenant_id is not None:
        payload[claim_name] = tenant_id
        payload["external_tenant_id"] = tenant_id
    if agent_role:
        payload["agent_role"] = agent_role
    if purpose:
        payload["purpose"] = purpose
    if allow_raw_rows is not None:
        payload["allow_raw_rows"] = bool(allow_raw_rows)
    if max_result_rows is not None:
        payload["max_result_rows"] = int(max_result_rows)

    return jwt.encode(payload, signing_secret, algorithm="HS256")


def resolve_standalone_gateway_auth(
    request: Request,
    config: OrionYamlConfig,
) -> AuthContext:
    """Authenticate an Orion Gate caller against standalone `orion.yaml` auth settings."""

    workspace = Workspace(
        id=config.workspace_id,
        name=config.workspace_name,
        plan="standalone",
        owner_email="standalone@oriongate.local",
    )

    authorization = request.headers.get("Authorization")
    if not authorization or not authorization.startswith("Bearer "):
        if config.auth.allow_anonymous_local:
            auth = AuthContext(
                workspace_id=str(workspace.id),
                workspace=workspace,
                auth_type="api_key",
                user_id="anonymous-local",
            )
            request.state.workspace = workspace
            request.state.auth_type = "api_key"
            return auth
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    expected_tokens: set[str] = set(config.auth.static_tokens)
    env_token = os.getenv(config.auth.token_env, "").strip()
    if env_token:
        expected_tokens.add(env_token)
    cloud_key = os.getenv(config.cloud.api_key_env, "").strip()
    if cloud_key:
        expected_tokens.add(cloud_key)

    for candidate in expected_tokens:
        if hmac.compare_digest(token.encode("utf-8"), candidate.encode("utf-8")):
            auth = AuthContext(
                workspace_id=str(workspace.id),
                workspace=workspace,
                auth_type="api_key",
                user_id="standalone-operator",
            )
            request.state.workspace = workspace
            request.state.auth_type = "api_key"
            return auth

    jwt_secret = (
        os.getenv(config.auth.jwt_secret_env, "").strip()
        or os.getenv("ORION_JWT_SECRET", "").strip()
        or os.getenv("ORION_EMBED_TOKEN_SECRET", "").strip()
        or os.getenv("ORION_SECRET_KEY", "").strip()
    )
    if jwt_secret:
        try:
            claims = jwt.decode(
                token,
                jwt_secret,
                algorithms=["HS256"],
                audience="orion-gate",
                options={"require_exp": True, "verify_aud": True},
            )
            claim_workspace_id = claims.get("workspace_id")
            if claim_workspace_id is not None and str(claim_workspace_id).strip().lower() != str(workspace.id).lower():
                raise ValueError("Token workspace_id does not match active orion.yaml workspace")
            tenant_values: dict[str, str] = {}
            raw_tv = claims.get("tenant_values")
            if isinstance(raw_tv, dict):
                tenant_values.update({str(k): str(v) for k, v in raw_tv.items()})
            claim_key = config.policy.tenant_isolation.claim
            if claims.get(claim_key) is not None:
                tenant_values.setdefault(claim_key, str(claims[claim_key]))
            if claims.get("external_tenant_id") is not None:
                tenant_values.setdefault(claim_key, str(claims["external_tenant_id"]))

            connector_id = UUID(
                str(claims.get("connector_id") or config.primary_datasource.id)
            )
            auth = AuthContext(
                workspace_id=str(workspace.id),
                workspace=workspace,
                auth_type="embed",
                user_id=str(claims.get("sub") or "standalone-agent"),
                connector_id=str(connector_id),
                embed_tenant_values=tenant_values,
            )
            setattr(auth, "embed_token_claims", claims)
            request.state.workspace = workspace
            request.state.auth_type = "embed"
            return auth
        except (JWTError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid standalone Bearer token or JWT",
            ) from exc

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid standalone Bearer token",
    )


def _mask_email_value(value: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        local = match.group("local")
        domain = match.group("domain")
        prefix = local[0] if local else "*"
        return f"{prefix}***@{domain}"

    if "@" in value:
        masked, count = EMAIL_MASK_RE.subn(_replace, value)
        if count > 0:
            return masked
        parts = value.split("@", 1)
        prefix = parts[0][:1] if parts[0] else "*"
        return f"{prefix}***@{parts[1]}"
    return "[REDACTED_EMAIL]"


def _mask_phone_value(value: str) -> str:
    digits = PHONE_DIGITS_RE.findall(value)
    if len(digits) >= 4:
        last4 = "".join(digits[-4:])
        return f"***-***-{last4}"
    return "[REDACTED_PHONE]"


def _mask_cell_value(value: Any, strategy: str) -> Any:
    if value is None:
        return None
    text = str(value)
    if strategy == "redact":
        return "[REDACTED]"
    if strategy == "redact_email":
        return _mask_email_value(text)
    if strategy == "mask_phone":
        return _mask_phone_value(text)
    if strategy == "last4":
        return f"****{text[-4:]}" if len(text) >= 4 else "****"
    if strategy == "hash":
        return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]}"
    return "[REDACTED]"


def apply_yaml_pii_masking(
    rows: list[dict[str, Any]],
    column_names: list[str],
    pii_masking: dict[str, str],
    referenced_tables: tuple[str, ...] = (),
) -> tuple[list[dict[str, Any]], list[str]]:
    """Apply declarative `orion.yaml` column masking strategies to returned rows."""

    if not pii_masking or not column_names:
        return rows, []

    normalized_tables = {_normalize_ident(tbl).split(".")[-1] for tbl in referenced_tables if tbl}
    column_strategies: dict[str, str] = {}

    for col in column_names:
        norm_col = _normalize_ident(col)
        base_col = norm_col.split(".")[-1]
        if norm_col in pii_masking and pii_masking[norm_col] != "drop":
            column_strategies[col] = pii_masking[norm_col]
            continue
        if base_col in pii_masking and pii_masking[base_col] != "drop":
            column_strategies[col] = pii_masking[base_col]
            continue
        for rule_key, strategy in pii_masking.items():
            if strategy == "drop" or "." not in rule_key:
                continue
            rule_table, rule_col = rule_key.rsplit(".", 1)
            if rule_col == base_col and (not normalized_tables or rule_table in normalized_tables):
                column_strategies[col] = strategy
                break

    if not column_strategies:
        return rows, []

    masked_rows: list[dict[str, Any]] = []
    for row in rows:
        new_row = dict(row)
        for col, strategy in column_strategies.items():
            if col in new_row:
                new_row[col] = _mask_cell_value(new_row[col], strategy)
        masked_rows.append(new_row)

    return masked_rows, sorted(column_strategies.keys())

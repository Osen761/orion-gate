"""Deterministic schema projection for connector schema visibility."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from typing import Any

from orion_gate.authz.connectors import EffectiveAccessScope, access_at_least
from orion_gate.models import Connector, SchemaSnapshot


SENSITIVE_OBJECT_NAMES = {
    "api_keys",
    "secrets",
    "credentials",
    "tokens",
    "passwords",
    "sessions",
    "payroll",
    "salaries",
    "employee_reviews",
    "internal_notes",
    "audit_logs",
}
SENSITIVE_COLUMN_NAMES = {
    "password",
    "password_hash",
    "token",
    "secret",
    "api_key",
    "api_token",
    "auth_token",
    "access_token",
    "refresh_token",
    "jwt",
    "private_key",
    "national_id",
    "ssn",
    "card_number",
    "card_cvc",
    "card_last_four",
}
JSON_COLUMN_TYPES = {
    "json",
    "jsonb",
    "super",
    "variant",
    "object",
    "struct",
}
OBJECT_HEADER_RE = re.compile(
    r"^(?P<kind>Table|Collection|Sheet):\s+(?P<name>.+?)(?:\s+\(|$)"
)
DATASET_HEADER_RE = re.compile(r"^Dataset:\s+(?P<name>.+?)\s*$")
COLUMN_RE = re.compile(r"^\s*-\s+(?P<name>[^:]+):\s*(?P<type>.+?)\s*$")


@dataclass(frozen=True)
class SchemaColumn:
    """One projected schema column or field."""

    name: str
    type: str


@dataclass(frozen=True)
class SchemaObject:
    """One projected schema object such as a table, sheet, or collection."""

    name: str
    kind: str
    columns: tuple[SchemaColumn, ...] = field(default_factory=tuple)
    parent: str | None = None

    @property
    def qualified_name(self) -> str:
        if self.parent:
            return f"{self.parent}.{self.name}"
        return self.name


@dataclass(frozen=True)
class ProjectedSchema:
    """Projected schema safe to return to API callers or send to the model."""

    workspace_id: str
    connector_id: str
    scope_version: str
    projection_hash: str
    schema_text: str
    schema_json: dict[str, Any]
    included_objects: tuple[str, ...]
    excluded_objects: tuple[str, ...]
    included_columns: tuple[str, ...]
    denied_columns: tuple[str, ...]
    warnings: tuple[str, ...]
    created_at: datetime
    raw_schema_hash: str | None = None


def _normalize_identifier(value: str) -> str:
    return value.strip().strip('"`[]').lower()


def _is_sensitive_object(name: str) -> bool:
    normalized = _normalize_identifier(name).replace("-", "_")
    return normalized in SENSITIVE_OBJECT_NAMES


def _is_sensitive_column(name: str) -> bool:
    normalized = _normalize_identifier(name).replace("-", "_")
    return normalized in SENSITIVE_COLUMN_NAMES


def _is_json_column_type(column_type: str) -> bool:
    normalized = _normalize_identifier(column_type)
    base_type = re.split(r"[\s(<]", normalized, maxsplit=1)[0]
    return base_type in JSON_COLUMN_TYPES


def _identifier_set(values: tuple[str, ...] | None) -> set[str] | None:
    if values is None:
        return None
    return {_normalize_identifier(value) for value in values}


class SchemaProjectionService:
    """Project connector schema text through an effective access scope."""

    def __init__(self, session: Any | None = None) -> None:
        self.session = session

    def project_schema(
        self,
        connector: Connector,
        raw_schema: str,
        scope: EffectiveAccessScope,
    ) -> ProjectedSchema:
        """Return a deterministic projected schema for an access scope."""

        raw_objects = self._parse_schema_text(raw_schema, connector)
        allowed_tables = _identifier_set(scope.allowed_tables)
        denied_tables = _identifier_set(scope.denied_tables) or set()
        allowed_columns = _identifier_set(scope.allowed_columns)
        denied_columns = _identifier_set(scope.denied_columns) or set()
        apply_sensitive_defaults = not access_at_least(
            scope.connector_access_level or "none",
            "manage",
        )
        allow_json_columns = bool(getattr(scope, "allow_json_columns", False))
        allowed_json_paths = tuple(
            _normalize_identifier(path).lstrip("$.")
            for path in (getattr(scope, "allowed_json_paths", ()) or ())
            if _normalize_identifier(path).lstrip("$.")
        )

        included: list[SchemaObject] = []
        excluded_objects: list[str] = []
        denied_column_names: list[str] = []
        warnings: list[str] = []

        for schema_object in raw_objects:
            if self._object_denied(
                schema_object,
                allowed_tables,
                denied_tables,
                apply_sensitive_defaults,
            ):
                excluded_objects.append(schema_object.qualified_name)
                continue

            columns: list[SchemaColumn] = []
            for column in schema_object.columns:
                if self._column_denied(
                    schema_object,
                    column.name,
                    column.type,
                    allowed_columns,
                    denied_columns,
                    apply_sensitive_defaults,
                    allow_json_columns=allow_json_columns,
                    allowed_json_paths=allowed_json_paths,
                ):
                    denied_column_names.append(
                        f"{schema_object.qualified_name}.{column.name}"
                    )
                    continue
                columns.append(column)
            included.append(
                SchemaObject(
                    name=schema_object.name,
                    kind=schema_object.kind,
                    parent=schema_object.parent,
                    columns=tuple(columns),
                )
            )

        if not included:
            warnings.append("No schema objects are visible for this access scope.")
        if allowed_tables is None and not scope.denied_tables:
            warnings.append("Projection uses broad connector object visibility.")
        if apply_sensitive_defaults:
            warnings.append("Sensitive default schema denylist applied.")

        schema_json = self._to_schema_json(connector, scope, included, warnings)
        schema_text = self._to_schema_text(connector, included, warnings)
        raw_schema_hash = hashlib.sha256(raw_schema.encode("utf-8")).hexdigest()
        projection_hash = self._projection_hash(schema_json, scope)

        return ProjectedSchema(
            workspace_id=scope.workspace_id,
            connector_id=scope.connector_id or str(connector.id),
            scope_version=scope.scope_version,
            projection_hash=projection_hash,
            schema_text=schema_text,
            schema_json=schema_json,
            included_objects=tuple(item.qualified_name for item in included),
            excluded_objects=tuple(excluded_objects),
            included_columns=tuple(
                f"{item.qualified_name}.{column.name}"
                for item in included
                for column in item.columns
            ),
            denied_columns=tuple(denied_column_names),
            warnings=tuple(warnings),
            created_at=datetime.now(timezone.utc),
            raw_schema_hash=raw_schema_hash,
        )

    async def persist_snapshot(
        self,
        projected_schema: ProjectedSchema,
        scope: EffectiveAccessScope,
    ) -> SchemaSnapshot | None:
        """Persist a projected schema snapshot when a DB session is available."""

        if self.session is None:
            return None
        snapshot = SchemaSnapshot(
            workspace_id=UUID(projected_schema.workspace_id),
            connector_id=UUID(projected_schema.connector_id),
            created_by_user_id=UUID(scope.user_id) if scope.user_id else None,
            member_id=UUID(scope.member_id) if scope.member_id else None,
            scope_version=projected_schema.scope_version,
            schema_version=None,
            projection_hash=projected_schema.projection_hash,
            raw_schema_hash=projected_schema.raw_schema_hash,
            projected_schema_json=json.dumps(
                projected_schema.schema_json,
                sort_keys=True,
                separators=(",", ":"),
            ),
            projected_schema_text=projected_schema.schema_text,
            tables_count=len(projected_schema.included_objects),
            columns_count=len(projected_schema.included_columns),
            expires_at=scope.expires_at,
        )
        self.session.add(snapshot)
        await self.session.flush()
        return snapshot

    def _parse_schema_text(
        self,
        raw_schema: str,
        connector: Connector,
    ) -> list[SchemaObject]:
        current_parent: str | None = None
        current_object: dict[str, Any] | None = None
        objects: list[dict[str, Any]] = []
        fallback_columns: list[SchemaColumn] = []

        for raw_line in raw_schema.splitlines():
            line = raw_line.rstrip()
            dataset_match = DATASET_HEADER_RE.match(line.strip())
            if dataset_match:
                current_parent = dataset_match.group("name").strip()
                current_object = None
                continue

            object_match = OBJECT_HEADER_RE.match(line.strip())
            if object_match:
                current_object = {
                    "name": object_match.group("name").strip(),
                    "kind": object_match.group("kind").lower(),
                    "parent": current_parent,
                    "columns": [],
                }
                objects.append(current_object)
                continue

            column_match = COLUMN_RE.match(line)
            if not column_match:
                continue
            column = SchemaColumn(
                name=column_match.group("name").strip(),
                type=column_match.group("type").strip(),
            )
            if current_object is None:
                fallback_columns.append(column)
            else:
                current_object["columns"].append(column)

        if not objects and fallback_columns:
            objects.append(
                {
                    "name": getattr(connector, "name", None) or "dataset",
                    "kind": connector.type or "dataset",
                    "parent": None,
                    "columns": fallback_columns,
                }
            )

        return [
            SchemaObject(
                name=item["name"],
                kind=item["kind"],
                parent=item["parent"],
                columns=tuple(item["columns"]),
            )
            for item in objects
        ]

    def _object_denied(
        self,
        schema_object: SchemaObject,
        allowed_tables: set[str] | None,
        denied_tables: set[str],
        apply_sensitive_defaults: bool,
    ) -> bool:
        names = {
            _normalize_identifier(schema_object.name),
            _normalize_identifier(schema_object.qualified_name),
        }
        if schema_object.parent:
            names.add(_normalize_identifier(schema_object.parent))

        if names & denied_tables:
            return True
        if allowed_tables is not None and not (names & allowed_tables):
            return True
        if apply_sensitive_defaults and any(_is_sensitive_object(name) for name in names):
            return True
        return False

    def _column_denied(
        self,
        schema_object: SchemaObject,
        column_name: str,
        column_type: str,
        allowed_columns: set[str] | None,
        denied_columns: set[str],
        apply_sensitive_defaults: bool,
        *,
        allow_json_columns: bool = False,
        allowed_json_paths: tuple[str, ...] = (),
    ) -> bool:
        normalized = _normalize_identifier(column_name)
        qualified = _normalize_identifier(f"{schema_object.qualified_name}.{column_name}")
        table_qualified = _normalize_identifier(f"{schema_object.name}.{column_name}")
        if normalized in denied_columns or qualified in denied_columns:
            return True
        if allowed_columns is not None and normalized not in allowed_columns and qualified not in allowed_columns:
            return True
        if apply_sensitive_defaults and _is_sensitive_column(normalized):
            return True
        if apply_sensitive_defaults and _is_json_column_type(column_type) and not allow_json_columns:
            prefixes = (f"{normalized}.", f"{table_qualified}.", f"{qualified}.")
            if not any(path.startswith(prefixes) for path in allowed_json_paths):
                return True
        return False

    def _to_schema_json(
        self,
        connector: Connector,
        scope: EffectiveAccessScope,
        objects: list[SchemaObject],
        warnings: list[str],
    ) -> dict[str, Any]:
        return {
            "workspace_id": scope.workspace_id,
            "connector_id": scope.connector_id or str(connector.id),
            "connector_type": connector.type,
            "scope_version": scope.scope_version,
            "objects": [
                {
                    "name": item.name,
                    "qualified_name": item.qualified_name,
                    "kind": item.kind,
                    "parent": item.parent,
                    "columns": [
                        {"name": column.name, "type": column.type}
                        for column in item.columns
                    ],
                }
                for item in objects
            ],
            "warnings": list(warnings),
        }

    def _to_schema_text(
        self,
        connector: Connector,
        objects: list[SchemaObject],
        warnings: list[str],
    ) -> str:
        if not objects:
            return "No schema objects are visible for this access scope."

        lines = [f"Projected schema for {connector.name} ({connector.type})"]
        for item in objects:
            label = item.kind.capitalize()
            lines.append(f"{label}: {item.qualified_name}")
            if not item.columns:
                lines.append("  - No visible columns")
                continue
            for column in item.columns:
                lines.append(f"  - {column.name}: {column.type}")
        if warnings:
            lines.append("Warnings:")
            for warning in warnings:
                lines.append(f"  - {warning}")
        return "\n".join(lines)

    def _projection_hash(
        self,
        schema_json: dict[str, Any],
        scope: EffectiveAccessScope,
    ) -> str:
        payload = {
            "schema": schema_json,
            "scope": {
                "workspace_id": scope.workspace_id,
                "connector_id": scope.connector_id,
                "scope_version": scope.scope_version,
                "principal_type": scope.principal_type,
                "role": scope.role,
                "access": scope.connector_access_level,
                "allowed_tables": scope.allowed_tables,
                "denied_tables": scope.denied_tables,
                "allowed_columns": scope.allowed_columns,
                "denied_columns": scope.denied_columns,
            },
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

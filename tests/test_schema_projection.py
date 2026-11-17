"""Standalone schema projection and column/table filtering tests for Orion Gate."""

from __future__ import annotations

import json
import unittest
import uuid
from dataclasses import FrozenInstanceError

from orion_gate.authz.connectors import EffectiveAccessScope
from orion_gate.models import Connector
from orion_gate.security.schema_projection import ProjectedSchema, SchemaProjectionService


RAW_SCHEMA = """Table: customers (10 rows)
  - id: integer
  - email: text
  - name: text
  - password_hash: text
Table: orders (20 rows)
  - id: integer
  - customer_id: integer
  - total: numeric
  - card_number: text
Table: api_keys (2 rows)
  - key_hash: text
  - secret: text
Table: payroll (3 rows)
  - employee_id: integer
  - salary: numeric
"""


def _public_schema_json_text(projected: ProjectedSchema) -> str:
    return json.dumps(projected.schema_json.get("objects", []))


def make_connector() -> Connector:
    return Connector(
        id=uuid.uuid4(),
        workspace_id=uuid.uuid4(),
        type="postgres",
        name="Warehouse",
        secret_id="orion_yaml_inline",
        is_active=True,
        workspace_default_access="restricted",
    )


def make_scope(
    connector: Connector,
    *,
    access: str = "query",
    allowed_tables: tuple[str, ...] | None = ("customers", "orders"),
    denied_tables: tuple[str, ...] = (),
    allowed_columns: tuple[str, ...] | None = None,
    denied_columns: tuple[str, ...] = (),
    role: str = "analyst",
) -> EffectiveAccessScope:
    return EffectiveAccessScope(
        workspace_id=str(connector.workspace_id),
        surface="gateway",
        principal_type="api_key",
        user_id=str(uuid.uuid4()),
        member_id=None,
        role=role,
        connector_id=str(connector.id),
        connector_access_level=access,
        allowed_tables=allowed_tables,
        denied_tables=denied_tables,
        allowed_columns=allowed_columns,
        denied_columns=denied_columns,
    )


class SchemaProjectionTests(unittest.TestCase):
    def test_projection_includes_allowed_tables(self):
        connector = make_connector()
        projected = SchemaProjectionService().project_schema(
            connector,
            RAW_SCHEMA,
            make_scope(connector, allowed_tables=("customers",)),
        )

        self.assertEqual(projected.included_objects, ("customers",))
        self.assertIn("Table: customers", projected.schema_text)
        self.assertNotIn("orders", projected.schema_text)

    def test_projection_excludes_denied_tables(self):
        connector = make_connector()
        projected = SchemaProjectionService().project_schema(
            connector,
            RAW_SCHEMA,
            make_scope(connector, allowed_tables=None, denied_tables=("payroll",)),
        )

        self.assertNotIn("payroll", projected.schema_text)
        self.assertNotIn("payroll", _public_schema_json_text(projected))

    def test_projection_excludes_denied_columns(self):
        connector = make_connector()
        projected = SchemaProjectionService().project_schema(
            connector,
            RAW_SCHEMA,
            make_scope(connector, denied_columns=("email",)),
        )

        self.assertNotIn("email", projected.schema_text)
        self.assertIn("customers.email", projected.denied_columns)

    def test_sensitive_default_denylist_excludes_secret_columns(self):
        connector = make_connector()
        projected = SchemaProjectionService().project_schema(
            connector,
            RAW_SCHEMA,
            make_scope(connector, allowed_tables=("customers", "orders")),
        )

        self.assertNotIn("password_hash", projected.schema_text)
        self.assertNotIn("card_number", projected.schema_text)
        self.assertIn("customers.password_hash", projected.denied_columns)
        self.assertIn("orders.card_number", projected.denied_columns)

    def test_sensitive_default_denylist_excludes_secret_tables(self):
        connector = make_connector()
        projected = SchemaProjectionService().project_schema(
            connector,
            RAW_SCHEMA,
            make_scope(connector, allowed_tables=None),
        )

        self.assertNotIn("api_keys", projected.schema_text)
        self.assertNotIn("payroll", projected.schema_text)
        self.assertNotIn("api_keys", _public_schema_json_text(projected))
        self.assertNotIn("payroll", _public_schema_json_text(projected))

    def test_manage_scope_can_see_connector_permitted_sensitive_schema(self):
        connector = make_connector()
        projected = SchemaProjectionService().project_schema(
            connector,
            RAW_SCHEMA,
            make_scope(connector, access="manage", allowed_tables=None, role="owner"),
        )

        self.assertIn("api_keys", projected.schema_text)
        self.assertIn("password_hash", projected.schema_text)

    def test_projection_hash_is_deterministic_for_same_input_and_scope(self):
        connector = make_connector()
        scope = make_scope(connector)
        service = SchemaProjectionService()

        first = service.project_schema(connector, RAW_SCHEMA, scope)
        second = service.project_schema(connector, RAW_SCHEMA, scope)

        self.assertEqual(first.projection_hash, second.projection_hash)

    def test_projected_schema_object_is_immutable(self):
        connector = make_connector()
        projected = SchemaProjectionService().project_schema(
            connector,
            RAW_SCHEMA,
            make_scope(connector),
        )

        with self.assertRaises(FrozenInstanceError):
            projected.schema_text = "raw"  # type: ignore[misc]

    def test_projected_schema_text_is_safe_to_send_to_model(self):
        connector = make_connector()
        projected = SchemaProjectionService().project_schema(
            connector,
            RAW_SCHEMA,
            make_scope(connector, allowed_tables=("customers",)),
        )

        self.assertIn("customers", projected.schema_text)
        self.assertNotIn("api_keys", projected.schema_text)
        self.assertNotIn("payroll", projected.schema_text)
        self.assertNotIn("password_hash", projected.schema_text)


if __name__ == "__main__":
    unittest.main()

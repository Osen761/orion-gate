"""Connector capability metadata for Orion Gate."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal


RiskLevel = Literal["production_supported", "limited_preview", "development_only"]


@dataclass(frozen=True)
class ConnectorCapabilities:
    policy_sql_supported: bool
    result_policy_supported: bool
    structured_schema_supported: bool
    production_ready: bool
    risk_level: RiskLevel

    def model_dump(self) -> dict[str, object]:
        return asdict(self)


CONNECTOR_CAPABILITIES: dict[str, ConnectorCapabilities] = {
    "postgres": ConnectorCapabilities(True, True, False, True, "production_supported"),
    "mysql": ConnectorCapabilities(True, True, False, True, "production_supported"),
    "bigquery": ConnectorCapabilities(True, True, False, True, "production_supported"),
}


def get_connector_capabilities(connector_type: str) -> ConnectorCapabilities:
    return CONNECTOR_CAPABILITIES.get(
        connector_type,
        ConnectorCapabilities(False, False, False, False, "development_only"),
    )

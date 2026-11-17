"""Connector registry for Orion Gate with lazy SQL driver imports."""

from __future__ import annotations

import importlib

from orion_gate.connectors.base import BaseConnector


CONNECTOR_TYPES: dict[str, tuple[str, str]] = {
    "postgres": ("orion_gate.connectors.postgres", "PostgresConnector"),
    "bigquery": ("orion_gate.connectors.bigquery", "BigQueryConnector"),
    "mysql": ("orion_gate.connectors.mysql", "MySQLConnector"),
}


def get_connector(connector_type: str, config: dict) -> BaseConnector:
    """Instantiate a SQL connector, importing only the requested driver."""

    target = CONNECTOR_TYPES.get(connector_type)
    if target is None:
        raise ValueError(f"Unsupported connector type: {connector_type}")
    module_name, class_name = target
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise RuntimeError(
            f"Database driver for '{connector_type}' is not installed. "
            f"Install with `pip install 'orion-gate[{connector_type}]'`."
        ) from exc
    connector_class = getattr(module, class_name)
    return connector_class(**config)

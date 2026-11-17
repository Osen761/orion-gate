"""Base connector interface for Orion Gate SQL datasources."""

from __future__ import annotations

from abc import ABC, abstractmethod

import pandas as pd


class BaseConnector(ABC):
    """Abstract base class implemented by every SQL connector."""

    @abstractmethod
    def get_schema(self) -> str:
        """Return a text schema summary."""

    @abstractmethod
    def execute_sql(self, sql: str) -> tuple[pd.DataFrame, str]:
        """Execute a governed read-only SQL query and return DataFrame + safe text output."""

    @abstractmethod
    def test_connection(self) -> bool:
        """Verify database connectivity."""

    @abstractmethod
    def get_sample(self, table: str, n: int = 5) -> pd.DataFrame:
        """Return a small sample DataFrame for a table."""

    def close(self) -> None:
        """Release any connector-owned resources cleanly."""
        return None

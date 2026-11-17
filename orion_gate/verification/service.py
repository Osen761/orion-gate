"""Deterministic verification foundation for safe analysis results."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID


if TYPE_CHECKING:
    from orion_gate.authz.connectors import EffectiveAccessScope
    from orion_gate.security.result_policy import ResultPolicyDecision, SafeQueryResult
    from orion_gate.security.schema_projection import ProjectedSchema
    from orion_gate.security.sql_policy import SQLPolicyDecision


logger = logging.getLogger("orion.verification")

VerificationStatus = Literal[
    "verified",
    "needs_review",
    "clarification_required",
    "incomplete_data",
    "unable_to_verify",
    "failed",
]
CheckStatus = Literal["passed", "warning", "failed", "skipped"]
ConfidenceLabel = Literal["high", "medium", "low", "not_available"]

POLICY_VERSION = "phase_1g_v1"
DEFAULT_SMALL_SAMPLE_ROWS = 3
DEFAULT_SMALL_GROUP_THRESHOLD = 5
DEFAULT_NULL_WARNING_THRESHOLD = 0.50
DEFAULT_NULL_INCOMPLETE_THRESHOLD = 0.75
DEFAULT_MANY_COLUMNS_THRESHOLD = 25

CURRENT_PERIOD_RE = re.compile(
    r"\b(today|this\s+week|this\s+month|current\s+month|current\s+quarter|this\s+year)\b",
    flags=re.IGNORECASE,
)
COMPLETED_PERIOD_RE = re.compile(
    r"\b(complete|completed|closed|previous|last\s+(?:week|month|quarter|year))\b",
    flags=re.IGNORECASE,
)
COUNT_COLUMN_NAMES = {"count", "n", "row_count", "total_count", "user_count", "customer_count"}


@dataclass(frozen=True)
class VerificationWarning:
    """One safe verification warning."""

    code: str
    message: str
    severity: str = "warning"


@dataclass(frozen=True)
class VerificationCheck:
    """One deterministic verification check result."""

    name: str
    status: CheckStatus
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VerificationContext:
    """Inputs required to verify a safe result and related analysis metadata."""

    scope: "EffectiveAccessScope | None" = None
    projected_schema: "ProjectedSchema | None" = None
    sql_policy_decision: "SQLPolicyDecision | None" = None
    result_policy_decision: "ResultPolicyDecision | None" = None
    safe_result: "SafeQueryResult | None" = None
    question: str = ""
    generated_sql: str | None = None
    connector_type: str | None = None
    analysis_metadata: dict[str, Any] = field(default_factory=dict)
    now: datetime | None = None


@dataclass(frozen=True)
class VerificationResult:
    """Structured verification output for an analysis run."""

    status: VerificationStatus
    checks: tuple[VerificationCheck, ...]
    warnings: tuple[VerificationWarning, ...]
    summary: str
    confidence_label: ConfidenceLabel
    should_show_answer: bool
    should_show_caveat: bool
    caveat_text: str | None
    verified_at: datetime
    policy_version: str = POLICY_VERSION

    def to_model_text(self) -> str:
        """Return short model-safe verification text for tool output."""

        lines = [f"Result verification: {self.status}"]
        if self.caveat_text:
            lines.append(f"Caveat: {self.caveat_text}")
        return "\n".join(lines)


def _json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _json_loads(value: str | None) -> Any:
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _uuid_or_none(value: Any) -> UUID | None:
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


def _safe_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Keep verification metadata count-based and schema-safe."""

    if not metadata:
        return {}
    safe: dict[str, Any] = {}
    for key, value in metadata.items():
        if isinstance(value, (int, float, bool)) or value is None:
            safe[key] = value
        elif isinstance(value, str):
            safe[key] = value[:120]
        elif isinstance(value, (list, tuple, set)):
            safe[f"{key}_count"] = len(value)
        elif isinstance(value, dict):
            safe[f"{key}_count"] = len(value)
        else:
            safe[key] = str(value)[:120]
    return safe


def _check_payload(checks: tuple[VerificationCheck, ...]) -> list[dict[str, Any]]:
    return [
        {
            "name": check.name,
            "status": check.status,
            "message": check.message,
            "metadata": _safe_metadata(check.metadata),
        }
        for check in checks
    ]


def _warning_payload(warnings: tuple[VerificationWarning, ...]) -> list[dict[str, str]]:
    return [
        {
            "code": warning.code,
            "message": warning.message,
            "severity": warning.severity,
        }
        for warning in warnings
    ]


class VerificationService:
    """Run deterministic verification checks and optionally persist results."""

    def __init__(
        self,
        session: Any | None = None,
        *,
        small_sample_rows: int = DEFAULT_SMALL_SAMPLE_ROWS,
        small_group_threshold: int = DEFAULT_SMALL_GROUP_THRESHOLD,
        null_warning_threshold: float = DEFAULT_NULL_WARNING_THRESHOLD,
        null_incomplete_threshold: float = DEFAULT_NULL_INCOMPLETE_THRESHOLD,
        many_columns_threshold: int = DEFAULT_MANY_COLUMNS_THRESHOLD,
    ) -> None:
        self.session = session
        self.small_sample_rows = small_sample_rows
        self.small_group_threshold = small_group_threshold
        self.null_warning_threshold = null_warning_threshold
        self.null_incomplete_threshold = null_incomplete_threshold
        self.many_columns_threshold = many_columns_threshold

    def verify(self, context: VerificationContext) -> VerificationResult:
        """Return deterministic verification output for a safe result."""

        checks: list[VerificationCheck] = []
        warnings: list[VerificationWarning] = []
        status_signals: list[VerificationStatus] = []

        try:
            self._policy_check(context, checks, warnings, status_signals)
            self._result_presence_check(context, checks, status_signals)
            self._empty_result_check(context, checks, warnings, status_signals)
            self._truncation_check(context, checks, warnings, status_signals)
            self._redaction_check(context, checks, warnings, status_signals)
            self._small_sample_check(context, checks, warnings, status_signals)
            self._null_rate_check(context, checks, warnings, status_signals)
            self._current_period_check(context, checks, warnings, status_signals)
            self._result_type_check(context, checks, warnings, status_signals)
            self._result_size_check(context, checks, warnings, status_signals)
            self._clarification_check(context, checks, warnings, status_signals)

            status = self._final_status(status_signals)
            summary = self._summary(status, checks)
            confidence = self._confidence_label(status)
            caveat = self._caveat_text(status, warnings, checks)
            return VerificationResult(
                status=status,
                checks=tuple(checks),
                warnings=tuple(warnings),
                summary=summary,
                confidence_label=confidence,
                should_show_answer=status != "failed",
                should_show_caveat=bool(caveat),
                caveat_text=caveat,
                verified_at=context.now or datetime.now(timezone.utc),
            )
        except Exception:
            logger.exception("Verification failed unexpectedly")
            failed_check = VerificationCheck(
                "verification_runtime",
                "failed",
                "Verification failed before completing deterministic checks.",
            )
            return VerificationResult(
                status="failed",
                checks=tuple([*checks, failed_check]),
                warnings=tuple(warnings),
                summary="Failed: verification could not complete.",
                confidence_label="not_available",
                should_show_answer=False,
                should_show_caveat=True,
                caveat_text="Verification failed before the result could be checked.",
                verified_at=context.now or datetime.now(timezone.utc),
            )


    def _policy_check(
        self,
        context: VerificationContext,
        checks: list[VerificationCheck],
        warnings: list[VerificationWarning],
        status_signals: list[VerificationStatus],
    ) -> None:
        sql_decision = context.sql_policy_decision
        result_decision = context.result_policy_decision
        if sql_decision is not None and not sql_decision.allowed:
            checks.append(
                VerificationCheck(
                    "policy_decision",
                    "failed",
                    "SQL policy denied the query.",
                    {"sql_allowed": False},
                )
            )
            status_signals.append("failed")
            return
        if result_decision is not None:
            if not result_decision.allowed:
                checks.append(
                    VerificationCheck(
                        "policy_decision",
                        "failed",
                        "Result policy denied or withheld the result.",
                        {"result_allowed": False, "decision": result_decision.decision},
                    )
                )
                status_signals.append(
                    "needs_review" if result_decision.decision == "requires_review" else "failed"
                )
                return
            if result_decision.decision in {"redacted", "requires_review"}:
                checks.append(
                    VerificationCheck(
                        "policy_decision",
                        "warning",
                        "Policy allowed the result with restrictions.",
                        {"decision": result_decision.decision},
                    )
                )
                status_signals.append("needs_review")
            else:
                checks.append(
                    VerificationCheck(
                        "policy_decision",
                        "passed",
                        "Policy decisions allowed the result.",
                    )
                )
            for warning in result_decision.warnings:
                warnings.append(
                    VerificationWarning("result_policy_warning", str(warning))
                )
                status_signals.append("needs_review")
            return
        if sql_decision is None:
            checks.append(
                VerificationCheck(
                    "policy_decision",
                    "skipped",
                    "No policy decision metadata was available.",
                )
            )
            if context.safe_result is None:
                status_signals.append("unable_to_verify")
            return
        checks.append(
            VerificationCheck(
                "policy_decision",
                "passed",
                "SQL policy allowed the query.",
            )
        )

    def _result_presence_check(
        self,
        context: VerificationContext,
        checks: list[VerificationCheck],
        status_signals: list[VerificationStatus],
    ) -> None:
        if context.safe_result is not None:
            checks.append(
                VerificationCheck(
                    "result_presence",
                    "passed",
                    "A safe result was available for verification.",
                    {
                        "row_count": context.safe_result.row_count,
                        "column_count": context.safe_result.column_count,
                    },
                )
            )
            return
        checks.append(
            VerificationCheck(
                "result_presence",
                "failed",
                "No safe result was available for verification.",
            )
        )
        if context.sql_policy_decision is not None and not context.sql_policy_decision.allowed:
            status_signals.append("failed")
        elif context.result_policy_decision is not None and not context.result_policy_decision.allowed:
            status_signals.append("failed")
        else:
            status_signals.append("unable_to_verify")

    def _empty_result_check(
        self,
        context: VerificationContext,
        checks: list[VerificationCheck],
        warnings: list[VerificationWarning],
        status_signals: list[VerificationStatus],
    ) -> None:
        result = context.safe_result
        if result is None:
            checks.append(VerificationCheck("empty_result", "skipped", "No result rows to inspect."))
            return
        if result.row_count == 0:
            checks.append(
                VerificationCheck(
                    "empty_result",
                    "warning",
                    "No matching rows were returned.",
                    {"row_count": 0},
                )
            )
            warnings.append(
                VerificationWarning(
                    "empty_result",
                    "No matching data was found for the requested filters.",
                )
            )
            status_signals.append("incomplete_data")
            return
        checks.append(
            VerificationCheck("empty_result", "passed", "Result contains at least one row.")
        )

    def _truncation_check(
        self,
        context: VerificationContext,
        checks: list[VerificationCheck],
        warnings: list[VerificationWarning],
        status_signals: list[VerificationStatus],
    ) -> None:
        result = context.safe_result
        if result is None:
            checks.append(VerificationCheck("row_truncation", "skipped", "No result to inspect."))
            return
        if result.truncated:
            checks.append(
                VerificationCheck(
                    "row_truncation",
                    "warning",
                    "Result was truncated before analysis.",
                    {"returned_row_count": result.row_count},
                )
            )
            warnings.append(
                VerificationWarning(
                    "row_truncation",
                    "Only a limited result was used for the answer.",
                )
            )
            status_signals.append("needs_review")
            return
        checks.append(VerificationCheck("row_truncation", "passed", "Result was not truncated."))

    def _redaction_check(
        self,
        context: VerificationContext,
        checks: list[VerificationCheck],
        warnings: list[VerificationWarning],
        status_signals: list[VerificationStatus],
    ) -> None:
        result = context.safe_result
        decision = context.result_policy_decision
        redacted = bool(result and result.redacted) or bool(
            decision and decision.redacted_columns
        )
        if redacted:
            redacted_count = len(decision.redacted_columns) if decision else 0
            checks.append(
                VerificationCheck(
                    "redaction",
                    "warning",
                    "Restricted fields or values were removed from the result.",
                    {"redacted_columns_count": redacted_count},
                )
            )
            warnings.append(
                VerificationWarning(
                    "redaction",
                    "Restricted fields were removed before analysis.",
                )
            )
            status_signals.append("needs_review")
            return
        checks.append(VerificationCheck("redaction", "passed", "No result redaction was reported."))

    def _small_sample_check(
        self,
        context: VerificationContext,
        checks: list[VerificationCheck],
        warnings: list[VerificationWarning],
        status_signals: list[VerificationStatus],
    ) -> None:
        result = context.safe_result
        if result is None or result.row_count == 0:
            checks.append(VerificationCheck("small_sample", "skipped", "No non-empty sample to inspect."))
            return

        small_group_count = self._small_group_count(result)
        policy_small_group = bool(
            context.result_policy_decision
            and context.result_policy_decision.small_group_warnings
        )
        if result.result_type == "single_value" and not policy_small_group:
            checks.append(
                VerificationCheck(
                    "small_sample",
                    "passed",
                    "Single-value aggregate result passed small-sample checks.",
                    {"row_count": result.row_count},
                )
            )
            return
        if result.result_type == "aggregate" and not small_group_count and not policy_small_group:
            checks.append(
                VerificationCheck(
                    "small_sample",
                    "passed",
                    "Aggregate result passed small-sample checks.",
                    {"row_count": result.row_count},
                )
            )
            return
        if result.row_count <= self.small_sample_rows or small_group_count or policy_small_group:
            checks.append(
                VerificationCheck(
                    "small_sample",
                    "warning",
                    "Result may be based on a small sample.",
                    {
                        "row_count": result.row_count,
                        "small_group_count": small_group_count,
                        "policy_small_group_warning": policy_small_group,
                    },
                )
            )
            warnings.append(
                VerificationWarning(
                    "small_sample",
                    "The result is based on a small sample or small groups.",
                )
            )
            status_signals.append("needs_review")
            return
        checks.append(
            VerificationCheck(
                "small_sample",
                "passed",
                "Result sample size passed basic checks.",
                {"row_count": result.row_count},
            )
        )

    def _null_rate_check(
        self,
        context: VerificationContext,
        checks: list[VerificationCheck],
        warnings: list[VerificationWarning],
        status_signals: list[VerificationStatus],
    ) -> None:
        result = context.safe_result
        if result is None or result.row_count == 0:
            checks.append(VerificationCheck("null_rate", "skipped", "No rows to inspect for nulls."))
            return

        high_null_columns = 0
        incomplete_null_columns = 0
        for column in result.columns:
            null_count = sum(1 for row in result.rows if row.get(column.name) is None)
            null_rate = null_count / max(result.row_count, 1)
            if null_rate >= self.null_incomplete_threshold:
                incomplete_null_columns += 1
            elif null_rate >= self.null_warning_threshold:
                high_null_columns += 1

        if incomplete_null_columns:
            checks.append(
                VerificationCheck(
                    "null_rate",
                    "warning",
                    "Some result columns are mostly null.",
                    {"affected_columns_count": incomplete_null_columns + high_null_columns},
                )
            )
            warnings.append(
                VerificationWarning(
                    "high_null_rate",
                    "Some result fields are mostly empty, so the data may be incomplete.",
                )
            )
            status_signals.append("incomplete_data")
            return
        if high_null_columns:
            checks.append(
                VerificationCheck(
                    "null_rate",
                    "warning",
                    "Some result columns have many null values.",
                    {"affected_columns_count": high_null_columns},
                )
            )
            warnings.append(
                VerificationWarning(
                    "high_null_rate",
                    "Some result fields contain many empty values.",
                )
            )
            status_signals.append("needs_review")
            return
        checks.append(VerificationCheck("null_rate", "passed", "Null rates passed basic checks."))

    def _current_period_check(
        self,
        context: VerificationContext,
        checks: list[VerificationCheck],
        warnings: list[VerificationWarning],
        status_signals: list[VerificationStatus],
    ) -> None:
        question = context.question or ""
        if not CURRENT_PERIOD_RE.search(question):
            checks.append(
                VerificationCheck(
                    "date_coverage",
                    "skipped",
                    "Question did not ask for an obviously current period.",
                )
            )
            return
        if COMPLETED_PERIOD_RE.search(question):
            checks.append(
                VerificationCheck(
                    "date_coverage",
                    "passed",
                    "Question appears to reference a completed period.",
                )
            )
            return
        checks.append(
            VerificationCheck(
                "date_coverage",
                "warning",
                "Question references a current period that may be incomplete.",
            )
        )
        warnings.append(
            VerificationWarning(
                "incomplete_period",
                "The requested current period may be incomplete.",
            )
        )
        status_signals.append("needs_review")

    def _result_type_check(
        self,
        context: VerificationContext,
        checks: list[VerificationCheck],
        warnings: list[VerificationWarning],
        status_signals: list[VerificationStatus],
    ) -> None:
        result = context.safe_result
        if result is None:
            checks.append(VerificationCheck("result_type", "skipped", "No result type to inspect."))
            return
        if result.result_type == "unknown":
            checks.append(
                VerificationCheck(
                    "result_type",
                    "warning",
                    "Result type could not be classified.",
                )
            )
            warnings.append(
                VerificationWarning(
                    "unknown_result_type",
                    "The result type could not be classified for verification.",
                )
            )
            status_signals.append("unable_to_verify")
            return
        checks.append(
            VerificationCheck(
                "result_type",
                "passed",
                "Result type was classified.",
                {"result_type": result.result_type},
            )
        )

    def _result_size_check(
        self,
        context: VerificationContext,
        checks: list[VerificationCheck],
        warnings: list[VerificationWarning],
        status_signals: list[VerificationStatus],
    ) -> None:
        result = context.safe_result
        if result is None:
            checks.append(VerificationCheck("result_size", "skipped", "No result size to inspect."))
            return
        if result.column_count > self.many_columns_threshold:
            checks.append(
                VerificationCheck(
                    "result_size",
                    "warning",
                    "Result has many columns and may be hard to verify.",
                    {"column_count": result.column_count},
                )
            )
            warnings.append(
                VerificationWarning(
                    "many_columns",
                    "The result has many columns and may need review.",
                )
            )
            status_signals.append("needs_review")
            return
        checks.append(
            VerificationCheck(
                "result_size",
                "passed",
                "Result size passed basic checks.",
                {"column_count": result.column_count},
            )
        )

    def _clarification_check(
        self,
        context: VerificationContext,
        checks: list[VerificationCheck],
        warnings: list[VerificationWarning],
        status_signals: list[VerificationStatus],
    ) -> None:
        if context.analysis_metadata.get("clarification_required"):
            checks.append(
                VerificationCheck(
                    "clarification",
                    "warning",
                    "The analysis metadata indicates unresolved ambiguity.",
                )
            )
            warnings.append(
                VerificationWarning(
                    "clarification_required",
                    "The request may need clarification before it can be fully trusted.",
                )
            )
            status_signals.append("clarification_required")
            return
        checks.append(
            VerificationCheck(
                "clarification",
                "passed",
                "No explicit clarification requirement was recorded.",
            )
        )

    def _small_group_count(self, result: "SafeQueryResult") -> int:
        count_columns = [
            column.name
            for column in result.columns
            if column.name.strip().lower().replace("-", "_") in COUNT_COLUMN_NAMES
        ]
        small = 0
        for row in result.rows:
            for column in count_columns:
                value = row.get(column)
                if isinstance(value, (int, float)) and value < self.small_group_threshold:
                    small += 1
                    break
        return small

    def _final_status(self, signals: list[VerificationStatus]) -> VerificationStatus:
        if "failed" in signals:
            return "failed"
        if "incomplete_data" in signals:
            return "incomplete_data"
        if "clarification_required" in signals:
            return "clarification_required"
        if "unable_to_verify" in signals:
            return "unable_to_verify"
        if "needs_review" in signals:
            return "needs_review"
        return "verified"

    def _confidence_label(self, status: VerificationStatus) -> ConfidenceLabel:
        if status == "verified":
            return "high"
        if status == "needs_review":
            return "medium"
        if status == "failed":
            return "not_available"
        return "low"

    def _summary(
        self,
        status: VerificationStatus,
        checks: list[VerificationCheck],
    ) -> str:
        warning_names = [
            check.name.replace("_", " ")
            for check in checks
            if check.status == "warning"
        ]
        if status == "verified":
            return "Verified: result passed applicable policy and data-shape checks."
        if status == "failed":
            return "Failed: verification could not approve the result."
        if status == "incomplete_data":
            return "Incomplete data: result may not contain enough matching data."
        if status == "clarification_required":
            return "Clarification required: the request has unresolved ambiguity."
        if status == "unable_to_verify":
            return "Unable to verify: result could not be fully checked."
        if warning_names:
            return f"Needs review: {', '.join(warning_names[:3])}."
        return "Needs review: result has verification warnings."

    def _caveat_text(
        self,
        status: VerificationStatus,
        warnings: list[VerificationWarning],
        checks: list[VerificationCheck],
    ) -> str | None:
        if status == "verified":
            return None
        if status == "failed":
            return "Verification failed; the answer should not be treated as trustworthy."
        if status == "incomplete_data":
            empty = any(check.name == "empty_result" and check.status == "warning" for check in checks)
            if empty:
                return "No matching data was found for the requested filters."
            return "The available data may be incomplete."
        if status == "clarification_required":
            return "The request may need clarification before the answer can be fully trusted."
        if status == "unable_to_verify":
            return "The result could not be fully verified with available metadata."
        if any(check.name == "row_truncation" and check.status == "warning" for check in checks):
            return "Only a limited result was used for the answer."
        if any(check.name == "redaction" and check.status == "warning" for check in checks):
            return "Restricted fields were removed before analysis."
        if warnings:
            return warnings[0].message
        return "The result has verification warnings and should be reviewed."


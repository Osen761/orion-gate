"""Stable, safe API error categories for Orion Gate operators."""

from __future__ import annotations

import re
from enum import StrEnum
from uuid import uuid4

from fastapi import Request


class FailureCategory(StrEnum):
    TRANSIENT_INFRASTRUCTURE = "transient_infrastructure"
    CONNECTOR_UNAVAILABLE = "connector_unavailable"
    CONNECTOR_TIMEOUT = "connector_timeout"
    CONNECTOR_AUTH_FAILED = "connector_auth_failed"
    SCHEMA_UNAVAILABLE = "schema_unavailable"
    POLICY_DENIED = "policy_denied"
    RESULT_HIDDEN = "result_hidden"
    VALIDATION_FAILED = "validation_failed"
    CONFIGURATION_INVALID = "configuration_invalid"
    DEPENDENCY_CONFLICT = "dependency_conflict"
    AUTHORIZATION_FAILED = "authorization_failed"
    AUTHENTICATION_FAILED = "authentication_failed"
    REQUEST_CONFLICT = "request_conflict"
    REQUEST_ALREADY_COMPLETED = "request_already_completed"
    UNEXPECTED_ERROR = "unexpected_error"


RETRYABLE_CATEGORIES = {
    FailureCategory.TRANSIENT_INFRASTRUCTURE,
    FailureCategory.CONNECTOR_UNAVAILABLE,
    FailureCategory.CONNECTOR_TIMEOUT,
}

REQUEST_ID_HEADER = "X-Orion-Request-ID"
IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")


def normalize_request_id(value: str | None) -> str:
    """Return a caller-supplied safe request id or generate a public one."""

    if value:
        candidate = value.strip()
        if _REQUEST_ID_RE.fullmatch(candidate):
            return candidate
    return f"req_{uuid4().hex}"


def request_id_from_request(request: Request | None) -> str:
    if request is None:
        return normalize_request_id(None)
    return str(getattr(request.state, "orion_request_id", "") or normalize_request_id(None))


def safe_message_for(category: FailureCategory) -> str:
    messages = {
        FailureCategory.AUTHENTICATION_FAILED: "Provide a valid bearer token and retry the request.",
        FailureCategory.AUTHORIZATION_FAILED: "Your token is not allowed to perform this action.",
        FailureCategory.REQUEST_CONFLICT: "The request conflicts with a previous request using the same idempotency key.",
        FailureCategory.REQUEST_ALREADY_COMPLETED: "This request was already completed.",
        FailureCategory.VALIDATION_FAILED: "Check the submitted values and try again.",
        FailureCategory.DEPENDENCY_CONFLICT: "Resolve the linked dependency before retrying.",
        FailureCategory.CONFIGURATION_INVALID: "Check the orion.yaml configuration and try again.",
    }
    return messages.get(category, "The request could not be completed safely.")


def recommended_action_for(category: FailureCategory, retryable: bool) -> str:
    if retryable:
        return "Retry after a short delay. Reference the request id in logs if it continues."
    if category in {FailureCategory.AUTHENTICATION_FAILED, FailureCategory.AUTHORIZATION_FAILED}:
        return "Check your bearer token, JWT claims, and orion.yaml policy."
    if category == FailureCategory.REQUEST_CONFLICT:
        return "Use a new idempotency key or resend the exact original request."
    return "Review the request details and policy violations."


def build_error_payload(
    *,
    category: FailureCategory,
    message: str | None = None,
    error: str | None = None,
    request_id: str,
    run_id: str | None = None,
    retryable: bool | None = None,
) -> dict[str, object]:
    is_retryable = category in RETRYABLE_CATEGORIES if retryable is None else retryable
    safe_msg = message or safe_message_for(category)
    return {
        "error": error or safe_msg,
        "message": safe_msg,
        "error_category": category.value,
        "retryable": is_retryable,
        "recommended_action": recommended_action_for(category, is_retryable),
        "request_id": request_id,
        "run_id": run_id,
    }

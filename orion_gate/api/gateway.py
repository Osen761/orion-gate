"""Orion Gate Direct Firewall REST routes (/v1/schema and /v1/query)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Query, Request, status
from fastapi.responses import JSONResponse

from orion_gate.errors import REQUEST_ID_HEADER, request_id_from_request
from orion_gate.schemas import (
    GovernedQueryRequest,
    GovernedQueryResponse,
    GovernedSchemaResponse,
)
from orion_gate.security.firewall import OrionGateFirewallService, resolve_gateway_auth


router = APIRouter(prefix="/v1", tags=["orion-gate"])


@router.get(
    "/schema",
    response_model=GovernedSchemaResponse,
    response_model_by_alias=True,
)
async def get_governed_schema(
    request: Request,
    connector_id: UUID | None = Query(default=None),
    table: str | None = Query(default=None, max_length=255),
) -> GovernedSchemaResponse:
    """Return the projected, PII-filtered schema visible to the caller's token."""

    auth = await resolve_gateway_auth(request)
    return await OrionGateFirewallService().describe_schema(
        request=request,
        auth=auth,
        connector_id=connector_id,
        table=table,
        surface="gateway",
    )


@router.post(
    "/query",
    response_model=GovernedQueryResponse,
    responses={status.HTTP_403_FORBIDDEN: {"model": GovernedQueryResponse}},
)
async def execute_governed_query(
    payload: GovernedQueryRequest,
    request: Request,
) -> GovernedQueryResponse | JSONResponse:
    """Validate, AST-rewrite, execute, and scrub a read-only SQL query."""

    auth = await resolve_gateway_auth(request)
    result = await OrionGateFirewallService().execute_query(
        request=request,
        auth=auth,
        sql=payload.sql,
        connector_id=payload.connector_id,
        tenant_values=payload.tenant_values,
        dry_run=payload.dry_run,
        surface="gateway",
    )
    if not result.allowed:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=result.model_dump(mode="json"),
            headers={REQUEST_ID_HEADER: request_id_from_request(request)},
        )
    return result

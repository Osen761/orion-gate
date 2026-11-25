"""Standalone Orion Gate ASGI entrypoint (Apache-2.0 OSS server)."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from orion_gate.api.demo_simulator import router as demo_simulator_router
from orion_gate.api.gateway import router as gateway_router
from orion_gate.api.mcp import router as mcp_router
from orion_gate.config import settings
from orion_gate.connectors.pool_manager import close_all_connector_pools
from orion_gate.errors import (
    FailureCategory,
    REQUEST_ID_HEADER,
    build_error_payload,
    normalize_request_id,
    request_id_from_request,
    safe_message_for,
)
from orion_gate.security.cloud_sync import CloudTelemetrySyncClient, GatewayControlPlaneAgent
from orion_gate.security.cors import (
    CORS_ALLOWED_HEADERS,
    CORS_ALLOWED_METHODS,
    parse_cors_allowed_origins,
)
from orion_gate.security.orion_yaml import get_active_orion_yaml


logger = logging.getLogger("orion.gate")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    sync_task: asyncio.Task[None] | None = None
    cfg = get_active_orion_yaml()
    if cfg is not None and CloudTelemetrySyncClient(cfg).control_plane_enabled:
        sync_task = asyncio.create_task(GatewayControlPlaneAgent().run_forever())
    try:
        yield
    finally:
        if sync_task is not None:
            sync_task.cancel()
            try:
                await sync_task
            except asyncio.CancelledError:
                pass
        close_all_connector_pools()


app = FastAPI(
    title="Orion Gate — SQL AST & MCP Firewall",
    description="Open-source zero-trust SQL firewall for AI agents (/v1/schema, /v1/query, /mcp).",
    version="0.4.1",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_allowed_origins(settings.CORS_ORIGINS),
    allow_credentials=False,
    allow_methods=CORS_ALLOWED_METHODS,
    allow_headers=CORS_ALLOWED_HEADERS,
)


@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    request_id = normalize_request_id(request.headers.get(REQUEST_ID_HEADER))
    request.state.orion_request_id = request_id
    response = await call_next(request)
    response.headers.setdefault(REQUEST_ID_HEADER, request_id)
    return response


@app.exception_handler(RequestValidationError)
async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    request_id = request_id_from_request(request)
    payload = build_error_payload(
        category=FailureCategory.VALIDATION_FAILED,
        message=safe_message_for(FailureCategory.VALIDATION_FAILED),
        error="Invalid request payload.",
        request_id=request_id,
    )
    payload["detail"] = exc.errors()
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=payload,
        headers={REQUEST_ID_HEADER: request_id},
    )


@app.exception_handler(HTTPException)
async def handle_http_exception(request: Request, exc: HTTPException) -> JSONResponse:
    request_id = request_id_from_request(request)
    category = (
        FailureCategory.AUTHENTICATION_FAILED
        if exc.status_code == status.HTTP_401_UNAUTHORIZED
        else FailureCategory.AUTHORIZATION_FAILED
        if exc.status_code == status.HTTP_403_FORBIDDEN
        else FailureCategory.VALIDATION_FAILED
    )
    detail = str(exc.detail) if exc.detail else safe_message_for(category)
    payload = build_error_payload(
        category=category,
        message=detail,
        error=detail,
        request_id=request_id,
    )
    payload["detail"] = detail
    return JSONResponse(
        status_code=exc.status_code,
        content=payload,
        headers={REQUEST_ID_HEADER: request_id},
    )


app.include_router(demo_simulator_router)
app.include_router(gateway_router)
app.include_router(mcp_router)


@app.get("/health")
async def gate_health() -> dict[str, object]:
    """Liveness endpoint for standalone Orion Gate containers."""

    cfg = get_active_orion_yaml()
    return {
        "status": "ok",
        "service": "orion-gate",
        "version": "0.4.1",
        "mode": "standalone_orion_yaml" if cfg is not None else "demo_simulator",
        "datasources": len(cfg.datasources) if cfg is not None else 0,
    }

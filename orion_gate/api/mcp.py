"""Model Context Protocol (MCP) Streamable HTTP server for Orion Gate (/mcp)."""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse

from orion_gate.auth import AuthContext
from orion_gate.security.firewall import OrionGateFirewallService, resolve_gateway_auth


router = APIRouter(tags=["mcp"])

SUPPORTED_MCP_VERSIONS = ("2025-03-26", "2024-11-05")
DEFAULT_MCP_VERSION = "2025-03-26"
MCP_SESSION_HEADER = "Mcp-Session-Id"

MCP_SERVER_INSTRUCTIONS = (
    "Orion Gate Zero-Trust SQL & Schema Firewall. "
    "1) Call list_allowed_tables or describe_table_schema to inspect visible tables and columns. "
    "2) Call query_governed_sql with read-only SELECT statements and explicit column names (never SELECT *). "
    "Tenant isolation predicates and row limits are injected automatically by the AST firewall."
)

MCP_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "list_allowed_tables",
        "description": "List database tables visible to the current governed session scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "connector_id": {
                    "type": "string",
                    "description": "Optional datasource UUID or name configured in orion.yaml.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "describe_table_schema",
        "description": (
            "Return the projected, PII-filtered column schema for one allowed table "
            "(or all allowed tables when table is omitted)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Optional table name to inspect.",
                },
                "connector_id": {
                    "type": "string",
                    "description": "Optional datasource UUID or name configured in orion.yaml.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "query_governed_sql",
        "description": (
            "Execute a read-only SQL SELECT query through the Orion Gate AST firewall. "
            "Explicit column names are required (no SELECT *). Tenant isolation predicates "
            "and row limits are injected automatically, and sensitive values are redacted."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "Read-only SQL SELECT statement with explicit visible columns.",
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "Validate and AST-rewrite the query without executing against the database.",
                },
                "connector_id": {
                    "type": "string",
                    "description": "Optional datasource UUID or name configured in orion.yaml.",
                },
            },
            "required": ["sql"],
            "additionalProperties": False,
        },
    },
)


def _jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _negotiate_version(requested: Any) -> str:
    if isinstance(requested, str) and requested in SUPPORTED_MCP_VERSIONS:
        return requested
    return DEFAULT_MCP_VERSION


async def _dispatch_tool_call(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    request: Request,
    auth: AuthContext,
) -> dict[str, Any]:
    firewall = OrionGateFirewallService()
    connector_id = arguments.get("connector_id")
    if connector_id is not None and not isinstance(connector_id, str):
        raise ValueError("connector_id must be a string")

    if tool_name == "list_allowed_tables":
        schema_resp = await firewall.describe_schema(
            request=request,
            auth=auth,
            connector_id=connector_id,
            surface="mcp",
        )
        structured = {
            "connector_id": str(schema_resp.connector_id),
            "dialect": schema_resp.dialect,
            "tenant_isolation_active": schema_resp.tenant_isolation_active,
            "tables": [
                {
                    "name": t.name,
                    "qualified_name": t.qualified_name,
                    "column_count": len(t.columns),
                    "row_estimate": t.row_estimate,
                }
                for t in schema_resp.tables
            ],
        }
        return {
            "content": [{"type": "text", "text": json.dumps(structured, indent=2)}],
            "structuredContent": structured,
            "isError": False,
        }

    if tool_name == "describe_table_schema":
        table = arguments.get("table")
        if table is not None and not isinstance(table, str):
            raise ValueError("table must be a string")
        try:
            schema_resp = await firewall.describe_schema(
                request=request,
                auth=auth,
                connector_id=connector_id,
                table=table,
                surface="mcp",
            )
        except HTTPException as exc:
            if exc.status_code == status.HTTP_404_NOT_FOUND:
                return {
                    "content": [{"type": "text", "text": str(exc.detail)}],
                    "isError": True,
                }
            raise

        structured = schema_resp.model_dump(mode="json", by_alias=True)
        return {
            "content": [{"type": "text", "text": schema_resp.schema_text}],
            "structuredContent": structured,
            "isError": False,
        }

    if tool_name == "query_governed_sql":
        sql = arguments.get("sql")
        if not isinstance(sql, str) or not sql.strip():
            raise ValueError("sql is required and must be a non-empty string")
        dry_run = bool(arguments.get("dry_run", False))
        try:
            query_resp = await firewall.execute_query(
                request=request,
                auth=auth,
                sql=sql,
                connector_id=connector_id,
                dry_run=dry_run,
                surface="mcp",
            )
        except HTTPException as exc:
            if exc.status_code == status.HTTP_400_BAD_REQUEST:
                return {
                    "content": [{"type": "text", "text": str(exc.detail)}],
                    "isError": True,
                }
            raise

        structured = query_resp.model_dump(mode="json")
        if not query_resp.allowed:
            violation_codes = [v.code for v in query_resp.policy.violations]
            text = query_resp.error or "ERROR: Query denied by Orion Gate policy."
            if violation_codes:
                text = f"{text} (violations: {', '.join(violation_codes)})"
            return {
                "content": [{"type": "text", "text": text}],
                "structuredContent": structured,
                "isError": True,
            }

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "status": query_resp.status,
                            "row_count": query_resp.row_count,
                            "truncated": query_resp.truncated,
                            "redacted": query_resp.redacted,
                            "columns": [c.model_dump() for c in query_resp.columns],
                            "rows": query_resp.rows,
                            "warnings": query_resp.policy.warnings,
                        },
                        indent=2,
                    ),
                }
            ],
            "structuredContent": structured,
            "isError": False,
        }

    raise KeyError(f"Unknown MCP tool: {tool_name}")


async def _handle_single_jsonrpc(
    message: Any,
    *,
    request: Request,
    auth: AuthContext,
) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _jsonrpc_error(None, -32600, "Invalid JSON-RPC 2.0 request"), None

    method = message.get("method")
    is_notification = "id" not in message
    req_id = message.get("id")
    params = message.get("params") if isinstance(message.get("params"), dict) else {}

    if not isinstance(method, str) or not method:
        return _jsonrpc_error(req_id, -32600, "Missing JSON-RPC method"), None

    if is_notification or method.startswith("notifications/"):
        return None, None

    if method == "initialize":
        session_id = request.headers.get(MCP_SESSION_HEADER) or str(uuid.uuid4())
        result = {
            "protocolVersion": _negotiate_version(params.get("protocolVersion")),
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": "orion-gate",
                "version": "0.4.1",
            },
            "instructions": MCP_SERVER_INSTRUCTIONS,
        }
        return _jsonrpc_result(req_id, result), session_id

    if method == "ping":
        return _jsonrpc_result(req_id, {}), None

    if method == "tools/list":
        return _jsonrpc_result(req_id, {"tools": list(MCP_TOOLS)}), None

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments")
        if not isinstance(tool_name, str) or not tool_name:
            return _jsonrpc_error(req_id, -32602, "Invalid params: tool name is required"), None
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return _jsonrpc_error(req_id, -32602, "Invalid params: arguments must be an object"), None
        try:
            tool_result = await _dispatch_tool_call(
                tool_name=tool_name,
                arguments=arguments,
                request=request,
                auth=auth,
            )
        except KeyError:
            return _jsonrpc_error(req_id, -32602, f"Unknown tool: {tool_name}"), None
        except ValueError as exc:
            return _jsonrpc_error(req_id, -32602, f"Invalid params: {exc}"), None
        return _jsonrpc_result(req_id, tool_result), None

    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}"), None


@router.post("/mcp")
async def mcp_post_endpoint(request: Request) -> Response:
    """Handle MCP Streamable HTTP JSON-RPC 2.0 requests and notifications."""

    auth = await resolve_gateway_auth(request)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=_jsonrpc_error(None, -32700, "Parse error: invalid JSON payload"),
        )

    session_header = request.headers.get(MCP_SESSION_HEADER)
    headers: dict[str, str] = {}
    if session_header:
        headers[MCP_SESSION_HEADER] = session_header

    if isinstance(body, list):
        if not body:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=_jsonrpc_error(None, -32600, "Empty JSON-RPC batch"),
            )
        responses: list[dict[str, Any]] = []
        for item in body:
            resp, new_session_id = await _handle_single_jsonrpc(
                item,
                request=request,
                auth=auth,
            )
            if new_session_id:
                headers[MCP_SESSION_HEADER] = new_session_id
            if resp is not None:
                responses.append(resp)
        if not responses:
            return Response(status_code=status.HTTP_202_ACCEPTED, headers=headers)
        return JSONResponse(status_code=status.HTTP_200_OK, content=responses, headers=headers)

    resp, new_session_id = await _handle_single_jsonrpc(
        body,
        request=request,
        auth=auth,
    )
    if new_session_id:
        headers[MCP_SESSION_HEADER] = new_session_id
    if resp is None:
        return Response(status_code=status.HTTP_202_ACCEPTED, headers=headers)
    return JSONResponse(status_code=status.HTTP_200_OK, content=resp, headers=headers)


@router.get("/mcp")
async def mcp_get_endpoint(request: Request) -> Response:
    """Support MCP Streamable HTTP SSE probe and authenticated server discovery."""

    await resolve_gateway_auth(request)
    accept = (request.headers.get("accept") or "").lower()
    if "text/event-stream" in accept:
        async def event_stream():
            yield ": orion-gate mcp stream ready\n\n"

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache"},
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "name": "orion-gate",
            "version": "0.4.1",
            "protocol": "mcp-streamable-http",
            "supportedProtocolVersions": list(SUPPORTED_MCP_VERSIONS),
            "tools": [tool["name"] for tool in MCP_TOOLS],
        },
    )


@router.delete("/mcp")
async def mcp_delete_endpoint(request: Request) -> Response:
    """Terminate an MCP Streamable HTTP session cleanly."""

    await resolve_gateway_auth(request)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

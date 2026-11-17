"""Session-level k-anonymity differencing guard for governed SQL queries."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

import sqlglot
from sqlglot import exp

from orion_gate.authz.connectors import EffectiveAccessScope
from orion_gate.cache import sync_cache_get, sync_cache_set
from orion_gate.security.sql_policy import SQLDialect, SQLPolicyDecision, _is_counting_expression


_LOCK = threading.Lock()
_MEMORY_STORE: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
_MAX_MEMORY_ENTRIES = 10_000


def reset_differencing_store() -> None:
    """Clear the in-memory differencing state store (primarily for tests)."""

    with _LOCK:
        _MEMORY_STORE.clear()


@dataclass(frozen=True)
class DifferencingDecision:
    """Result of checking a governed aggregate query for differencing risk."""

    allowed: bool
    code: str = "allowed"
    message: str = ""
    template_hash: str = ""
    variant_hash: str = ""
    distinct_variants: int = 0
    budget: int = 5


def _load_state(key: str) -> dict[str, Any] | None:
    raw = sync_cache_get(key)
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    now = time.monotonic()
    with _LOCK:
        item = _MEMORY_STORE.get(key)
        if item is None:
            return None
        expires_at, state = item
        if expires_at <= now:
            _MEMORY_STORE.pop(key, None)
            return None
        _MEMORY_STORE.move_to_end(key)
        return dict(state)


def _save_state(key: str, state: dict[str, Any], ttl_seconds: int) -> None:
    serialized = json.dumps(state, sort_keys=True, separators=(",", ":"))
    sync_cache_set(key, serialized, ttl_seconds=ttl_seconds)

    expires_at = time.monotonic() + ttl_seconds
    with _LOCK:
        _MEMORY_STORE[key] = (expires_at, dict(state))
        _MEMORY_STORE.move_to_end(key)
        while len(_MEMORY_STORE) > _MAX_MEMORY_ENTRIES:
            _MEMORY_STORE.popitem(last=False)


def _strip_predicates_for_template(expression: exp.Expression) -> exp.Expression:
    cloned = expression.copy()
    for node_type in (exp.Where, exp.Having, exp.Limit, exp.Offset, exp.Order):
        for node in list(cloned.find_all(node_type)):
            node.pop()
    for filt in list(cloned.find_all(exp.Filter)):
        if filt.this is not None:
            filt.replace(filt.this)
    for count_node in list(cloned.find_all(exp.Count, exp.ApproxDistinct)):
        if any(count_node.find_all(exp.Nullif, exp.Case, exp.If)):
            count_node.replace(exp.Count(this=exp.Star()))
    for sum_node in list(cloned.find_all(exp.Sum)):
        if isinstance(sum_node.this, (exp.Case, exp.If)):
            sum_node.replace(exp.Count(this=exp.Star()))
    for alias in list(cloned.find_all(exp.Alias)):
        if alias.this is not None:
            alias.replace(alias.this)
    return cloned


def _has_range_exclusion(expression: exp.Expression) -> bool:
    for or_node in expression.find_all(exp.Or):
        lt_cols = {
            expr.this.sql().lower()
            for expr in or_node.find_all(exp.LT, exp.LTE)
            if isinstance(expr.this, exp.Column)
        }
        gt_cols = {
            expr.this.sql().lower()
            for expr in or_node.find_all(exp.GT, exp.GTE)
            if isinstance(expr.this, exp.Column)
        }
        if lt_cols & gt_cols:
            return True
    return False


def _is_conditional_count_node(node: exp.Expression) -> bool:
    if isinstance(node, exp.Filter):
        return True
    if isinstance(node, (exp.Count, exp.ApproxDistinct)):
        return any(node.find_all(exp.Nullif, exp.Case, exp.If))
    if isinstance(node, exp.Sum) and isinstance(node.this, (exp.Case, exp.If)):
        return _is_counting_expression(node)
    if isinstance(node, (exp.Func, exp.Anonymous)):
        name = (
            (node.sql_name() or "").lower()
            if isinstance(node, exp.Func)
            else str(node.name or "").lower()
        )
        return name in {"count_if", "countif"}
    return False


def _has_single_query_differencing(expression: exp.Expression) -> bool:
    for select in expression.find_all(exp.Select):
        count_nodes: list[exp.Expression] = []
        for node in select.walk():
            if node is not select and node.find_ancestor(exp.Select) is not select:
                continue
            if isinstance(node, exp.Filter) and _is_counting_expression(node.this):
                count_nodes.append(node)
            elif _is_counting_expression(node) and not isinstance(node.parent, exp.Filter):
                count_nodes.append(node)
        if len(count_nodes) < 2:
            continue
        if any(_is_conditional_count_node(node) for node in count_nodes):
            return True
        for arith in select.find_all(exp.Add, exp.Sub, exp.Mul, exp.Div):
            if arith.find_ancestor(exp.Select) is not select:
                continue
            arith_counts = [
                n
                for n in arith.walk()
                if (isinstance(n, exp.Filter) and _is_counting_expression(n.this))
                or (_is_counting_expression(n) and not isinstance(n.parent, exp.Filter))
            ]
            if len(arith_counts) >= 2:
                return True
    return False


def _has_negation_predicate(expression: exp.Expression) -> bool:
    if any(expression.find_all(exp.Except, exp.NEQ, exp.Not)):
        return True
    if any(
        isinstance(node, exp.AggFunc) and any(node.find_all(exp.Nullif))
        for node in expression.find_all(exp.AggFunc)
    ):
        return True
    return _has_range_exclusion(expression)


def compute_query_fingerprints(
    sql: str,
    *,
    dialect: SQLDialect = "postgres",
    tables_referenced: tuple[str, ...] = (),
) -> tuple[str, str, bool]:
    """Return (template_hash, variant_hash, has_negation_predicate)."""

    try:
        parsed = sqlglot.parse_one(sql, read=dialect)
    except Exception:
        digest = hashlib.sha256(sql.strip().encode("utf-8")).hexdigest()[:24]
        return digest, digest, False

    template_ast = _strip_predicates_for_template(parsed)
    template_payload = "|".join(
        (
            ",".join(sorted(tables_referenced)),
            template_ast.sql(dialect=dialect),
        )
    )
    template_hash = hashlib.sha256(template_payload.encode("utf-8")).hexdigest()[:24]

    variant_ast = parsed.copy()
    for node_type in (exp.Limit, exp.Offset):
        for node in list(variant_ast.find_all(node_type)):
            node.pop()
    variant_hash = hashlib.sha256(variant_ast.sql(dialect=dialect).encode("utf-8")).hexdigest()[:24]
    has_negation = _has_negation_predicate(parsed)
    return template_hash, variant_hash, has_negation


def actor_session_key(
    *,
    scope: EffectiveAccessScope,
    request_actor_hint: str | None = None,
) -> str:
    """Derive a stable per-session / per-JWT subject key."""

    actor = (
        scope.embed_subject_id
        or scope.external_user_id
        or scope.user_id
        or request_actor_hint
        or scope.external_tenant_id
        or scope.principal_type
    )
    raw = f"{scope.workspace_id}:{scope.connector_id or 'default'}:{actor}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


class DifferencingGuard:
    """Detect and block iterative differencing attacks against k-anonymity."""

    def check_and_record(
        self,
        *,
        sql: str,
        dialect: SQLDialect,
        scope: EffectiveAccessScope,
        sql_decision: SQLPolicyDecision,
        session_key: str,
        record_query: bool = True,
    ) -> DifferencingDecision:
        if getattr(scope, "minimum_group_size", None) is None:
            return DifferencingDecision(allowed=True)

        if not (
            getattr(sql_decision, "has_group_by_or_aggregate", False)
            or getattr(sql_decision, "count_output_columns", ())
        ):
            return DifferencingDecision(allowed=True)

        budget = max(1, int(getattr(scope, "differencing_budget", 5) or 5))
        window_seconds = max(10, int(getattr(scope, "differencing_window_seconds", 300) or 300))

        try:
            parsed = sqlglot.parse_one(sql, read=dialect)
        except Exception:
            parsed = None

        if parsed is not None and _has_single_query_differencing(parsed):
            return DifferencingDecision(
                allowed=False,
                code="differencing_attack_denied",
                message=(
                    "Query denied: combining conditional or arithmetic counts in a single "
                    "query can isolate small groups and violate k-anonymity."
                ),
                budget=budget,
            )

        template_hash, variant_hash, has_negation = compute_query_fingerprints(
            sql,
            dialect=dialect,
            tables_referenced=sql_decision.tables_referenced,
        )
        store_key = f"orion:diff:{session_key}:{template_hash}"
        state = _load_state(store_key) or {"variants": [], "had_suppression": False}
        variants: list[str] = list(state.get("variants") or [])
        had_suppression = bool(state.get("had_suppression", False))

        if variant_hash in variants:
            return DifferencingDecision(
                allowed=True,
                template_hash=template_hash,
                variant_hash=variant_hash,
                distinct_variants=len(variants),
                budget=budget,
            )

        if variants and has_negation:
            return DifferencingDecision(
                allowed=False,
                code="differencing_attack_denied",
                message=(
                    "Query denied: complementary or negated filter predicates on an "
                    "already-queried aggregate violate k-anonymity protection."
                ),
                template_hash=template_hash,
                variant_hash=variant_hash,
                distinct_variants=len(variants),
                budget=budget,
            )

        if variants and had_suppression:
            return DifferencingDecision(
                allowed=False,
                code="differencing_attack_denied",
                message=(
                    "Query denied: follow-up aggregate variation after small-group "
                    "suppression violates k-anonymity protection."
                ),
                template_hash=template_hash,
                variant_hash=variant_hash,
                distinct_variants=len(variants),
                budget=budget,
            )

        if len(variants) >= budget:
            return DifferencingDecision(
                allowed=False,
                code="differencing_budget_exceeded",
                message=(
                    "Query denied: k-anonymity aggregate predicate budget exceeded "
                    "for this session."
                ),
                template_hash=template_hash,
                variant_hash=variant_hash,
                distinct_variants=len(variants),
                budget=budget,
            )

        if record_query:
            variants.append(variant_hash)
            state["variants"] = variants
            _save_state(store_key, state, ttl_seconds=window_seconds)

        return DifferencingDecision(
            allowed=True,
            template_hash=template_hash,
            variant_hash=variant_hash,
            distinct_variants=len(variants),
            budget=budget,
        )

    def mark_small_group_suppressed(
        self,
        *,
        scope: EffectiveAccessScope,
        session_key: str,
        template_hash: str,
    ) -> None:
        if getattr(scope, "minimum_group_size", None) is None or not template_hash:
            return
        window_seconds = max(10, int(getattr(scope, "differencing_window_seconds", 300) or 300))
        store_key = f"orion:diff:{session_key}:{template_hash}"
        state = _load_state(store_key) or {"variants": [], "had_suppression": False}
        state["had_suppression"] = True
        _save_state(store_key, state, ttl_seconds=window_seconds)

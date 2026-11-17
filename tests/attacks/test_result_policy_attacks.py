"""Result policy bypass attack tests."""

from __future__ import annotations

import unittest

import pandas as pd

from orion_gate.security.result_policy import ResultPolicyGateway, MAX_COLUMNS

from tests.attacks.helpers import JWT_VALUE, PRIVATE_KEY_VALUE, SECRET_VALUE, assert_no_terms, make_result_context


class ResultPolicyAttackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = ResultPolicyGateway()

    def _safe_text_for_decision(self, decision) -> str:
        if decision.safe_result is None:
            return decision.safe_error_message
        return self.gateway.to_model_text(decision.safe_result)

    def assert_safe_decision(self, df: pd.DataFrame, forbidden: tuple[str, ...], **context_kwargs):
        decision = self.gateway.validate(df, make_result_context(**context_kwargs))
        text = self._safe_text_for_decision(decision)

        self.assertIn(decision.decision, {"redacted", "denied", "requires_review", "allowed"})
        assert_no_terms(self, text, forbidden)
        return decision, text

    def test_email_column_is_not_exposed(self):
        decision, text = self.assert_safe_decision(
            pd.DataFrame({"total": [10], "email": ["ada@example.com"]}),
            ("ada@example.com",),
        )

        self.assertEqual(decision.decision, "redacted")
        self.assertNotIn("email", text.lower())

    def test_phone_column_is_not_exposed(self):
        decision, text = self.assert_safe_decision(
            pd.DataFrame({"total": [10], "phone": ["+15551234567"]}),
            ("+15551234567",),
        )

        self.assertEqual(decision.decision, "redacted")
        self.assertNotIn("phone", text.lower())

    def test_password_hash_column_is_denied(self):
        decision, text = self.assert_safe_decision(
            pd.DataFrame({"password_hash": ["$2b$12$abcdefghijklmnopqrstuvwxyzABCDEFGHijklmno123456"]}),
            ("password_hash", "$2b$12$"),
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.decision, "denied")

    def test_token_like_value_is_redacted(self):
        decision, text = self.assert_safe_decision(
            pd.DataFrame({"total": [10], "note": [f"token={SECRET_VALUE}"]}),
            (SECRET_VALUE,),
            sql="SELECT total, note FROM customers",
        )

        self.assertTrue(decision.allowed)
        self.assertIn("[REDACTED]", text)

    def test_jwt_like_value_is_redacted(self):
        _, text = self.assert_safe_decision(
            pd.DataFrame({"total": [10], "note": [JWT_VALUE]}),
            (JWT_VALUE,),
            sql="SELECT total, note FROM customers",
        )

        self.assertIn("[REDACTED]", text)

    def test_private_key_text_is_redacted_or_withheld(self):
        _, text = self.assert_safe_decision(
            pd.DataFrame({"total": [10], "note": [PRIVATE_KEY_VALUE]}),
            ("BEGIN PRIVATE KEY", "abc123secret"),
            sql="SELECT total, note FROM customers",
        )

        self.assertNotIn("PRIVATE KEY", text)

    def test_sensitive_column_under_alias_requires_review(self):
        decision = self.gateway.validate(
            pd.DataFrame({"customer_id": ["ada@example.com"]}),
            make_result_context(sql="SELECT email AS customer_id FROM customers"),
        )

        self.assertFalse(decision.allowed)
        self.assertIn(decision.decision, {"denied", "requires_review"})
        self.assertNotIn("ada@example.com", decision.safe_error_message)

    def test_raw_customer_list_is_denied_when_raw_rows_disallowed(self):
        decision = self.gateway.validate(
            pd.DataFrame({"id": [1, 2], "name": ["Ada", "Grace"], "total": [10, 20]}),
            make_result_context(allow_raw_rows=False),
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.decision, "denied")
        self.assertNotIn("Ada", decision.safe_error_message)

    def test_many_identifier_columns_are_denied(self):
        decision = self.gateway.validate(
            pd.DataFrame(
                {
                    "id": [1],
                    "user_id": [2],
                    "customer_id": [3],
                    "account_id": [4],
                    "name": ["Ada"],
                    "total": [10],
                }
            ),
            make_result_context(allow_raw_rows=False),
        )

        self.assertFalse(decision.allowed)

    def test_too_many_rows_are_truncated(self):
        decision = self.gateway.validate(
            pd.DataFrame({"total": list(range(5))}),
            make_result_context(max_result_rows=2),
        )

        self.assertTrue(decision.allowed)
        self.assertTrue(decision.safe_result.truncated)
        self.assertEqual(decision.safe_result.row_count, 2)

    def test_too_many_columns_require_review(self):
        df = pd.DataFrame({f"metric_{index}": [index] for index in range(MAX_COLUMNS + 1)})
        decision = self.gateway.validate(df, make_result_context())

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.decision, "requires_review")

    def test_long_text_cell_containing_secret_is_redacted(self):
        _, text = self.assert_safe_decision(
            pd.DataFrame({"total": [10], "note": ["prefix " + SECRET_VALUE + " " + ("x" * 1000)]}),
            (SECRET_VALUE,),
            sql="SELECT total, note FROM customers",
        )

        self.assertIn("[REDACTED]", text)
        self.assertLess(len(text), 900)

    def test_small_group_count_below_threshold_is_suppressed(self):
        decision = self.gateway.validate(
            pd.DataFrame({"department": ["sales"], "count": [2]}),
            make_result_context(minimum_group_size=5, sql="SELECT status AS department, count FROM orders"),
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.decision, "denied")

    def test_group_suppression_does_not_leak_sensitive_values(self):
        decision = self.gateway.validate(
            pd.DataFrame({"department": ["sales"], "count": [2], "api_token": [SECRET_VALUE]}),
            make_result_context(minimum_group_size=5, sql="SELECT status AS department, count FROM orders"),
        )

        text = self._safe_text_for_decision(decision)
        assert_no_terms(self, text, ("api_token", SECRET_VALUE))

    def test_redacted_serialization_excludes_original_secret(self):
        decision = self.gateway.validate(
            pd.DataFrame({"total": [10], "note": [f"access_token={SECRET_VALUE}"]}),
            make_result_context(sql="SELECT total, note FROM customers"),
        )
        text = self.gateway.to_model_text(decision.safe_result)

        self.assertNotIn(SECRET_VALUE, text)
        self.assertIn("[REDACTED]", text)

    def test_model_safe_error_does_not_include_denied_column_name(self):
        decision = self.gateway.validate(
            pd.DataFrame({"api_token": [SECRET_VALUE]}),
            make_result_context(),
        )

        self.assertFalse(decision.allowed)
        assert_no_terms(self, decision.safe_error_message, ("api_token", SECRET_VALUE))

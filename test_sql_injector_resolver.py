"""
Tests for sql_injector_resolver module
=======================================
Run with:  python -m pytest test_sql_injector_resolver.py -v
"""

import pytest
from sql_injector_resolver import (
    SQLInjectionDetector,
    SQLSanitizer,
    ParameterizedQueryBuilder,
)


# ===========================================================================
# SQLInjectionDetector
# ===========================================================================

class TestSQLInjectionDetectorSafeInputs:
    """Inputs that must NOT be flagged as suspicious."""

    def setup_method(self):
        self.detector = SQLInjectionDetector()

    def test_plain_name(self):
        assert self.detector.is_safe("Alice")

    def test_plain_email(self):
        assert self.detector.is_safe("user@example.com")

    def test_plain_number(self):
        assert self.detector.is_safe("12345")

    def test_plain_sentence(self):
        assert self.detector.is_safe("Hello, world!")

    def test_empty_string(self):
        assert self.detector.is_safe("")

    def test_alphanumeric_with_spaces(self):
        assert self.detector.is_safe("John Doe 42")

    def test_password_with_symbols(self):
        # A normal password that has special chars but no injection pattern
        assert self.detector.is_safe("P@ssw0rd!")


class TestSQLInjectionDetectorMaliciousInputs:
    """Inputs that MUST be flagged as suspicious."""

    def setup_method(self):
        self.detector = SQLInjectionDetector()

    # -- SQL comment sequences ------------------------------------------------
    def test_double_dash_comment(self):
        is_sus, reasons = self.detector.is_suspicious("admin'--")
        assert is_sus
        assert any("comment" in r.lower() for r in reasons)

    def test_hash_comment(self):
        is_sus, reasons = self.detector.is_suspicious("admin'#")
        assert is_sus

    def test_block_comment_open(self):
        is_sus, _ = self.detector.is_suspicious("admin'/*")
        assert is_sus

    # -- Tautologies ----------------------------------------------------------
    def test_or_1_equals_1(self):
        is_sus, reasons = self.detector.is_suspicious("' OR 1=1")
        assert is_sus
        assert any("tautology" in r.lower() or "boolean" in r.lower() for r in reasons)

    def test_or_1_equals_1_no_spaces(self):
        is_sus, _ = self.detector.is_suspicious("'OR 1=1")
        assert is_sus

    def test_and_1_equals_1(self):
        is_sus, _ = self.detector.is_suspicious("x' AND 1=1")
        assert is_sus

    # -- Stacked queries ------------------------------------------------------
    def test_stacked_drop(self):
        is_sus, reasons = self.detector.is_suspicious("'; DROP TABLE users")
        assert is_sus
        assert any("stacked" in r.lower() or "semicolon" in r.lower() for r in reasons)

    def test_stacked_insert(self):
        is_sus, _ = self.detector.is_suspicious("x'; INSERT INTO logs VALUES(1)")
        assert is_sus

    # -- Hex encoding ---------------------------------------------------------
    def test_hex_payload(self):
        is_sus, reasons = self.detector.is_suspicious("0x414243")
        assert is_sus
        assert any("hex" in r.lower() for r in reasons)

    # -- SQL keywords ---------------------------------------------------------
    def test_select_keyword(self):
        is_sus, reasons = self.detector.is_suspicious("SELECT * FROM users")
        assert is_sus
        assert any("keyword" in r.lower() for r in reasons)

    def test_union_keyword(self):
        is_sus, _ = self.detector.is_suspicious("' UNION SELECT password FROM users--")
        assert is_sus

    def test_drop_keyword(self):
        is_sus, _ = self.detector.is_suspicious("DROP TABLE students")
        assert is_sus

    def test_sleep_keyword(self):
        is_sus, _ = self.detector.is_suspicious("'; SLEEP(5)--")
        assert is_sus

    def test_exec_keyword(self):
        is_sus, _ = self.detector.is_suspicious("EXEC xp_cmdshell('dir')")
        assert is_sus

    def test_xp_cmdshell(self):
        is_sus, _ = self.detector.is_suspicious("xp_cmdshell('whoami')")
        assert is_sus

    def test_information_schema(self):
        is_sus, _ = self.detector.is_suspicious(
            "' UNION SELECT table_name FROM INFORMATION_SCHEMA.TABLES--"
        )
        assert is_sus


class TestSQLInjectionDetectorConfiguration:
    """Verify that individual checks can be disabled."""

    def test_disable_keyword_check(self):
        detector = SQLInjectionDetector(check_keywords=False)
        # With keyword check off, a bare SELECT with no other indicators is safe
        is_sus, reasons = detector.is_suspicious("SELECT")
        assert not is_sus

    def test_disable_comment_check(self):
        detector = SQLInjectionDetector(check_comments=False)
        # A comment by itself (no other patterns) should pass
        is_sus, _ = detector.is_suspicious("--")
        assert not is_sus

    def test_disable_tautology_check(self):
        detector = SQLInjectionDetector(check_tautologies=False)
        # A bare tautology with no keywords/comments should pass
        detector2 = SQLInjectionDetector(
            check_keywords=False,
            check_comments=False,
            check_tautologies=False,
            check_stacked_queries=False,
            check_hex_encoding=False,
        )
        is_sus, _ = detector2.is_suspicious("OR 1=1")
        assert not is_sus

    def test_type_error_on_non_string(self):
        detector = SQLInjectionDetector()
        with pytest.raises(TypeError):
            detector.is_suspicious(12345)

    def test_is_safe_returns_bool(self):
        detector = SQLInjectionDetector()
        result = detector.is_safe("hello")
        assert isinstance(result, bool)
        assert result is True


# ===========================================================================
# SQLSanitizer
# ===========================================================================

class TestSQLSanitizerSanitize:
    """Test the string sanitizer."""

    def setup_method(self):
        self.s = SQLSanitizer()

    def test_no_special_chars(self):
        assert self.s.sanitize("hello") == "hello"

    def test_single_quote_escaped(self):
        assert self.s.sanitize("O'Reilly") == "O''Reilly"

    def test_multiple_single_quotes(self):
        assert self.s.sanitize("it's a 'test'") == "it''s a ''test''"

    def test_backslash_escaped(self):
        assert self.s.sanitize("C:\\Users\\Bob") == "C:\\\\Users\\\\Bob"

    def test_null_byte_escaped(self):
        assert self.s.sanitize("abc\x00def") == "abc\\0def"

    def test_newline_escaped(self):
        assert self.s.sanitize("line1\nline2") == "line1\\nline2"

    def test_carriage_return_escaped(self):
        assert self.s.sanitize("line1\rline2") == "line1\\rline2"

    def test_empty_string(self):
        assert self.s.sanitize("") == ""

    def test_type_error_on_non_string(self):
        with pytest.raises(TypeError):
            self.s.sanitize(42)


class TestSQLSanitizerIdentifier:
    """Test identifier sanitization."""

    def setup_method(self):
        self.s = SQLSanitizer()

    def test_clean_identifier(self):
        assert self.s.sanitize_identifier("users") == "users"

    def test_identifier_with_spaces_stripped(self):
        assert self.s.sanitize_identifier("user name") == "username"

    def test_identifier_with_quotes_stripped(self):
        assert self.s.sanitize_identifier("user'name") == "username"

    def test_identifier_with_injection_attempt_stripped(self):
        assert self.s.sanitize_identifier("users;DROP TABLE students") == "usersDROPTABLEstudents"

    def test_empty_identifier_raises(self):
        with pytest.raises(ValueError):
            self.s.sanitize_identifier("'''")

    def test_type_error_on_non_string(self):
        with pytest.raises(TypeError):
            self.s.sanitize_identifier(None)


class TestSQLSanitizerInteger:
    """Test integer sanitization."""

    def setup_method(self):
        self.s = SQLSanitizer()

    def test_int_passthrough(self):
        assert self.s.sanitize_integer(42) == 42

    def test_string_number(self):
        assert self.s.sanitize_integer("99") == 99

    def test_float_truncated(self):
        assert self.s.sanitize_integer(3.9) == 3

    def test_invalid_string_raises(self):
        with pytest.raises(ValueError):
            self.s.sanitize_integer("abc")

    def test_sql_injection_in_integer_raises(self):
        with pytest.raises(ValueError):
            self.s.sanitize_integer("1; DROP TABLE users")


# ===========================================================================
# ParameterizedQueryBuilder
# ===========================================================================

class TestParameterizedQueryBuilderSelect:
    """Tests for SELECT query building."""

    def setup_method(self):
        self.builder = ParameterizedQueryBuilder()

    def test_select_all_no_where(self):
        sql, params = self.builder.select("users")
        assert sql == "SELECT * FROM users"
        assert params == ()

    def test_select_columns_no_where(self):
        sql, params = self.builder.select("users", ["id", "email"])
        assert sql == "SELECT id, email FROM users"
        assert params == ()

    def test_select_with_where(self):
        sql, params = self.builder.select("users", ["id"], {"username": "alice"})
        assert sql == "SELECT id FROM users WHERE username = ?"
        assert params == ("alice",)

    def test_select_with_limit(self):
        sql, params = self.builder.select("users", limit=10)
        assert "LIMIT 10" in sql
        assert params == ()

    def test_select_with_offset(self):
        sql, params = self.builder.select("users", limit=10, offset=20)
        assert "OFFSET 20" in sql

    def test_select_with_multiple_where_conditions(self):
        sql, params = self.builder.select(
            "orders", where={"status": "active", "user_id": 5}
        )
        assert "status = ?" in sql
        assert "user_id = ?" in sql
        assert "active" in params
        assert 5 in params

    def test_malicious_table_name_sanitized(self):
        # Non-word chars (semicolons, spaces, dashes) are stripped from the table name
        sql, _params = self.builder.select("users; DROP TABLE students--")
        # Extract the table identifier that appears after FROM
        table_token = sql.split("FROM")[1].strip().split()[0]
        assert ";" not in table_token
        assert " " not in table_token
        assert "-" not in table_token

    def test_custom_placeholder(self):
        builder = ParameterizedQueryBuilder(placeholder="%s")
        sql, params = builder.select("users", ["id"], {"name": "bob"})
        assert "%s" in sql
        assert "?" not in sql


class TestParameterizedQueryBuilderInsert:
    """Tests for INSERT query building."""

    def setup_method(self):
        self.builder = ParameterizedQueryBuilder()

    def test_basic_insert(self):
        sql, params = self.builder.insert("users", {"name": "Alice", "age": 30})
        assert sql.startswith("INSERT INTO users")
        assert "name" in sql
        assert "age" in sql
        assert "Alice" in params
        assert 30 in params

    def test_insert_preserves_value_order(self):
        data = {"a": 1, "b": 2, "c": 3}
        sql, params = self.builder.insert("t", data)
        assert params == (1, 2, 3)

    def test_insert_empty_data_raises(self):
        with pytest.raises(ValueError):
            self.builder.insert("users", {})

    def test_insert_placeholders_count(self):
        data = {"x": 1, "y": 2, "z": 3}
        sql, params = self.builder.insert("tbl", data)
        assert sql.count("?") == 3
        assert len(params) == 3


class TestParameterizedQueryBuilderUpdate:
    """Tests for UPDATE query building."""

    def setup_method(self):
        self.builder = ParameterizedQueryBuilder()

    def test_basic_update(self):
        sql, params = self.builder.update(
            "users", {"email": "new@example.com"}, {"id": 1}
        )
        assert sql.startswith("UPDATE users SET")
        assert "email = ?" in sql
        assert "WHERE id = ?" in sql
        assert "new@example.com" in params
        assert 1 in params

    def test_update_empty_data_raises(self):
        with pytest.raises(ValueError):
            self.builder.update("users", {}, {"id": 1})

    def test_update_empty_where_raises(self):
        with pytest.raises(ValueError):
            self.builder.update("users", {"name": "x"}, {})

    def test_update_multiple_set_columns(self):
        sql, params = self.builder.update(
            "users",
            {"name": "Bob", "age": 25},
            {"id": 42},
        )
        assert "name = ?" in sql
        assert "age = ?" in sql
        assert "Bob" in params
        assert 25 in params
        assert 42 in params


class TestParameterizedQueryBuilderDelete:
    """Tests for DELETE query building."""

    def setup_method(self):
        self.builder = ParameterizedQueryBuilder()

    def test_basic_delete(self):
        sql, params = self.builder.delete("users", {"id": 7})
        assert sql == "DELETE FROM users WHERE id = ?"
        assert params == (7,)

    def test_delete_empty_where_raises(self):
        with pytest.raises(ValueError):
            self.builder.delete("users", {})

    def test_delete_multiple_conditions(self):
        sql, params = self.builder.delete("sessions", {"user_id": 1, "token": "abc"})
        assert "user_id = ?" in sql
        assert "token = ?" in sql
        assert 1 in params
        assert "abc" in params


# ===========================================================================
# Integration: Detector + Sanitizer working together
# ===========================================================================

class TestIntegration:
    """End-to-end scenarios combining detection and sanitization."""

    def setup_method(self):
        self.detector = SQLInjectionDetector()
        self.sanitizer = SQLSanitizer()
        self.builder = ParameterizedQueryBuilder()

    def test_safe_login_query(self):
        username = "alice"
        # Detector should say it's fine
        assert self.detector.is_safe(username)
        # Builder produces a parameterized query
        sql, params = self.builder.select("users", ["id", "role"], {"username": username})
        assert sql == "SELECT id, role FROM users WHERE username = ?"
        assert params == ("alice",)

    def test_malicious_login_blocked_by_detector(self):
        username = "' OR '1'='1"
        is_sus, reasons = self.detector.is_suspicious(username)
        assert is_sus
        # Even if it slipped through, the builder would parameterize it safely
        sql, params = self.builder.select("users", ["id"], {"username": username})
        # The injected string is a bound parameter, not embedded in SQL text
        assert "OR" not in sql
        assert username in params

    def test_sanitizer_cleans_name_with_quotes(self):
        raw = "O'Brien"
        assert self.detector.is_safe(raw)  # Not a classic injection
        sanitized = self.sanitizer.sanitize(raw)
        assert sanitized == "O''Brien"

    def test_union_attack_detected(self):
        payload = "1 UNION SELECT password FROM users--"
        is_sus, _ = self.detector.is_suspicious(payload)
        assert is_sus

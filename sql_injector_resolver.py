"""
SQL Injection Resolver
======================
Provides utilities to detect and prevent SQL injection attacks:
  - SQLInjectionDetector  : checks whether a string contains suspicious patterns
  - SQLSanitizer          : escapes/sanitizes raw user input for safe use in queries
  - ParameterizedQueryBuilder : builds parameterized query strings that avoid injection
"""

import re
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Patterns used by the detector
# ---------------------------------------------------------------------------

# SQL keywords / operators commonly abused in injection attacks
_SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE|"
    r"UNION|INTERSECT|EXCEPT|FROM|WHERE|JOIN|HAVING|GROUP\s+BY|ORDER\s+BY|"
    r"LIMIT|OFFSET|INTO|VALUES|SET|GRANT|REVOKE|CALL|DECLARE|CAST|CONVERT|"
    r"SLEEP|BENCHMARK|WAITFOR|DELAY|XP_CMDSHELL|SP_EXECUTESQL|LOAD_FILE|"
    r"OUTFILE|DUMPFILE|INFORMATION_SCHEMA|SYS\.|SYSOBJECTS|SYSCOLUMNS)\b",
    re.IGNORECASE,
)

# Comment sequences that can silence the rest of a query
_SQL_COMMENTS = re.compile(r"(--|\#|/\*|\*/)")

# Tautologies / boolean-injection snippets  e.g.  ' OR '1'='1
_TAUTOLOGY = re.compile(
    r"(\bOR\b\s*[\'\"]?\s*\d+\s*=\s*\d+|"
    r"\bAND\b\s*[\'\"]?\s*\d+\s*=\s*\d+|"
    r"\bOR\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?|"
    r"\bAND\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)",
    re.IGNORECASE,
)

# Stacked / terminated queries using semicolons
_STACKED_QUERY = re.compile(r";\s*\w")

# Hex-encoded payloads  0x41424344
_HEX_ENCODING = re.compile(r"0x[0-9a-fA-F]{2,}")

# Unbalanced or strategically placed single/double quotes
_UNBALANCED_QUOTES = re.compile(r"'[^']*$|\"[^\"]*$")

# Characters that should almost never appear in ordinary user input
_DANGEROUS_CHARS = re.compile(r"[;'\"\-\-]")


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class SQLInjectionDetector:
    """
    Detect potential SQL injection patterns in raw user-supplied strings.

    Usage::

        detector = SQLInjectionDetector()
        is_dangerous, reasons = detector.is_suspicious("admin' OR '1'='1")
        if is_dangerous:
            print("Injection detected:", reasons)
    """

    def __init__(
        self,
        check_keywords: bool = True,
        check_comments: bool = True,
        check_tautologies: bool = True,
        check_stacked_queries: bool = True,
        check_hex_encoding: bool = True,
    ) -> None:
        self.check_keywords = check_keywords
        self.check_comments = check_comments
        self.check_tautologies = check_tautologies
        self.check_stacked_queries = check_stacked_queries
        self.check_hex_encoding = check_hex_encoding

    # ------------------------------------------------------------------
    def is_suspicious(self, user_input: str) -> Tuple[bool, List[str]]:
        """
        Return ``(True, reasons)`` when *user_input* looks suspicious,
        ``(False, [])`` otherwise.

        :param user_input: Raw string supplied by the user.
        :returns: 2-tuple ``(is_suspicious: bool, reasons: list[str])``.
        """
        if not isinstance(user_input, str):
            raise TypeError(f"Expected str, got {type(user_input).__name__}")

        reasons: List[str] = []

        if self.check_comments and _SQL_COMMENTS.search(user_input):
            reasons.append("SQL comment sequence detected")

        if self.check_tautologies and _TAUTOLOGY.search(user_input):
            reasons.append("Boolean tautology / OR-AND injection detected")

        if self.check_stacked_queries and _STACKED_QUERY.search(user_input):
            reasons.append("Stacked query (semicolon) detected")

        if self.check_hex_encoding and _HEX_ENCODING.search(user_input):
            reasons.append("Hex-encoded payload detected")

        if self.check_keywords and _SQL_KEYWORDS.search(user_input):
            reasons.append("SQL keyword detected")

        return bool(reasons), reasons

    # ------------------------------------------------------------------
    def is_safe(self, user_input: str) -> bool:
        """Convenience wrapper – returns ``True`` when input is *not* suspicious."""
        suspicious, _ = self.is_suspicious(user_input)
        return not suspicious


# ---------------------------------------------------------------------------
# Sanitizer
# ---------------------------------------------------------------------------

class SQLSanitizer:
    """
    Escape user-supplied strings for safer (though not perfectly safe) inclusion
    in SQL queries.  **Prefer parameterized queries** whenever possible; use
    this class only when parameterization is not an option.

    Usage::

        sanitizer = SQLSanitizer()
        safe_value = sanitizer.sanitize("O'Reilly")  # -> "O''Reilly"
    """

    # Characters that are escaped by this sanitizer
    _ESCAPE_MAP: Dict[str, str] = {
        "'":  "''",        # SQL standard – double the single quote
        "\\": "\\\\",      # back-slash
        "\x00": "\\0",     # NULL byte
        "\n":  "\\n",
        "\r":  "\\r",
        "\x1a": "\\Z",     # Ctrl-Z (MySQL-specific)
    }

    def sanitize(self, value: str) -> str:
        """
        Escape *value* so it can be placed inside single-quoted SQL strings.

        :param value: Raw user input.
        :returns: Escaped string (without surrounding quotes).
        :raises TypeError: If *value* is not a string.
        """
        if not isinstance(value, str):
            raise TypeError(f"Expected str, got {type(value).__name__}")

        result = []
        for ch in value:
            result.append(self._ESCAPE_MAP.get(ch, ch))
        return "".join(result)

    # ------------------------------------------------------------------
    def sanitize_identifier(self, identifier: str) -> str:
        """
        Sanitize a SQL *identifier* (table / column name) by stripping any
        character that is not alphanumeric or an underscore.

        :param identifier: Raw identifier string.
        :returns: Sanitized identifier.
        :raises ValueError: If the sanitized result is empty.
        """
        if not isinstance(identifier, str):
            raise TypeError(f"Expected str, got {type(identifier).__name__}")

        clean = re.sub(r"[^\w]", "", identifier)
        if not clean:
            raise ValueError(
                f"Identifier {identifier!r} becomes empty after sanitization"
            )
        return clean

    # ------------------------------------------------------------------
    def sanitize_integer(self, value: Any) -> int:
        """
        Safely convert *value* to a Python ``int``.

        :param value: Value to convert.
        :returns: Integer.
        :raises ValueError: If *value* cannot be converted to int.
        """
        try:
            return int(value)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Cannot convert {value!r} to integer: {exc}") from exc


# ---------------------------------------------------------------------------
# Parameterized query builder
# ---------------------------------------------------------------------------

class ParameterizedQueryBuilder:
    """
    Build parameterized query strings that are safe against SQL injection.

    This builder works with *positional* (``?``) or *named* (``:name``) placeholders
    and is intentionally database-agnostic – it just constructs the SQL text and
    the matching parameter tuple/dict.  Pass the result to your database driver's
    ``cursor.execute(sql, params)`` call.

    Usage::

        builder = ParameterizedQueryBuilder()
        sql, params = builder.select("users", ["id", "email"], {"username": "alice"})
        # -> ("SELECT id, email FROM users WHERE username = ?", ("alice",))
    """

    def __init__(self, placeholder: str = "?") -> None:
        """
        :param placeholder: The parameter placeholder style used by your database
            driver.  Use ``"?"`` for SQLite / ODBC, ``"%s"`` for psycopg2 / MySQLdb,
            or ``":name"`` for named placeholders (not supported for WHERE building,
            which always uses positional style).
        """
        self._ph = placeholder
        self._sanitizer = SQLSanitizer()

    # ------------------------------------------------------------------
    def _safe_col_list(self, columns: Optional[List[str]]) -> str:
        if not columns:
            return "*"
        return ", ".join(self._sanitizer.sanitize_identifier(c) for c in columns)

    def _safe_table(self, table: str) -> str:
        return self._sanitizer.sanitize_identifier(table)

    # ------------------------------------------------------------------
    def select(
        self,
        table: str,
        columns: Optional[List[str]] = None,
        where: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Tuple[str, tuple]:
        """
        Build a parameterized ``SELECT`` statement.

        :param table:   Table name.
        :param columns: Column names to retrieve; ``None`` means ``*``.
        :param where:   ``{column: value}`` equality conditions (AND-joined).
        :param limit:   Maximum number of rows to return.
        :param offset:  Number of rows to skip.
        :returns: ``(sql_string, params_tuple)``.
        """
        col_clause = self._safe_col_list(columns)
        tbl = self._safe_table(table)
        sql = f"SELECT {col_clause} FROM {tbl}"
        params: list = []

        if where:
            clauses = []
            for col, val in where.items():
                safe_col = self._sanitizer.sanitize_identifier(col)
                clauses.append(f"{safe_col} = {self._ph}")
                params.append(val)
            sql += " WHERE " + " AND ".join(clauses)

        if limit is not None:
            sql += f" LIMIT {self._sanitizer.sanitize_integer(limit)}"
        if offset is not None:
            sql += f" OFFSET {self._sanitizer.sanitize_integer(offset)}"

        return sql, tuple(params)

    # ------------------------------------------------------------------
    def insert(
        self,
        table: str,
        data: Dict[str, Any],
    ) -> Tuple[str, tuple]:
        """
        Build a parameterized ``INSERT`` statement.

        :param table: Table name.
        :param data:  ``{column: value}`` mapping of values to insert.
        :returns: ``(sql_string, params_tuple)``.
        """
        if not data:
            raise ValueError("'data' must not be empty")

        tbl = self._safe_table(table)
        cols = [self._sanitizer.sanitize_identifier(c) for c in data.keys()]
        placeholders = ", ".join(self._ph for _ in cols)
        col_list = ", ".join(cols)
        sql = f"INSERT INTO {tbl} ({col_list}) VALUES ({placeholders})"
        return sql, tuple(data.values())

    # ------------------------------------------------------------------
    def update(
        self,
        table: str,
        data: Dict[str, Any],
        where: Dict[str, Any],
    ) -> Tuple[str, tuple]:
        """
        Build a parameterized ``UPDATE`` statement.

        :param table: Table name.
        :param data:  ``{column: new_value}`` columns to update.
        :param where: ``{column: value}`` WHERE conditions (AND-joined).
        :returns: ``(sql_string, params_tuple)``.
        """
        if not data:
            raise ValueError("'data' must not be empty")
        if not where:
            raise ValueError("'where' must not be empty (refusing bare UPDATE)")

        tbl = self._safe_table(table)
        set_clauses = []
        params: list = []
        for col, val in data.items():
            set_clauses.append(f"{self._sanitizer.sanitize_identifier(col)} = {self._ph}")
            params.append(val)

        where_clauses = []
        for col, val in where.items():
            where_clauses.append(
                f"{self._sanitizer.sanitize_identifier(col)} = {self._ph}"
            )
            params.append(val)

        sql = (
            f"UPDATE {tbl} SET {', '.join(set_clauses)} "
            f"WHERE {' AND '.join(where_clauses)}"
        )
        return sql, tuple(params)

    # ------------------------------------------------------------------
    def delete(
        self,
        table: str,
        where: Dict[str, Any],
    ) -> Tuple[str, tuple]:
        """
        Build a parameterized ``DELETE`` statement.

        :param table: Table name.
        :param where: ``{column: value}`` WHERE conditions (AND-joined).
        :returns: ``(sql_string, params_tuple)``.
        """
        if not where:
            raise ValueError("'where' must not be empty (refusing bare DELETE)")

        tbl = self._safe_table(table)
        clauses = []
        params: list = []
        for col, val in where.items():
            clauses.append(f"{self._sanitizer.sanitize_identifier(col)} = {self._ph}")
            params.append(val)

        sql = f"DELETE FROM {tbl} WHERE {' AND '.join(clauses)}"
        return sql, tuple(params)

# SQL Injection Resolver

A Python library that detects, sanitizes, and prevents SQL injection attacks.

## Components

### `SQLInjectionDetector`
Scans raw user input for common SQL injection patterns:
- SQL comment sequences (`--`, `#`, `/* */`)
- Boolean tautologies (`OR 1=1`, `AND 1=1`, etc.)
- Stacked / terminated queries (`;DROP TABLE …`)
- Hex-encoded payloads (`0x414243`)
- Dangerous SQL keywords (`SELECT`, `UNION`, `DROP`, `SLEEP`, `EXEC`, …)

```python
from sql_injector_resolver import SQLInjectionDetector

detector = SQLInjectionDetector()
is_dangerous, reasons = detector.is_suspicious("' OR '1'='1")
# is_dangerous -> True
# reasons      -> ["Boolean tautology / OR-AND injection detected"]
```

### `SQLSanitizer`
Escapes strings, identifiers, and integers for safe use in SQL:

```python
from sql_injector_resolver import SQLSanitizer

s = SQLSanitizer()
s.sanitize("O'Reilly")            # -> "O''Reilly"
s.sanitize_identifier("users")   # -> "users"
s.sanitize_integer("42")          # -> 42
```

### `ParameterizedQueryBuilder`
Builds safe parameterized SQL (SELECT / INSERT / UPDATE / DELETE) that
can be passed directly to a database driver's `cursor.execute(sql, params)`:

```python
from sql_injector_resolver import ParameterizedQueryBuilder

builder = ParameterizedQueryBuilder()

sql, params = builder.select("users", ["id", "email"], {"username": "alice"})
# sql    -> "SELECT id, email FROM users WHERE username = ?"
# params -> ("alice",)

sql, params = builder.insert("users", {"name": "Bob", "age": 30})
# sql    -> "INSERT INTO users (name, age) VALUES (?, ?)"
# params -> ("Bob", 30)
```

## Running the tests

```bash
pip install pytest
python -m pytest test_sql_injector_resolver.py -v
```

All 71 tests should pass.
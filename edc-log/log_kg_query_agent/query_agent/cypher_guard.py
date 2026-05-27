from __future__ import annotations

import re


BANNED_PATTERNS = (
    r"\bCREATE\b",
    r"\bMERGE\b",
    r"\bDELETE\b",
    r"\bDETACH\b",
    r"\bSET\b",
    r"\bREMOVE\b",
    r"\bDROP\b",
    r"\bLOAD\s+CSV\b",
    r"\bFOREACH\b",
    r"\bAPOC\.PERIODIC\b",
    r"\bDBMS\.",
)

ALLOWED_START_PATTERNS = (
    "MATCH",
    "OPTIONAL MATCH",
    "WITH",
    "UNWIND",
    "CALL",
    "RETURN",
)


class CypherSafetyError(ValueError):
    """Raised when generated Cypher is not safe for read-only execution."""


def _strip_strings_and_comments(text: str) -> str:
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"'(?:[^'\\\\]|\\\\.)*'", "''", text)
    text = re.sub(r'"(?:[^"\\\\]|\\\\.)*"', '""', text)
    return text


def ensure_read_only_cypher(cypher: str) -> str:
    query = cypher.strip().rstrip(";").strip()
    if not query:
        raise CypherSafetyError("Generated Cypher is empty")

    normalized = _strip_strings_and_comments(query).upper()
    if ";" in normalized:
        raise CypherSafetyError("Multiple Cypher statements are not allowed")
    if not normalized.startswith(ALLOWED_START_PATTERNS):
        raise CypherSafetyError("Cypher must start with a read-only clause")

    for pattern in BANNED_PATTERNS:
        if re.search(pattern, normalized, flags=re.IGNORECASE):
            raise CypherSafetyError(f"Cypher contains a forbidden write clause: {pattern}")

    return query


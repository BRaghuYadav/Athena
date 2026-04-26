"""
validator.py — Query preflight checker
Every generated query passes through this BEFORE being shown to the analyst.
Checks: field existence, operator compatibility, event category compatibility, pipe sanity.
"""
import re
import json
import os
from typing import Dict, List, Tuple

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema_registry.json")

def load_schema() -> dict:
    with open(SCHEMA_PATH, "r") as f:
        return json.load(f)

_schema_cache = None
def get_schema():
    global _schema_cache
    if _schema_cache is None:
        _schema_cache = load_schema()
    return _schema_cache

def reload_schema():
    global _schema_cache
    _schema_cache = load_schema()
    return _schema_cache


# ── Field extraction from S1QL ──

# Known S1QL field patterns (dot-separated identifiers)
FIELD_PATTERN = re.compile(
    r'\b((?:event|src|tgt|dst|osSrc|url|agent|endpoint|registry|task|cmdScript|module|site|account)'
    r'(?:\.[a-zA-Z][a-zA-Z0-9]*)+)\b'
)

# Known S1QL operators
OPERATORS = [
    "contains:anycase", "in:anycase", "in:matchcase", "contains",
    "matches", "startsWith", "endsWith", "RegExp",
    ">=", "<=", "!=", "=", ">", "<", "NOT IN", "IN", "in"
]

def extract_fields(query: str) -> List[str]:
    """Extract all S1QL field references from a query."""
    # Remove comments
    lines = [l for l in query.split('\n') if not l.strip().startswith('//')]
    text = '\n'.join(lines)
    fields = FIELD_PATTERN.findall(text)
    return list(set(fields))


def extract_field_operators(query: str) -> List[Tuple[str, str]]:
    """Extract (field, operator) pairs from the query."""
    pairs = []
    lines = [l for l in query.split('\n') if not l.strip().startswith('//')]
    text = '\n'.join(lines)

    for op in OPERATORS:
        # Match: field <operator>
        pattern = rf'(\b(?:event|src|tgt|dst|osSrc|url|agent|endpoint|registry|task|cmdScript|module|site|account)(?:\.[a-zA-Z][a-zA-Z0-9]*)+)\s+{re.escape(op)}\b'
        for match in re.finditer(pattern, text, re.IGNORECASE):
            pairs.append((match.group(1), op))

        # Match: field <operator> (no word boundary for symbols like >=)
        if op in (">=", "<=", "!=", "=", ">", "<"):
            pattern2 = rf'(\b(?:event|src|tgt|dst|osSrc|url|agent|endpoint|registry|task|cmdScript|module|site|account)(?:\.[a-zA-Z][a-zA-Z0-9]*)+)\s*{re.escape(op)}'
            for match in re.finditer(pattern2, text):
                field = match.group(1)
                if (field, op) not in pairs:
                    pairs.append((field, op))

    return pairs


def extract_event_category(query: str) -> str | None:
    """Extract the event.category value if present."""
    match = re.search(r'event\.category\s*=\s*["\'](\w+)["\']', query)
    return match.group(1) if match else None


def extract_pipe_fields(query: str) -> List[str]:
    """Extract fields referenced in | columns, | group, | sort."""
    pipe_fields = []
    # After | columns or | group ... by
    for match in re.finditer(r'\|\s*(?:columns|sort)\s+(.*?)(?:\||$)', query, re.DOTALL):
        segment = match.group(1)
        pipe_fields.extend(FIELD_PATTERN.findall(segment))

    for match in re.finditer(r'\|\s*group\s+.*?\bby\b\s+(.*?)(?:\||$)', query, re.DOTALL):
        segment = match.group(1)
        pipe_fields.extend(FIELD_PATTERN.findall(segment))

    return list(set(pipe_fields))


# ── Main Validator ──

def validate_query(query_text: str) -> dict:
    """
    Validate an S1QL query against the schema registry.
    Returns: {status, confidence, warnings[], errors[], field_count, checked_at}
    """
    schema = get_schema()
    fields_db = schema.get("fields", {})
    op_map = schema.get("operator_map", {})

    result = {
        "status": "PASS",
        "confidence": 1.0,
        "warnings": [],
        "errors": [],
        "field_count": 0,
        "checked_at": None,
    }

    if not query_text or not query_text.strip():
        result["status"] = "BLOCKED"
        result["errors"].append("Empty query")
        result["confidence"] = 0.0
        return result

    # 1. Extract fields
    fields_used = extract_fields(query_text)
    result["field_count"] = len(fields_used)

    # 2. Check field existence
    for field in fields_used:
        if field not in fields_db:
            result["errors"].append(f"Unknown field: {field}")
            result["confidence"] -= 0.15

    # 3. Check operator compatibility
    field_ops = extract_field_operators(query_text)
    for field, operator in field_ops:
        field_def = fields_db.get(field)
        if not field_def:
            continue  # already flagged above
        field_type = field_def.get("type", "string")
        valid_ops = op_map.get(field_type, [])
        # Normalize operator for comparison
        op_normalized = operator.lower().strip()
        valid_ops_lower = [o.lower() for o in valid_ops]
        if op_normalized not in valid_ops_lower:
            result["errors"].append(f"Operator '{operator}' not valid for field '{field}' (type: {field_type})")
            result["confidence"] -= 0.2

    # 4. Check event category compatibility
    event_cat = extract_event_category(query_text)
    if event_cat:
        for field in fields_used:
            field_def = fields_db.get(field)
            if not field_def:
                continue
            valid_in = field_def.get("valid_in", ["*"])
            if "*" not in valid_in and event_cat not in valid_in:
                result["warnings"].append(
                    f"Field '{field}' may not be available for event.category=\"{event_cat}\" "
                    f"(valid in: {', '.join(valid_in)})"
                )
                result["confidence"] -= 0.08

    # 5. Check pipe fields exist in schema
    pipe_fields = extract_pipe_fields(query_text)
    for field in pipe_fields:
        if field not in fields_db:
            result["warnings"].append(f"Pipe references unknown field: {field}")
            result["confidence"] -= 0.05

    # 6. Basic structural checks
    if '| columns' not in query_text and '| group' not in query_text:
        result["warnings"].append("No | columns or | group — query may return too many fields")
        result["confidence"] -= 0.05

    if '| limit' not in query_text and '| group' not in query_text:
        result["warnings"].append("No | limit — query may return excessive results")
        result["confidence"] -= 0.05

    # Determine final status
    if result["errors"]:
        result["status"] = "BLOCKED"
    elif result["warnings"]:
        result["status"] = "PASS_WITH_WARNINGS"

    result["confidence"] = round(max(0.0, min(1.0, result["confidence"])), 2)

    from datetime import datetime
    result["checked_at"] = datetime.utcnow().isoformat()

    return result

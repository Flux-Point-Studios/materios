"""
Content validation gate for blob payloads.

Parses the blob data and runs game-specific plausibility checks.
If validation fails, the receipt is not certified — the score is
visible on-chain but ignored by leaderboard indexers.

Schemas are loaded from a JSON registry file. Each schema defines
required fields, types, bounds, and computed plausibility checks.
"""

import ast
import json
import logging
import operator
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from daemon.config import DaemonConfig

logger = logging.getLogger(__name__)

# Default registry path (relative to package root or absolute via env)
DEFAULT_REGISTRY_PATH = str(Path(__file__).parent.parent / "schemas" / "registry.json")


@dataclass
class ValidationResult:
    valid: bool = True
    errors: list[str] = field(default_factory=list)
    schema_version: Optional[int] = None
    schema_id: Optional[str] = None
    payload: Optional[dict] = None


class SchemaRegistry:
    """Loads and caches schema definitions from a JSON registry file."""

    def __init__(self, registry_path: str):
        self.registry_path = registry_path
        self.schemas: dict[str, dict] = {}
        self.schema_lookup: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.registry_path, "r") as f:
                data = json.load(f)
            self.schemas = data.get("schemas", {})
            self.schema_lookup = data.get("schema_lookup", {})
            logger.info(
                f"Schema registry loaded: {len(self.schemas)} schemas, "
                f"{len(self.schema_lookup)} version mappings from {self.registry_path}"
            )
        except FileNotFoundError:
            logger.warning(f"Schema registry not found at {self.registry_path}, content validation will pass-through")
        except json.JSONDecodeError as e:
            logger.error(f"Schema registry JSON parse error: {e}")

    def reload(self) -> None:
        """Hot-reload the registry from disk."""
        self._load()

    def get_schema(self, version: int, schema_id: Optional[str] = None) -> Optional[dict]:
        """Resolve a schema by explicit schema_id or by version lookup."""
        if schema_id and schema_id in self.schemas:
            return self.schemas[schema_id]
        key = str(version)
        if key in self.schema_lookup:
            resolved_id = self.schema_lookup[key]
            return self.schemas.get(resolved_id)
        return None

    def get_schema_id(self, version: int, schema_id: Optional[str] = None) -> Optional[str]:
        """Return the resolved schema ID string."""
        if schema_id and schema_id in self.schemas:
            return schema_id
        key = str(version)
        return self.schema_lookup.get(key)


def _cast_field(value: Any, field_type: str) -> Any:
    """Cast a field value to the declared type. Raises ValueError on failure."""
    if field_type == "int":
        return int(value)
    elif field_type == "float":
        return float(value)
    elif field_type == "string":
        return str(value)
    elif field_type == "bool":
        return bool(value)
    else:
        return value


_SAFE_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

_SAFE_CMP = {
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
}


def _safe_eval_node(node: ast.AST, fields: dict[str, float]) -> float:
    """Recursively evaluate an AST node using only arithmetic operations."""
    if isinstance(node, ast.Expression):
        return _safe_eval_node(node.body, fields)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.Name) and node.id in fields:
        return float(fields[node.id])
    if isinstance(node, ast.BinOp) and type(node.op) in _SAFE_OPS:
        left = _safe_eval_node(node.left, fields)
        right = _safe_eval_node(node.right, fields)
        return float(_SAFE_OPS[type(node.op)](left, right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _SAFE_OPS:
        operand = _safe_eval_node(node.operand, fields)
        return float(_SAFE_OPS[type(node.op)](operand))
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in _SAFE_CMP:
        left = _safe_eval_node(node.left, fields)
        right = _safe_eval_node(node.comparators[0], fields)
        return float(_SAFE_CMP[type(node.ops[0])](left, right))
    if isinstance(node, ast.BoolOp):
        # and / or
        values = [_safe_eval_node(v, fields) for v in node.values]
        if isinstance(node.op, ast.And):
            return float(all(v for v in values))
        return float(any(v for v in values))
    raise ValueError(f"Unsupported expression node: {ast.dump(node)}")


def _eval_expr(expr: str, fields: dict[str, Any]) -> float:
    """Safely evaluate an arithmetic expression using field values.

    Uses AST parsing — only literal numbers, field names, and basic
    arithmetic/comparison operators are allowed. No function calls,
    attribute access, imports, or arbitrary code execution.
    """
    namespace = {k: float(v) for k, v in fields.items() if isinstance(v, (int, float))}
    try:
        tree = ast.parse(expr, mode="eval")
        return _safe_eval_node(tree, namespace)
    except Exception as e:
        raise ValueError(f"Expression eval failed: {expr} — {e}")


class ContentValidator:
    def __init__(self, config: DaemonConfig):
        self.config = config
        registry_path = os.environ.get("SCHEMA_REGISTRY_PATH", DEFAULT_REGISTRY_PATH)
        self.registry = SchemaRegistry(registry_path)

    def validate(self, chunk_data_list: list[bytes], receipt_id: str) -> ValidationResult:
        """Validate blob content after integrity checks pass.

        Args:
            chunk_data_list: Raw bytes of each verified chunk (in order).
            receipt_id: For logging context.

        Returns:
            ValidationResult with valid=True if content is plausible.
        """
        result = ValidationResult()

        raw = b"".join(chunk_data_list)

        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            result.valid = False
            result.errors.append(f"Blob is not valid JSON: {e}")
            return result

        result.payload = payload

        version = payload.get("v")
        result.schema_version = version

        if version is None:
            result.valid = False
            result.errors.append("Missing schema version field 'v'")
            return result

        # Resolve schema — check explicit schema_id first, fall back to version lookup
        explicit_schema_id = payload.get("schema_id")
        schema = self.registry.get_schema(version, explicit_schema_id)
        result.schema_id = self.registry.get_schema_id(version, explicit_schema_id)

        if schema is None:
            logger.info(
                f"No schema registered for v={version} (schema_id={explicit_schema_id}) "
                f"for {receipt_id[:16]}..., skipping content validation"
            )
            return result

        return self._validate_against_schema(payload, schema, result, receipt_id)

    def _validate_against_schema(
        self, payload: dict, schema: dict, result: ValidationResult, receipt_id: str
    ) -> ValidationResult:
        """Validate a payload against a loaded schema definition."""

        fields_def = schema.get("fields", {})
        computed_checks = schema.get("computed_checks", [])

        # --- Step 1: Required fields presence ---
        for field_name in fields_def:
            if field_name not in payload:
                result.valid = False
                result.errors.append(f"Missing required field: {field_name}")
                return result

        # --- Step 2: Type casting and bounds ---
        typed_fields: dict[str, Any] = {}
        for field_name, field_def in fields_def.items():
            raw_value = payload[field_name]
            field_type = field_def.get("type", "string")

            try:
                typed_value = _cast_field(raw_value, field_type)
            except (ValueError, TypeError) as e:
                result.valid = False
                result.errors.append(f"Invalid type for '{field_name}': {e}")
                return result

            typed_fields[field_name] = typed_value

            # Static min/max bounds
            if "min" in field_def and isinstance(typed_value, (int, float)):
                if typed_value < field_def["min"]:
                    result.valid = False
                    result.errors.append(
                        f"{field_name} below minimum: {typed_value} < {field_def['min']}"
                    )
                    return result

            if "max" in field_def and isinstance(typed_value, (int, float)):
                if typed_value > field_def["max"]:
                    result.valid = False
                    result.errors.append(
                        f"{field_name} above maximum: {typed_value} > {field_def['max']}"
                    )
                    return result

        # --- Step 3: Computed plausibility checks ---
        for check in computed_checks:
            check_name = check.get("name", "unnamed")

            # Optional condition gate
            condition = check.get("condition")
            if condition:
                try:
                    if not _eval_expr(condition, typed_fields):
                        continue
                except ValueError:
                    continue

            # Evaluate the expression
            try:
                value = _eval_expr(check["expr"], typed_fields)
            except ValueError as e:
                result.valid = False
                result.errors.append(f"Computed check '{check_name}' failed: {e}")
                return result

            # Compare against static max or computed max_expr
            if "max" in check:
                max_val = float(check["max"])
            elif "max_expr" in check:
                try:
                    max_val = _eval_expr(check["max_expr"], typed_fields)
                except ValueError as e:
                    result.valid = False
                    result.errors.append(f"Computed check '{check_name}' max_expr failed: {e}")
                    return result
            else:
                continue

            if value > max_val:
                error_template = check.get("error", f"{check_name}: {{value}} > {{max}}")
                result.valid = False
                result.errors.append(error_template.format(value=value, max=max_val))
                return result

        # All checks passed
        game_name = schema.get("game", "unknown")
        logger.info(
            f"Content valid ({game_name}) for {receipt_id[:16]}...: "
            + " ".join(f"{k}={v}" for k, v in typed_fields.items() if k != "player")
        )
        return result

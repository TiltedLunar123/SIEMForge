"""Sigma condition parser and base converter."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


# ── AST Nodes ──────────────────────────────────


@dataclass
class ConditionAnd:
    operands: list


@dataclass
class ConditionOr:
    operands: list


@dataclass
class ConditionNot:
    operand: object


@dataclass
class ConditionRef:
    name: str


# ── Condition Parser ───────────────────────────


def _tokenize(condition: str) -> list:
    """Split a Sigma condition string into tokens."""
    text = " ".join(condition.split())
    tokens: list = []
    i = 0
    while i < len(text):
        if text[i] in " \t":
            i += 1
            continue
        if text[i] == "(":
            tokens.append("(")
            i += 1
        elif text[i] == ")":
            tokens.append(")")
            i += 1
        else:
            j = i
            while j < len(text) and text[j] not in " \t()":
                j += 1
            tokens.append(text[i:j])
            i = j
    return tokens


def parse_condition(condition: str) -> object:
    """Parse a Sigma condition string into an AST.

    Grammar (operator precedence: not > and > or):
        expression := term ('or' term)*
        term       := factor ('and' factor)*
        factor     := 'not' factor | '(' expression ')' | IDENTIFIER
    """
    stripped = condition.strip()
    if not stripped:
        raise ValueError("Empty condition string")

    tokens = _tokenize(stripped)
    pos = [0]

    def _peek():
        if pos[0] < len(tokens):
            return tokens[pos[0]]
        return None

    def _advance():
        tok = tokens[pos[0]]
        pos[0] += 1
        return tok

    def _parse_expression():
        node = _parse_term()
        operands = [node]
        while _peek() == "or":
            _advance()
            operands.append(_parse_term())
        if len(operands) == 1:
            return operands[0]
        return ConditionOr(operands)

    def _parse_term():
        node = _parse_factor()
        operands = [node]
        while _peek() == "and":
            _advance()
            operands.append(_parse_factor())
        if len(operands) == 1:
            return operands[0]
        return ConditionAnd(operands)

    def _parse_factor():
        tok = _peek()
        if tok == "not":
            _advance()
            return ConditionNot(_parse_factor())
        if tok == "(":
            _advance()
            node = _parse_expression()
            if _peek() != ")":
                raise ValueError("Expected closing parenthesis")
            _advance()
            return node
        if tok is None:
            raise ValueError("Unexpected end of condition")
        _advance()
        return ConditionRef(tok)

    result = _parse_expression()

    if pos[0] != len(tokens):
        raise ValueError(f"Unexpected token: {tokens[pos[0]]}")

    return result


# ── Base Converter ─────────────────────────────


class BaseConverter(ABC):
    """Abstract base for Sigma to SIEM query converters."""

    @staticmethod
    def parse_field_name(field_name: str):
        """Split 'Field|modifier' into (field, [modifier])."""
        parts = field_name.split("|")
        return parts[0], parts[1:]

    def apply_wildcard(self, value: str, modifiers: list) -> str:
        """Apply Sigma modifiers to a value string."""
        val = str(value)
        if "contains" in modifiers:
            return f"*{val}*"
        if "endswith" in modifiers:
            return f"*{val}"
        if "startswith" in modifiers:
            return f"{val}*"
        return val

    def convert_rule(self, rule: dict) -> str:
        """Convert a full Sigma rule dict to a query string."""
        detection = rule["detection"]
        condition_str = detection["condition"].strip()
        ast = parse_condition(condition_str)

        selections: dict = {}
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                fields = []
                for field_name, field_values in value.items():
                    field, mods = self.parse_field_name(field_name)
                    if not isinstance(field_values, list):
                        field_values = [field_values]
                    fields.append((field, mods, field_values))
                selections[key] = fields
            elif isinstance(value, list):
                selections[key] = [("_keyword", [], value)]

        return self._render_ast(ast, selections)

    def _render_ast(self, node: object, selections: dict) -> str:
        """Walk the AST and produce the query string."""
        if isinstance(node, ConditionRef):
            if node.name not in selections:
                return f"/* unknown selection: {node.name} */"
            return self.convert_selection(selections[node.name])
        if isinstance(node, ConditionAnd):
            parts = [self._render_ast(op, selections) for op in node.operands]
            return self.join_and(parts)
        if isinstance(node, ConditionOr):
            parts = [self._render_ast(op, selections) for op in node.operands]
            return self.join_or(parts)
        if isinstance(node, ConditionNot):
            inner = self._render_ast(node.operand, selections)
            return self.negate(inner)
        raise ValueError(f"Unknown AST node: {node}")

    def convert_selection(self, fields: list) -> str:
        """Convert a single selection's field list to a query fragment."""
        parts = []
        for field, mods, values in fields:
            parts.append(self.convert_field_match(field, mods, values))
        return self.join_and(parts)

    @abstractmethod
    def convert_field_match(self, field: str, modifiers: list, values: list) -> str:
        """Convert a single field match to query syntax."""

    @abstractmethod
    def join_and(self, clauses: list) -> str:
        """Join clauses with AND."""

    @abstractmethod
    def join_or(self, clauses: list) -> str:
        """Join clauses with OR."""

    @abstractmethod
    def negate(self, clause: str) -> str:
        """Negate a clause."""

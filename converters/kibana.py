"""Kibana KQL converter for Sigma rules."""
from __future__ import annotations

from .base import BaseConverter

__all__ = ["KibanaConverter"]


class KibanaConverter(BaseConverter):
    """Convert Sigma detection rules to Kibana Query Language (KQL)."""

    def convert_field_match(self, field: str, modifiers: list, values: list) -> str:
        parts = []
        for value in values:
            wild = self.apply_wildcard(str(value), modifiers)
            if field == "_keyword":
                parts.append(f'"{wild}"')
            else:
                parts.append(f'{field}: "{wild}"')
        if len(parts) == 1:
            return parts[0]
        return "(" + " or ".join(parts) + ")"

    def join_and(self, clauses: list) -> str:
        if len(clauses) == 1:
            return clauses[0]
        return "(" + " and ".join(clauses) + ")"

    def join_or(self, clauses: list) -> str:
        if len(clauses) == 1:
            return clauses[0]
        return "(" + " or ".join(clauses) + ")"

    def negate(self, clause: str) -> str:
        return f"not ({clause})"

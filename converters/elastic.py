"""Elasticsearch Lucene query converter for Sigma rules."""
from __future__ import annotations

from .base import BaseConverter

__all__ = ["ElasticConverter"]


class ElasticConverter(BaseConverter):
    """Convert Sigma detection rules to Elasticsearch Lucene queries."""

    def convert_field_match(self, field: str, modifiers: list, values: list) -> str:
        parts = []
        for value in values:
            wild = self.apply_wildcard(str(value), modifiers)
            if field == "_keyword":
                parts.append(f'"{wild}"')
            else:
                parts.append(f'{field}:"{wild}"')
        if len(parts) == 1:
            return parts[0]
        return "(" + " OR ".join(parts) + ")"

    def join_and(self, clauses: list) -> str:
        if len(clauses) == 1:
            return clauses[0]
        return "(" + " AND ".join(clauses) + ")"

    def join_or(self, clauses: list) -> str:
        if len(clauses) == 1:
            return clauses[0]
        return "(" + " OR ".join(clauses) + ")"

    def negate(self, clause: str) -> str:
        return f"NOT {clause}"

#!/usr/bin/env python3
"""SIEMForge CLI — backward-compatible entry point.

Delegates to the siemforge package. Prefer: python -m siemforge
"""
# Re-export public API so existing tests/imports keep working
from siemforge._version import VERSION  # noqa: F401
from siemforge.loader import load_sigma_rules, load_config_file  # noqa: F401
from siemforge.loader import SIGMA_RULES_DIR, CONFIGS_DIR  # noqa: F401
from siemforge.validator import (  # noqa: F401
    validate_sigma_rule, validate_rules,
    VALID_LEVELS, REQUIRED_SIGMA_FIELDS, UUID_PATTERN,
)
from siemforge.mitre import MITRE_MAP, collect_techniques as _collect_techniques  # noqa: F401
from siemforge.stats import count_levels as _count_levels  # noqa: F401
from siemforge.export import export_sigma_rules, export_all  # noqa: F401
from siemforge.cli import main  # noqa: F401

if __name__ == "__main__":
    main()

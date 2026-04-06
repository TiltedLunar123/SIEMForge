#!/usr/bin/env python3
"""SIEMForge CLI — backward-compatible entry point.

Delegates to the siemforge package. Prefer: python -m siemforge
"""
# Re-export public API so existing tests/imports keep working
from siemforge._version import VERSION  # noqa: F401
from siemforge.cli import main  # noqa: F401
from siemforge.export import export_all, export_sigma_rules  # noqa: F401
from siemforge.loader import (  # noqa: F401  # noqa: F401
    CONFIGS_DIR,
    SIGMA_RULES_DIR,
    load_config_file,
    load_sigma_rules,
)
from siemforge.mitre import MITRE_MAP  # noqa: F401
from siemforge.stats import count_levels as _count_levels  # noqa: F401
from siemforge.validator import (  # noqa: F401
    REQUIRED_SIGMA_FIELDS,
    UUID_PATTERN,
    VALID_LEVELS,
    validate_rules,
    validate_sigma_rule,
)

if __name__ == "__main__":
    main()

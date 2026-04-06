"""SIEMForge -- SIEM Detection Content Toolkit."""

from siemforge._version import VERSION
from siemforge.cli import main
from siemforge.export import export_all, export_sigma_rules
from siemforge.loader import CONFIGS_DIR, SIGMA_RULES_DIR, load_config_file, load_sigma_rules
from siemforge.mitre import MITRE_MAP, collect_techniques
from siemforge.stats import count_levels
from siemforge.validator import (
    REQUIRED_SIGMA_FIELDS,
    UUID_PATTERN,
    VALID_LEVELS,
    validate_rules,
    validate_sigma_rule,
)

# Backward-compatible aliases
_collect_techniques = collect_techniques
_count_levels = count_levels

__all__ = [
    "VERSION",
    "load_sigma_rules",
    "load_config_file",
    "SIGMA_RULES_DIR",
    "CONFIGS_DIR",
    "validate_sigma_rule",
    "validate_rules",
    "VALID_LEVELS",
    "REQUIRED_SIGMA_FIELDS",
    "UUID_PATTERN",
    "MITRE_MAP",
    "collect_techniques",
    "_collect_techniques",
    "count_levels",
    "_count_levels",
    "export_sigma_rules",
    "export_all",
    "main",
]

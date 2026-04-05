"""SIEMForge -- SIEM Detection Content Toolkit."""

from siemforge._version import VERSION
from siemforge.loader import load_sigma_rules, load_config_file, SIGMA_RULES_DIR, CONFIGS_DIR
from siemforge.validator import (
    validate_sigma_rule, validate_rules, VALID_LEVELS,
    REQUIRED_SIGMA_FIELDS, UUID_PATTERN,
)
from siemforge.mitre import MITRE_MAP, collect_techniques
from siemforge.stats import count_levels
from siemforge.export import export_sigma_rules, export_all
from siemforge.cli import main

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

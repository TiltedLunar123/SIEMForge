"""Load Sigma rules and config files from disk."""
from __future__ import annotations

from pathlib import Path

import yaml

from siemforge.display import err

_SCRIPT_DIR = Path(__file__).resolve().parent.parent
SIGMA_RULES_DIR = _SCRIPT_DIR / "rules" / "sigma"
CONFIGS_DIR = _SCRIPT_DIR / "configs"


def load_sigma_rules(rules_dir: Path | None = None) -> dict[str, dict]:
    """Load all Sigma YAML rules from disk and return {filename: parsed_dict}."""
    rules_dir = rules_dir or SIGMA_RULES_DIR
    rules: dict[str, dict] = {}
    if not rules_dir.is_dir():
        return rules
    for filepath in sorted(rules_dir.glob("*.yml")):
        try:
            data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                rules[filepath.name] = data
        except (yaml.YAMLError, OSError) as exc:
            err(f"Failed to load {filepath.name}: {exc}")
    return rules


def load_config_file(filename: str, configs_dir: Path | None = None) -> str:
    """Load a config file (XML) from the configs directory."""
    configs_dir = configs_dir or CONFIGS_DIR
    filepath = configs_dir / filename
    return filepath.read_text(encoding="utf-8")

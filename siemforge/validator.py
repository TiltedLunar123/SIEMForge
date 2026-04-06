"""Sigma rule validation."""
from __future__ import annotations

import re

from siemforge.display import C, bullet, err, header, ok

REQUIRED_SIGMA_FIELDS = [
    "title", "id", "status", "description", "author",
    "date", "logsource", "detection", "level",
]

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)


def validate_sigma_rule(filename: str, rule: dict) -> tuple[list[str], list[str]]:
    """Validate a single parsed Sigma rule. Returns (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    for field in REQUIRED_SIGMA_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    rule_id = rule.get("id", "")
    if rule_id and not UUID_PATTERN.match(str(rule_id)):
        errors.append(f"ID is not valid UUID format: {rule_id}")

    level = rule.get("level", "")
    if level and level not in VALID_LEVELS:
        errors.append(f"Invalid level: {level}")

    logsource = rule.get("logsource")
    if logsource is not None and not isinstance(logsource, dict):
        errors.append("logsource must be a mapping")

    detection = rule.get("detection")
    if detection is not None:
        if not isinstance(detection, dict):
            errors.append("detection must be a mapping")
        elif "condition" not in detection:
            errors.append("detection is missing 'condition' field")

    tags = rule.get("tags", [])
    if not any(str(t).startswith("attack.t") for t in (tags or [])):
        warnings.append("No MITRE ATT&CK technique tag found")

    if "falsepositives" not in rule:
        warnings.append("No falsepositives section (recommended)")

    return errors, warnings


def validate_rules(rules: dict[str, dict] | None = None) -> tuple[int, int, int]:
    """Validate all Sigma rules for required fields and structure."""
    from siemforge.loader import load_sigma_rules

    header("VALIDATING SIGMA RULES")

    if rules is None:
        rules = load_sigma_rules()

    total = len(rules)
    passed = 0
    failed = 0
    warnings_count = 0

    for filename, rule in rules.items():
        errors, warns = validate_sigma_rule(filename, rule)

        if errors:
            err(f"{filename}")
            for issue in errors:
                bullet(f"{C.RED}{issue}{C.RESET}")
            failed += 1
        else:
            ok(f"{filename}")
            passed += 1

        for w in warns:
            bullet(f"{C.YELLOW}{w}{C.RESET}")
            warnings_count += 1

    print(f"\n  {C.BOLD}Results:{C.RESET} {C.GREEN}{passed} passed{C.RESET}  "
          f"{C.RED}{failed} failed{C.RESET}  "
          f"{C.YELLOW}{warnings_count} warnings{C.RESET}  "
          f"/ {total} total")

    return passed, failed, warnings_count

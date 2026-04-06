# Contributing to SIEMForge

## Development Setup

```bash
git clone https://github.com/TiltedLunar123/SIEMForge.git
cd SIEMForge
pip install -r requirements-dev.txt
```

## Running Tests

```bash
pytest tests/ -v
pytest tests/ -v --cov=siemforge --cov=converters --cov-report=term-missing
```

## Linting

```bash
ruff check .
ruff check . --fix  # auto-fix
```

## Branch Strategy

- Work on feature branches off `master`
- Open a pull request to `master` when ready
- CI must pass before merging

## Adding a New Sigma Rule

1. Create `rules/sigma/your_rule_name.yml` following the [Sigma specification](https://sigmahq.io/docs/basics/rules.html)
2. Required fields: `title`, `id` (uuid4), `status`, `description`, `author`, `date`, `logsource`, `detection`, `level`
3. Include MITRE ATT&CK tags (e.g., `attack.t1059.001`)
4. Include `falsepositives` section
5. Add a sample log event to `samples/` that triggers the rule
6. Run `python -m siemforge --validate` to verify
7. Run `pytest tests/ -v` to confirm nothing breaks

### Rule Template

```yaml
title: Your Rule Title
id: <generate a uuid4>
status: experimental
description: >
    What this rule detects and why it matters.
references:
    - https://attack.mitre.org/techniques/TXXXX/
    - https://github.com/TiltedLunar123/SIEMForge
author: Jude Hilgendorf
date: YYYY/MM/DD
modified: YYYY/MM/DD
tags:
    - attack.tactic_name
    - attack.tXXXX.XXX
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection:
        FieldName|modifier:
            - value1
            - value2
    condition: selection
fields:
    - RelevantField1
    - RelevantField2
falsepositives:
    - Known benign scenario
level: medium
```

### Rule Review Checklist

- [ ] Has a unique uuid4 `id`
- [ ] All required fields present (`title`, `id`, `status`, `description`, `author`, `date`, `logsource`, `detection`, `level`)
- [ ] MITRE ATT&CK tags included and valid
- [ ] `falsepositives` section is populated
- [ ] Sample log event added to `samples/`
- [ ] `python -m siemforge --validate` passes
- [ ] All converter backends produce valid output for the rule
- [ ] Tests pass

## Adding a Converter Backend

1. Create `converters/your_backend.py` extending `BaseConverter` from `converters/base.py`
2. Implement: `convert_field_match()`, `join_and()`, `join_or()`, `negate()`
3. Add `__all__ = ["YourConverter"]` to the module
4. Register in `converters/__init__.py` and update `__all__`
5. Add tests in `tests/test_converters.py`
6. Verify all existing rules convert without error

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation
- `test:` adding tests
- `refactor:` code restructure
- `ci:` CI/CD changes

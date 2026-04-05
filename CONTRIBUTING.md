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
pytest tests/ -v --cov=siemforge --cov=converters
```

## Linting

```bash
ruff check .
ruff check . --fix  # auto-fix
```

## Adding a New Sigma Rule

1. Create `rules/sigma/your_rule_name.yml` following the [Sigma specification](https://sigmahq.io/docs/basics/rules.html)
2. Required fields: `title`, `id` (uuid4), `status`, `description`, `author`, `date`, `logsource`, `detection`, `level`
3. Include MITRE ATT&CK tags (e.g., `attack.t1059.001`)
4. Include `falsepositives` section
5. Run `python -m siemforge --validate` to verify
6. Add a sample log event to `samples/` that triggers the rule

## Adding a Converter Backend

1. Create `converters/your_backend.py` extending `BaseConverter` from `converters/base.py`
2. Implement: `convert_field_match()`, `join_and()`, `join_or()`, `negate()`
3. Register in `converters/__init__.py`
4. Add tests in `tests/test_converters.py`

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation
- `test:` adding tests
- `refactor:` code restructure
- `ci:` CI/CD changes

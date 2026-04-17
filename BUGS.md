# Known Bugs

## [Severity: High] Missing return values in convert_rules error paths
- **File:** siemforge/cli.py:50, 61, 67
- **Issue:** Function is typed `-> int` but bare `return` statements in error paths return `None`, causing `TypeError: unsupported operand type(s) for +=: 'int' and 'NoneType'` at the caller (line 248).
- **Repro:** Trigger any error path, e.g. `python -m siemforge --convert splunk --convert-rule nonexistent.yml`.
- **Fix:** Replace the bare `return` at lines 50, 61, 67 with `return 0` (or an appropriate error count).

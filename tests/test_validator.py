"""Tests for Sigma rule validation using proper YAML parsing."""


from siemforge import VALID_LEVELS, load_sigma_rules, validate_sigma_rule


class TestValidateSigmaRule:
    """Tests for the YAML-based validator."""

    def test_valid_rule_passes(self):
        rule = {
            "title": "Test Rule",
            "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "status": "experimental",
            "description": "A test rule",
            "author": "Tester",
            "date": "2025/01/01",
            "logsource": {"category": "test", "product": "test"},
            "detection": {"selection": {"field": "value"}, "condition": "selection"},
            "level": "high",
            "tags": ["attack.execution", "attack.t1059.001"],
            "falsepositives": ["None known"],
        }
        errors, warnings = validate_sigma_rule("test.yml", rule)
        assert errors == []
        assert warnings == []

    def test_missing_required_fields(self):
        rule = {"title": "Incomplete Rule"}
        errors, warnings = validate_sigma_rule("incomplete.yml", rule)
        missing_fields = [e for e in errors if "Missing required field" in e]
        # Should be missing: id, status, description, author, date, logsource, detection, level
        assert len(missing_fields) == 8

    def test_invalid_uuid_format(self):
        rule = {
            "title": "Bad ID", "id": "not-a-uuid",
            "status": "experimental", "description": "test",
            "author": "test", "date": "2025/01/01",
            "logsource": {"category": "test"},
            "detection": {"selection": {}, "condition": "selection"},
            "level": "high",
        }
        errors, _ = validate_sigma_rule("bad_id.yml", rule)
        assert any("UUID" in e for e in errors)

    def test_valid_uuid_passes(self):
        rule = {
            "title": "Good ID", "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "status": "experimental", "description": "test",
            "author": "test", "date": "2025/01/01",
            "logsource": {"category": "test"},
            "detection": {"selection": {}, "condition": "selection"},
            "level": "high",
            "tags": ["attack.t1059.001"],
            "falsepositives": ["None"],
        }
        errors, _ = validate_sigma_rule("good_id.yml", rule)
        assert errors == []

    def test_invalid_level(self):
        rule = {
            "title": "Bad Level", "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "status": "experimental", "description": "test",
            "author": "test", "date": "2025/01/01",
            "logsource": {"category": "test"},
            "detection": {"selection": {}, "condition": "selection"},
            "level": "super_critical",
        }
        errors, _ = validate_sigma_rule("bad_level.yml", rule)
        assert any("Invalid level" in e for e in errors)

    def test_all_valid_levels_accepted(self):
        for level in VALID_LEVELS:
            rule = {
                "title": "Test", "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                "status": "experimental", "description": "test",
                "author": "test", "date": "2025/01/01",
                "logsource": {"category": "test"},
                "detection": {"selection": {}, "condition": "selection"},
                "level": level,
                "tags": ["attack.t1059.001"],
                "falsepositives": ["None"],
            }
            errors, _ = validate_sigma_rule("test.yml", rule)
            assert not any("Invalid level" in e for e in errors), f"Level {level} rejected"

    def test_logsource_must_be_dict(self):
        rule = {
            "title": "Test", "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "status": "experimental", "description": "test",
            "author": "test", "date": "2025/01/01",
            "logsource": "not a dict",
            "detection": {"selection": {}, "condition": "selection"},
            "level": "high",
        }
        errors, _ = validate_sigma_rule("test.yml", rule)
        assert any("logsource must be a mapping" in e for e in errors)

    def test_detection_must_be_dict(self):
        rule = {
            "title": "Test", "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "status": "experimental", "description": "test",
            "author": "test", "date": "2025/01/01",
            "logsource": {"category": "test"},
            "detection": "not a dict",
            "level": "high",
        }
        errors, _ = validate_sigma_rule("test.yml", rule)
        assert any("detection must be a mapping" in e for e in errors)

    def test_detection_missing_condition(self):
        rule = {
            "title": "Test", "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "status": "experimental", "description": "test",
            "author": "test", "date": "2025/01/01",
            "logsource": {"category": "test"},
            "detection": {"selection": {"field": "value"}},
            "level": "high",
        }
        errors, _ = validate_sigma_rule("test.yml", rule)
        assert any("condition" in e for e in errors)

    def test_warns_on_missing_mitre_tags(self):
        rule = {
            "title": "Test", "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "status": "experimental", "description": "test",
            "author": "test", "date": "2025/01/01",
            "logsource": {"category": "test"},
            "detection": {"selection": {}, "condition": "selection"},
            "level": "high",
            "tags": ["attack.execution"],
            "falsepositives": ["None"],
        }
        _, warnings = validate_sigma_rule("test.yml", rule)
        assert any("MITRE" in w for w in warnings)

    def test_warns_on_missing_falsepositives(self):
        rule = {
            "title": "Test", "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "status": "experimental", "description": "test",
            "author": "test", "date": "2025/01/01",
            "logsource": {"category": "test"},
            "detection": {"selection": {}, "condition": "selection"},
            "level": "high",
            "tags": ["attack.t1059.001"],
        }
        _, warnings = validate_sigma_rule("test.yml", rule)
        assert any("falsepositives" in w for w in warnings)


class TestAllRulesValid:
    """Validate every shipped Sigma rule passes validation."""

    def test_all_shipped_rules_pass(self):
        rules = load_sigma_rules()
        assert len(rules) > 0, "No rules found"
        for filename, rule in rules.items():
            errors, _ = validate_sigma_rule(filename, rule)
            assert errors == [], f"{filename} has validation errors: {errors}"

    def test_all_shipped_rules_have_mitre_tags(self):
        rules = load_sigma_rules()
        for filename, rule in rules.items():
            tags = rule.get("tags", [])
            has_technique = any(str(t).startswith("attack.t") for t in tags)
            assert has_technique, f"{filename} is missing MITRE technique tags"

    def test_all_shipped_rules_have_falsepositives(self):
        rules = load_sigma_rules()
        for filename, rule in rules.items():
            assert "falsepositives" in rule, f"{filename} is missing falsepositives"

    def test_all_ids_unique(self):
        rules = load_sigma_rules()
        ids = [rule["id"] for rule in rules.values()]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

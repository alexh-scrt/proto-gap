"""Unit tests for proto_gap.rules — rule registry, rule types, and lookup functions."""

from __future__ import annotations

import pytest

from proto_gap.models import Category, Severity
from proto_gap.rules import (
    ALL_RULES,
    ASTRule,
    FilePresenceRule,
    RegexRule,
    AUTH_RULES,
    ERROR_HANDLING_RULES,
    ENV_CONFIG_RULES,
    LOGGING_RULES,
    MIGRATION_RULES,
    SECURITY_RULES,
    TESTING_RULES,
    get_all_rule_ids,
    get_rule_by_id,
    get_rules_by_category,
    get_rules_by_type,
)


# ---------------------------------------------------------------------------
# Registry completeness tests
# ---------------------------------------------------------------------------


class TestAllRulesRegistry:
    """Tests verifying the overall structure of the ALL_RULES registry."""

    def test_all_rules_is_non_empty(self) -> None:
        """ALL_RULES must contain at least one rule."""
        assert len(ALL_RULES) > 0

    def test_all_rules_contains_expected_categories(self) -> None:
        """Every Category enum value must have at least one rule."""
        categories_covered = {rule.category for rule in ALL_RULES}
        for category in Category:
            assert category in categories_covered, (
                f"Category {category.value} has no rules in ALL_RULES"
            )

    def test_all_rule_ids_are_unique(self) -> None:
        """No two rules should share the same rule_id."""
        ids = [rule.rule_id for rule in ALL_RULES]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found in ALL_RULES"

    def test_all_rules_have_non_empty_fields(self) -> None:
        """Every rule must have non-empty required string fields."""
        for rule in ALL_RULES:
            assert rule.rule_id, f"Rule has empty rule_id: {rule}"
            assert rule.title, f"Rule {rule.rule_id} has empty title"
            assert rule.description, f"Rule {rule.rule_id} has empty description"
            assert rule.remediation, f"Rule {rule.rule_id} has empty remediation"

    def test_all_rules_have_valid_severity(self) -> None:
        """Every rule must have a valid Severity value."""
        valid_severities = set(Severity)
        for rule in ALL_RULES:
            assert rule.severity in valid_severities, (
                f"Rule {rule.rule_id} has invalid severity: {rule.severity}"
            )

    def test_all_rules_have_valid_category(self) -> None:
        """Every rule must have a valid Category value."""
        valid_categories = set(Category)
        for rule in ALL_RULES:
            assert rule.category in valid_categories, (
                f"Rule {rule.rule_id} has invalid category: {rule.category}"
            )

    def test_rule_id_format(self) -> None:
        """Rule IDs should follow the PREFIX + 3-digit number format."""
        import re
        pattern = re.compile(r'^[A-Z]{2,5}\d{3}$')
        for rule in ALL_RULES:
            assert pattern.match(rule.rule_id), (
                f"Rule ID '{rule.rule_id}' does not match expected format (e.g. AUTH001)"
            )

    def test_all_rules_are_correct_types(self) -> None:
        """Every item in ALL_RULES must be a RegexRule, ASTRule, or FilePresenceRule."""
        valid_types = (RegexRule, ASTRule, FilePresenceRule)
        for rule in ALL_RULES:
            assert isinstance(rule, valid_types), (
                f"Unexpected rule type: {type(rule)} for rule {rule.rule_id}"
            )


# ---------------------------------------------------------------------------
# Category-specific list tests
# ---------------------------------------------------------------------------


class TestCategoryRuleLists:
    """Tests verifying the per-category rule lists."""

    def test_auth_rules_non_empty(self) -> None:
        """AUTH_RULES must contain at least one rule."""
        assert len(AUTH_RULES) >= 1

    def test_auth_rules_all_in_auth_category(self) -> None:
        """All AUTH_RULES must belong to the AUTHENTICATION category."""
        for rule in AUTH_RULES:
            assert rule.category == Category.AUTHENTICATION

    def test_error_handling_rules_non_empty(self) -> None:
        """ERROR_HANDLING_RULES must contain at least one rule."""
        assert len(ERROR_HANDLING_RULES) >= 1

    def test_error_handling_rules_all_in_category(self) -> None:
        """All ERROR_HANDLING_RULES must belong to the ERROR_HANDLING category."""
        for rule in ERROR_HANDLING_RULES:
            assert rule.category == Category.ERROR_HANDLING

    def test_env_config_rules_non_empty(self) -> None:
        """ENV_CONFIG_RULES must contain at least one rule."""
        assert len(ENV_CONFIG_RULES) >= 1

    def test_env_config_rules_all_in_category(self) -> None:
        """All ENV_CONFIG_RULES must belong to the ENV_CONFIG category."""
        for rule in ENV_CONFIG_RULES:
            assert rule.category == Category.ENV_CONFIG

    def test_security_rules_non_empty(self) -> None:
        """SECURITY_RULES must contain at least one rule."""
        assert len(SECURITY_RULES) >= 1

    def test_security_rules_all_in_category(self) -> None:
        """All SECURITY_RULES must belong to the SECURITY category."""
        for rule in SECURITY_RULES:
            assert rule.category == Category.SECURITY

    def test_migration_rules_non_empty(self) -> None:
        """MIGRATION_RULES must contain at least one rule."""
        assert len(MIGRATION_RULES) >= 1

    def test_migration_rules_all_in_category(self) -> None:
        """All MIGRATION_RULES must belong to the MIGRATIONS category."""
        for rule in MIGRATION_RULES:
            assert rule.category == Category.MIGRATIONS

    def test_logging_rules_non_empty(self) -> None:
        """LOGGING_RULES must contain at least one rule."""
        assert len(LOGGING_RULES) >= 1

    def test_logging_rules_all_in_category(self) -> None:
        """All LOGGING_RULES must belong to the LOGGING category."""
        for rule in LOGGING_RULES:
            assert rule.category == Category.LOGGING

    def test_testing_rules_non_empty(self) -> None:
        """TESTING_RULES must contain at least one rule."""
        assert len(TESTING_RULES) >= 1

    def test_testing_rules_all_in_category(self) -> None:
        """All TESTING_RULES must belong to the TESTING category."""
        for rule in TESTING_RULES:
            assert rule.category == Category.TESTING

    def test_all_rules_is_union_of_category_lists(self) -> None:
        """ALL_RULES should be the concatenation of all category-specific lists."""
        combined = (
            AUTH_RULES
            + ERROR_HANDLING_RULES
            + ENV_CONFIG_RULES
            + SECURITY_RULES
            + MIGRATION_RULES
            + LOGGING_RULES
            + TESTING_RULES
        )
        assert len(ALL_RULES) == len(combined)
        for rule in combined:
            assert rule in ALL_RULES


# ---------------------------------------------------------------------------
# RegexRule-specific tests
# ---------------------------------------------------------------------------


class TestRegexRule:
    """Tests for RegexRule dataclass structure and field defaults."""

    def test_regex_rule_required_fields(self) -> None:
        """RegexRule should be constructible with all required fields."""
        rule = RegexRule(
            rule_id="TST999",
            category=Category.SECURITY,
            severity=Severity.HIGH,
            pattern=r"dangerous_pattern",
            title="Test rule",
            description="A test description.",
            remediation="Fix it.",
        )
        assert rule.rule_id == "TST999"
        assert rule.pattern == r"dangerous_pattern"
        assert rule.file_extensions == []
        assert rule.negate is False

    def test_regex_rule_with_extensions(self) -> None:
        """RegexRule should store file extensions correctly."""
        rule = RegexRule(
            rule_id="TST998",
            category=Category.SECURITY,
            severity=Severity.LOW,
            pattern=r"test",
            title="Title",
            description="Desc",
            remediation="Fix",
            file_extensions=[".py", ".js"],
        )
        assert rule.file_extensions == [".py", ".js"]

    def test_regex_rule_negate_flag(self) -> None:
        """RegexRule negate flag should default False and be settable."""
        rule = RegexRule(
            rule_id="TST997",
            category=Category.TESTING,
            severity=Severity.LOW,
            pattern=r"def test_",
            title="No tests",
            description="Missing tests.",
            remediation="Add tests.",
            negate=True,
        )
        assert rule.negate is True

    def test_all_regex_rules_have_valid_patterns(self) -> None:
        """All RegexRule patterns should compile without error."""
        import re
        regex_rules = get_rules_by_type(RegexRule)
        for rule in regex_rules:
            assert isinstance(rule, RegexRule)
            try:
                re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as exc:
                pytest.fail(f"Rule {rule.rule_id} has invalid regex pattern: {exc}")


# ---------------------------------------------------------------------------
# ASTRule-specific tests
# ---------------------------------------------------------------------------


class TestASTRule:
    """Tests for ASTRule dataclass structure."""

    def test_ast_rule_required_fields(self) -> None:
        """ASTRule should be constructible with all required fields."""
        rule = ASTRule(
            rule_id="TST996",
            category=Category.ERROR_HANDLING,
            severity=Severity.HIGH,
            node_type="ExceptHandler",
            title="Bare except",
            description="A bare except.",
            remediation="Fix it.",
            hook="bare_except",
        )
        assert rule.rule_id == "TST996"
        assert rule.node_type == "ExceptHandler"
        assert rule.hook == "bare_except"

    def test_ast_rules_have_non_empty_hooks(self) -> None:
        """All ASTRule objects must have a non-empty hook string."""
        ast_rules = get_rules_by_type(ASTRule)
        for rule in ast_rules:
            assert isinstance(rule, ASTRule)
            assert rule.hook, f"ASTRule {rule.rule_id} has empty hook"

    def test_ast_rules_have_non_empty_node_types(self) -> None:
        """All ASTRule objects must have a non-empty node_type string."""
        ast_rules = get_rules_by_type(ASTRule)
        for rule in ast_rules:
            assert isinstance(rule, ASTRule)
            assert rule.node_type, f"ASTRule {rule.rule_id} has empty node_type"


# ---------------------------------------------------------------------------
# FilePresenceRule-specific tests
# ---------------------------------------------------------------------------


class TestFilePresenceRule:
    """Tests for FilePresenceRule dataclass structure."""

    def test_file_presence_rule_required_fields(self) -> None:
        """FilePresenceRule should be constructible with all required fields."""
        rule = FilePresenceRule(
            rule_id="TST995",
            category=Category.ENV_CONFIG,
            severity=Severity.MEDIUM,
            filename_patterns=[".env.example"],
            title="Missing env example",
            description="No env example found.",
            remediation="Create .env.example.",
        )
        assert rule.rule_id == "TST995"
        assert rule.filename_patterns == [".env.example"]
        assert rule.expect_present is True

    def test_file_presence_rule_expect_absent(self) -> None:
        """FilePresenceRule expect_present=False should be settable."""
        rule = FilePresenceRule(
            rule_id="TST994",
            category=Category.SECURITY,
            severity=Severity.CRITICAL,
            filename_patterns=[".env"],
            title=".env committed",
            description="Found committed .env.",
            remediation="Remove .env from git.",
            expect_present=False,
        )
        assert rule.expect_present is False

    def test_file_presence_rules_have_non_empty_patterns(self) -> None:
        """All FilePresenceRule objects must have at least one filename pattern."""
        fp_rules = get_rules_by_type(FilePresenceRule)
        for rule in fp_rules:
            assert isinstance(rule, FilePresenceRule)
            assert len(rule.filename_patterns) >= 1, (
                f"FilePresenceRule {rule.rule_id} has empty filename_patterns"
            )


# ---------------------------------------------------------------------------
# get_rules_by_category tests
# ---------------------------------------------------------------------------


class TestGetRulesByCategory:
    """Tests for the get_rules_by_category() lookup function."""

    def test_get_auth_rules(self) -> None:
        """get_rules_by_category(AUTHENTICATION) should return auth rules."""
        rules = get_rules_by_category(Category.AUTHENTICATION)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.category == Category.AUTHENTICATION

    def test_get_security_rules(self) -> None:
        """get_rules_by_category(SECURITY) should return security rules."""
        rules = get_rules_by_category(Category.SECURITY)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.category == Category.SECURITY

    def test_get_rules_returns_list(self) -> None:
        """get_rules_by_category() should always return a list."""
        for category in Category:
            result = get_rules_by_category(category)
            assert isinstance(result, list)

    def test_get_rules_all_categories_non_empty(self) -> None:
        """Every category should have at least one rule."""
        for category in Category:
            rules = get_rules_by_category(category)
            assert len(rules) >= 1, (
                f"Category {category.value} returned no rules from get_rules_by_category()"
            )

    def test_get_rules_sum_equals_all_rules(self) -> None:
        """The sum of rules across all categories should equal ALL_RULES length."""
        total = sum(len(get_rules_by_category(cat)) for cat in Category)
        assert total == len(ALL_RULES)


# ---------------------------------------------------------------------------
# get_rule_by_id tests
# ---------------------------------------------------------------------------


class TestGetRuleById:
    """Tests for the get_rule_by_id() lookup function."""

    def test_get_existing_rule(self) -> None:
        """get_rule_by_id() should return the correct rule for a known ID."""
        # AUTH001 is defined as the first auth rule
        rule = get_rule_by_id("AUTH001")
        assert rule is not None
        assert rule.rule_id == "AUTH001"
        assert rule.category == Category.AUTHENTICATION

    def test_get_security_rule(self) -> None:
        """get_rule_by_id() should return SEC001 correctly."""
        rule = get_rule_by_id("SEC001")
        assert rule is not None
        assert rule.rule_id == "SEC001"
        assert rule.category == Category.SECURITY

    def test_get_nonexistent_rule_returns_none(self) -> None:
        """get_rule_by_id() should return None for unknown rule IDs."""
        assert get_rule_by_id("FAKE999") is None
        assert get_rule_by_id("") is None
        assert get_rule_by_id("auth001") is None  # case-sensitive

    def test_get_all_rules_by_id_roundtrip(self) -> None:
        """Every rule ID in ALL_RULES should be retrievable by get_rule_by_id()."""
        for rule in ALL_RULES:
            found = get_rule_by_id(rule.rule_id)
            assert found is not None
            assert found.rule_id == rule.rule_id

    def test_get_rule_returns_correct_type(self) -> None:
        """get_rule_by_id() should return the original rule object."""
        for rule in ALL_RULES:
            found = get_rule_by_id(rule.rule_id)
            assert type(found) is type(rule)


# ---------------------------------------------------------------------------
# get_all_rule_ids tests
# ---------------------------------------------------------------------------


class TestGetAllRuleIds:
    """Tests for the get_all_rule_ids() utility function."""

    def test_returns_list_of_strings(self) -> None:
        """get_all_rule_ids() should return a list of string IDs."""
        ids = get_all_rule_ids()
        assert isinstance(ids, list)
        assert all(isinstance(id_, str) for id_ in ids)

    def test_returns_sorted_ids(self) -> None:
        """get_all_rule_ids() should return IDs in sorted order."""
        ids = get_all_rule_ids()
        assert ids == sorted(ids)

    def test_returns_all_rule_ids(self) -> None:
        """get_all_rule_ids() should return the same count as ALL_RULES."""
        ids = get_all_rule_ids()
        assert len(ids) == len(ALL_RULES)

    def test_ids_match_all_rules(self) -> None:
        """Every ID from get_all_rule_ids() should correspond to a rule in ALL_RULES."""
        ids = set(get_all_rule_ids())
        all_ids = {rule.rule_id for rule in ALL_RULES}
        assert ids == all_ids


# ---------------------------------------------------------------------------
# get_rules_by_type tests
# ---------------------------------------------------------------------------


class TestGetRulesByType:
    """Tests for the get_rules_by_type() utility function."""

    def test_get_regex_rules(self) -> None:
        """get_rules_by_type(RegexRule) should return only RegexRule instances."""
        rules = get_rules_by_type(RegexRule)
        assert len(rules) >= 1
        for rule in rules:
            assert isinstance(rule, RegexRule)

    def test_get_ast_rules(self) -> None:
        """get_rules_by_type(ASTRule) should return only ASTRule instances."""
        rules = get_rules_by_type(ASTRule)
        assert len(rules) >= 1
        for rule in rules:
            assert isinstance(rule, ASTRule)

    def test_get_file_presence_rules(self) -> None:
        """get_rules_by_type(FilePresenceRule) should return only FilePresenceRule."""
        rules = get_rules_by_type(FilePresenceRule)
        assert len(rules) >= 1
        for rule in rules:
            assert isinstance(rule, FilePresenceRule)

    def test_type_counts_sum_to_total(self) -> None:
        """The sum of rules by type should equal ALL_RULES count."""
        regex_count = len(get_rules_by_type(RegexRule))
        ast_count = len(get_rules_by_type(ASTRule))
        fp_count = len(get_rules_by_type(FilePresenceRule))
        assert regex_count + ast_count + fp_count == len(ALL_RULES)

    def test_unknown_type_returns_empty(self) -> None:
        """get_rules_by_type() with an unknown type returns an empty list."""
        result = get_rules_by_type(str)  # type: ignore[arg-type]
        assert result == []


# ---------------------------------------------------------------------------
# Specific critical rule content tests
# ---------------------------------------------------------------------------


class TestSpecificRuleContent:
    """Tests verifying the content of specific high-value rules."""

    def test_auth001_is_critical_severity(self) -> None:
        """AUTH001 (hardcoded JWT secret) must be CRITICAL severity."""
        rule = get_rule_by_id("AUTH001")
        assert rule is not None
        assert rule.severity == Severity.CRITICAL

    def test_sec001_is_critical_severity(self) -> None:
        """SEC001 (eval/exec) must be CRITICAL severity."""
        rule = get_rule_by_id("SEC001")
        assert rule is not None
        assert rule.severity == Severity.CRITICAL

    def test_sec002_is_critical_severity(self) -> None:
        """SEC002 (shell injection) must be CRITICAL severity."""
        rule = get_rule_by_id("SEC002")
        assert rule is not None
        assert rule.severity == Severity.CRITICAL

    def test_mig002_is_critical_severity(self) -> None:
        """MIG002 (create_all) must be CRITICAL severity."""
        rule = get_rule_by_id("MIG002")
        assert rule is not None
        assert rule.severity == Severity.CRITICAL

    def test_err001_is_ast_rule(self) -> None:
        """ERR001 (bare except) must be an ASTRule."""
        rule = get_rule_by_id("ERR001")
        assert rule is not None
        assert isinstance(rule, ASTRule)
        assert rule.hook == "bare_except"

    def test_err002_is_ast_rule(self) -> None:
        """ERR002 (silent except) must be an ASTRule."""
        rule = get_rule_by_id("ERR002")
        assert rule is not None
        assert isinstance(rule, ASTRule)
        assert rule.hook == "silent_except"

    def test_env003_is_file_presence_rule(self) -> None:
        """ENV003 (.env example) must be a FilePresenceRule expecting files present."""
        rule = get_rule_by_id("ENV003")
        assert rule is not None
        assert isinstance(rule, FilePresenceRule)
        assert rule.expect_present is True

    def test_tst001_is_file_presence_rule(self) -> None:
        """TST001 (no tests) must be a FilePresenceRule expecting files present."""
        rule = get_rule_by_id("TST001")
        assert rule is not None
        assert isinstance(rule, FilePresenceRule)
        assert rule.expect_present is True

    def test_log003_is_negated_regex_rule(self) -> None:
        """LOG003 (module logger) must be a negated RegexRule."""
        rule = get_rule_by_id("LOG003")
        assert rule is not None
        assert isinstance(rule, RegexRule)
        assert rule.negate is True

    def test_mig001_expects_alembic(self) -> None:
        """MIG001 should look for alembic.ini or migrations/env.py."""
        rule = get_rule_by_id("MIG001")
        assert rule is not None
        assert isinstance(rule, FilePresenceRule)
        assert any("alembic" in p for p in rule.filename_patterns)

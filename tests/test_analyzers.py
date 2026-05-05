"""Unit tests for proto_gap.analyzers — individual analyzer functions.

Each test class focuses on one analyzer function and uses temporary directories
with synthetic file contents to verify that the correct Finding objects are
produced (or not produced) for the given source code patterns.
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from proto_gap.analyzers import (
    _apply_ast_rule,
    _apply_file_presence_rule,
    _apply_regex_rule,
    _check_file_patterns,
    _extract_call_name,
    _filter_by_extension,
    _hook_bare_except,
    _hook_function_no_error_handling,
    _hook_silent_except,
    _line_number_for_offset,
    _read_file_safe,
    analyze_authentication,
    analyze_env_config,
    analyze_error_handling,
    analyze_logging,
    analyze_migrations,
    analyze_security,
    analyze_testing,
)
from proto_gap.models import Category, Finding, Severity
from proto_gap.rules import (
    ASTRule,
    FilePresenceRule,
    RegexRule,
    get_rule_by_id,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def write_file(directory: Path, name: str, content: str) -> Path:
    """Write content to a named file inside directory and return the path."""
    path = directory / name
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


@pytest.fixture()
def tmp_repo(tmp_path: Path) -> Path:
    """Return a temporary directory to serve as the repo root."""
    return tmp_path


# ---------------------------------------------------------------------------
# _filter_by_extension
# ---------------------------------------------------------------------------


class TestFilterByExtension:
    """Tests for the _filter_by_extension() helper."""

    def test_filters_by_single_extension(self, tmp_path: Path) -> None:
        """Only files with the requested extension should be returned."""
        py_file = tmp_path / "app.py"
        js_file = tmp_path / "main.js"
        py_file.touch()
        js_file.touch()
        result = _filter_by_extension([py_file, js_file], [".py"])
        assert py_file in result
        assert js_file not in result

    def test_filters_by_multiple_extensions(self, tmp_path: Path) -> None:
        """Files matching any of the requested extensions should be returned."""
        py_file = tmp_path / "app.py"
        js_file = tmp_path / "main.js"
        txt_file = tmp_path / "readme.txt"
        py_file.touch()
        js_file.touch()
        txt_file.touch()
        result = _filter_by_extension([py_file, js_file, txt_file], [".py", ".js"])
        assert py_file in result
        assert js_file in result
        assert txt_file not in result

    def test_empty_extensions_returns_all(self, tmp_path: Path) -> None:
        """An empty extension list should return all files."""
        py_file = tmp_path / "app.py"
        js_file = tmp_path / "main.js"
        py_file.touch()
        js_file.touch()
        result = _filter_by_extension([py_file, js_file], [])
        assert py_file in result
        assert js_file in result

    def test_no_matching_files_returns_empty(self, tmp_path: Path) -> None:
        """If no file matches the extension, an empty list is returned."""
        py_file = tmp_path / "app.py"
        py_file.touch()
        result = _filter_by_extension([py_file], [".rb"])
        assert result == []

    def test_empty_file_list_returns_empty(self) -> None:
        """An empty file list should always return an empty list."""
        result = _filter_by_extension([], [".py"])
        assert result == []


# ---------------------------------------------------------------------------
# _read_file_safe
# ---------------------------------------------------------------------------


class TestReadFileSafe:
    """Tests for the _read_file_safe() helper."""

    def test_reads_existing_file(self, tmp_path: Path) -> None:
        """Should return file contents for an existing file."""
        f = tmp_path / "test.py"
        f.write_text("hello world", encoding="utf-8")
        result = _read_file_safe(f)
        assert result == "hello world"

    def test_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        """Should return None when the file does not exist."""
        result = _read_file_safe(tmp_path / "nonexistent.py")
        assert result is None

    def test_handles_non_utf8_gracefully(self, tmp_path: Path) -> None:
        """Should not raise for non-UTF-8 content — uses replacement chars."""
        f = tmp_path / "binary.py"
        f.write_bytes(b"\xff\xfe some content")
        result = _read_file_safe(f)
        assert result is not None  # Should not raise

    def test_reads_empty_file(self, tmp_path: Path) -> None:
        """Should return an empty string for an empty file."""
        f = tmp_path / "empty.py"
        f.write_text("", encoding="utf-8")
        result = _read_file_safe(f)
        assert result == ""

    def test_reads_multiline_file(self, tmp_path: Path) -> None:
        """Should correctly read a multi-line file."""
        content = "line1\nline2\nline3\n"
        f = tmp_path / "multi.py"
        f.write_text(content, encoding="utf-8")
        result = _read_file_safe(f)
        assert result == content


# ---------------------------------------------------------------------------
# _line_number_for_offset
# ---------------------------------------------------------------------------


class TestLineNumberForOffset:
    """Tests for the _line_number_for_offset() helper."""

    def test_first_line(self) -> None:
        """An offset at the very start should return line 1."""
        assert _line_number_for_offset("abc\ndef", 0) == 1

    def test_second_line(self) -> None:
        """An offset past the first newline should return line 2."""
        assert _line_number_for_offset("abc\ndef", 4) == 2

    def test_end_of_first_line(self) -> None:
        """An offset just before a newline should still be line 1."""
        assert _line_number_for_offset("abc\ndef", 3) == 1

    def test_multiline(self) -> None:
        """Should correctly count lines in multi-line source."""
        source = "line1\nline2\nline3\nline4"
        assert _line_number_for_offset(source, source.index("line4")) == 4

    def test_single_line_no_newline(self) -> None:
        """A single line with no newline should return line 1."""
        assert _line_number_for_offset("abc", 2) == 1

    def test_offset_zero_always_line_one(self) -> None:
        """Offset 0 should always be line 1 regardless of content."""
        assert _line_number_for_offset("\n\n\n", 0) == 1


# ---------------------------------------------------------------------------
# _check_file_patterns
# ---------------------------------------------------------------------------


class TestCheckFilePatterns:
    """Tests for _check_file_patterns()."""

    def test_matches_exact_filename(self, tmp_path: Path) -> None:
        """Exact filename pattern should match."""
        f = tmp_path / ".gitignore"
        f.touch()
        assert _check_file_patterns([".gitignore"], [f], tmp_path) is True

    def test_matches_wildcard_filename(self, tmp_path: Path) -> None:
        """Wildcard filename pattern should match."""
        f = tmp_path / "test_app.py"
        f.touch()
        assert _check_file_patterns(["test_*.py"], [f], tmp_path) is True

    def test_matches_relative_path_pattern(self, tmp_path: Path) -> None:
        """Relative path pattern with directory should match."""
        subdir = tmp_path / "tests"
        subdir.mkdir()
        f = subdir / "test_something.py"
        f.touch()
        assert _check_file_patterns(["tests/*.py"], [f], tmp_path) is True

    def test_no_match_returns_false(self, tmp_path: Path) -> None:
        """Should return False when no file matches any pattern."""
        f = tmp_path / "app.py"
        f.touch()
        assert _check_file_patterns([".env.example"], [f], tmp_path) is False

    def test_empty_files_returns_false(self, tmp_path: Path) -> None:
        """Empty file list should always return False."""
        assert _check_file_patterns([".gitignore"], [], tmp_path) is False

    def test_empty_patterns_returns_false(self, tmp_path: Path) -> None:
        """Empty patterns list should always return False."""
        f = tmp_path / "app.py"
        f.touch()
        assert _check_file_patterns([], [f], tmp_path) is False

    def test_multiple_patterns_first_matches(self, tmp_path: Path) -> None:
        """Should return True if first pattern matches, even if others don't."""
        f = tmp_path / ".env.example"
        f.touch()
        assert _check_file_patterns(
            [".env.example", ".env.sample"], [f], tmp_path
        ) is True

    def test_multiple_patterns_second_matches(self, tmp_path: Path) -> None:
        """Should return True if second pattern matches."""
        f = tmp_path / ".env.sample"
        f.touch()
        assert _check_file_patterns(
            [".env.example", ".env.sample"], [f], tmp_path
        ) is True

    def test_nested_path_pattern(self, tmp_path: Path) -> None:
        """Should match files in nested subdirectories via relative path."""
        subdir = tmp_path / ".github" / "workflows"
        subdir.mkdir(parents=True)
        f = subdir / "ci.yml"
        f.touch()
        assert _check_file_patterns([".github/workflows/*.yml"], [f], tmp_path) is True

    def test_non_matching_wildcard_returns_false(self, tmp_path: Path) -> None:
        """A wildcard that does not match any file returns False."""
        f = tmp_path / "app.py"
        f.touch()
        assert _check_file_patterns(["migrations/env.py"], [f], tmp_path) is False


# ---------------------------------------------------------------------------
# _extract_call_name
# ---------------------------------------------------------------------------


class TestExtractCallName:
    """Tests for _extract_call_name()."""

    def _parse_call(self, expr: str) -> ast.Call:
        """Parse a Python call expression and return the ast.Call node."""
        tree = ast.parse(expr, mode="eval")
        assert isinstance(tree.body, ast.Call)
        return tree.body

    def test_simple_name_call(self) -> None:
        """A simple function call like 'open(...)' should return 'open'."""
        call = self._parse_call("open('file.txt')")
        assert _extract_call_name(call) == "open"

    def test_attribute_call(self) -> None:
        """An attribute call like 'requests.get(...)' should return 'requests.get'."""
        call = self._parse_call("requests.get('http://example.com')")
        assert _extract_call_name(call) == "requests.get"

    def test_deep_attribute_call(self) -> None:
        """A deeply nested attribute call should return the full dotted name."""
        call = self._parse_call("os.path.join('a', 'b')")
        assert _extract_call_name(call) == "os.path.join"

    def test_subscript_call_returns_none(self) -> None:
        """A call on a subscript (e.g. funcs['x']()) should return None."""
        call = self._parse_call("funcs['x']()")
        assert _extract_call_name(call) is None

    def test_socket_connect_call(self) -> None:
        """Should extract the name for socket.connect() calls."""
        call = self._parse_call("socket.connect(addr)")
        assert _extract_call_name(call) == "socket.connect"


# ---------------------------------------------------------------------------
# _apply_regex_rule
# ---------------------------------------------------------------------------


class TestApplyRegexRule:
    """Tests for _apply_regex_rule()."""

    def _make_regex_rule(
        self,
        pattern: str,
        extensions: list[str] | None = None,
        negate: bool = False,
        severity: Severity = Severity.HIGH,
        category: Category = Category.SECURITY,
        rule_id: str = "TST001",
    ) -> RegexRule:
        return RegexRule(
            rule_id=rule_id,
            category=category,
            severity=severity,
            pattern=pattern,
            title="Test rule",
            description="A test rule.",
            remediation="Fix it.",
            file_extensions=extensions or [],
            negate=negate,
        )

    def test_produces_finding_on_match(self, tmp_path: Path) -> None:
        """A match should produce a Finding."""
        f = write_file(tmp_path, "app.py", "eval(user_input)\n")
        rule = self._make_regex_rule(r"\beval\s*\(", extensions=[".py"])
        findings = _apply_regex_rule(rule, [f])
        assert len(findings) == 1
        assert findings[0].file_path == f
        assert findings[0].line_number == 1

    def test_no_finding_when_no_match(self, tmp_path: Path) -> None:
        """No match should produce no findings."""
        f = write_file(tmp_path, "app.py", "x = 1 + 2\n")
        rule = self._make_regex_rule(r"\beval\s*\(", extensions=[".py"])
        findings = _apply_regex_rule(rule, [f])
        assert findings == []

    def test_one_finding_per_file(self, tmp_path: Path) -> None:
        """Only one finding per file per rule, even with multiple matches."""
        f = write_file(tmp_path, "app.py", "eval('x')\neval('y')\n")
        rule = self._make_regex_rule(r"\beval\s*\(", extensions=[".py"])
        findings = _apply_regex_rule(rule, [f])
        assert len(findings) == 1

    def test_finding_per_file_across_files(self, tmp_path: Path) -> None:
        """One finding per matching file."""
        f1 = write_file(tmp_path, "app.py", "eval('x')\n")
        f2 = write_file(tmp_path, "util.py", "eval('y')\n")
        rule = self._make_regex_rule(r"\beval\s*\(", extensions=[".py"])
        findings = _apply_regex_rule(rule, [f1, f2])
        assert len(findings) == 2

    def test_extension_filter_applied(self, tmp_path: Path) -> None:
        """Files with non-matching extensions should be skipped."""
        f = write_file(tmp_path, "app.js", "eval(x);\n")
        rule = self._make_regex_rule(r"\beval\s*\(", extensions=[".py"])
        findings = _apply_regex_rule(rule, [f])
        assert findings == []

    def test_no_extension_filter_scans_all(self, tmp_path: Path) -> None:
        """Empty extensions list should scan all files."""
        f = write_file(tmp_path, "app.js", "eval(x);\n")
        rule = self._make_regex_rule(r"\beval\s*\(", extensions=[])
        findings = _apply_regex_rule(rule, [f])
        assert len(findings) == 1

    def test_negated_rule_fires_when_no_match(self, tmp_path: Path) -> None:
        """A negated rule should fire when pattern is NOT found anywhere."""
        f = write_file(tmp_path, "app.py", "x = 1\n")
        rule = self._make_regex_rule(
            r"logging\.getLogger\(__name__\)", negate=True
        )
        findings = _apply_regex_rule(rule, [f])
        assert len(findings) == 1
        assert findings[0].file_path is None

    def test_negated_rule_silent_when_match_found(self, tmp_path: Path) -> None:
        """A negated rule should NOT fire when pattern IS found."""
        f = write_file(tmp_path, "app.py", "logger = logging.getLogger(__name__)\n")
        rule = self._make_regex_rule(
            r"logging\.getLogger\(__name__\)", negate=True
        )
        findings = _apply_regex_rule(rule, [f])
        assert findings == []

    def test_correct_line_number_second_line(self, tmp_path: Path) -> None:
        """Line number should reflect the actual line of the match."""
        f = write_file(tmp_path, "app.py", "x = 1\neval('bad')\n")
        rule = self._make_regex_rule(r"\beval\s*\(", extensions=[".py"])
        findings = _apply_regex_rule(rule, [f])
        assert findings[0].line_number == 2

    def test_invalid_regex_returns_empty(self, tmp_path: Path) -> None:
        """An invalid regex pattern should return an empty list without crashing."""
        f = write_file(tmp_path, "app.py", "some code\n")
        rule = self._make_regex_rule(r"[invalid(", extensions=[".py"])
        findings = _apply_regex_rule(rule, [f])
        assert findings == []

    def test_finding_has_correct_rule_id(self, tmp_path: Path) -> None:
        """The Finding's rule_id should match the rule."""
        f = write_file(tmp_path, "app.py", "eval('x')\n")
        rule = self._make_regex_rule(r"\beval\s*\(", extensions=[".py"])
        findings = _apply_regex_rule(rule, [f])
        assert findings[0].rule_id == "TST001"

    def test_finding_has_correct_category(self, tmp_path: Path) -> None:
        """The Finding's category should match the rule's category."""
        f = write_file(tmp_path, "app.py", "eval('x')\n")
        rule = self._make_regex_rule(
            r"\beval\s*\(", extensions=[".py"], category=Category.SECURITY
        )
        findings = _apply_regex_rule(rule, [f])
        assert findings[0].category == Category.SECURITY

    def test_finding_has_correct_severity(self, tmp_path: Path) -> None:
        """The Finding's severity should match the rule's severity."""
        f = write_file(tmp_path, "app.py", "eval('x')\n")
        rule = self._make_regex_rule(
            r"\beval\s*\(", extensions=[".py"], severity=Severity.CRITICAL
        )
        findings = _apply_regex_rule(rule, [f])
        assert findings[0].severity == Severity.CRITICAL

    def test_empty_file_list_returns_empty(self, tmp_path: Path) -> None:
        """Empty file list should return no findings."""
        rule = self._make_regex_rule(r"\beval\s*\(", extensions=[".py"])
        findings = _apply_regex_rule(rule, [])
        # Negated rule would fire; non-negated should be empty
        assert findings == []

    def test_negated_rule_empty_file_list_fires(self) -> None:
        """A negated rule with empty file list should still fire (nothing matched)."""
        rule = RegexRule(
            rule_id="TST_NEG",
            category=Category.TESTING,
            severity=Severity.LOW,
            pattern=r"def test_",
            title="No test functions",
            description="No tests found.",
            remediation="Add tests.",
            negate=True,
            file_extensions=[".py"],
        )
        findings = _apply_regex_rule(rule, [])
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# _apply_ast_rule
# ---------------------------------------------------------------------------


class TestApplyAstRule:
    """Tests for _apply_ast_rule()."""

    def _make_ast_rule(self, hook: str, severity: Severity = Severity.HIGH) -> ASTRule:
        return ASTRule(
            rule_id="TST002",
            category=Category.ERROR_HANDLING,
            severity=severity,
            node_type="ExceptHandler",
            title="Test AST rule",
            description="AST test description.",
            remediation="Fix it.",
            hook=hook,
        )

    def test_bare_except_hook_detects_bare_except(self, tmp_path: Path) -> None:
        """bare_except hook should detect bare except: clauses."""
        f = write_file(
            tmp_path,
            "app.py",
            """\
            try:
                pass
            except:
                print('error')
            """,
        )
        rule = self._make_ast_rule("bare_except")
        findings = _apply_ast_rule(rule, [f])
        assert len(findings) == 1
        assert findings[0].file_path == f

    def test_bare_except_hook_ignores_typed_except(self, tmp_path: Path) -> None:
        """bare_except hook should NOT fire for typed except handlers."""
        f = write_file(
            tmp_path,
            "app.py",
            """\
            try:
                pass
            except ValueError:
                pass
            """,
        )
        rule = self._make_ast_rule("bare_except")
        findings = _apply_ast_rule(rule, [f])
        assert findings == []

    def test_silent_except_hook_detects_pass_only(self, tmp_path: Path) -> None:
        """silent_except hook should detect except handlers containing only pass."""
        f = write_file(
            tmp_path,
            "app.py",
            """\
            try:
                pass
            except ValueError:
                pass
            """,
        )
        rule = self._make_ast_rule("silent_except")
        findings = _apply_ast_rule(rule, [f])
        assert len(findings) == 1

    def test_silent_except_hook_ignores_non_pass(self, tmp_path: Path) -> None:
        """silent_except hook should NOT fire when except body has real code."""
        f = write_file(
            tmp_path,
            "app.py",
            """\
            import logging
            try:
                pass
            except ValueError as e:
                logging.exception(e)
            """,
        )
        rule = self._make_ast_rule("silent_except")
        findings = _apply_ast_rule(rule, [f])
        assert findings == []

    def test_skips_non_python_files(self, tmp_path: Path) -> None:
        """AST rules should not be applied to non-.py files."""
        f = write_file(tmp_path, "app.js", "try {} catch(e) {}")
        rule = self._make_ast_rule("bare_except")
        findings = _apply_ast_rule(rule, [f])
        assert findings == []

    def test_skips_files_with_syntax_errors(self, tmp_path: Path) -> None:
        """Files with syntax errors should be silently skipped."""
        f = write_file(tmp_path, "broken.py", "def foo(\n")
        rule = self._make_ast_rule("bare_except")
        findings = _apply_ast_rule(rule, [f])
        assert findings == []

    def test_unknown_hook_returns_empty(self, tmp_path: Path) -> None:
        """An unknown hook name should produce no findings."""
        f = write_file(tmp_path, "app.py", "x = 1\n")
        rule = self._make_ast_rule("totally_unknown_hook")
        findings = _apply_ast_rule(rule, [f])
        assert findings == []

    def test_multiple_python_files_aggregated(self, tmp_path: Path) -> None:
        """Findings from multiple Python files should all be returned."""
        f1 = write_file(
            tmp_path, "app.py", "try:\n    pass\nexcept:\n    pass\n"
        )
        f2 = write_file(
            tmp_path, "util.py", "try:\n    pass\nexcept:\n    pass\n"
        )
        rule = self._make_ast_rule("bare_except")
        findings = _apply_ast_rule(rule, [f1, f2])
        assert len(findings) == 2

    def test_function_no_error_handling_hook(self, tmp_path: Path) -> None:
        """function_no_error_handling hook should detect functions with external calls."""
        f = write_file(
            tmp_path,
            "app.py",
            "def read_file(path):\n    data = open(path).read()\n    return data\n",
        )
        rule = ASTRule(
            rule_id="ERR005",
            category=Category.ERROR_HANDLING,
            severity=Severity.MEDIUM,
            node_type="FunctionDef",
            title="No error handling",
            description="External call without try.",
            remediation="Add try/except.",
            hook="function_no_error_handling",
        )
        findings = _apply_ast_rule(rule, [f])
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# _apply_file_presence_rule
# ---------------------------------------------------------------------------


class TestApplyFilePresenceRule:
    """Tests for _apply_file_presence_rule()."""

    def _make_fp_rule(
        self,
        patterns: list[str],
        expect_present: bool = True,
        severity: Severity = Severity.MEDIUM,
    ) -> FilePresenceRule:
        return FilePresenceRule(
            rule_id="TST003",
            category=Category.ENV_CONFIG,
            severity=severity,
            filename_patterns=patterns,
            title="Missing file",
            description="File is missing.",
            remediation="Create the file.",
            expect_present=expect_present,
        )

    def test_fires_when_expected_file_missing(self, tmp_path: Path) -> None:
        """Should produce a finding when expect_present=True and file is absent."""
        rule = self._make_fp_rule([".gitignore"])
        findings = _apply_file_presence_rule(rule, [], tmp_path)
        assert len(findings) == 1
        assert findings[0].file_path == tmp_path

    def test_silent_when_expected_file_present(self, tmp_path: Path) -> None:
        """Should produce no finding when expect_present=True and file exists."""
        f = tmp_path / ".gitignore"
        f.touch()
        rule = self._make_fp_rule([".gitignore"])
        findings = _apply_file_presence_rule(rule, [f], tmp_path)
        assert findings == []

    def test_fires_when_unexpected_file_present(self, tmp_path: Path) -> None:
        """Should produce a finding when expect_present=False and file IS found."""
        f = tmp_path / ".env"
        f.touch()
        rule = self._make_fp_rule([".env"], expect_present=False)
        findings = _apply_file_presence_rule(rule, [f], tmp_path)
        assert len(findings) == 1

    def test_silent_when_unexpected_file_absent(self, tmp_path: Path) -> None:
        """Should produce no finding when expect_present=False and file is absent."""
        rule = self._make_fp_rule([".env"], expect_present=False)
        findings = _apply_file_presence_rule(rule, [], tmp_path)
        assert findings == []

    def test_matches_wildcard_pattern(self, tmp_path: Path) -> None:
        """Should match files using wildcard patterns."""
        f = tmp_path / "test_app.py"
        f.touch()
        rule = self._make_fp_rule(["test_*.py"])
        findings = _apply_file_presence_rule(rule, [f], tmp_path)
        assert findings == []  # file found, so no finding

    def test_matches_any_pattern_in_list(self, tmp_path: Path) -> None:
        """Should match if any one of the patterns matches."""
        f = tmp_path / ".env.sample"
        f.touch()
        rule = self._make_fp_rule([".env.example", ".env.sample"])
        findings = _apply_file_presence_rule(rule, [f], tmp_path)
        assert findings == []  # found via second pattern

    def test_finding_has_correct_severity(self, tmp_path: Path) -> None:
        """Finding from file presence rule should have the rule's severity."""
        rule = self._make_fp_rule([".gitignore"], severity=Severity.HIGH)
        findings = _apply_file_presence_rule(rule, [], tmp_path)
        assert findings[0].severity == Severity.HIGH

    def test_finding_has_repo_root_as_file_path(self, tmp_path: Path) -> None:
        """Finding's file_path should be set to repo_root."""
        rule = self._make_fp_rule([".gitignore"])
        findings = _apply_file_presence_rule(rule, [], tmp_path)
        assert findings[0].file_path == tmp_path

    def test_finding_has_correct_rule_id(self, tmp_path: Path) -> None:
        """Finding should carry the rule's rule_id."""
        rule = self._make_fp_rule([".gitignore"])
        findings = _apply_file_presence_rule(rule, [], tmp_path)
        assert findings[0].rule_id == "TST003"


# ---------------------------------------------------------------------------
# _hook_bare_except
# ---------------------------------------------------------------------------


class TestHookBareExcept:
    """Tests for _hook_bare_except()."""

    def _make_rule(self) -> ASTRule:
        return ASTRule(
            rule_id="ERR001",
            category=Category.ERROR_HANDLING,
            severity=Severity.HIGH,
            node_type="ExceptHandler",
            title="Bare except",
            description="Bare except detected.",
            remediation="Use specific exceptions.",
            hook="bare_except",
        )

    def _parse(self, source: str) -> ast.AST:
        return ast.parse(textwrap.dedent(source))

    def test_detects_bare_except(self, tmp_path: Path) -> None:
        """Should find bare except: clauses."""
        source = """\
        try:
            x = 1
        except:
            pass
        """
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_bare_except(rule, tree, tmp_path / "app.py")
        assert len(findings) == 1
        assert findings[0].line_number == 3

    def test_ignores_typed_except(self, tmp_path: Path) -> None:
        """Should not fire for properly typed except handlers."""
        source = """\
        try:
            x = 1
        except ValueError:
            pass
        """
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_bare_except(rule, tree, tmp_path / "app.py")
        assert findings == []

    def test_multiple_bare_excepts(self, tmp_path: Path) -> None:
        """Should find all bare except clauses in the file."""
        source = """\
        try:
            x = 1
        except:
            pass

        try:
            y = 2
        except:
            pass
        """
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_bare_except(rule, tree, tmp_path / "app.py")
        assert len(findings) == 2

    def test_finding_has_correct_file_path(self, tmp_path: Path) -> None:
        """Finding should reference the source file path."""
        source = "try:\n    pass\nexcept:\n    pass\n"
        tree = self._parse(source)
        rule = self._make_rule()
        file_path = tmp_path / "app.py"
        findings = _hook_bare_except(rule, tree, file_path)
        assert findings[0].file_path == file_path

    def test_no_excepts_at_all_returns_empty(self, tmp_path: Path) -> None:
        """No try/except in code should return empty list."""
        source = "x = 1 + 2\n"
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_bare_except(rule, tree, tmp_path / "app.py")
        assert findings == []


# ---------------------------------------------------------------------------
# _hook_silent_except
# ---------------------------------------------------------------------------


class TestHookSilentExcept:
    """Tests for _hook_silent_except()."""

    def _make_rule(self) -> ASTRule:
        return ASTRule(
            rule_id="ERR002",
            category=Category.ERROR_HANDLING,
            severity=Severity.MEDIUM,
            node_type="ExceptHandler",
            title="Silent except",
            description="Silent except detected.",
            remediation="Log the exception.",
            hook="silent_except",
        )

    def _parse(self, source: str) -> ast.AST:
        return ast.parse(textwrap.dedent(source))

    def test_detects_pass_only_except(self, tmp_path: Path) -> None:
        """Should fire for except handlers containing only pass."""
        source = """\
        try:
            x = 1
        except ValueError:
            pass
        """
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_silent_except(rule, tree, tmp_path / "app.py")
        assert len(findings) == 1

    def test_ignores_except_with_logging(self, tmp_path: Path) -> None:
        """Should not fire when except body has real handling code."""
        source = """\
        import logging
        try:
            x = 1
        except ValueError as e:
            logging.error(e)
        """
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_silent_except(rule, tree, tmp_path / "app.py")
        assert findings == []

    def test_ignores_except_with_multiple_statements(self, tmp_path: Path) -> None:
        """Should not fire when except body has more than one statement."""
        source = """\
        try:
            x = 1
        except ValueError:
            x = 0
            print('handled')
        """
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_silent_except(rule, tree, tmp_path / "app.py")
        assert findings == []

    def test_bare_except_with_pass_also_caught(self, tmp_path: Path) -> None:
        """A bare except with only pass should also trigger this hook."""
        source = "try:\n    x = 1\nexcept:\n    pass\n"
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_silent_except(rule, tree, tmp_path / "app.py")
        # A bare except with pass is also a silent except
        assert len(findings) == 1

    def test_finding_has_correct_line_number(self, tmp_path: Path) -> None:
        """Finding line number should point to the except handler."""
        source = "x = 1\ntry:\n    y = 2\nexcept ValueError:\n    pass\n"
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_silent_except(rule, tree, tmp_path / "app.py")
        assert len(findings) == 1
        assert findings[0].line_number == 4


# ---------------------------------------------------------------------------
# _hook_function_no_error_handling
# ---------------------------------------------------------------------------


class TestHookFunctionNoErrorHandling:
    """Tests for _hook_function_no_error_handling()."""

    def _make_rule(self) -> ASTRule:
        return ASTRule(
            rule_id="ERR005",
            category=Category.ERROR_HANDLING,
            severity=Severity.MEDIUM,
            node_type="FunctionDef",
            title="No error handling",
            description="Function has no error handling.",
            remediation="Add try/except.",
            hook="function_no_error_handling",
        )

    def _parse(self, source: str) -> ast.AST:
        return ast.parse(textwrap.dedent(source))

    def test_detects_function_with_open_no_try(self, tmp_path: Path) -> None:
        """Should fire for functions using open() without try/except."""
        source = """\
        def read_file(path):
            data = open(path).read()
            return data
        """
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_function_no_error_handling(rule, tree, tmp_path / "app.py")
        assert len(findings) >= 1

    def test_no_finding_when_try_present(self, tmp_path: Path) -> None:
        """Should not fire for functions that have try/except."""
        source = """\
        def read_file(path):
            try:
                data = open(path).read()
                return data
            except OSError:
                return None
        """
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_function_no_error_handling(rule, tree, tmp_path / "app.py")
        assert findings == []

    def test_no_finding_for_simple_function(self, tmp_path: Path) -> None:
        """Should not fire for functions with no external calls."""
        source = """\
        def add(a, b):
            return a + b
        """
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_function_no_error_handling(rule, tree, tmp_path / "app.py")
        assert findings == []

    def test_detects_requests_call_without_try(self, tmp_path: Path) -> None:
        """Should fire for functions making requests calls without try."""
        source = """\
        import requests
        def fetch_data(url):
            response = requests.get(url)
            return response.json()
        """
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_function_no_error_handling(rule, tree, tmp_path / "app.py")
        assert len(findings) >= 1

    def test_no_finding_for_empty_tree(self, tmp_path: Path) -> None:
        """No functions in the AST should produce no findings."""
        source = "x = 1\ny = 2\n"
        tree = self._parse(source)
        rule = self._make_rule()
        findings = _hook_function_no_error_handling(rule, tree, tmp_path / "app.py")
        assert findings == []


# ---------------------------------------------------------------------------
# analyze_authentication
# ---------------------------------------------------------------------------


class TestAnalyzeAuthentication:
    """Integration tests for analyze_authentication()."""

    def test_detects_hardcoded_secret_key(self, tmp_repo: Path) -> None:
        """AUTH001: Should detect a hardcoded short SECRET_KEY."""
        f = write_file(
            tmp_repo,
            "settings.py",
            'SECRET_KEY = "mysecret123"\n',
        )
        findings = analyze_authentication([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "AUTH001" in rule_ids

    def test_detects_hardcoded_jwt_secret(self, tmp_repo: Path) -> None:
        """AUTH001: Should detect a hardcoded JWT_SECRET."""
        f = write_file(
            tmp_repo,
            "config.py",
            'JWT_SECRET = "topsecret"\n',
        )
        findings = analyze_authentication([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "AUTH001" in rule_ids

    def test_detects_hardcoded_password(self, tmp_repo: Path) -> None:
        """AUTH003: Should detect a hardcoded password literal."""
        f = write_file(
            tmp_repo,
            "db.py",
            'password = "hunter2"\n',
        )
        findings = analyze_authentication([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "AUTH003" in rule_ids

    def test_detects_wildcard_cors(self, tmp_repo: Path) -> None:
        """AUTH004: Should detect wildcard CORS configuration."""
        f = write_file(
            tmp_repo,
            "app.py",
            'CORS(app, allow_origins=["*"])\n',
        )
        findings = analyze_authentication([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "AUTH004" in rule_ids

    def test_detects_route_definition(self, tmp_repo: Path) -> None:
        """AUTH002: Should flag route definitions for auth review."""
        f = write_file(
            tmp_repo,
            "routes.py",
            '@app.route("/secret")\ndef secret(): pass\n',
        )
        findings = analyze_authentication([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "AUTH002" in rule_ids

    def test_detects_fastapi_router_route(self, tmp_repo: Path) -> None:
        """AUTH002: Should flag FastAPI router route definitions."""
        f = write_file(
            tmp_repo,
            "routes.py",
            '@router.get("/users")\ndef list_users(): pass\n',
        )
        findings = analyze_authentication([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "AUTH002" in rule_ids

    def test_no_auth001_on_clean_settings(self, tmp_repo: Path) -> None:
        """AUTH001 should not fire when secret key is loaded from env."""
        f = write_file(
            tmp_repo,
            "settings.py",
            "import os\nSECRET_KEY = os.environ.get('SECRET_KEY')\n",
        )
        findings = analyze_authentication([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "AUTH001" not in rule_ids

    def test_no_auth003_on_env_password(self, tmp_repo: Path) -> None:
        """AUTH003 should not fire for env variable assignments."""
        f = write_file(
            tmp_repo,
            "db.py",
            "import os\npassword = os.environ.get('DB_PASSWORD')\n",
        )
        findings = analyze_authentication([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "AUTH003" not in rule_ids

    def test_returns_list(self, tmp_repo: Path) -> None:
        """analyze_authentication should always return a list."""
        result = analyze_authentication([], tmp_repo)
        assert isinstance(result, list)

    def test_all_findings_are_finding_instances(self, tmp_repo: Path) -> None:
        """All returned items should be Finding instances."""
        f = write_file(tmp_repo, "app.py", 'password = "secret"\n')
        findings = analyze_authentication([f], tmp_repo)
        for finding in findings:
            assert isinstance(finding, Finding)


# ---------------------------------------------------------------------------
# analyze_error_handling
# ---------------------------------------------------------------------------


class TestAnalyzeErrorHandling:
    """Integration tests for analyze_error_handling()."""

    def test_detects_bare_except(self, tmp_repo: Path) -> None:
        """ERR001: Should detect bare except: clauses."""
        f = write_file(
            tmp_repo,
            "app.py",
            "try:\n    x = 1\nexcept:\n    pass\n",
        )
        findings = analyze_error_handling([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ERR001" in rule_ids

    def test_detects_silent_except(self, tmp_repo: Path) -> None:
        """ERR002: Should detect except handlers with only pass."""
        f = write_file(
            tmp_repo,
            "app.py",
            "try:\n    x = 1\nexcept ValueError:\n    pass\n",
        )
        findings = analyze_error_handling([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ERR002" in rule_ids

    def test_detects_generic_exception_raise(self, tmp_repo: Path) -> None:
        """ERR004: Should detect raise Exception() patterns."""
        f = write_file(
            tmp_repo,
            "app.py",
            'raise Exception("something went wrong")\n',
        )
        findings = analyze_error_handling([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ERR004" in rule_ids

    def test_detects_print_error(self, tmp_repo: Path) -> None:
        """ERR003: Should detect printing errors instead of logging."""
        f = write_file(
            tmp_repo,
            "app.py",
            'print("Error: something failed")\n',
        )
        findings = analyze_error_handling([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ERR003" in rule_ids

    def test_detects_print_exception(self, tmp_repo: Path) -> None:
        """ERR003: Should detect print(exception) patterns."""
        f = write_file(
            tmp_repo,
            "app.py",
            'print("Exception occurred")\n',
        )
        findings = analyze_error_handling([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ERR003" in rule_ids

    def test_no_findings_for_proper_error_handling(self, tmp_repo: Path) -> None:
        """Clean error handling should not trigger ERR001, ERR002, ERR004."""
        f = write_file(
            tmp_repo,
            "app.py",
            textwrap.dedent("""\
            import logging
            logger = logging.getLogger(__name__)

            def process():
                try:
                    result = compute()
                    return result
                except ValueError as e:
                    logger.error("Computation failed: %s", e)
                    raise
            """),
        )
        findings = analyze_error_handling([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ERR001" not in rule_ids
        assert "ERR002" not in rule_ids
        assert "ERR004" not in rule_ids

    def test_returns_list(self, tmp_repo: Path) -> None:
        """analyze_error_handling should always return a list."""
        assert isinstance(analyze_error_handling([], tmp_repo), list)

    def test_all_findings_are_finding_instances(self, tmp_repo: Path) -> None:
        """All returned items should be Finding instances."""
        f = write_file(
            tmp_repo, "app.py", "try:\n    x=1\nexcept:\n    pass\n"
        )
        for finding in analyze_error_handling([f], tmp_repo):
            assert isinstance(finding, Finding)

    def test_bare_except_finding_has_line_number(self, tmp_repo: Path) -> None:
        """ERR001 finding should include a line number."""
        f = write_file(
            tmp_repo, "app.py", "x = 1\ntry:\n    y=2\nexcept:\n    pass\n"
        )
        findings = analyze_error_handling([f], tmp_repo)
        err001_findings = [fn for fn in findings if fn.rule_id == "ERR001"]
        assert len(err001_findings) >= 1
        assert err001_findings[0].line_number is not None


# ---------------------------------------------------------------------------
# analyze_env_config
# ---------------------------------------------------------------------------


class TestAnalyzeEnvConfig:
    """Integration tests for analyze_env_config()."""

    def test_detects_debug_true(self, tmp_repo: Path) -> None:
        """ENV001: Should detect DEBUG=True in source code."""
        f = write_file(tmp_repo, "settings.py", "DEBUG = True\n")
        findings = analyze_env_config([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ENV001" in rule_ids

    def test_detects_hardcoded_database_url(self, tmp_repo: Path) -> None:
        """ENV002: Should detect hardcoded DATABASE_URL."""
        f = write_file(
            tmp_repo,
            "settings.py",
            'DATABASE_URL = "postgresql://user:pass@localhost/db"\n',
        )
        findings = analyze_env_config([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ENV002" in rule_ids

    def test_detects_hardcoded_api_key(self, tmp_repo: Path) -> None:
        """ENV002: Should detect hardcoded API_KEY."""
        f = write_file(
            tmp_repo,
            "config.py",
            'API_KEY = "abc123xyz"\n',
        )
        findings = analyze_env_config([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ENV002" in rule_ids

    def test_detects_missing_env_example(self, tmp_repo: Path) -> None:
        """ENV003: Should detect missing .env.example file."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        findings = analyze_env_config([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ENV003" in rule_ids

    def test_no_env003_when_env_example_present(self, tmp_repo: Path) -> None:
        """ENV003: Should not fire when .env.example exists."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        env_ex = write_file(tmp_repo, ".env.example", "DATABASE_URL=\n")
        findings = analyze_env_config([f, env_ex], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ENV003" not in rule_ids

    def test_no_env003_when_env_sample_present(self, tmp_repo: Path) -> None:
        """ENV003: Should not fire when .env.sample exists."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        env_s = write_file(tmp_repo, ".env.sample", "DATABASE_URL=\n")
        findings = analyze_env_config([f, env_s], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ENV003" not in rule_ids

    def test_detects_missing_gitignore(self, tmp_repo: Path) -> None:
        """ENV004: Should detect missing .gitignore file."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        findings = analyze_env_config([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ENV004" in rule_ids

    def test_no_env004_when_gitignore_present(self, tmp_repo: Path) -> None:
        """ENV004: Should not fire when .gitignore exists."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        gi = write_file(tmp_repo, ".gitignore", ".env\n")
        findings = analyze_env_config([f, gi], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ENV004" not in rule_ids

    def test_no_env001_when_debug_from_env(self, tmp_repo: Path) -> None:
        """ENV001: Should not fire when DEBUG is loaded from environment."""
        f = write_file(
            tmp_repo,
            "settings.py",
            "import os\nDEBUG = os.environ.get('DEBUG', 'false') == 'true'\n",
        )
        findings = analyze_env_config([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "ENV001" not in rule_ids

    def test_returns_list(self, tmp_repo: Path) -> None:
        """analyze_env_config should always return a list."""
        assert isinstance(analyze_env_config([], tmp_repo), list)


# ---------------------------------------------------------------------------
# analyze_security
# ---------------------------------------------------------------------------


class TestAnalyzeSecurity:
    """Integration tests for analyze_security()."""

    def test_detects_eval(self, tmp_repo: Path) -> None:
        """SEC001: Should detect eval() usage."""
        f = write_file(tmp_repo, "app.py", "eval(user_input)\n")
        findings = analyze_security([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "SEC001" in rule_ids

    def test_detects_exec(self, tmp_repo: Path) -> None:
        """SEC001: Should detect exec() usage."""
        f = write_file(tmp_repo, "app.py", "exec(code)\n")
        findings = analyze_security([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "SEC001" in rule_ids

    def test_detects_subprocess_shell_true(self, tmp_repo: Path) -> None:
        """SEC002: Should detect subprocess.run with shell=True."""
        f = write_file(
            tmp_repo,
            "app.py",
            "import subprocess\nsubprocess.run(cmd, shell=True)\n",
        )
        findings = analyze_security([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "SEC002" in rule_ids

    def test_detects_subprocess_call_shell_true(self, tmp_repo: Path) -> None:
        """SEC002: Should detect subprocess.call with shell=True."""
        f = write_file(
            tmp_repo,
            "app.py",
            "import subprocess\nsubprocess.call(cmd, shell=True)\n",
        )
        findings = analyze_security([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "SEC002" in rule_ids

    def test_detects_pickle_loads(self, tmp_repo: Path) -> None:
        """SEC003: Should detect pickle.loads() usage."""
        f = write_file(
            tmp_repo,
            "app.py",
            "import pickle\ndata = pickle.loads(raw)\n",
        )
        findings = analyze_security([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "SEC003" in rule_ids

    def test_detects_pickle_load(self, tmp_repo: Path) -> None:
        """SEC003: Should detect pickle.load() usage."""
        f = write_file(
            tmp_repo,
            "app.py",
            "import pickle\ndata = pickle.load(f)\n",
        )
        findings = analyze_security([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "SEC003" in rule_ids

    def test_detects_md5(self, tmp_repo: Path) -> None:
        """SEC005: Should detect hashlib.md5() usage."""
        f = write_file(
            tmp_repo,
            "app.py",
            "import hashlib\nhash = hashlib.md5(data)\n",
        )
        findings = analyze_security([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "SEC005" in rule_ids

    def test_detects_sha1(self, tmp_repo: Path) -> None:
        """SEC005: Should detect hashlib.sha1() usage."""
        f = write_file(
            tmp_repo,
            "app.py",
            "import hashlib\nhash = hashlib.sha1(data)\n",
        )
        findings = analyze_security([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "SEC005" in rule_ids

    def test_detects_ssl_verify_false(self, tmp_repo: Path) -> None:
        """SEC006: Should detect verify=False in SSL calls."""
        f = write_file(
            tmp_repo,
            "app.py",
            "requests.get(url, verify=False)\n",
        )
        findings = analyze_security([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "SEC006" in rule_ids

    def test_detects_random_usage(self, tmp_repo: Path) -> None:
        """SEC008: Should detect non-cryptographic random usage."""
        f = write_file(
            tmp_repo,
            "app.py",
            "import random\ntoken = random.randint(1, 100)\n",
        )
        findings = analyze_security([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "SEC008" in rule_ids

    def test_no_sec001_on_clean_file(self, tmp_repo: Path) -> None:
        """SEC001 should not fire on code without eval/exec."""
        f = write_file(tmp_repo, "app.py", "x = 1 + 2\n")
        findings = analyze_security([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "SEC001" not in rule_ids

    def test_no_sec002_when_shell_false(self, tmp_repo: Path) -> None:
        """SEC002 should not fire when shell=False (default)."""
        f = write_file(
            tmp_repo,
            "app.py",
            "import subprocess\nsubprocess.run(['ls', '-la'])\n",
        )
        findings = analyze_security([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "SEC002" not in rule_ids

    def test_returns_list(self, tmp_repo: Path) -> None:
        """analyze_security should always return a list."""
        assert isinstance(analyze_security([], tmp_repo), list)

    def test_eval_finding_is_critical(self, tmp_repo: Path) -> None:
        """eval() finding should have CRITICAL severity."""
        f = write_file(tmp_repo, "app.py", "eval(x)\n")
        findings = analyze_security([f], tmp_repo)
        sec001 = [fn for fn in findings if fn.rule_id == "SEC001"]
        assert sec001[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# analyze_migrations
# ---------------------------------------------------------------------------


class TestAnalyzeMigrations:
    """Integration tests for analyze_migrations()."""

    def test_detects_create_all(self, tmp_repo: Path) -> None:
        """MIG002: Should detect Base.metadata.create_all() usage."""
        f = write_file(
            tmp_repo,
            "app.py",
            "Base.metadata.create_all(engine)\n",
        )
        findings = analyze_migrations([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "MIG002" in rule_ids

    def test_detects_metadata_create_all(self, tmp_repo: Path) -> None:
        """MIG002: Should detect metadata.create_all() variant."""
        f = write_file(
            tmp_repo,
            "app.py",
            "metadata.create_all(bind=engine)\n",
        )
        findings = analyze_migrations([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "MIG002" in rule_ids

    def test_detects_sqlite_url(self, tmp_repo: Path) -> None:
        """MIG003: Should detect SQLite database URLs."""
        f = write_file(
            tmp_repo,
            "db.py",
            'DATABASE_URL = "sqlite:///app.db"\n',
        )
        findings = analyze_migrations([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "MIG003" in rule_ids

    def test_detects_sqlite_memory(self, tmp_repo: Path) -> None:
        """MIG003: Should detect :memory: SQLite URLs."""
        f = write_file(
            tmp_repo,
            "db.py",
            'engine = create_engine(":memory:")\n',
        )
        findings = analyze_migrations([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "MIG003" in rule_ids

    def test_detects_missing_alembic(self, tmp_repo: Path) -> None:
        """MIG001: Should detect missing Alembic configuration."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        findings = analyze_migrations([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "MIG001" in rule_ids

    def test_no_mig001_when_alembic_ini_present(self, tmp_repo: Path) -> None:
        """MIG001: Should not fire when alembic.ini exists."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        alembic = write_file(tmp_repo, "alembic.ini", "[alembic]\n")
        findings = analyze_migrations([f, alembic], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "MIG001" not in rule_ids

    def test_detects_destructive_sql(self, tmp_repo: Path) -> None:
        """MIG004: Should detect DROP TABLE statements."""
        f = write_file(
            tmp_repo,
            "app.py",
            'cursor.execute("DROP TABLE users")\n',
        )
        findings = analyze_migrations([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "MIG004" in rule_ids

    def test_detects_drop_database(self, tmp_repo: Path) -> None:
        """MIG004: Should detect DROP DATABASE statements."""
        f = write_file(
            tmp_repo,
            "app.py",
            'conn.execute("DROP DATABASE mydb")\n',
        )
        findings = analyze_migrations([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "MIG004" in rule_ids

    def test_create_all_finding_is_critical(self, tmp_repo: Path) -> None:
        """MIG002 finding should have CRITICAL severity."""
        f = write_file(tmp_repo, "app.py", "Base.metadata.create_all(engine)\n")
        findings = analyze_migrations([f], tmp_repo)
        mig002 = [fn for fn in findings if fn.rule_id == "MIG002"]
        assert mig002[0].severity == Severity.CRITICAL

    def test_returns_list(self, tmp_repo: Path) -> None:
        """analyze_migrations should always return a list."""
        assert isinstance(analyze_migrations([], tmp_repo), list)


# ---------------------------------------------------------------------------
# analyze_logging
# ---------------------------------------------------------------------------


class TestAnalyzeLogging:
    """Integration tests for analyze_logging()."""

    def test_detects_basic_config(self, tmp_repo: Path) -> None:
        """LOG002: Should detect logging.basicConfig() usage."""
        f = write_file(
            tmp_repo,
            "app.py",
            "import logging\nlogging.basicConfig(level=logging.DEBUG)\n",
        )
        findings = analyze_logging([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "LOG002" in rule_ids

    def test_detects_root_logger_error(self, tmp_repo: Path) -> None:
        """LOG004: Should detect direct use of logging.error()."""
        f = write_file(
            tmp_repo,
            "app.py",
            'import logging\nlogging.error("oops")\n',
        )
        findings = analyze_logging([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "LOG004" in rule_ids

    def test_detects_root_logger_warning(self, tmp_repo: Path) -> None:
        """LOG004: Should detect direct use of logging.warning()."""
        f = write_file(
            tmp_repo,
            "app.py",
            'import logging\nlogging.warning("be careful")\n',
        )
        findings = analyze_logging([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "LOG004" in rule_ids

    def test_log003_fires_when_no_module_logger(self, tmp_repo: Path) -> None:
        """LOG003 (negated): Should fire when no module logger is defined."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        findings = analyze_logging([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "LOG003" in rule_ids

    def test_log003_silent_when_module_logger_present(self, tmp_repo: Path) -> None:
        """LOG003 (negated): Should NOT fire when module logger is present."""
        f = write_file(
            tmp_repo,
            "app.py",
            "import logging\nlogger = logging.getLogger(__name__)\n",
        )
        findings = analyze_logging([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "LOG003" not in rule_ids

    def test_detects_fstring_in_logger_info(self, tmp_repo: Path) -> None:
        """LOG005: Should detect f-strings in logger.info() calls."""
        f = write_file(
            tmp_repo,
            "app.py",
            'logger.info(f"Processing {item}")\n',
        )
        findings = analyze_logging([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "LOG005" in rule_ids

    def test_detects_fstring_in_logger_error(self, tmp_repo: Path) -> None:
        """LOG005: Should detect f-strings in logger.error() calls."""
        f = write_file(
            tmp_repo,
            "app.py",
            'logger.error(f"Failed to process {item}")\n',
        )
        findings = analyze_logging([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "LOG005" in rule_ids

    def test_no_log005_for_percent_formatting(self, tmp_repo: Path) -> None:
        """LOG005: Should not fire for % formatting (correct approach)."""
        f = write_file(
            tmp_repo,
            "app.py",
            'logger.info("Processing %s", item)\n',
        )
        findings = analyze_logging([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "LOG005" not in rule_ids

    def test_returns_list(self, tmp_repo: Path) -> None:
        """analyze_logging should always return a list."""
        assert isinstance(analyze_logging([], tmp_repo), list)


# ---------------------------------------------------------------------------
# analyze_testing
# ---------------------------------------------------------------------------


class TestAnalyzeTesting:
    """Integration tests for analyze_testing()."""

    def test_detects_missing_test_files(self, tmp_repo: Path) -> None:
        """TST001: Should fire when no test files are present."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        findings = analyze_testing([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "TST001" in rule_ids

    def test_no_tst001_when_test_file_present(self, tmp_repo: Path) -> None:
        """TST001: Should not fire when test files are present."""
        test_file = write_file(tmp_repo, "test_app.py", "def test_something(): pass\n")
        findings = analyze_testing([test_file], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "TST001" not in rule_ids

    def test_detects_skipped_tests(self, tmp_repo: Path) -> None:
        """TST004: Should detect @pytest.mark.skip decorators."""
        f = write_file(
            tmp_repo,
            "test_app.py",
            "import pytest\n@pytest.mark.skip\ndef test_broken(): pass\n",
        )
        findings = analyze_testing([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "TST004" in rule_ids

    def test_detects_unittest_skip(self, tmp_repo: Path) -> None:
        """TST004: Should detect @unittest.skip decorator."""
        f = write_file(
            tmp_repo,
            "test_app.py",
            "import unittest\n@unittest.skip\ndef test_broken(): pass\n",
        )
        findings = analyze_testing([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "TST004" in rule_ids

    def test_tst002_fires_without_config(self, tmp_repo: Path) -> None:
        """TST002: Should fire when no test runner config is present."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        findings = analyze_testing([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "TST002" in rule_ids

    def test_no_tst002_when_pyproject_present(self, tmp_repo: Path) -> None:
        """TST002: Should not fire when pyproject.toml is present."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        cfg = write_file(tmp_repo, "pyproject.toml", "[tool.pytest.ini_options]\n")
        findings = analyze_testing([f, cfg], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "TST002" not in rule_ids

    def test_no_tst002_when_pytest_ini_present(self, tmp_repo: Path) -> None:
        """TST002: Should not fire when pytest.ini is present."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        ini = write_file(tmp_repo, "pytest.ini", "[pytest]\ntestpaths = tests\n")
        findings = analyze_testing([f, ini], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "TST002" not in rule_ids

    def test_tst003_fires_when_no_test_functions(self, tmp_repo: Path) -> None:
        """TST003 (negated): Should fire when no test_ functions exist."""
        f = write_file(tmp_repo, "app.py", "def my_function(): pass\n")
        findings = analyze_testing([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "TST003" in rule_ids

    def test_tst003_silent_when_test_functions_present(self, tmp_repo: Path) -> None:
        """TST003 (negated): Should not fire when test_ functions exist."""
        f = write_file(
            tmp_repo,
            "test_app.py",
            "def test_something():\n    assert True\n",
        )
        findings = analyze_testing([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "TST003" not in rule_ids

    def test_tst005_fires_without_ci_config(self, tmp_repo: Path) -> None:
        """TST005: Should fire when no CI configuration is found."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        findings = analyze_testing([f], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "TST005" in rule_ids

    def test_no_tst005_when_github_actions_present(self, tmp_repo: Path) -> None:
        """TST005: Should not fire when a GitHub Actions workflow exists."""
        workflows_dir = tmp_repo / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        ci_file = workflows_dir / "ci.yml"
        ci_file.write_text("name: CI\n", encoding="utf-8")
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        findings = analyze_testing([f, ci_file], tmp_repo)
        rule_ids = [fn.rule_id for fn in findings]
        assert "TST005" not in rule_ids

    def test_returns_list(self, tmp_repo: Path) -> None:
        """analyze_testing should always return a list."""
        assert isinstance(analyze_testing([], tmp_repo), list)


# ---------------------------------------------------------------------------
# Cross-cutting / regression tests
# ---------------------------------------------------------------------------


class TestAnalyzersCrosscuts:
    """Cross-cutting regression tests for all analyzer functions."""

    def test_all_analyzers_return_lists_on_empty_input(
        self, tmp_repo: Path
    ) -> None:
        """Every analyzer should return a list on empty file input."""
        analyzers = [
            analyze_authentication,
            analyze_error_handling,
            analyze_env_config,
            analyze_security,
            analyze_migrations,
            analyze_logging,
            analyze_testing,
        ]
        for analyzer in analyzers:
            result = analyzer([], tmp_repo)
            assert isinstance(result, list), (
                f"{analyzer.__name__} did not return a list"
            )

    def test_all_findings_have_required_fields(self, tmp_repo: Path) -> None:
        """All returned Finding objects must have non-None required fields."""
        f = write_file(
            tmp_repo,
            "app.py",
            textwrap.dedent("""\
            password = 'hardcoded'
            DEBUG = True
            eval(user)
            try:
                x = 1
            except:
                pass
            Base.metadata.create_all(engine)
            """),
        )
        analyzers = [
            analyze_authentication,
            analyze_error_handling,
            analyze_env_config,
            analyze_security,
            analyze_migrations,
            analyze_logging,
            analyze_testing,
        ]
        for analyzer in analyzers:
            for finding in analyzer([f], tmp_repo):
                assert finding.category is not None, (
                    f"{analyzer.__name__}: finding missing category"
                )
                assert finding.severity is not None, (
                    f"{analyzer.__name__}: finding missing severity"
                )
                assert finding.title, (
                    f"{analyzer.__name__}: finding has empty title"
                )
                assert finding.description, (
                    f"{analyzer.__name__}: finding has empty description"
                )
                assert finding.remediation, (
                    f"{analyzer.__name__}: finding has empty remediation"
                )

    def test_findings_have_valid_severity_values(self, tmp_repo: Path) -> None:
        """All findings must have a valid Severity enum value."""
        f = write_file(tmp_repo, "app.py", "eval('x')\nDEBUG = True\n")
        all_findings = (
            analyze_security([f], tmp_repo)
            + analyze_env_config([f], tmp_repo)
        )
        for finding in all_findings:
            assert finding.severity in list(Severity), (
                f"Invalid severity: {finding.severity}"
            )

    def test_findings_have_valid_category_values(self, tmp_repo: Path) -> None:
        """All findings must have a valid Category enum value."""
        f = write_file(tmp_repo, "app.py", "eval('x')\n")
        for finding in analyze_security([f], tmp_repo):
            assert finding.category in list(Category), (
                f"Invalid category: {finding.category}"
            )

    def test_finding_to_dict_roundtrip(self, tmp_repo: Path) -> None:
        """All findings should serialize to dict and then JSON without error."""
        import json
        f = write_file(tmp_repo, "app.py", "eval('x')\n")
        for finding in analyze_security([f], tmp_repo):
            d = finding.to_dict()
            # Should be JSON-serializable
            json_str = json.dumps(d, default=str)
            assert json_str  # Non-empty

    def test_analyzer_does_not_crash_on_unreadable_directory(
        self, tmp_repo: Path
    ) -> None:
        """Passing a list with a non-existent file should not crash the analyzer."""
        fake_file = tmp_repo / "nonexistent.py"
        # Do not create the file — it should be silently skipped
        result = analyze_security([fake_file], tmp_repo)
        assert isinstance(result, list)

    def test_auth_findings_have_auth_category(self, tmp_repo: Path) -> None:
        """All findings from analyze_authentication should have AUTHENTICATION category."""
        f = write_file(tmp_repo, "app.py", 'SECRET_KEY = "tiny"\n')
        for finding in analyze_authentication([f], tmp_repo):
            assert finding.category == Category.AUTHENTICATION

    def test_security_findings_have_security_category(self, tmp_repo: Path) -> None:
        """All findings from analyze_security should have SECURITY category."""
        f = write_file(tmp_repo, "app.py", "eval(x)\n")
        for finding in analyze_security([f], tmp_repo):
            assert finding.category == Category.SECURITY

    def test_migration_findings_have_migrations_category(
        self, tmp_repo: Path
    ) -> None:
        """All findings from analyze_migrations should have MIGRATIONS category."""
        f = write_file(tmp_repo, "app.py", 'x = "sqlite:///a.db"\n')
        for finding in analyze_migrations([f], tmp_repo):
            assert finding.category == Category.MIGRATIONS

    def test_logging_findings_have_logging_category(self, tmp_repo: Path) -> None:
        """All findings from analyze_logging should have LOGGING category."""
        f = write_file(tmp_repo, "app.py", "import logging\nlogging.basicConfig()\n")
        for finding in analyze_logging([f], tmp_repo):
            assert finding.category == Category.LOGGING

    def test_testing_findings_have_testing_category(self, tmp_repo: Path) -> None:
        """All findings from analyze_testing should have TESTING category."""
        f = write_file(tmp_repo, "app.py", "x = 1\n")
        for finding in analyze_testing([f], tmp_repo):
            assert finding.category == Category.TESTING

    def test_env_config_findings_have_env_config_category(
        self, tmp_repo: Path
    ) -> None:
        """All findings from analyze_env_config should have ENV_CONFIG category."""
        f = write_file(tmp_repo, "app.py", "DEBUG = True\n")
        for finding in analyze_env_config([f], tmp_repo):
            assert finding.category == Category.ENV_CONFIG

    def test_error_handling_findings_have_error_handling_category(
        self, tmp_repo: Path
    ) -> None:
        """All findings from analyze_error_handling should have ERROR_HANDLING category."""
        f = write_file(
            tmp_repo, "app.py", "try:\n    x=1\nexcept:\n    pass\n"
        )
        for finding in analyze_error_handling([f], tmp_repo):
            assert finding.category == Category.ERROR_HANDLING

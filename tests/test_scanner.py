"""Integration tests for proto_gap.scanner — full Scanner orchestration.

Tests run the Scanner and scan_repository() function against synthetic
prototype directory trees to verify that the full pipeline (file discovery
→ analysis → aggregation) works correctly end-to-end.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Callable

import pytest

from proto_gap.models import Category, Finding, ScanReport, Severity
from proto_gap.scanner import (
    EXCLUDED_DIRS,
    SCANNABLE_EXTENSIONS,
    SPECIAL_FILENAMES,
    Scanner,
    scan_repository,
)


# ---------------------------------------------------------------------------
# Helpers and fixtures
# ---------------------------------------------------------------------------


def write_file(directory: Path, name: str, content: str) -> Path:
    """Write content to a named file inside directory and return the path."""
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


@pytest.fixture()
def empty_repo(tmp_path: Path) -> Path:
    """Return an empty temporary directory to serve as a clean repo root."""
    return tmp_path


@pytest.fixture()
def minimal_repo(tmp_path: Path) -> Path:
    """Return a repo with a single minimal Python app file."""
    write_file(tmp_path, "app.py", "x = 1 + 2\nprint(x)\n")
    return tmp_path


@pytest.fixture()
def prototype_repo(tmp_path: Path) -> Path:
    """Build a realistic prototype repo with many production gaps.

    The prototype:
    - Has a hardcoded SECRET_KEY and DATABASE_URL
    - Uses DEBUG=True
    - Uses SQLite
    - Calls Base.metadata.create_all()
    - Has bare except and silent except handlers
    - Uses eval() and pickle
    - Has no test files
    - Has no .gitignore or .env.example
    - Uses print() for logging
    """
    write_file(
        tmp_path,
        "app.py",
        """\
        from flask import Flask
        import pickle

        SECRET_KEY = "hardcoded_secret"
        DEBUG = True

        app = Flask(__name__)

        @app.route("/run")
        def run_command():
            data = eval(request.args.get("cmd"))
            return str(data)

        @app.route("/load")
        def load_data():
            raw = request.get_data()
            obj = pickle.loads(raw)
            return str(obj)

        if __name__ == "__main__":
            app.run(debug=True)
        """,
    )
    write_file(
        tmp_path,
        "database.py",
        """\
        from sqlalchemy import create_engine
        from sqlalchemy.ext.declarative import declarative_base

        DATABASE_URL = "sqlite:///app.db"
        engine = create_engine(DATABASE_URL)
        Base = declarative_base()

        def init_db():
            Base.metadata.create_all(engine)
        """,
    )
    write_file(
        tmp_path,
        "utils.py",
        """\
        def parse_data(raw):
            try:
                return int(raw)
            except:
                pass

        def safe_divide(a, b):
            try:
                return a / b
            except ValueError:
                pass
        """,
    )
    write_file(
        tmp_path,
        "requirements.txt",
        """\
        flask==2.3.0
        sqlalchemy==2.0.0
        requests==2.31.0
        """,
    )
    return tmp_path


@pytest.fixture()\def clean_repo(tmp_path: Path) -> Path:
    """Build a well-configured prototype repo with fewer gaps."""
    write_file(
        tmp_path,
        "app.py",
        """\
        import logging
        import os

        logger = logging.getLogger(__name__)

        SECRET_KEY = os.environ.get("SECRET_KEY", "")
        DATABASE_URL = os.environ.get("DATABASE_URL", "")
        DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

        def process(value):
            try:
                return int(value)
            except ValueError as exc:
                logger.error("Invalid value: %s", exc)
                raise
        """,
    )
    write_file(
        tmp_path,
        "tests/test_app.py",
        """\
        def test_process():
            from app import process
            assert process("42") == 42
        """,
    )
    write_file(tmp_path, ".gitignore", ".env\n__pycache__/\n.venv/\n")
    write_file(tmp_path, ".env.example", "SECRET_KEY=\nDATABASE_URL=\nDEBUG=false\n")
    write_file(
        tmp_path,
        "pyproject.toml",
        "[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n",
    )
    return tmp_path


# ---------------------------------------------------------------------------
# Scanner.__init__ tests
# ---------------------------------------------------------------------------


class TestScannerInit:
    """Tests for Scanner initialization and validation."""

    def test_accepts_valid_directory(self, tmp_path: Path) -> None:
        """Scanner should initialize without error for a valid directory."""
        scanner = Scanner(tmp_path)
        assert scanner.repo_path == tmp_path.resolve()

    def test_resolves_repo_path(self, tmp_path: Path) -> None:
        """repo_path should be resolved to an absolute path."""
        scanner = Scanner(tmp_path)
        assert scanner.repo_path.is_absolute()

    def test_raises_for_nonexistent_path(self, tmp_path: Path) -> None:
        """Should raise ValueError for a path that does not exist."""
        nonexistent = tmp_path / "does_not_exist"
        with pytest.raises(ValueError, match="does not exist"):
            Scanner(nonexistent)

    def test_raises_for_file_path(self, tmp_path: Path) -> None:
        """Should raise ValueError when given a file instead of a directory."""
        f = tmp_path / "file.py"
        f.write_text("x = 1", encoding="utf-8")
        with pytest.raises(ValueError, match="not a directory"):
            Scanner(f)

    def test_default_max_file_size(self, tmp_path: Path) -> None:
        """Default max_file_size_bytes should be 1 MB."""
        scanner = Scanner(tmp_path)
        assert scanner.max_file_size_bytes == 1_000_000

    def test_custom_max_file_size(self, tmp_path: Path) -> None:
        """Custom max_file_size_bytes should be stored on the instance."""
        scanner = Scanner(tmp_path, max_file_size_bytes=512_000)
        assert scanner.max_file_size_bytes == 512_000

    def test_extra_analyzers_appended(self, tmp_path: Path) -> None:
        """Extra analyzers should be stored alongside built-in analyzers."""

        def dummy_analyzer(files: list[Path], repo_root: Path) -> list[Finding]:
            return []

        scanner = Scanner(tmp_path, extra_analyzers=[dummy_analyzer])
        # The dummy should be in the analyzer list
        assert dummy_analyzer in scanner._analyzers

    def test_no_extra_analyzers_by_default(self, tmp_path: Path) -> None:
        """Without extra_analyzers, only built-in analyzers are registered."""
        scanner = Scanner(tmp_path)
        # Should have exactly the 7 built-in analyzers
        assert len(scanner._analyzers) == 7


# ---------------------------------------------------------------------------
# Scanner._collect_files tests
# ---------------------------------------------------------------------------


class TestScannerCollectFiles:
    """Tests for the file discovery logic inside Scanner._collect_files()."""

    def test_collects_python_files(self, tmp_path: Path) -> None:
        """Python files should be included in the collected file list."""
        write_file(tmp_path, "app.py", "x = 1\n")
        scanner = Scanner(tmp_path)
        files, errors = scanner._collect_files()
        names = [f.name for f in files]
        assert "app.py" in names
        assert errors == []

    def test_collects_yaml_files(self, tmp_path: Path) -> None:
        """YAML files should be included."""
        write_file(tmp_path, "config.yaml", "key: value\n")
        scanner = Scanner(tmp_path)
        files, _ = scanner._collect_files()
        names = [f.name for f in files]
        assert "config.yaml" in names

    def test_collects_toml_files(self, tmp_path: Path) -> None:
        """TOML files should be included."""
        write_file(tmp_path, "pyproject.toml", "[project]\nname = 'test'\n")
        scanner = Scanner(tmp_path)
        files, _ = scanner._collect_files()
        names = [f.name for f in files]
        assert "pyproject.toml" in names

    def test_collects_special_filenames(self, tmp_path: Path) -> None:
        """Special filenames like .gitignore should be included."""
        write_file(tmp_path, ".gitignore", ".env\n")
        write_file(tmp_path, ".env.example", "KEY=value\n")
        scanner = Scanner(tmp_path)
        files, _ = scanner._collect_files()
        names = [f.name for f in files]
        assert ".gitignore" in names
        assert ".env.example" in names

    def test_excludes_non_scannable_extensions(self, tmp_path: Path) -> None:
        """Files with non-scannable extensions should not be collected."""
        write_file(tmp_path, "image.png", "\x89PNG\r\n")
        write_file(tmp_path, "binary.exe", "MZ")
        scanner = Scanner(tmp_path)
        files, _ = scanner._collect_files()
        names = [f.name for f in files]
        assert "image.png" not in names
        assert "binary.exe" not in names

    def test_excludes_excluded_directories(self, tmp_path: Path) -> None:
        """Files inside excluded directories should not be collected."""
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        write_file(venv_dir, "site_package.py", "x = 1\n")

        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        write_file(git_dir, "config", "[core]\n")

        node_dir = tmp_path / "node_modules"
        node_dir.mkdir()
        write_file(node_dir, "package.js", "module.exports = {}\n")

        write_file(tmp_path, "app.py", "x = 1\n")
        scanner = Scanner(tmp_path)
        files, _ = scanner._collect_files()

        for f in files:
            assert ".venv" not in f.parts
            assert ".git" not in f.parts
            assert "node_modules" not in f.parts

    def test_excludes_pycache_directories(self, tmp_path: Path) -> None:
        """__pycache__ directories should be excluded."""
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        write_file(cache_dir, "app.cpython-311.pyc", "\xed\n")
        write_file(tmp_path, "app.py", "x = 1\n")
        scanner = Scanner(tmp_path)
        files, _ = scanner._collect_files()
        for f in files:
            assert "__pycache__" not in f.parts

    def test_excludes_egg_info_directories(self, tmp_path: Path) -> None:
        """Directories ending in .egg-info should be excluded."""
        egg_dir = tmp_path / "mypackage.egg-info"
        egg_dir.mkdir()
        write_file(egg_dir, "PKG-INFO", "Name: mypackage\n")
        write_file(tmp_path, "app.py", "x = 1\n")
        scanner = Scanner(tmp_path)
        files, _ = scanner._collect_files()
        for f in files:
            assert not any(p.endswith(".egg-info") for p in f.parts)

    def test_skips_large_files(self, tmp_path: Path) -> None:
        """Files exceeding max_file_size_bytes should be skipped with an error."""
        large_file = tmp_path / "large.py"
        large_file.write_bytes(b"x = 1\n" * 300_000)  # ~1.8 MB
        scanner = Scanner(tmp_path, max_file_size_bytes=100_000)
        files, errors = scanner._collect_files()
        names = [f.name for f in files]
        assert "large.py" not in names
        assert len(errors) >= 1
        assert any("large.py" in e for e in errors)

    def test_collects_files_recursively(self, tmp_path: Path) -> None:
        """Files in subdirectories should be included."""
        subdir = tmp_path / "models"
        subdir.mkdir()
        write_file(subdir, "user.py", "class User: pass\n")
        write_file(tmp_path, "app.py", "x = 1\n")
        scanner = Scanner(tmp_path)
        files, _ = scanner._collect_files()
        names = [f.name for f in files]
        assert "user.py" in names
        assert "app.py" in names

    def test_returns_path_objects(self, tmp_path: Path) -> None:
        """Collected files should be Path objects."""
        write_file(tmp_path, "app.py", "x = 1\n")
        scanner = Scanner(tmp_path)
        files, _ = scanner._collect_files()
        assert all(isinstance(f, Path) for f in files)

    def test_empty_directory_returns_empty_list(self, tmp_path: Path) -> None:
        """An empty directory should return no files and no errors."""
        scanner = Scanner(tmp_path)
        files, errors = scanner._collect_files()
        assert files == []
        assert errors == []

    def test_sql_files_collected(self, tmp_path: Path) -> None:
        """SQL files should be included in the scan."""
        write_file(tmp_path, "schema.sql", "CREATE TABLE users (id INTEGER);\n")
        scanner = Scanner(tmp_path)
        files, _ = scanner._collect_files()
        names = [f.name for f in files]
        assert "schema.sql" in names

    def test_js_and_ts_files_collected(self, tmp_path: Path) -> None:
        """JavaScript and TypeScript files should be collected."""
        write_file(tmp_path, "index.js", "const x = 1;\n")
        write_file(tmp_path, "app.ts", "const y: number = 2;\n")
        scanner = Scanner(tmp_path)
        files, _ = scanner._collect_files()
        names = [f.name for f in files]
        assert "index.js" in names
        assert "app.ts" in names


# ---------------------------------------------------------------------------
# Scanner.scan() tests
# ---------------------------------------------------------------------------


class TestScannerScan:
    """Tests for the Scanner.scan() method."""

    def test_scan_returns_scan_report(self, empty_repo: Path) -> None:
        """scan() should always return a ScanReport instance."""
        scanner = Scanner(empty_repo)
        report = scanner.scan()
        assert isinstance(report, ScanReport)

    def test_scan_report_has_correct_repo_path(self, minimal_repo: Path) -> None:
        """The report's repo_path should match the scanned directory."""
        scanner = Scanner(minimal_repo)
        report = scanner.scan()
        assert report.repo_path == minimal_repo.resolve()

    def test_scan_report_has_scanned_files(self, minimal_repo: Path) -> None:
        """The report should list the files that were scanned."""
        scanner = Scanner(minimal_repo)
        report = scanner.scan()
        assert len(report.scanned_files) >= 1
        assert all(isinstance(f, Path) for f in report.scanned_files)

    def test_scan_report_findings_is_list(self, minimal_repo: Path) -> None:
        """report.findings should be a list."""
        scanner = Scanner(minimal_repo)
        report = scanner.scan()
        assert isinstance(report.findings, list)

    def test_scan_report_errors_is_list(self, minimal_repo: Path) -> None:
        """report.errors should be a list."""
        scanner = Scanner(minimal_repo)
        report = scanner.scan()
        assert isinstance(report.errors, list)

    def test_scan_prototype_produces_findings(self, prototype_repo: Path) -> None:
        """Scanning a prototype repo with many gaps should produce findings."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        assert report.total_count > 0

    def test_scan_prototype_has_critical_findings(self, prototype_repo: Path) -> None:
        """A prototype with eval() and create_all() should have CRITICAL findings."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        assert report.critical_count > 0

    def test_scan_prototype_has_high_findings(self, prototype_repo: Path) -> None:
        """A prototype with various gaps should have HIGH findings."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        assert report.high_count > 0

    def test_scan_prototype_detects_eval(self, prototype_repo: Path) -> None:
        """Scanner should detect SEC001 (eval) in the prototype."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "SEC001" in rule_ids

    def test_scan_prototype_detects_create_all(self, prototype_repo: Path) -> None:
        """Scanner should detect MIG002 (create_all) in the prototype."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "MIG002" in rule_ids

    def test_scan_prototype_detects_sqlite(self, prototype_repo: Path) -> None:
        """Scanner should detect MIG003 (SQLite) in the prototype."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "MIG003" in rule_ids

    def test_scan_prototype_detects_debug_true(self, prototype_repo: Path) -> None:
        """Scanner should detect ENV001 (DEBUG=True) in the prototype."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "ENV001" in rule_ids

    def test_scan_prototype_detects_missing_tests(self, prototype_repo: Path) -> None:
        """Scanner should detect TST001 (no test files) in the prototype."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "TST001" in rule_ids

    def test_scan_prototype_detects_missing_gitignore(self, prototype_repo: Path) -> None:
        """Scanner should detect ENV004 (no .gitignore) in the prototype."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "ENV004" in rule_ids

    def test_scan_prototype_detects_missing_env_example(self, prototype_repo: Path) -> None:
        """Scanner should detect ENV003 (no .env.example) in the prototype."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "ENV003" in rule_ids

    def test_scan_prototype_detects_bare_except(self, prototype_repo: Path) -> None:
        """Scanner should detect ERR001 (bare except) in the prototype."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "ERR001" in rule_ids

    def test_scan_prototype_detects_silent_except(self, prototype_repo: Path) -> None:
        """Scanner should detect ERR002 (silent except) in the prototype."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "ERR002" in rule_ids

    def test_scan_prototype_detects_pickle(self, prototype_repo: Path) -> None:
        """Scanner should detect SEC003 (pickle) in the prototype."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "SEC003" in rule_ids

    def test_scan_prototype_detects_hardcoded_secret(self, prototype_repo: Path) -> None:
        """Scanner should detect AUTH001 (hardcoded SECRET_KEY) in the prototype."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "AUTH001" in rule_ids

    def test_scan_prototype_detects_missing_alembic(self, prototype_repo: Path) -> None:
        """Scanner should detect MIG001 (no Alembic) in the prototype."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "MIG001" in rule_ids

    def test_scan_all_findings_are_finding_instances(self, prototype_repo: Path) -> None:
        """Every finding in the report must be a Finding instance."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        for finding in report.findings:
            assert isinstance(finding, Finding)

    def test_scan_findings_have_valid_categories(self, prototype_repo: Path) -> None:
        """All findings must have a valid Category."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        valid_categories = set(Category)
        for finding in report.findings:
            assert finding.category in valid_categories

    def test_scan_findings_have_valid_severities(self, prototype_repo: Path) -> None:
        """All findings must have a valid Severity."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        valid_severities = set(Severity)
        for finding in report.findings:
            assert finding.severity in valid_severities

    def test_scan_findings_have_non_empty_text_fields(self, prototype_repo: Path) -> None:
        """All findings must have non-empty title, description, and remediation."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        for finding in report.findings:
            assert finding.title, f"Finding {finding.rule_id} has empty title"
            assert finding.description, f"Finding {finding.rule_id} has empty description"
            assert finding.remediation, f"Finding {finding.rule_id} has empty remediation"

    def test_scan_report_count_properties_consistent(self, prototype_repo: Path) -> None:
        """Severity count properties must sum to total_count."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        assert (
            report.critical_count
            + report.high_count
            + report.medium_count
            + report.low_count
        ) == report.total_count

    def test_scan_scanned_files_exist_on_disk(self, prototype_repo: Path) -> None:
        """All files in report.scanned_files should actually exist on disk."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        for file_path in report.scanned_files:
            assert file_path.exists(), f"Scanned file does not exist: {file_path}"

    def test_scan_scanned_files_are_under_repo_root(self, prototype_repo: Path) -> None:
        """All scanned files must be within the repo root directory."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        resolved_root = prototype_repo.resolve()
        for file_path in report.scanned_files:
            assert str(file_path).startswith(str(resolved_root)), (
                f"File outside repo root: {file_path}"
            )

    def test_scan_empty_repo_has_no_scanned_files(self, empty_repo: Path) -> None:
        """An empty directory should result in zero scanned files."""
        scanner = Scanner(empty_repo)
        report = scanner.scan()
        assert report.scanned_files == []

    def test_scan_with_extra_analyzer(self, minimal_repo: Path) -> None:
        """Extra analyzers should contribute findings to the report."""
        sentinel: list[bool] = []

        def my_analyzer(files: list[Path], repo_root: Path) -> list[Finding]:
            sentinel.append(True)
            return [
                Finding(
                    category=Category.SECURITY,
                    severity=Severity.LOW,
                    title="Custom finding",
                    description="From extra analyzer.",
                    remediation="Fix it.",
                    rule_id="CUSTOM001",
                )
            ]

        scanner = Scanner(minimal_repo, extra_analyzers=[my_analyzer])
        report = scanner.scan()

        assert sentinel, "Extra analyzer was never called"
        rule_ids = {f.rule_id for f in report.findings}
        assert "CUSTOM001" in rule_ids

    def test_scan_captures_analyzer_failures_as_errors(self, minimal_repo: Path) -> None:
        """If an analyzer raises, the error should be captured, not propagated."""

        def failing_analyzer(files: list[Path], repo_root: Path) -> list[Finding]:
            raise RuntimeError("Analyzer exploded!")

        scanner = Scanner(minimal_repo, extra_analyzers=[failing_analyzer])
        # Should not raise
        report = scanner.scan()
        assert any("failing_analyzer" in e for e in report.errors)

    def test_scan_clean_repo_fewer_critical(self, clean_repo: Path) -> None:
        """A well-configured repo should have fewer (or zero) CRITICAL findings."""
        prototype_scanner = Scanner(clean_repo)
        clean_report = prototype_scanner.scan()
        # A clean repo should have fewer critical issues than a prototype
        # (it may still have some due to missing CI config etc.)
        # The key check: no AUTH001/ENV002 hardcoded credential findings
        rule_ids = {f.rule_id for f in clean_report.findings}
        assert "AUTH001" not in rule_ids
        assert "ENV001" not in rule_ids
        assert "ENV002" not in rule_ids

    def test_scan_clean_repo_no_missing_gitignore(self, clean_repo: Path) -> None:
        """A repo with .gitignore should not trigger ENV004."""
        scanner = Scanner(clean_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "ENV004" not in rule_ids

    def test_scan_clean_repo_no_missing_env_example(self, clean_repo: Path) -> None:
        """A repo with .env.example should not trigger ENV003."""
        scanner = Scanner(clean_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "ENV003" not in rule_ids

    def test_scan_clean_repo_no_missing_test_files(self, clean_repo: Path) -> None:
        """A repo with test files should not trigger TST001."""
        scanner = Scanner(clean_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "TST001" not in rule_ids

    def test_scan_clean_repo_no_missing_test_runner_config(self, clean_repo: Path) -> None:
        """A repo with pyproject.toml should not trigger TST002."""
        scanner = Scanner(clean_repo)
        report = scanner.scan()
        rule_ids = {f.rule_id for f in report.findings}
        assert "TST002" not in rule_ids

    def test_scan_report_to_dict_serializable(self, prototype_repo: Path) -> None:
        """The scan report should be serializable to a dictionary."""
        import json

        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        d = report.to_dict()
        # Should not raise
        json_str = json.dumps(d, default=str)
        assert json_str

    def test_scan_report_dict_has_expected_keys(self, minimal_repo: Path) -> None:
        """The to_dict() output should contain all expected top-level keys."""
        scanner = Scanner(minimal_repo)
        report = scanner.scan()
        d = report.to_dict()
        expected_keys = {
            "repo_path",
            "total_findings",
            "summary",
            "scanned_files",
            "errors",
            "findings",
        }
        assert expected_keys.issubset(set(d.keys()))

    def test_scan_report_dict_summary_counts_correct(self, prototype_repo: Path) -> None:
        """Summary counts in to_dict() should match report property values."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        d = report.to_dict()
        summary = d["summary"]
        assert summary["critical"] == report.critical_count
        assert summary["high"] == report.high_count
        assert summary["medium"] == report.medium_count
        assert summary["low"] == report.low_count

    def test_scan_max_file_size_respected(self, tmp_path: Path) -> None:
        """Files above max_file_size_bytes should not be scanned."""
        # Create a file large enough to be excluded
        big = tmp_path / "huge.py"
        big.write_bytes(b"x = 1\n" * 200_000)  # ~1.2 MB
        small = tmp_path / "small.py"
        small.write_text("y = 2\n", encoding="utf-8")

        scanner = Scanner(tmp_path, max_file_size_bytes=500_000)
        report = scanner.scan()

        scanned_names = [f.name for f in report.scanned_files]
        assert "huge.py" not in scanned_names
        assert "small.py" in scanned_names
        # Should have an error entry about the skipped file
        assert any("huge.py" in e for e in report.errors)


# ---------------------------------------------------------------------------
# scan_repository() convenience function tests
# ---------------------------------------------------------------------------


class TestScanRepository:
    """Tests for the scan_repository() convenience function."""

    def test_returns_scan_report(self, minimal_repo: Path) -> None:
        """scan_repository() should return a ScanReport."""
        report = scan_repository(minimal_repo)
        assert isinstance(report, ScanReport)

    def test_raises_for_nonexistent_path(self, tmp_path: Path) -> None:
        """scan_repository() should raise ValueError for non-existent paths."""
        with pytest.raises(ValueError, match="does not exist"):
            scan_repository(tmp_path / "no_such_dir")

    def test_raises_for_file_path(self, tmp_path: Path) -> None:
        """scan_repository() should raise ValueError when given a file."""
        f = tmp_path / "file.py"
        f.write_text("x = 1", encoding="utf-8")
        with pytest.raises(ValueError, match="not a directory"):
            scan_repository(f)

    def test_accepts_extra_analyzers(self, minimal_repo: Path) -> None:
        """scan_repository() should forward extra_analyzers to the Scanner."""
        called: list[bool] = []

        def extra(files: list[Path], repo_root: Path) -> list[Finding]:
            called.append(True)
            return []

        scan_repository(minimal_repo, extra_analyzers=[extra])
        assert called, "Extra analyzer was not called by scan_repository()"

    def test_prototype_has_findings(self, prototype_repo: Path) -> None:
        """scan_repository() on a prototype should find production gaps."""
        report = scan_repository(prototype_repo)
        assert report.total_count > 0

    def test_default_max_file_size_is_1mb(self, minimal_repo: Path) -> None:
        """Default max_file_size_bytes should be 1 MB."""
        # Create a file just under 1 MB — should be scanned
        under_limit = minimal_repo / "under.py"
        under_limit.write_bytes(b"x = 1\n" * 160_000)  # ~960 KB
        report = scan_repository(minimal_repo)
        scanned_names = [f.name for f in report.scanned_files]
        assert "under.py" in scanned_names

    def test_custom_max_file_size_excludes_files(self, minimal_repo: Path) -> None:
        """A custom max_file_size_bytes should exclude files above the limit."""
        big = minimal_repo / "big.py"
        big.write_bytes(b"x = 1\n" * 20_000)  # ~120 KB
        report = scan_repository(minimal_repo, max_file_size_bytes=50_000)
        scanned_names = [f.name for f in report.scanned_files]
        assert "big.py" not in scanned_names

    def test_scan_report_findings_sorted_by_severity(self, prototype_repo: Path) -> None:
        """findings_by_severity() should return CRITICAL findings first."""
        report = scan_repository(prototype_repo)
        if report.total_count >= 2:
            ordered = report.findings_by_severity()
            severity_order = {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
            }
            for i in range(len(ordered) - 1):
                assert severity_order[ordered[i].severity] <= severity_order[ordered[i + 1].severity]

    def test_scan_report_findings_by_category_covers_all_categories(self, prototype_repo: Path) -> None:
        """findings_by_category() should return a key for every Category."""
        report = scan_repository(prototype_repo)
        by_cat = report.findings_by_category()
        for cat in Category:
            assert cat in by_cat


# ---------------------------------------------------------------------------
# Module-level constants tests
# ---------------------------------------------------------------------------


class TestScannerConstants:
    """Tests for the module-level constants used by the Scanner."""

    def test_scannable_extensions_is_frozenset(self) -> None:
        """SCANNABLE_EXTENSIONS should be a frozenset."""
        assert isinstance(SCANNABLE_EXTENSIONS, frozenset)

    def test_scannable_extensions_contains_python(self) -> None:
        """SCANNABLE_EXTENSIONS must include .py."""
        assert ".py" in SCANNABLE_EXTENSIONS

    def test_scannable_extensions_contains_yaml(self) -> None:
        """SCANNABLE_EXTENSIONS must include .yaml and .yml."""
        assert ".yaml" in SCANNABLE_EXTENSIONS
        assert ".yml" in SCANNABLE_EXTENSIONS

    def test_scannable_extensions_contains_toml(self) -> None:
        """SCANNABLE_EXTENSIONS must include .toml."""
        assert ".toml" in SCANNABLE_EXTENSIONS

    def test_excluded_dirs_is_frozenset(self) -> None:
        """EXCLUDED_DIRS should be a frozenset."""
        assert isinstance(EXCLUDED_DIRS, frozenset)

    def test_excluded_dirs_contains_git(self) -> None:
        """EXCLUDED_DIRS must include .git."""
        assert ".git" in EXCLUDED_DIRS

    def test_excluded_dirs_contains_venv(self) -> None:
        """EXCLUDED_DIRS must include common venv directory names."""
        assert ".venv" in EXCLUDED_DIRS or "venv" in EXCLUDED_DIRS

    def test_excluded_dirs_contains_node_modules(self) -> None:
        """EXCLUDED_DIRS must include node_modules."""
        assert "node_modules" in EXCLUDED_DIRS

    def test_excluded_dirs_contains_pycache(self) -> None:
        """EXCLUDED_DIRS must include __pycache__."""
        assert "__pycache__" in EXCLUDED_DIRS

    def test_special_filenames_is_frozenset(self) -> None:
        """SPECIAL_FILENAMES should be a frozenset."""
        assert isinstance(SPECIAL_FILENAMES, frozenset)

    def test_special_filenames_contains_gitignore(self) -> None:
        """SPECIAL_FILENAMES must include .gitignore."""
        assert ".gitignore" in SPECIAL_FILENAMES

    def test_special_filenames_contains_env_example(self) -> None:
        """SPECIAL_FILENAMES must include .env.example."""
        assert ".env.example" in SPECIAL_FILENAMES


# ---------------------------------------------------------------------------
# Edge case and regression tests
# ---------------------------------------------------------------------------


class TestScannerEdgeCases:
    """Edge case and regression tests for the Scanner."""

    def test_scan_directory_with_only_excluded_dirs(self, tmp_path: Path) -> None:
        """A repo containing only excluded directories should scan cleanly."""
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        write_file(venv, "something.py", "x = 1\n")
        scanner = Scanner(tmp_path)
        report = scanner.scan()
        # No Python files should have been scanned from inside .venv
        assert report.scanned_files == []

    def test_scan_deeply_nested_files(self, tmp_path: Path) -> None:
        """Files nested several levels deep should be discovered."""
        deep_dir = tmp_path / "a" / "b" / "c" / "d"
        deep_dir.mkdir(parents=True)
        write_file(deep_dir, "deep.py", "eval('x')\n")
        scanner = Scanner(tmp_path)
        report = scanner.scan()
        scanned_names = [f.name for f in report.scanned_files]
        assert "deep.py" in scanned_names
        rule_ids = {f.rule_id for f in report.findings}
        assert "SEC001" in rule_ids

    def test_scan_with_syntax_error_file_does_not_crash(self, tmp_path: Path) -> None:
        """A Python file with syntax errors should be skipped without crashing."""
        write_file(tmp_path, "broken.py", "def foo(\n")
        write_file(tmp_path, "good.py", "x = 1\n")
        scanner = Scanner(tmp_path)
        # Should not raise
        report = scanner.scan()
        assert isinstance(report, ScanReport)

    def test_scan_binary_like_file_does_not_crash(self, tmp_path: Path) -> None:
        """Files with non-UTF-8 content should not crash the scanner."""
        binary_file = tmp_path / "weird.py"
        binary_file.write_bytes(b"\xff\xfe" + b"x = 1\n")
        scanner = Scanner(tmp_path)
        report = scanner.scan()
        assert isinstance(report, ScanReport)

    def test_scan_does_not_mutate_between_calls(self, minimal_repo: Path) -> None:
        """Two separate scan() calls should produce independent reports."""
        scanner = Scanner(minimal_repo)
        report1 = scanner.scan()
        report2 = scanner.scan()
        # Mutating report1 should not affect report2
        initial_count = len(report2.findings)
        report1.findings.clear()
        assert len(report2.findings) == initial_count

    def test_scan_report_has_string_repr(self, minimal_repo: Path) -> None:
        """ScanReport __str__ should produce a non-empty string."""
        scanner = Scanner(minimal_repo)
        report = scanner.scan()
        text = str(report)
        assert "ScanReport" in text

    def test_scan_with_multiple_file_types(self, tmp_path: Path) -> None:
        """Scanner should handle repos with mixed file types."""
        write_file(tmp_path, "app.py", "eval('x')\n")
        write_file(tmp_path, "config.yaml", "debug: true\n")
        write_file(tmp_path, "package.json", '{"name": "test"}\n')
        write_file(tmp_path, "README.md", "# My App\n")
        write_file(tmp_path, ".gitignore", ".env\n")
        scanner = Scanner(tmp_path)
        report = scanner.scan()
        scanned_names = [f.name for f in report.scanned_files]
        assert "app.py" in scanned_names
        assert "config.yaml" in scanned_names
        assert ".gitignore" in scanned_names

    def test_scan_findings_file_paths_are_absolute(self, prototype_repo: Path) -> None:
        """Findings with file_path set should have absolute paths."""
        scanner = Scanner(prototype_repo)
        report = scanner.scan()
        for finding in report.findings:
            if finding.file_path is not None and finding.file_path != prototype_repo.resolve():
                assert finding.file_path.is_absolute(), (
                    f"Finding {finding.rule_id} has non-absolute file_path: {finding.file_path}"
                )

    def test_scan_no_duplicate_scanned_files(self, minimal_repo: Path) -> None:
        """Each file should appear only once in scanned_files."""
        scanner = Scanner(minimal_repo)
        report = scanner.scan()
        assert len(report.scanned_files) == len(set(report.scanned_files))

    def test_scan_respects_topdown_pruning(self, tmp_path: Path) -> None:
        """Excluded directories should be pruned before descending."""
        # Create a deeply nested structure inside an excluded dir
        excluded = tmp_path / "node_modules" / "lodash" / "src"
        excluded.mkdir(parents=True)
        for i in range(10):
            write_file(excluded, f"module_{i}.js", f"eval({i});\n")

        # Also create some legitimate files
        write_file(tmp_path, "app.py", "x = 1\n")

        scanner = Scanner(tmp_path)
        report = scanner.scan()

        # None of the node_modules files should be scanned
        for f in report.scanned_files:
            assert "node_modules" not in f.parts

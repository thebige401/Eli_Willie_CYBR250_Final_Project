#!/usr/bin/env python3
"""
================================================================================
ForensicKit - Test Suite
================================================================================
Author      : Eli Willie
Course      : CYBR 250 - Final Project
Date        : May 30, 2026

I wrote these tests to cover every major component of the collector:
  * Unit tests for every collector method
  * Integration smoke-test (run_all on a temp directory)
  * Report generation (JSON + HTML)
  * SHA-256 manifest generation
  * CLI argument parsing
  * Helper utilities (_sha256_string, _read_file, _run, make_evidence)
  * Edge cases: missing files, empty data, permission errors (mocked)

The test classes mirror the structure of the main script — one class per
component — so it's easy to run just the tests for the thing you're working on.

Run:
    python -m pytest tests/test_forensic_collector.py -v
  or
    python tests/test_forensic_collector.py
================================================================================
"""

import datetime
import hashlib
import json
import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add the parent directory to sys.path so we can import the collector module
# regardless of where this test file is run from
sys.path.insert(0, str(Path(__file__).parent.parent))

from forensic_collector import (
    ForensicCollector,
    ReportGenerator,
    _read_file,
    _run,
    _sha256_file,
    _sha256_string,
    build_parser,
    main,
    make_evidence,
)

IS_WINDOWS = platform.system() == "Windows"


# ============================================================================
# Helper utility tests
# These test the small standalone functions that the collectors rely on.
# ============================================================================

class TestMakeEvidence(unittest.TestCase):
    """
    Tests for the make_evidence factory function.

    Every evidence item in the collection uses this structure, so getting
    it right is important — if the keys are wrong, the report generator breaks.
    """

    def test_required_keys_present(self):
        """All six required keys should be present in every evidence item."""
        evidence_item = make_evidence("System", "Hostname", {"host": "testbox"})
        for required_key in ("category", "title", "source", "timestamp", "data", "raw"):
            self.assertIn(required_key, evidence_item)

    def test_category_and_title(self):
        """Category and title should be stored exactly as passed in."""
        evidence_item = make_evidence("Network", "Connections", [])
        self.assertEqual(evidence_item["category"], "Network")
        self.assertEqual(evidence_item["title"], "Connections")

    def test_timestamp_format(self):
        """Timestamp should be a valid ISO 8601 datetime string."""
        evidence_item = make_evidence("X", "Y", None)
        # fromisoformat will raise if the format is wrong
        timestamp_string = evidence_item["timestamp"].rstrip("Z")
        datetime.datetime.fromisoformat(timestamp_string)

    def test_empty_data(self):
        """Empty dict should be stored as-is, not converted to something else."""
        evidence_item = make_evidence("X", "Y", {})
        self.assertEqual(evidence_item["data"], {})

    def test_source_and_raw(self):
        """Optional source and raw fields should be stored correctly."""
        evidence_item = make_evidence("X", "Y", None, source="/etc/hosts", raw="raw text")
        self.assertEqual(evidence_item["source"], "/etc/hosts")
        self.assertEqual(evidence_item["raw"], "raw text")


class TestSha256String(unittest.TestCase):
    """Tests for the _sha256_string helper."""

    def test_known_hash(self):
        """Should produce the same digest as hashlib for the same input."""
        expected_digest = hashlib.sha256(b"hello").hexdigest()
        self.assertEqual(_sha256_string("hello"), expected_digest)

    def test_empty_string(self):
        """SHA-256 of an empty string should still be a 64-character hex string."""
        self.assertEqual(len(_sha256_string("")), 64)

    def test_returns_hex(self):
        """Output should only contain valid hex characters."""
        digest = _sha256_string("test")
        self.assertTrue(all(char in "0123456789abcdef" for char in digest))


class TestSha256File(unittest.TestCase):
    """Tests for the _sha256_file helper."""

    def test_file_hash(self):
        """Should produce the correct hash for a file with known content."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as temp_file:
            temp_file.write(b"hello world")
            temp_file_path = temp_file.name
        expected_digest = hashlib.sha256(b"hello world").hexdigest()
        actual_digest = _sha256_file(temp_file_path)
        os.unlink(temp_file_path)
        self.assertEqual(actual_digest, expected_digest)

    def test_missing_file_returns_none(self):
        """Should return None gracefully if the file doesn't exist."""
        result = _sha256_file("/nonexistent/path/file.bin")
        self.assertIsNone(result)

    def test_empty_file(self):
        """Should correctly hash an empty file (not crash or return None)."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file_path = temp_file.name
        expected_digest = hashlib.sha256(b"").hexdigest()
        actual_digest = _sha256_file(temp_file_path)
        os.unlink(temp_file_path)
        self.assertEqual(actual_digest, expected_digest)


class TestReadFile(unittest.TestCase):
    """Tests for the _read_file helper."""

    def test_reads_content(self):
        """Should successfully read and return file content."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as temp_file:
            temp_file.write("line1\nline2\nline3\n")
            temp_file_path = temp_file.name
        file_content = _read_file(temp_file_path)
        os.unlink(temp_file_path)
        self.assertIn("line1", file_content)

    def test_max_lines_truncation(self):
        """Should return only the last max_lines lines of a long file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as temp_file:
            for line_number in range(1000):
                temp_file.write(f"line {line_number}\n")
            temp_file_path = temp_file.name
        truncated_content = _read_file(temp_file_path, max_lines=10)
        os.unlink(temp_file_path)
        self.assertLessEqual(truncated_content.count("\n"), 10)

    def test_missing_file(self):
        """Should return a descriptive error string instead of raising."""
        result = _read_file("/nonexistent/path.txt")
        self.assertIn("Could not read", result)

    def test_binary_file_does_not_crash(self):
        """Should handle binary content gracefully without raising."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as temp_file:
            temp_file.write(bytes(range(256)))
            temp_file_path = temp_file.name
        result = _read_file(temp_file_path)
        os.unlink(temp_file_path)
        self.assertIsInstance(result, str)


class TestRun(unittest.TestCase):
    """Tests for the _run subprocess helper."""

    def test_simple_command(self):
        """Should execute a basic command and return its output."""
        if IS_WINDOWS:
            test_command = ["cmd", "/c", "echo", "hello"]
        else:
            test_command = ["echo", "hello"]
        stdout_text, stderr_text, return_code = _run(test_command)
        self.assertEqual(return_code, 0)
        self.assertIn("hello", stdout_text)

    def test_missing_command(self):
        """Should return return code 127 and a descriptive error for missing commands."""
        stdout_text, stderr_text, return_code = _run(["__nonexistent_command_xyz__"])
        self.assertEqual(return_code, 127)
        self.assertIn("not found", stderr_text.lower())

    def test_timeout(self):
        """Should return return code 124 when the command exceeds the timeout."""
        if IS_WINDOWS:
            slow_command = ["ping", "-n", "10", "127.0.0.1"]
        else:
            slow_command = ["sleep", "10"]
        stdout_text, stderr_text, return_code = _run(slow_command, timeout=1)
        self.assertEqual(return_code, 124)

    def test_returncode_nonzero(self):
        """Should pass through non-zero return codes from failed commands."""
        if IS_WINDOWS:
            failing_command = ["cmd", "/c", "exit", "1"]
        else:
            failing_command = ["false"]
        stdout_text, stderr_text, return_code = _run(failing_command)
        self.assertNotEqual(return_code, 0)


# ============================================================================
# ForensicCollector unit tests
# One class per collector method, so you can run just one section at a time.
# ============================================================================

class TestCollectorInit(unittest.TestCase):
    """Tests for ForensicCollector.__init__."""

    def test_defaults(self):
        """Default constructor should set sensible defaults."""
        collector = ForensicCollector()
        self.assertEqual(collector.recent_hours, 24)
        self.assertFalse(collector.verbose)
        self.assertEqual(collector.evidence, [])

    def test_custom_params(self):
        """Custom constructor params should override the defaults."""
        collector = ForensicCollector(target_root="/tmp", recent_hours=48, verbose=True)
        self.assertEqual(str(collector.target_root), "/tmp")
        self.assertEqual(collector.recent_hours, 48)
        self.assertTrue(collector.verbose)


class TestCollectorSystemInfo(unittest.TestCase):
    def setUp(self):
        self.collector = ForensicCollector(verbose=False)

    def test_collects_one_item(self):
        """collect_system_info should add exactly one evidence item."""
        self.collector.collect_system_info()
        self.assertEqual(len(self.collector.evidence), 1)

    def test_category_is_system(self):
        self.collector.collect_system_info()
        self.assertEqual(self.collector.evidence[0]["category"], "System")

    def test_hostname_present(self):
        """Hostname is a required field — every system has one."""
        self.collector.collect_system_info()
        evidence_data = self.collector.evidence[0]["data"]
        self.assertIn("hostname", evidence_data)
        self.assertIsInstance(evidence_data["hostname"], str)

    def test_platform_present(self):
        self.collector.collect_system_info()
        evidence_data = self.collector.evidence[0]["data"]
        self.assertIn("platform", evidence_data)


class TestCollectorProcesses(unittest.TestCase):
    def setUp(self):
        self.collector = ForensicCollector(verbose=False)

    def test_collects_one_item(self):
        self.collector.collect_processes()
        self.assertEqual(len(self.collector.evidence), 1)

    def test_category_is_processes(self):
        self.collector.collect_processes()
        self.assertEqual(self.collector.evidence[0]["category"], "Processes")

    def test_data_is_list(self):
        """Process data should always be a list, even in fallback mode."""
        self.collector.collect_processes()
        evidence_data = self.collector.evidence[0]["data"]
        self.assertIsInstance(evidence_data, list)

    def test_at_least_one_process(self):
        """There should always be at least one running process on any machine."""
        self.collector.collect_processes()
        evidence_data = self.collector.evidence[0]["data"]
        self.assertGreater(len(evidence_data), 0)


class TestCollectorNetwork(unittest.TestCase):
    def setUp(self):
        self.collector = ForensicCollector(verbose=False)

    def test_collects_one_item(self):
        self.collector.collect_network()
        self.assertEqual(len(self.collector.evidence), 1)

    def test_category_is_network(self):
        self.collector.collect_network()
        self.assertEqual(self.collector.evidence[0]["category"], "Network")

    def test_data_has_connections_key(self):
        """The connections key should always be present in network evidence."""
        self.collector.collect_network()
        evidence_data = self.collector.evidence[0]["data"]
        self.assertIn("connections", evidence_data)


class TestCollectorDns(unittest.TestCase):
    def test_collects_dns(self):
        """DNS collector should always capture the hosts file at minimum."""
        collector = ForensicCollector()
        collector.collect_dns()
        self.assertEqual(len(collector.evidence), 1)
        self.assertIn("hosts_file", collector.evidence[0]["data"])


class TestCollectorUsers(unittest.TestCase):
    def test_collects_users(self):
        collector = ForensicCollector()
        collector.collect_users()
        self.assertEqual(len(collector.evidence), 1)
        self.assertEqual(collector.evidence[0]["category"], "Users")


class TestCollectorScheduledTasks(unittest.TestCase):
    def test_collects_tasks(self):
        """Scheduled tasks should be categorized under Persistence."""
        collector = ForensicCollector()
        collector.collect_scheduled_tasks()
        self.assertEqual(len(collector.evidence), 1)
        self.assertEqual(collector.evidence[0]["category"], "Persistence")


class TestCollectorStartupItems(unittest.TestCase):
    def test_collects_startup(self):
        """Startup items should be categorized under Persistence."""
        collector = ForensicCollector()
        collector.collect_startup_items()
        self.assertEqual(len(collector.evidence), 1)


class TestCollectorRecentFiles(unittest.TestCase):
    """
    Tests for collect_recent_files.

    These use temp directories with known file timestamps so we can reliably
    test the time-window filtering without depending on the real filesystem.
    """

    def test_finds_recently_created_file(self):
        """A file created just now should show up in a 1-hour window."""
        with tempfile.TemporaryDirectory() as temp_dir:
            recent_test_file = Path(temp_dir) / "recent_test.txt"
            recent_test_file.write_text("test content")

            collector = ForensicCollector(target_root=temp_dir, recent_hours=1)
            collector.collect_recent_files()
            evidence_data = collector.evidence[0]["data"]

            collected_paths = [file_entry["path"] for file_entry in evidence_data["files"]]
            self.assertIn(str(recent_test_file), collected_paths)

    def test_count_matches_files_list(self):
        """The count field should always match the actual length of the files list."""
        with tempfile.TemporaryDirectory() as temp_dir:
            for file_index in range(5):
                (Path(temp_dir) / f"file{file_index}.txt").write_text(f"content {file_index}")

            collector = ForensicCollector(target_root=temp_dir, recent_hours=1)
            collector.collect_recent_files()
            evidence_data = collector.evidence[0]["data"]
            self.assertEqual(evidence_data["count"], len(evidence_data["files"]))

    def test_old_files_not_included(self):
        """Files older than the time window should be filtered out."""
        with tempfile.TemporaryDirectory() as temp_dir:
            old_test_file = Path(temp_dir) / "old_file.txt"
            old_test_file.write_text("old content")
            # Force the mtime to 100 hours ago so it falls outside the 1-hour window
            old_file_mtime = old_test_file.stat().st_mtime - 100 * 3600
            os.utime(str(old_test_file), (old_file_mtime, old_file_mtime))

            collector = ForensicCollector(target_root=temp_dir, recent_hours=1)
            collector.collect_recent_files()
            evidence_data = collector.evidence[0]["data"]
            collected_paths = [file_entry["path"] for file_entry in evidence_data["files"]]
            self.assertNotIn(str(old_test_file), collected_paths)

    def test_respects_limit(self):
        """Collection should stop at 1000 files to prevent runaway on large filesystems."""
        with tempfile.TemporaryDirectory() as temp_dir:
            for file_index in range(1100):
                (Path(temp_dir) / f"f{file_index}.txt").write_text("x")

            collector = ForensicCollector(target_root=temp_dir, recent_hours=24)
            collector.collect_recent_files()
            evidence_data = collector.evidence[0]["data"]
            self.assertLessEqual(evidence_data["count"], 1000)


class TestCollectorLogs(unittest.TestCase):
    def test_collects_logs(self):
        collector = ForensicCollector()
        collector.collect_logs()
        self.assertEqual(len(collector.evidence), 1)
        self.assertEqual(collector.evidence[0]["category"], "Logs")

    def test_data_is_dict(self):
        """Log data should be a dict of log file name -> content."""
        collector = ForensicCollector()
        collector.collect_logs()
        self.assertIsInstance(collector.evidence[0]["data"], dict)


class TestCollectorOpenHandles(unittest.TestCase):
    def test_collects_open_handles(self):
        """open handles evidence should always have a raw_output key."""
        collector = ForensicCollector()
        collector.collect_open_handles()
        self.assertEqual(len(collector.evidence), 1)
        self.assertIn("raw_output", collector.evidence[0]["data"])


class TestRunAll(unittest.TestCase):
    """
    Integration smoke-test for run_all.

    This runs the full collection pipeline to make sure all collectors
    run together without errors and produce the expected categories.
    """

    def test_run_all_returns_evidence_list(self):
        """run_all should return a non-empty list."""
        with tempfile.TemporaryDirectory() as temp_dir:
            collector = ForensicCollector(target_root=temp_dir, recent_hours=1, verbose=False)
            collected_evidence = collector.run_all()
            self.assertIsInstance(collected_evidence, list)
            self.assertGreater(len(collected_evidence), 0)

    def test_run_all_all_categories_present(self):
        """All seven expected evidence categories should be present after run_all."""
        collector = ForensicCollector(verbose=False)
        collected_evidence = collector.run_all()
        collected_categories = {evidence_item["category"] for evidence_item in collected_evidence}
        expected_categories = {"System", "Processes", "Network", "Users",
                    "Persistence", "Filesystem", "Logs"}
        for expected_category in expected_categories:
            self.assertIn(expected_category, collected_categories,
                          f"Category '{expected_category}' missing from evidence")

    def test_run_all_survives_collector_exception(self):
        """A broken collector should not crash the entire run — others should still complete."""
        collector = ForensicCollector(verbose=False)
        # Replace one collector with a version that always raises
        collector.collect_system_info = MagicMock(side_effect=RuntimeError("boom"))
        collected_evidence = collector.run_all()
        # The remaining collectors should have still run
        self.assertIsInstance(collected_evidence, list)


# ============================================================================
# ReportGenerator tests
# ============================================================================

class TestReportGeneratorJson(unittest.TestCase):
    """Tests for ReportGenerator.write_json."""

    def _make_sample_evidence(self):
        """Build a small evidence list for testing — reused across test methods."""
        return [
            make_evidence("System", "Info", {"host": "testbox", "os": "Linux"}),
            make_evidence("Network", "Conns", [{"laddr": "0.0.0.0:22"}]),
        ]

    def test_json_file_created(self):
        """write_json should create a file at the expected path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            report_generator = ReportGenerator(self._make_sample_evidence(), Path(temp_dir),
                                 case_id="TEST-001")
            output_path = report_generator.write_json()
            self.assertTrue(output_path.exists())

    def test_json_is_valid(self):
        """The output file should be valid JSON with the expected top-level keys."""
        with tempfile.TemporaryDirectory() as temp_dir:
            report_generator = ReportGenerator(self._make_sample_evidence(), Path(temp_dir),
                                 case_id="TEST-002")
            output_path = report_generator.write_json()
            with open(output_path) as json_file:
                parsed_json = json.load(json_file)
            self.assertIn("case_id", parsed_json)
            self.assertIn("evidence", parsed_json)

    def test_json_contains_all_evidence(self):
        """All evidence items should be present in the output file."""
        sample_evidence = self._make_sample_evidence()
        with tempfile.TemporaryDirectory() as temp_dir:
            report_generator = ReportGenerator(sample_evidence, Path(temp_dir), case_id="TEST-003")
            output_path = report_generator.write_json()
            with open(output_path) as json_file:
                parsed_json = json.load(json_file)
            self.assertEqual(len(parsed_json["evidence"]), len(sample_evidence))

    def test_json_case_id_in_filename(self):
        """The case ID should appear in the output filename."""
        with tempfile.TemporaryDirectory() as temp_dir:
            report_generator = ReportGenerator(self._make_sample_evidence(), Path(temp_dir),
                                 case_id="MYCASE-999")
            output_path = report_generator.write_json()
            self.assertIn("MYCASE-999", output_path.name)


class TestReportGeneratorHtml(unittest.TestCase):
    """Tests for ReportGenerator.write_html."""

    def _make_sample_evidence(self):
        """Build a varied evidence list that exercises different render paths."""
        return [
            make_evidence("System", "Info", {"host": "box", "ip": "1.2.3.4"}),
            make_evidence("Logs", "Syslog", "/var/log/syslog: line1\nline2\n"),
            make_evidence("Processes", "Running", [
                {"pid": 1, "name": "init", "user": "root"},
                {"pid": 2, "name": "kthreadd", "user": "root"},
            ]),
        ]

    def test_html_file_created(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_generator = ReportGenerator(self._make_sample_evidence(), Path(temp_dir),
                                 case_id="HTML-001")
            output_path = report_generator.write_html()
            self.assertTrue(output_path.exists())

    def test_html_has_doctype(self):
        """Output should be a proper HTML5 document."""
        with tempfile.TemporaryDirectory() as temp_dir:
            report_generator = ReportGenerator(self._make_sample_evidence(), Path(temp_dir),
                                 case_id="HTML-002")
            output_path = report_generator.write_html()
            html_content = output_path.read_text()
            self.assertIn("<!DOCTYPE html>", html_content)

    def test_html_contains_case_id(self):
        """The case ID should appear somewhere in the HTML output."""
        with tempfile.TemporaryDirectory() as temp_dir:
            report_generator = ReportGenerator(self._make_sample_evidence(), Path(temp_dir),
                                 case_id="FINDME-007")
            output_path = report_generator.write_html()
            html_content = output_path.read_text()
            self.assertIn("FINDME-007", html_content)

    def test_html_contains_category_names(self):
        """All evidence categories should appear as section headers in the HTML."""
        with tempfile.TemporaryDirectory() as temp_dir:
            report_generator = ReportGenerator(self._make_sample_evidence(), Path(temp_dir),
                                 case_id="HTML-003")
            output_path = report_generator.write_html()
            html_content = output_path.read_text()
            for expected_category in ("System", "Logs", "Processes"):
                self.assertIn(expected_category, html_content)

    def test_html_xss_escape(self):
        """Script tags in evidence data should be escaped, not rendered."""
        xss_evidence = make_evidence("Test", "XSS", {"key": "<script>alert(1)</script>"})
        with tempfile.TemporaryDirectory() as temp_dir:
            report_generator = ReportGenerator([xss_evidence], Path(temp_dir), case_id="XSS-TEST")
            output_path = report_generator.write_html()
            html_content = output_path.read_text()
            self.assertNotIn("<script>alert(1)</script>", html_content)
            self.assertIn("&lt;script&gt;", html_content)


class TestReportGeneratorManifest(unittest.TestCase):
    """Tests for ReportGenerator.write_manifest."""

    def test_manifest_created(self):
        """write_manifest should create a manifest file in the output directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Pre-create a file so there's something to hash
            sample_file = Path(temp_dir) / "evidence.json"
            sample_file.write_text('{"test": true}')
            report_generator = ReportGenerator([], Path(temp_dir), case_id="MANI-001")
            manifest_path = report_generator.write_manifest()
            self.assertTrue(manifest_path.exists())

    def test_manifest_contains_sha256_lines(self):
        """The manifest should contain at least one 64-character SHA-256 hex digest."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sample_file = Path(temp_dir) / "file_to_hash.txt"
            sample_file.write_text("some content")
            report_generator = ReportGenerator([], Path(temp_dir), case_id="MANI-002")
            manifest_path = report_generator.write_manifest()
            manifest_content = manifest_path.read_text()
            import re
            found_hashes = re.findall(r"[0-9a-f]{64}", manifest_content)
            self.assertGreater(len(found_hashes), 0)

    def test_manifest_not_hashed_itself(self):
        """The manifest file should not include a hash of itself."""
        with tempfile.TemporaryDirectory() as temp_dir:
            other_file = Path(temp_dir) / "other.txt"
            other_file.write_text("x")
            report_generator = ReportGenerator([], Path(temp_dir), case_id="MANI-003")
            manifest_path = report_generator.write_manifest()
            manifest_content = manifest_path.read_text()
            self.assertNotIn(manifest_path.name + "  " + manifest_path.name, manifest_content)


# ============================================================================
# CLI argument parsing tests
# ============================================================================

class TestCliParser(unittest.TestCase):
    """Tests for build_parser / build_argument_parser."""

    def test_defaults(self):
        """All flags should have sensible defaults when nothing is passed."""
        argument_parser = build_parser()
        parsed_args = argument_parser.parse_args([])
        self.assertEqual(parsed_args.output, "reports")
        self.assertEqual(parsed_args.target, "/")
        self.assertEqual(parsed_args.recent, 24)
        self.assertFalse(parsed_args.verbose)
        self.assertFalse(parsed_args.no_html)
        self.assertFalse(parsed_args.no_hash)

    def test_custom_output(self):
        argument_parser = build_parser()
        parsed_args = argument_parser.parse_args(["-o", "/tmp/out"])
        self.assertEqual(parsed_args.output, "/tmp/out")

    def test_verbose_flag(self):
        argument_parser = build_parser()
        parsed_args = argument_parser.parse_args(["-v"])
        self.assertTrue(parsed_args.verbose)

    def test_recent_hours(self):
        argument_parser = build_parser()
        parsed_args = argument_parser.parse_args(["-r", "48"])
        self.assertEqual(parsed_args.recent, 48)

    def test_no_html_flag(self):
        argument_parser = build_parser()
        parsed_args = argument_parser.parse_args(["--no-html"])
        self.assertTrue(parsed_args.no_html)

    def test_no_hash_flag(self):
        argument_parser = build_parser()
        parsed_args = argument_parser.parse_args(["--no-hash"])
        self.assertTrue(parsed_args.no_hash)

    def test_case_id(self):
        argument_parser = build_parser()
        parsed_args = argument_parser.parse_args(["--case-id", "MYCASE"])
        self.assertEqual(parsed_args.case_id, "MYCASE")


class TestMainFunction(unittest.TestCase):
    """
    End-to-end integration tests for main().

    These run the full tool in a temp directory to verify that the output
    files are actually created with the right names and contents.
    """

    def test_main_runs_successfully(self):
        """main() should return exit code 0 on a successful run."""
        with tempfile.TemporaryDirectory() as temp_dir:
            return_code = main(["-o", temp_dir, "-t", temp_dir, "-r", "1",
                       "--case-id", "INTEG-001"])
            self.assertEqual(return_code, 0)

    def test_main_creates_output_files(self):
        """A default run should produce JSON, HTML, and manifest files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            main(["-o", temp_dir, "-t", temp_dir, "-r", "1",
                  "--case-id", "INTEG-002"])
            output_file_names = [output_file.name for output_file in Path(temp_dir).glob("*")]
            self.assertTrue(any("evidence.json" in name for name in output_file_names))
            self.assertTrue(any("report.html" in name for name in output_file_names))
            self.assertTrue(any("manifest.txt" in name for name in output_file_names))

    def test_main_no_html(self):
        """--no-html should skip HTML report generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            main(["-o", temp_dir, "-t", temp_dir, "-r", "1",
                  "--no-html", "--case-id", "INTEG-003"])
            html_files = list(Path(temp_dir).glob("*.html"))
            self.assertEqual(len(html_files), 0)

    def test_main_no_hash(self):
        """--no-hash should skip manifest generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            main(["-o", temp_dir, "-t", temp_dir, "-r", "1",
                  "--no-hash", "--case-id", "INTEG-004"])
            manifest_files = list(Path(temp_dir).glob("*manifest*"))
            self.assertEqual(len(manifest_files), 0)


# ============================================================================
# Edge case / robustness tests
# These test boundary conditions and unusual inputs that the main tests
# don't cover — things like empty lists, deeply nested data, and XSS attempts.
# ============================================================================

class TestEdgeCases(unittest.TestCase):

    def test_render_data_string(self):
        """A plain string should appear somewhere in the rendered HTML."""
        report_generator = ReportGenerator([], Path(tempfile.mkdtemp()))
        rendered_html = report_generator._render_data("hello world")
        self.assertIn("hello world", rendered_html)

    def test_render_data_number(self):
        """Numbers should be rendered as their string representation."""
        report_generator = ReportGenerator([], Path(tempfile.mkdtemp()))
        rendered_html = report_generator._render_data(42)
        self.assertIn("42", rendered_html)

    def test_render_data_empty_list(self):
        """An empty list should render as 'empty', not crash or show nothing."""
        report_generator = ReportGenerator([], Path(tempfile.mkdtemp()))
        rendered_html = report_generator._render_data([])
        self.assertIn("empty", rendered_html)

    def test_render_data_none(self):
        """None should render as a string without raising."""
        report_generator = ReportGenerator([], Path(tempfile.mkdtemp()))
        rendered_html = report_generator._render_data(None)
        self.assertIsInstance(rendered_html, str)

    def test_render_data_nested_dict(self):
        """Nested dicts should be rendered recursively — inner keys should appear."""
        report_generator = ReportGenerator([], Path(tempfile.mkdtemp()))
        rendered_html = report_generator._render_data({"outer": {"inner": "value"}})
        self.assertIn("inner", rendered_html)

    def test_render_table_empty(self):
        """An empty table input should return an empty string."""
        report_generator = ReportGenerator([], Path(tempfile.mkdtemp()))
        rendered_html = report_generator._render_table([])
        self.assertEqual(rendered_html, "")

    def test_render_table_limits_rows(self):
        """Tables should cap at 500 rows to keep the HTML report a manageable size."""
        oversized_rows = [{"a": row_index, "b": str(row_index)} for row_index in range(600)]
        report_generator = ReportGenerator([], Path(tempfile.mkdtemp()))
        rendered_html = report_generator._render_table(oversized_rows)
        # +1 accounts for the header row
        self.assertLessEqual(rendered_html.count("<tr>"), 501)

    def test_escape_html(self):
        """_escape should neutralize script tags to prevent XSS in the report."""
        report_generator = ReportGenerator([], Path(tempfile.mkdtemp()))
        escaped_html = report_generator._escape('<script>alert("xss")</script>')
        self.assertNotIn("<script>", escaped_html)
        self.assertIn("&lt;script&gt;", escaped_html)

    def test_collector_verbose_log(self):
        """Verbose mode should print to stdout without raising exceptions."""
        import io
        from contextlib import redirect_stdout
        output_buffer = io.StringIO()
        collector = ForensicCollector(verbose=True)
        with redirect_stdout(output_buffer):
            collector._log("test message")
        self.assertIn("test message", output_buffer.getvalue())

    def test_report_auto_case_id(self):
        """If no case_id is supplied, one should be auto-generated starting with 'CASE-'."""
        report_generator = ReportGenerator([], Path(tempfile.mkdtemp()))
        self.assertNotEqual(report_generator.case_id, "")
        self.assertTrue(report_generator.case_id.startswith("CASE-"))


# ============================================================================
# Runner
# ============================================================================

if __name__ == "__main__":
    # When run directly (not via pytest), discover and run all tests with verbose output
    test_loader = unittest.TestLoader()
    test_suite  = test_loader.discover(start_dir=str(Path(__file__).parent),
                             pattern="test_*.py")
    test_runner = unittest.TextTestRunner(verbosity=2)
    test_result = test_runner.run(test_suite)
    sys.exit(0 if test_result.wasSuccessful() else 1)

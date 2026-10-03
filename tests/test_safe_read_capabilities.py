"""Missing or invalid safe-read capability refuses before opening input."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from registry_hive_review import cli, files
from registry_hive_review.model import ParseIssue


class SafeReadCapabilities(unittest.TestCase):
    def test_required_flags_refuse_api_and_cli_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            original_open = files.os.open
            for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"):
                for value in (None, "invalid", "MISSING", 0, True, False):
                    with self.subTest(flag=flag, value=value):
                        with patch.object(files.os, flag, value, create=True):
                            if value == "MISSING":
                                delattr(files.os, flag)
                            with patch.object(files.os, "open", wraps=original_open) as opened:
                                with patch.object(
                                    files.os,
                                    "supports_dir_fd",
                                    set(files.os.supports_dir_fd) | {opened},
                                ):
                                    with self.assertRaises(ParseIssue) as failure:
                                        files.read_local(str(sample))
                                    self.assertEqual(
                                        failure.exception.code, "safe_file_platform_not_supported"
                                    )
                                    stream = io.StringIO()
                                    with redirect_stdout(stream):
                                        code = cli.main([str(sample), "--hive-type", "SOFTWARE"])
                                    report = json.loads(stream.getvalue())
                                    self.assertEqual(code, 2)
                                    self.assertEqual(report["status"], "OPEN")
                                    self.assertEqual(
                                        report["issues"][0]["code"],
                                        "safe_file_platform_not_supported",
                                    )
                                    opened.assert_not_called()
            self.assertEqual(sample.read_bytes(), b"synthetic")

    def test_normal_file_and_symbolic_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            self.assertEqual(files.read_local(str(sample)), b"synthetic")
            link = sample.with_name("link.bin")
            link.symlink_to(sample)
            with self.assertRaises(ParseIssue):
                files.read_local(str(link))
            self.assertEqual(sample.read_bytes(), b"synthetic")

    def test_zero_nofollow_cannot_open_symbolic_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            link = sample.with_name("link.bin")
            link.symlink_to(sample)
            with patch.object(files.os, "O_NOFOLLOW", 0):
                with self.assertRaises(ParseIssue) as failure:
                    files.read_local(str(link))
                self.assertEqual(failure.exception.code, "safe_file_platform_not_supported")
                stream = io.StringIO()
                with redirect_stdout(stream):
                    code = cli.main([str(link), "--hive-type", "SOFTWARE"])
                report = json.loads(stream.getvalue())
                self.assertEqual(code, 2)
                self.assertEqual(report["status"], "OPEN")
                self.assertEqual(report["issues"][0]["code"], "safe_file_platform_not_supported")
            self.assertEqual(sample.read_bytes(), b"synthetic")

    def test_support_collections_refuse_api_cli_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            original_open = files.os.open
            dir_fd_support = set(files.os.supports_dir_fd)
            for attribute in ('supports_dir_fd',):
                for value in ("MISSING", None, set(), frozenset(), [], (), {}, True):
                    with self.subTest(attribute=attribute, value=value):
                        with patch.object(files.os, "open", wraps=original_open) as opened:
                            with patch.object(files.os, "supports_dir_fd", dir_fd_support | {opened}):
                                with patch.object(files.os, attribute, value, create=True):
                                    if value == "MISSING":
                                        delattr(files.os, attribute)
                                    with self.assertRaises(ParseIssue) as failure:
                                        files.read_local(str(sample))
                                    self.assertEqual(failure.exception.code, 'safe_file_platform_not_supported')
                                    output = io.StringIO()
                                    with redirect_stdout(output):
                                        exitcode = cli.main([str(sample), "--hive-type", "SOFTWARE"])
                                    self.assertEqual(exitcode, 2)
                                    if output.getvalue():
                                        self.assertEqual(json.loads(output.getvalue())["status"], "OPEN")
                                    opened.assert_not_called()
            self.assertEqual(sample.read_bytes(), b"synthetic")

    def test_normal_set_and_frozenset_support_collections(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            for collection in (set, frozenset):
                with patch.object(files.os, "supports_dir_fd", collection(files.os.supports_dir_fd)):
                    self.assertEqual(files.read_local(str(sample)), b"synthetic")

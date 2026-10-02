import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fixtures import RUN, example
from registry_hive_review.cli import main
from registry_hive_review.files import read_local
from registry_hive_review.model import ParseIssue


class FileCLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.file = self.root / "PRIVATE_PATH_SENTINEL.bin"
        self.raw, _ = example()
        self.file.write_bytes(self.raw)

    def invoke(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(args)
        self.assertEqual(err.getvalue(), "")
        self.assertNotIn("PRIVATE_PATH_SENTINEL", out.getvalue())
        self.assertNotIn(str(self.root), out.getvalue())
        return code, json.loads(out.getvalue())

    def test_exact_bytes_and_input_unchanged(self):
        self.assertEqual(read_local(str(self.file)), self.raw)
        before = hashlib.sha256(self.file.read_bytes()).digest()
        for args in (
            [str(self.file), "--hive-type", "SOFTWARE"],
            [str(self.file), "--hive-type", "SOFTWARE", "--select", RUN + "::Demo"],
            [
                str(self.file),
                "--hive-type",
                "SOFTWARE",
                "--select",
                RUN + "::Demo",
                "--reveal-selected",
            ],
        ):
            code, result = self.invoke(args)
            self.assertEqual(code, 0, result)
        self.assertEqual(hashlib.sha256(self.file.read_bytes()).digest(), before)

    def test_relative_regular_path_without_resolution(self):
        previous = os.getcwd()
        try:
            os.chdir(self.root)
            self.assertEqual(read_local(self.file.name), self.raw)
        finally:
            os.chdir(previous)

    def test_leaf_parent_and_nested_symlinks(self):
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "data").write_bytes(self.raw)
        cases = [
            self.root / "link",
            self.root / "alias" / "data",
            self.root / "one" / "alias" / "data",
        ]
        cases[0].symlink_to(self.file)
        (self.root / "alias").symlink_to(nested, target_is_directory=True)
        (self.root / "one").mkdir()
        (self.root / "one" / "alias").symlink_to(nested, target_is_directory=True)
        for path in cases:
            with self.subTest(path=path), self.assertRaises(ParseIssue):
                read_local(str(path))

    def test_special_files_directory_fifo_socket(self):
        import socket

        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(sock.close)
        sockfile = self.root / "socket"
        sock.bind(str(sockfile))
        for path in (self.root, fifo, sockfile, Path("/dev/null")):
            with self.subTest(path=path), self.assertRaises(ParseIssue):
                read_local(str(path))

    def test_missing_components_unicode_nul_and_dotdot(self):
        cases = [
            str(self.root / "missing"),
            "",
            "/",
            ".",
            "..",
            str(self.root) + "/../x",
            str(self.root) + "//x",
            str(self.root) + "/./x",
            "\0",
            "\ud800",
            "a" * 8193,
        ]
        for path in cases:
            with self.subTest(path=repr(path)), self.assertRaises(ParseIssue):
                read_local(path)
        self.assertEqual(self.invoke([str(self.root / "PRIVATE_PATH_SENTINEL-missing")])[0], 2)

    def test_platform_requires_real_dirfd_support(self):
        with patch("registry_hive_review.files.os.supports_dir_fd", set()):
            with self.assertRaises(ParseIssue) as ctx:
                read_local(str(self.file))
        self.assertEqual(ctx.exception.code, "safe_file_platform_not_supported")

    def test_controlled_short_read(self):
        original = os.read
        calls = []

        def short(fd, size):
            calls.append(fd)
            return original(fd, 1) if len(calls) == 1 else b""

        with patch("registry_hive_review.files.os.read", short):
            with self.assertRaises(ParseIssue) as ctx:
                read_local(str(self.file))
        self.assertEqual(ctx.exception.code, "file_changed_or_short_read")

    def test_every_after_identity_field_and_regular_state(self):
        original = os.fstat
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
        for changed in fields:
            calls = []

            def observed(fd):
                info = original(fd)
                calls.append(fd)
                values = {name: getattr(info, name) for name in fields}
                if len(calls) == 2:
                    values[changed] = stat.S_IFDIR if changed == "st_mode" else values[changed] + 1
                return SimpleNamespace(**values)

            with (
                self.subTest(field=changed),
                patch("registry_hive_review.files.os.fstat", observed),
            ):
                with self.assertRaises(ParseIssue) as ctx:
                    read_local(str(self.file))
                self.assertEqual(ctx.exception.code, "file_changed_or_short_read")

    def test_sparse_byte_limit_before_read(self):
        with self.file.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        with patch(
            "registry_hive_review.files.os.read",
            side_effect=AssertionError("must reject before read"),
        ):
            with self.assertRaises(ParseIssue) as ctx:
                read_local(str(self.file))
        self.assertEqual(ctx.exception.code, "file_not_regular_or_byte_budget")

    def test_arguments_are_sanitized_and_unknown_remains_open(self):
        cases = [
            [],
            [str(self.file), "--hive-type", "PRIVATE_PATH_SENTINEL"],
            [str(self.file), "--PRIVATE_PATH_SENTINEL"],
            [str(self.file), "--select", "PRIVATE_PATH_SENTINEL"],
            [str(self.file), "--hive-type", "SOFTWARE", "--select", "PRIVATE_PATH_SENTINEL::x"],
        ]
        for args in cases:
            code, result = self.invoke(args)
            self.assertEqual(code, 2)
            self.assertEqual(result["status"], "OPEN")
            self.assertEqual(result["evidence"], [])
        self.assertEqual(self.invoke([str(self.file)])[0], 2)

    def test_filename_does_not_establish_hive_type(self):
        misleading = self.root / "SAM"
        misleading.write_bytes(self.raw)
        self.assertEqual(self.invoke([str(misleading), "--hive-type", "SOFTWARE"])[0], 0)
        raw, _ = example(hive_type="SAM")
        self.file.write_bytes(raw)
        self.assertEqual(self.invoke([str(self.file), "--hive-type", "SOFTWARE"])[0], 2)

    def test_no_network_or_execution_import_needed(self):
        with (
            patch("socket.socket", side_effect=AssertionError("network forbidden")),
            patch("subprocess.Popen", side_effect=AssertionError("execution forbidden")),
        ):
            self.assertEqual(self.invoke([str(self.file), "--hive-type", "SOFTWARE"])[0], 0)

import dataclasses
import hashlib
import json
import random
import struct
import unittest

from fixtures import Builder, RUN, STAMP, checksum, example, integer, multi, string
from registry_hive_review import Limits, review
from registry_hive_review.model import ParseIssue, filetime


class Helpers:
    def assert_open(self, raw, code=None, selections=((RUN, "Demo"),), limits=Limits()):
        before = hashlib.sha256(raw).digest()
        result = review(raw, "SOFTWARE", selections, True, limits)
        self.assertEqual(result["status"], "OPEN", result)
        self.assertNotIn('"value":', json.dumps(result))
        self.assertEqual(hashlib.sha256(raw).digest(), before)
        if code:
            self.assertIn(code, [item["code"] for item in result["issues"]])
        return result

    def change(self, raw, offset, value, fmt="<I", header=False):
        data = bytearray(raw)
        integer(data, offset, value, fmt)
        if header:
            checksum(data)
        return bytes(data)


class Structure(Helpers, unittest.TestCase):
    def test_complete_graph_and_offsets(self):
        raw, builder = example()
        result = review(raw, "SOFTWARE", [(RUN, "Demo")], True)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["counts"]["reachable_keys"], 5)
        self.assertEqual(result["counts"]["reachable_values"], 1)
        row = result["evidence"][0]
        self.assertEqual(row["key_cell_offset"], 4096 + builder.offsets[RUN])
        self.assertEqual(row["value_record_offset"], 4100 + builder.offsets[(RUN, "Demo")])
        self.assertEqual(row["value"], '"C:\\Synthetic\\app.exe" --review')
        self.assertEqual(result["input_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(row["key_last_write"]["utc"], "1970-01-01T00:00:00Z")

    def test_all_four_index_forms_and_both_versions(self):
        for minor in (3, 5):
            for index in ("li", "lf", "lh", "ri"):
                for compressed in (True, False):
                    with self.subTest(minor=minor, index=index, compressed=compressed):
                        raw, _ = example(minor=minor, index=index, compressed=compressed)
                        self.assertEqual(review(raw, "SOFTWARE", [(RUN, "Demo")])["status"], "PASS")

    def test_hive_types_and_exact_com_paths(self):
        paths = {
            "SOFTWARE": RUN,
            "NTUSER": "Software\\" + RUN,
            "USRCLASS": "CLSID\\{01234567-89ab-cdef-0123-456789abcdef}\\InprocServer32",
        }
        for kind, path in paths.items():
            builder = Builder(hive_type=kind)
            builder.add(path, "", 1, string("C:\\Synthetic\\component.dll"))
            result = review(builder.build(), kind, [(path, "")], True)
            self.assertEqual(result["status"], "PASS", result)
            self.assertEqual(result["evidence"][0]["value"], "C:\\Synthetic\\component.dll")

    def test_redaction_and_no_full_tree_dump(self):
        builder = Builder()
        builder.add(RUN, "Demo", 1, string("PRIVATE_VALUE_SENTINEL"))
        builder.add("PrivateKeySentinel", "PrivateValueSentinel", 3, b"SECRET_SENTINEL")
        raw = builder.build()
        for chosen in ((), [(RUN, "Demo")]):
            result = review(raw, "SOFTWARE", chosen)
            text = json.dumps(result)
            for private in (
                "PRIVATE_VALUE_SENTINEL",
                "PrivateKeySentinel",
                "PrivateValueSentinel",
                "SECRET_SENTINEL",
            ):
                self.assertNotIn(private, text)
            self.assertEqual(result["status"], "PASS")

    def test_no_type_assertion_and_mismatch_never_decode(self):
        raw, _ = example(data=string("PRIVATE_VALUE_SENTINEL"))
        for kind in (None, "NTUSER", "USRCLASS"):
            selections = (
                [] if kind is None else [("Software\\" + RUN, "Demo")] if kind == "NTUSER" else []
            )
            result = review(raw, kind, selections, True)
            self.assertEqual(result["status"], "OPEN")
            self.assertNotIn("PRIVATE_VALUE_SENTINEL", json.dumps(result))

    def test_sensitive_headers_and_renamed_unknowns(self):
        for kind in ("SAM", "SECURITY", "unknown"):
            builder = Builder(hive_type=kind)
            builder.add(RUN, "Demo", 1, string("PRIVATE_VALUE_SENTINEL"))
            result = review(builder.build(), "SOFTWARE", [(RUN, "Demo")], True)
            self.assertEqual(result["status"], "OPEN")
            self.assertNotIn("PRIVATE_VALUE_SENTINEL", json.dumps(result))

    def test_sensitive_tree_markers_despite_software_header(self):
        for marker in ("SAM", "SECURITY", "Policy", "Domains"):
            builder = Builder()
            builder.add(marker, "Secret", 3, b"PRIVATE_CREDENTIAL_BYTES")
            builder.add(RUN, "Demo", 1, string("PRIVATE_VALUE_SENTINEL"))
            self.assert_open(builder.build(), "sensitive_hive_tree_marker")

    def test_sensitive_root_marker(self):
        builder = Builder()
        builder.root["name"] = "SAM"
        builder.add(RUN, "Demo", 1, string("demo"))
        self.assert_open(builder.build(), "sensitive_hive_tree_marker")

    def test_header_signatures_versions_filetypes_and_clusters(self):
        raw, _ = example()
        for offset, values, expected in [
            (0, [0], "record_signature"),
            (20, [0, 2], "format_version_not_supported"),
            (24, [1, 2, 4, 6], "format_version_not_supported"),
            (28, [1, 2, 6, 99], "transaction_or_file_type_not_supported"),
            (32, [0, 2], "format_or_clustering_not_supported"),
            (44, [0, 2], "format_or_clustering_not_supported"),
        ]:
            for value in values:
                self.assert_open(self.change(raw, offset, value, header=True), expected)

    def test_header_name_encoding_and_embedded_nul(self):
        raw, _ = example()
        for name in (b"\x00\xd8" + bytes(62), "SOFT\0WARE".encode("utf-16le").ljust(64, b"\0")):
            changed = bytearray(raw)
            changed[48:112] = name
            checksum(changed)
            self.assert_open(bytes(changed))

    def test_checksum_and_dirty_suppress_reveal(self):
        raw, _ = example()
        self.assert_open(self.change(raw, 0x1FC, 0), "header_checksum_mismatch")
        result = self.assert_open(self.change(raw, 8, 2, header=True), "dirty_sequence_mismatch")
        self.assertTrue(result["header"]["dirty"])
        self.assertEqual(result["evidence"][0]["status"], "PRESENT_UNVERIFIED_REDACTED")

    def test_checksum_zero_and_allones_edge_cases(self):
        raw, _ = example()
        for target, stored in ((0, 1), (0xFFFFFFFF, 0xFFFFFFFE)):
            changed = bytearray(raw)
            value = 0
            for offset in range(0, 0x1FC, 4):
                value ^= struct.unpack_from("<I", changed, offset)[0]
            integer(changed, 0x100, value ^ target)
            checksum(changed)
            self.assertEqual(struct.unpack_from("<I", changed, 0x1FC)[0], stored)
            self.assertEqual(review(bytes(changed), "SOFTWARE")["status"], "PASS")

    def test_truncated_inputs_at_every_boundary(self):
        raw, _ = example()
        for size in (0, 1, 3, 4, 511, 512, 4095, 4096, 4097, 8191):
            self.assert_open(raw[:size])

    def test_hbin_declared_extent_and_bin_offset(self):
        raw, _ = example()
        for size in (0, 1, 4095, 8192, 0xFFFFFFFF):
            self.assert_open(self.change(raw, 40, size, header=True), "hbin_declared_extent")
        self.assert_open(self.change(raw, 4096 + 4, 1), "hbin_offset_or_size")
        for size in (0, 4095, 8192):
            self.assert_open(self.change(raw, 4096 + 8, size), "hbin_offset_or_size")

    def test_cell_sizes_zero_positive_free_negative_and_alignment(self):
        raw, builder = example()
        offset = 4096 + builder.offsets[""]
        for size in (0, 1, -1, -7, -9, -0x80000000, -8192):
            self.assert_open(self.change(raw, offset, size, "<i"), "cell_size_or_extent")
        size = struct.unpack_from("<i", raw, offset)[0]
        self.assert_open(self.change(raw, offset, -size, "<i"), "reference_to_free_cell")

    def test_root_reference_not_allocated_boundary(self):
        raw, builder = example()
        for pointer in (0, 1, 8192, 0xFFFFFFFF, builder.offsets[""] + 4):
            self.assert_open(
                self.change(raw, 36, pointer, header=True), "reference_not_cell_boundary"
            )

    def test_parent_reference_and_root_flag(self):
        raw, builder = example()
        offset = 4100 + builder.offsets[RUN]
        self.assert_open(self.change(raw, offset + 16, 0), "key_parent_reference")
        self.assert_open(self.change(raw, offset + 2, 36, "<H"), "key_root_flag")
        self.assert_open(
            self.change(raw, offset + 2, 0x21, "<H"), "volatile_link_or_key_flags_not_supported"
        )

    def test_unknown_key_flag_and_volatile_subkey_group(self):
        raw, builder = example()
        root = 4100 + builder.offsets[""]
        self.assert_open(
            self.change(raw, root + 2, 0x1024, "<H"), "volatile_link_or_key_flags_not_supported"
        )
        self.assert_open(self.change(raw, root + 0x18, 1), "volatile_subkeys_not_supported")

    def test_child_index_count_signature_hint_and_hash(self):
        for form in ("li", "lf", "lh", "ri"):
            raw, builder = example(index=form)
            root = 4100 + builder.offsets[""]
            pointer = struct.unpack_from("<I", raw, root + 0x1C)[0]
            listing = 4100 + pointer
            self.assert_open(self.change(raw, root + 0x14, 2), "subkey_index_count_mismatch")
            self.assert_open(self.change(raw, listing, 0, "<H"), "index_signature_not_supported")
            if form in ("lf", "lh"):
                self.assert_open(
                    self.change(raw, listing + 8, 0),
                    "lf_name_hint_mismatch" if form == "lf" else "lh_name_hash_mismatch",
                )
            if form == "ri":
                self.assert_open(self.change(raw, listing + 4, pointer), "index_cycle_or_duplicate")

    def test_key_cycle_and_duplicate_value_pointer(self):
        raw, builder = example()
        root = 4100 + builder.offsets[""]
        listing = 4100 + struct.unpack_from("<I", raw, root + 0x1C)[0]
        self.assert_open(
            self.change(raw, listing + 4, builder.offsets[""]), "key_cycle_or_multiple_parent"
        )
        builder = Builder()
        builder.add(RUN, "A", 4, struct.pack("<I", 1))
        builder.add(RUN, "B", 4, struct.pack("<I", 2))
        raw = builder.build()
        key = 4100 + builder.offsets[RUN]
        listing = 4100 + struct.unpack_from("<I", raw, key + 0x28)[0]
        first = struct.unpack_from("<I", raw, listing)[0]
        self.assert_open(
            self.change(raw, listing + 4, first), "duplicate_value_reference", selections=()
        )

    def test_duplicate_key_and_value_name_ambiguity(self):
        for key_case in (True, False):
            builder = Builder()
            if key_case:
                builder.add("Root\\Run", "A", 4, struct.pack("<I", 1))
                builder.add("Root\\run", "B", 4, struct.pack("<I", 2))
            else:
                builder.add(RUN, "Demo", 4, struct.pack("<I", 1))
                builder.add(RUN, "demo", 4, struct.pack("<I", 2))
            self.assert_open(
                builder.build(),
                "ambiguous_key_name" if key_case else "ambiguous_value_name",
                selections=(),
            )

    def test_cell_role_collision(self):
        raw, builder = example()
        key = 4100 + builder.offsets[RUN]
        self.assert_open(self.change(raw, key + 0x28, builder.offsets[""]), "cell_role_collision")

    def test_unreachable_allocated_cell_is_open(self):
        raw, builder = example()
        changed = bytearray(raw)
        position = 4096 + 32
        while position < len(raw):
            size = struct.unpack_from("<i", raw, position)[0]
            if size > 0:
                break
            position += abs(size)
        integer(changed, position, -8, "<i")
        integer(changed, position + 8, size - 8, "<i")
        self.assert_open(bytes(changed), "unreachable_allocated_cells_not_interpreted")

    def test_security_envelope_links_and_reference_count(self):
        raw, _ = example()
        security = 4100 + 32
        for offset, value, code in [
            (security + 12, 0, "security_envelope"),
            (security + 16, 19, "security_envelope"),
            (security + 16, 0xFFFFFFFF, "record_field_bounds"),
            (security + 4, 0xFFFFFFFF, "reference_not_cell_boundary"),
            (security + 24, 24, "security_descriptor_reference"),
        ]:
            self.assert_open(self.change(raw, offset, value), code)
        self.assert_open(self.change(raw, security + 12, 1), "security_reference_count_mismatch")

    def test_security_neighbor_without_key_is_open(self):
        raw, b = example()
        data = bytearray(raw)
        sk = struct.unpack_from("<I", data, 0x1004 + b.offsets[""] + 0x2C)[0]
        free = 0x1020
        while struct.unpack_from("<i", data, free)[0] < 0:
            free += -struct.unpack_from("<i", data, free)[0]
        size = struct.unpack_from("<i", data, free)[0]
        neighbor = free - 0x1000
        integer(data, free, -48, "<i")
        integer(data, free + 48, size - 48, "<i")
        data[free + 4 : free + 44] = data[0x1004 + sk : 0x102C + sk]
        integer(data, free + 8, sk)
        integer(data, free + 12, sk)
        integer(data, free + 16, 1)
        integer(data, 0x1008 + sk, neighbor)
        integer(data, 0x100C + sk, neighbor)
        self.assert_open(bytes(data), "security_list_member_not_key_referenced")

    def test_type_and_count_and_input_budgets(self):
        raw, builder = example()
        key = 4100 + builder.offsets[RUN]
        self.assert_open(self.change(raw, key + 0x24, 50001), "value_count_budget")
        for field, value in [
            ("file_bytes", 8191),
            ("cells", 1),
            ("bins", 1),
            ("keys", 1),
            ("values", 1),
            ("references", 1),
            ("depth", 1),
        ]:
            limits = dataclasses.replace(Limits(), **{field: value})
            sample = raw
            if field == "values":
                b = Builder()
                b.add(RUN, "A", 4, bytes(4))
                b.add(RUN, "B", 4, bytes(4))
                sample = b.build()
            if field == "bins":
                sample, _ = example(data=string("X" * 10000))
            self.assert_open(sample, limits=limits)

    def test_index_depth_and_issue_budgets(self):
        raw, b = example(index="ri")
        data = bytearray(raw)
        root = 0x1004 + b.offsets[""]
        pointer = struct.unpack_from("<I", data, root + 0x1C)[0]
        free = 0x1020
        while struct.unpack_from("<i", data, free)[0] < 0:
            free += -struct.unpack_from("<i", data, free)[0]
        length = struct.unpack_from("<i", data, free)[0]
        for n in range(2):
            target = free + 16 * n
            integer(data, target, -16, "<i")
            data[target + 4 : target + 12] = struct.pack("<2sHI", b"ri", 1, pointer)
            pointer = target - 0x1000
        integer(data, free + 32, length - 32, "<i")
        integer(data, root + 0x1C, pointer)
        self.assertEqual(
            review(bytes(data), "SOFTWARE", limits=dataclasses.replace(Limits(), index_depth=3))[
                "status"
            ],
            "PASS",
        )
        self.assert_open(
            bytes(data), "index_depth_budget", limits=dataclasses.replace(Limits(), index_depth=1)
        )
        data = bytearray(raw)
        integer(data, 8, 2)
        self.assert_open(
            bytes(data), "issue_budget", limits=dataclasses.replace(Limits(), issues=1)
        )

    def test_class_name_utf16_and_shared_owner(self):
        raw, b = example()
        data = bytearray(raw)
        key = 0x1004 + b.offsets[RUN]
        free = 0x1020
        while struct.unpack_from("<i", data, free)[0] < 0:
            free += -struct.unpack_from("<i", data, free)[0]
        length = struct.unpack_from("<i", data, free)[0]
        integer(data, free, -16, "<i")
        integer(data, free + 16, length - 16, "<i")
        data[free + 4 : free + 12] = "Class"[:4].encode("utf-16le")
        integer(data, key + 0x30, free - 0x1000)
        integer(data, key + 0x4A, 8, "<H")
        self.assertEqual(review(bytes(data), "SOFTWARE")["status"], "PASS")
        self.assert_open(self.change(bytes(data), key + 0x4A, 7, "<H"), "utf16_odd_length")
        self.assert_open(self.change(bytes(data), key + 0x4A, 4097, "<H"), "class_name_budget")
        self.assert_open(self.change(bytes(data), key + 0x30, b.offsets[""]), "cell_role_collision")

    def test_exact_tree_depth_boundary(self):
        builder = Builder()
        builder.add("One\\Two", "Demo", 4, bytes(4))
        raw = builder.build()
        self.assertEqual(
            review(raw, "SOFTWARE", limits=dataclasses.replace(Limits(), depth=2))["status"], "PASS"
        )
        self.assert_open(
            raw,
            "key_count_or_depth_budget",
            selections=(),
            limits=dataclasses.replace(Limits(), depth=1),
        )

    def test_invalid_api_limits_and_inputs(self):
        raw, _ = example()
        for data in (None, "raw", bytearray(raw), memoryview(raw)):
            self.assertEqual(review(data, "SOFTWARE")["status"], "OPEN")
        for limits in (
            None,
            {},
            dataclasses.replace(Limits(), file_bytes=-1),
            dataclasses.replace(Limits(), report_bytes="bad"),
            dataclasses.replace(Limits(), depth=True),
            dataclasses.replace(Limits(), report_bytes=1),
            dataclasses.replace(Limits(), cells=100001),
        ):
            self.assertEqual(review(raw, "SOFTWARE", limits=limits)["status"], "OPEN")
        self.assertEqual(review(raw, "SOFTWARE", reveal="yes")["status"], "OPEN")

    def test_report_budget_does_not_return_prefix_clean(self):
        raw, _ = example()
        self.assert_open(
            raw, "report_budget", limits=dataclasses.replace(Limits(), report_bytes=256)
        )

    def test_zero_and_overflow_and_submicrosecond_time(self):
        self.assertEqual(filetime(0, 0)["status"], "UNSET")
        row = filetime(STAMP + 9, 0)
        self.assertEqual(row["utc"], "1970-01-01T00:00:00Z")
        self.assertEqual(row["submicrosecond_nanoseconds"], 900)
        with self.assertRaises(ParseIssue):
            filetime(0xFFFFFFFFFFFFFFFF, 123)
        raw, builder = example()
        root = 4100 + builder.offsets[""]
        self.assert_open(self.change(raw, root + 4, 0xFFFFFFFFFFFFFFFF, "<Q"), "filetime_range")

    def test_zero_trailing_blocks_and_nonzero_or_partial_rejection(self):
        raw, _ = example()
        self.assertEqual(review(raw + bytes(4096), "SOFTWARE")["status"], "PASS")
        self.assert_open(raw + b"\0", "trailing_data_not_supported")
        self.assert_open(raw + bytes(4095) + b"X", "trailing_data_not_supported")

    def test_fixed_random_malformed_smoke(self):
        raw, _ = example()
        rng = random.Random(20261002)
        for number in range(500):
            sample = bytearray(raw)
            for _ in range(3):
                sample[rng.randrange(len(sample))] = rng.randrange(256)
            result = review(bytes(sample), "SOFTWARE")
            self.assertIn(result["status"], ("PASS", "OPEN"))
            self.assertEqual(result["evidence"], [])
            self.assertLessEqual(len(json.dumps(result).encode()), 1024 * 1024)


class TypedValues(Helpers, unittest.TestCase):
    # Independent expected values, not a call back to the production decoder.
    def test_all_supported_types_and_inline_external_storage(self):
        cases = [
            (1, string("plain"), "plain"),
            (1, string(""), ""),
            (2, string("%TEMP%\\sample.exe"), "%TEMP%\\sample.exe"),
            (1, string("合成 😀"), "合成 😀"),
            (7, multi(["first", "second"]), ["first", "second"]),
            (7, multi([]), []),
            (7, b"\0\0", []),
            (4, bytes.fromhex("78563412"), 0x12345678),
            (5, bytes.fromhex("12345678"), 0x12345678),
            (11, bytes.fromhex("0807060504030201"), 0x0102030405060708),
        ]
        for kind, data, expected in cases:
            for inline in [True, False] if len(data) <= 4 else [False]:
                builder = Builder()
                builder.add(RUN, "Demo", kind, data, inline)
                result = review(builder.build(), "SOFTWARE", [(RUN, "Demo")], True)
                self.assertEqual(result["status"], "PASS", result)
                self.assertEqual(result["evidence"][0]["value"], expected)

    def test_segmented_large_and_standard_direct_values(self):
        for minor in (3, 5):
            raw, builder = example(data=string("X" * 10000), minor=minor)
            result = review(raw, "SOFTWARE", [(RUN, "Demo")], True)
            self.assertEqual(result["status"], "PASS", result)
            self.assertEqual(result["evidence"][0]["value"], "X" * 10000)
            self.assertEqual(len(result["evidence"][0]["data_extents"]), 2 if minor == 5 else 1)

    def test_db_count_list_segment_references_and_lengths(self):
        raw, builder = example(data=string("X" * 10000))
        data = builder.data_offsets[(RUN, "Demo")]
        db, listing = 4100 + data["db"], 4100 + data["list"]
        self.assert_open(self.change(raw, db + 2, 3, "<H"), "large_data_segment_count")
        self.assert_open(self.change(raw, db + 4, 0xFFFFFFFF), "reference_not_cell_boundary")
        self.assert_open(
            self.change(raw, listing + 4, data["segments"][0]), "large_data_duplicate_segment"
        )
        self.assert_open(self.change(raw, listing, 0xFFFFFFFF), "reference_not_cell_boundary")
        last = 4096 + data["segments"][-1]
        length = abs(struct.unpack_from("<i", raw, last)[0])
        self.assert_open(self.change(raw, last, length, "<i"), "reference_to_free_cell")

    def test_inline_length_storage_and_unsupported_selected_type(self):
        raw, builder = example(kind=4, data=bytes(4))
        value = 4100 + builder.offsets[(RUN, "Demo")]
        self.assert_open(self.change(raw, value + 4, 0x80000005), "inline_value_size")
        for kind in (0, 3, 6, 8, 9, 10, 16, 0x100, 0xFFFFFFFF):
            self.assert_open(self.change(raw, value + 12, kind), "selected_value_type_not_decoded")

    def test_integer_lengths_and_value_flags(self):
        for kind, size in [(4, 3), (4, 8), (5, 1), (5, 8), (11, 4), (11, 12)]:
            self.assert_open(example(kind=kind, data=bytes(size))[0], "integer_size")
        raw, builder = example()
        value = 4100 + builder.offsets[(RUN, "Demo")]
        self.assert_open(self.change(raw, value + 16, 2, "<H"), "value_flags_not_supported")

    def test_string_termination_and_encoding_are_not_repaired(self):
        for raw, code in [
            (b"X", "utf16_odd_length"),
            (b"\x00\xd8\0\0", "utf16_encoding"),
            ("no terminator".encode("utf-16le"), "string_termination"),
            (string("A\0B"), "string_embedded_nul"),
            (b"", "string_termination"),
        ]:
            self.assert_open(example(data=raw)[0], code)
        for raw, code in [
            (string("one"), "multi_string_termination"),
            (multi(["a", "", "b"]), "multi_string_empty_component"),
        ]:
            self.assert_open(example(kind=7, data=raw)[0], code)

    def test_key_value_name_codepages_nuls_and_unicode_mapping(self):
        raw, builder = example()
        value = 4100 + builder.offsets[(RUN, "Demo")]
        data = bytearray(raw)
        data[value + 20] = 0x80
        self.assert_open(bytes(data), "compressed_name_codepage_not_supported")
        data[value + 20] = 0
        self.assert_open(bytes(data), "name_nul_or_key_separator")
        builder = Builder(compressed=False)
        builder.add(RUN, "合成", 1, string("PRIVATE_VALUE_SENTINEL"))
        self.assert_open(builder.build(), "windows_unicode_name_case_mapping_open", selections=())

    def test_case_insensitive_ascii_selection_and_missing_evidence(self):
        raw, _ = example()
        result = review(raw, "SOFTWARE", [(RUN.lower(), "DEMO")], True)
        self.assertEqual(result["evidence"][0]["status"], "PRESENT_UNAUTHENTICATED")
        result = review(raw, "SOFTWARE", [(RUN, "absent"), (RUN + "Once", "Demo")])
        self.assertEqual([r["status"] for r in result["evidence"]], ["NOT_PRESENT", "NOT_PRESENT"])

    def test_selection_allowlist_shape_limits_and_nonascii(self):
        raw, _ = example()
        for selections in [
            None,
            {},
            ["x"],
            [("x", "y", "z")],
            [("SAM\\Domains", "F")],
            [(RUN, "Demo")] * 2,
            [(RUN, "合成")],
            [(RUN, "A\0B")],
            [(RUN + "\\..", "Demo")],
            [(RUN, "x" * 513)],
            [(RUN, "Demo")] * 17,
        ]:
            self.assertEqual(review(raw, "SOFTWARE", selections, True)["status"], "OPEN")
        for kind in ("SAM", "SECURITY", "SYSTEM", "SETTINGS", "software", "UNKNOWN", 1):
            self.assertEqual(review(raw, kind)["status"], "OPEN")

    def test_selected_byte_and_value_budget(self):
        raw, _ = example(data=string("X" * 10000))
        self.assert_open(
            raw, "selected_value_budget", limits=dataclasses.replace(Limits(), selected_bytes=100)
        )
        self.assert_open(
            raw, "value_data_budget", limits=dataclasses.replace(Limits(), value_bytes=100)
        )


if __name__ == "__main__":
    unittest.main()

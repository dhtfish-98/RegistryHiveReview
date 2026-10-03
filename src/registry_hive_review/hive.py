"""Independent REGF/HBIN allocation and reachable key/value structure review."""

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
import struct

from .model import DEFAULT_LIMITS, ParseIssue, check_limits, filetime
from .selection import TYPES, validate_selection
from .values import TYPE_NAMES, decode, utf16


NIL = 0xFFFFFFFF
SEGMENT = 0x3FD8


@dataclass(frozen=True)
class Cell:
    offset: int
    size: int
    allocated: bool


class View:
    def __init__(self, data, offset, length):
        self.data, self.offset, self.length = data, offset, length

    def raw(self, offset, length):
        if offset < 0 or length < 0 or offset + length > self.length:
            raise ParseIssue("record_field_bounds", self.offset + max(offset, 0))
        return self.data[self.offset + offset : self.offset + offset + length]

    def number(self, offset, fmt):
        raw = self.raw(offset, struct.calcsize(fmt))
        return struct.unpack(fmt, raw)[0]

    def u16(self, offset):
        return self.number(offset, "<H")

    def u32(self, offset):
        return self.number(offset, "<I")

    def u64(self, offset):
        return self.number(offset, "<Q")

    def signature(self, expected):
        if bytes(self.raw(0, len(expected))) != expected:
            raise ParseIssue("record_signature", self.offset)


class Hive:
    def __init__(self, data, limits):
        self.raw = data
        self.data = memoryview(data)
        self.limits = limits
        self.cells = {}
        self.roles = {}
        self.issues = []
        self.references = 0
        self.keys = {}
        self.values_count = 0
        self.security = {}
        self.types = Counter()
        self.bins = 0
        self.declared_type = None
        self.header = {}

    def issue(self, code, offset=None):
        if len(self.issues) >= self.limits.issues:
            raise ParseIssue("issue_budget", offset)
        self.issues.append({"code": code, "offset": offset})

    def name(self, view, offset, length, compressed, key=False):
        if length > ((255 if compressed else 510) if key else 1024):
            raise ParseIssue("name_budget", view.offset + offset)
        raw = view.raw(offset, length)
        if compressed:
            try:
                name = bytes(raw).decode("ascii", "strict")
            except UnicodeError:
                raise ParseIssue(
                    "compressed_name_codepage_not_supported", view.offset + offset
                ) from None
        else:
            name = utf16(raw, view.offset + offset)
        if "\0" in name or (key and (not name or "\\" in name)):
            raise ParseIssue("name_nul_or_key_separator", view.offset + offset)
        if not name.isascii():
            self.issue("windows_unicode_name_case_mapping_open", view.offset + offset)
        return name

    def reference(self, pointer, role, owner):
        self.references += 1
        absolute = 0x1000 + pointer
        if self.references > self.limits.references:
            raise ParseIssue("reference_budget", absolute)
        cell = self.cells.get(absolute)
        if cell is None:
            raise ParseIssue("reference_not_cell_boundary", absolute)
        if not cell.allocated:
            raise ParseIssue("reference_to_free_cell", absolute)
        previous = self.roles.get(absolute)
        if previous and previous[0] != role:
            raise ParseIssue("cell_role_collision", absolute)
        if previous and role != "security" and previous[1] != owner:
            raise ParseIssue("cell_shared_reference_not_supported", absolute)
        self.roles[absolute] = (role, owner)
        return View(self.data, absolute + 4, cell.size - 4)

    def parse_header(self):
        if len(self.data) < 0x1000:
            raise ParseIssue("header_truncated", 0)
        v = View(self.data, 0, 0x1000)
        v.signature(b"regf")
        major, minor = v.u32(0x14), v.u32(0x18)
        if major != 1 or minor not in (3, 5):
            raise ParseIssue("format_version_not_supported", 0x14)
        self.minor = minor
        if v.u32(0x1C) != 0:
            raise ParseIssue("transaction_or_file_type_not_supported", 0x1C)
        if v.u32(0x20) != 1 or v.u32(0x2C) != 1:
            raise ParseIssue("format_or_clustering_not_supported", 0x20)
        name = utf16(v.raw(0x30, 64), 0x30)
        name = name.rstrip("\0")
        if "\0" in name:
            raise ParseIssue("header_name_embedded_nul", 0x30)
        basename = name.replace("/", "\\").rsplit("\\", 1)[-1].lower()
        if basename in ("sam", "security"):
            raise ParseIssue("sensitive_hive_declared", 0x30)
        self.declared_type = next(
            (kind for kind, value in TYPES.items() if value == basename), None
        )
        checksum = 0
        for offset in range(0, 0x1FC, 4):
            checksum ^= v.u32(offset)
        checksum = 1 if checksum == 0 else 0xFFFFFFFE if checksum == NIL else checksum
        good = checksum == v.u32(0x1FC)
        dirty = v.u32(4) != v.u32(8)
        self.header = {
            "major": major,
            "minor": minor,
            "declared_type": self.declared_type,
            "type_identity": "OPEN",
            "checksum_matches": good,
            "dirty": dirty,
            "sequence_primary": v.u32(4),
            "sequence_secondary": v.u32(8),
            "last_write": filetime(v.u64(0xC), 0xC),
            "root_cell_offset": 0x1000 + v.u32(0x24),
        }
        if not good:
            self.issue("header_checksum_mismatch", 0x1FC)
        if dirty:
            self.issue("dirty_sequence_mismatch", 4)
        if v.u32(0x90) not in (0, 1):
            self.issue("header_flags_not_supported", 0x90)
        size = v.u32(0x28)
        if size < 0x1000 or size % 0x1000 or 0x1000 + size > len(self.data):
            raise ParseIssue("hbin_declared_extent", 0x28)
        self.end = size + 0x1000
        extra = self.data[self.end :]
        if len(extra) % 0x1000 or any(extra):
            raise ParseIssue("trailing_data_not_supported", self.end)
        self.header["trailing_zero_bytes"] = len(extra)
        self.root_pointer = v.u32(0x24)

    def allocation(self):
        position = 0x1000
        while position < self.end:
            self.bins += 1
            if self.bins > self.limits.bins:
                raise ParseIssue("hbin_budget", position)
            v = View(self.data, position, self.end - position)
            v.signature(b"hbin")
            size = v.u32(8)
            if (
                v.u32(4) != position - 0x1000
                or size < 0x1000
                or size % 0x1000
                or position + size > self.end
            ):
                raise ParseIssue("hbin_offset_or_size", position + 4)
            finish, cell_position = position + size, position + 0x20
            while cell_position < finish:
                if len(self.cells) >= self.limits.cells:
                    raise ParseIssue("cell_budget", cell_position)
                signed = struct.unpack_from("<i", self.data, cell_position)[0]
                length = abs(signed)
                if length < 8 or length % 8 or cell_position + length > finish:
                    raise ParseIssue("cell_size_or_extent", cell_position)
                self.cells[cell_position] = Cell(cell_position, length, signed < 0)
                cell_position += length
            position = finish

    def index(self, pointer, owner, depth=0, seen=None):
        if depth > self.limits.index_depth:
            raise ParseIssue("index_depth_budget", 0x1000 + pointer)
        seen = set() if seen is None else seen
        if pointer in seen:
            raise ParseIssue("index_cycle_or_duplicate", 0x1000 + pointer)
        seen.add(pointer)
        v = self.reference(pointer, "index", owner)
        signature = bytes(v.raw(0, 2))
        count = v.u16(2)
        if count > self.limits.keys:
            raise ParseIssue("index_count_budget", v.offset + 2)
        stride = 8 if signature in (b"lf", b"lh") else 4
        if signature not in (b"ri", b"li", b"lf", b"lh"):
            raise ParseIssue("index_signature_not_supported", v.offset)
        v.raw(4, count * stride)
        references = []
        for number in range(count):
            start = 4 + number * stride
            child = v.u32(start)
            if signature == b"ri":
                references.extend(self.index(child, owner, depth + 1, seen))
            else:
                hint = bytes(v.raw(start + 4, 4)) if stride == 8 else None
                references.append((child, signature, hint, v.offset + start))
            if len(references) > self.limits.keys:
                raise ParseIssue("index_flattened_budget", v.offset)
        return references

    def security_record(self, pointer, owner):
        v = self.reference(pointer, "security", owner)
        if pointer in self.security:
            self.security[pointer][1] += 1
            return
        v.signature(b"sk")
        v.raw(0, 20)
        previous, following, count, size = v.u32(4), v.u32(8), v.u32(12), v.u32(16)
        if count == 0 or size < 20:
            raise ParseIssue("security_envelope", v.offset + 12)
        descriptor = v.raw(20, size)
        if descriptor[0] != 1 or not struct.unpack_from("<H", descriptor, 2)[0] & 0x8000:
            raise ParseIssue("security_descriptor_envelope", v.offset + 20)
        for relative in struct.unpack_from("<IIII", descriptor, 4):
            if relative and (relative < 20 or relative % 4 or relative >= size):
                raise ParseIssue("security_descriptor_reference", v.offset + 24)
        self.security[pointer] = [count, 1]
        for other, field in ((previous, 8), (following, 4)):
            neighbor = self.reference(other, "security", owner)
            neighbor.signature(b"sk")
            if neighbor.u32(field) != pointer:
                raise ParseIssue("security_link_reciprocity", neighbor.offset + field)

    def storage(self, v, owner):
        encoded = v.u32(4)
        size, inline = encoded & 0x7FFFFFFF, bool(encoded & 0x80000000)
        if size > self.limits.value_bytes:
            raise ParseIssue("value_data_budget", v.offset + 4)
        if inline:
            if size > 4:
                raise ParseIssue("inline_value_size", v.offset + 4)
            return [(v.offset + 8, size)]
        if size == 0:
            return []
        pointer = v.u32(8)
        if self.minor == 5 and size > SEGMENT:
            block = self.reference(pointer, "large_data_header", owner)
            block.signature(b"db")
            count = block.u16(2)
            if count != (size + SEGMENT - 1) // SEGMENT:
                raise ParseIssue("large_data_segment_count", block.offset + 2)
            indirect = self.reference(block.u32(4), "large_data_list", owner)
            indirect.raw(0, 4 * count)
            pieces, visited, remaining = [], set(), size
            for number in range(count):
                segment_pointer = indirect.u32(number * 4)
                if segment_pointer in visited:
                    raise ParseIssue("large_data_duplicate_segment", indirect.offset + number * 4)
                visited.add(segment_pointer)
                segment = self.reference(segment_pointer, "value_data", owner)
                take = min(remaining, SEGMENT)
                segment.raw(0, take)
                pieces.append((segment.offset, take))
                remaining -= take
            return pieces
        data = self.reference(pointer, "value_data", owner)
        data.raw(0, size)
        return [(data.offset, size)]

    def value_records(self, key, pointer):
        count = key.u32(0x24)
        if count > self.limits.values or self.values_count + count > self.limits.values:
            raise ParseIssue("value_count_budget", key.offset + 0x24)
        if not count:
            return {}
        values = self.reference(key.u32(0x28), "values_list", pointer)
        values.raw(0, count * 4)
        result, offsets = {}, set()
        for number in range(count):
            target = values.u32(number * 4)
            if target in offsets:
                raise ParseIssue("duplicate_value_reference", values.offset + number * 4)
            offsets.add(target)
            v = self.reference(target, "value", pointer)
            v.signature(b"vk")
            v.raw(0, 20)
            flags = v.u16(16)
            if flags & ~1:
                raise ParseIssue("value_flags_not_supported", v.offset + 16)
            name = self.name(v, 20, v.u16(2), bool(flags & 1))
            identity = name.lower() if name.isascii() else name
            if identity in result:
                raise ParseIssue("ambiguous_value_name", v.offset + 20)
            kind = v.u32(12)
            pieces = self.storage(v, target)
            size = v.u32(4) & 0x7FFFFFFF
            if kind in (4, 5, 11) and size != (8 if kind == 11 else 4):
                raise ParseIssue("integer_size", v.offset + 4)
            self.types[kind] += 1
            result[identity] = {
                "type": kind,
                "offset": v.offset,
                "cell_offset": v.offset - 4,
                "byte_length": size,
                "pieces": pieces,
            }
            self.values_count += 1
        return result

    def traversal(self):
        stack = [(self.root_pointer, (), None, None)]
        visited, paths = set(), set()
        while stack:
            pointer, path, parent, hint_info = stack.pop()
            if pointer in visited:
                raise ParseIssue("key_cycle_or_multiple_parent", 0x1000 + pointer)
            if (
                len(visited) >= self.limits.keys
                or len(path) + int(parent is not None) > self.limits.depth
            ):
                raise ParseIssue("key_count_or_depth_budget", 0x1000 + pointer)
            visited.add(pointer)
            v = self.reference(pointer, "key", parent)
            v.signature(b"nk")
            v.raw(0, 0x4C)
            flags = v.u16(2)
            if flags & ~(4 | 8 | 0x20):
                raise ParseIssue("volatile_link_or_key_flags_not_supported", v.offset + 2)
            if bool(flags & 4) != (parent is None):
                raise ParseIssue("key_root_flag", v.offset + 2)
            if parent is not None and v.u32(0x10) != parent:
                raise ParseIssue("key_parent_reference", v.offset + 0x10)
            name = self.name(v, 0x4C, v.u16(0x48), bool(flags & 0x20), key=True)
            if (parent is None and name.lower() in ("sam", "security")) or (
                len(path) == 0
                and parent is not None
                and name.lower() in ("sam", "security", "policy", "domains")
            ):
                raise ParseIssue("sensitive_hive_tree_marker", v.offset + 0x4C)
            if parent is not None:
                path += (name,)
            identity = tuple(part.lower() if part.isascii() else part for part in path)
            if identity in paths:
                raise ParseIssue("ambiguous_key_name", v.offset + 0x4C)
            paths.add(identity)
            if hint_info:
                signature, hint, source = hint_info
                if name.isascii() and signature == b"lh":
                    hash_value = 0
                    for character in name.upper():
                        hash_value = (hash_value * 37 + ord(character)) & NIL
                    if int.from_bytes(hint, "little") != hash_value:
                        raise ParseIssue("lh_name_hash_mismatch", source + 4)
                elif name.isascii() and signature == b"lf":
                    expected = name[:4].encode("ascii").ljust(4, b"\0")
                    if hint.lower() != expected.lower():
                        raise ParseIssue("lf_name_hint_mismatch", source + 4)
            timestamp = filetime(v.u64(4), v.offset + 4)
            self.security_record(v.u32(0x2C), pointer)
            class_length = v.u16(0x4A)
            if class_length:
                if class_length > 4096:
                    raise ParseIssue("class_name_budget", v.offset + 0x4A)
                class_data = self.reference(v.u32(0x30), "class_name", pointer)
                utf16(class_data.raw(0, class_length), class_data.offset)
            values = self.value_records(v, pointer)
            self.keys[identity] = {
                "offset": v.offset,
                "cell_offset": v.offset - 4,
                "last_write": timestamp,
                "values": values,
            }
            if v.u32(0x18):
                raise ParseIssue("volatile_subkeys_not_supported", v.offset + 0x18)
            count = v.u32(0x14)
            if count > self.limits.keys:
                raise ParseIssue("subkey_count_budget", v.offset + 0x14)
            if count:
                children = self.index(v.u32(0x1C), pointer)
                if len(children) != count:
                    raise ParseIssue("subkey_index_count_mismatch", v.offset + 0x14)
                for child, signature, hint, offset in reversed(children):
                    stack.append((child, path, pointer, (signature, hint, offset)))
                if len(stack) > self.limits.keys:
                    raise ParseIssue("key_pending_budget", v.offset)
        for pointer, (declared, observed) in self.security.items():
            if declared != observed:
                self.issue("security_reference_count_mismatch", 0x1004 + pointer + 12)
        if any(
            role == "security" and offset - 0x1000 not in self.security
            for offset, (role, _) in self.roles.items()
        ):
            self.issue("security_list_member_not_key_referenced")
        unreachable = sum(
            cell.allocated and offset not in self.roles for offset, cell in self.cells.items()
        )
        if unreachable:
            self.issue("unreachable_allocated_cells_not_interpreted")

    def selected(self, selections, reveal):
        evidence = []
        for path, name in selections:
            key = self.keys.get(tuple(part.lower() for part in path.split("\\")))
            row = {"selected_key": path, "selected_value": name, "status": "NOT_PRESENT"}
            if key is not None:
                row.update(
                    key_cell_offset=key["cell_offset"],
                    key_record_offset=key["offset"],
                    key_last_write=key["last_write"],
                )
                value = key["values"].get(name.lower())
                if value is not None:
                    row.update(
                        status="PRESENT_REDACTED",
                        value_cell_offset=value["cell_offset"],
                        value_record_offset=value["offset"],
                        byte_length=value["byte_length"],
                        type_code=value["type"],
                        type_name=TYPE_NAMES.get(value["type"], "UNKNOWN"),
                        data_extents=[
                            {"offset": offset, "length": length}
                            for offset, length in value["pieces"]
                        ],
                    )
                    if self.issues:
                        row["status"] = "PRESENT_UNVERIFIED_REDACTED"
                        evidence.append(row)
                        continue
                    try:
                        if value["byte_length"] > self.limits.selected_bytes:
                            raise ParseIssue("selected_value_budget", value["offset"] + 4)
                        raw = b"".join(
                            self.raw[offset : offset + size] for offset, size in value["pieces"]
                        )
                        decoded = decode(
                            value["type"],
                            raw,
                            value["pieces"][0][0] if value["pieces"] else value["offset"] + 8,
                        )
                        row["decoded_type"] = (
                            "integer"
                            if type(decoded) is int
                            else "strings"
                            if type(decoded) is list
                            else "string"
                        )
                        if reveal:
                            row.update(status="PRESENT_UNAUTHENTICATED", value=decoded)
                    except ParseIssue as error:
                        self.issue(error.code, error.offset)
                        row["status"] = "OPEN"
            evidence.append(row)
        # An incomplete, dirty or unsupported review never reveals a raw value.
        if self.issues:
            for row in evidence:
                row.pop("value", None)
                if row["status"] in ("PRESENT_REDACTED", "PRESENT_UNAUTHENTICATED"):
                    row["status"] = "PRESENT_UNVERIFIED_REDACTED"
                elif row["status"] == "NOT_PRESENT":
                    row["status"] = "OPEN_NOT_OBSERVED"
        return evidence


def review(data, hive_type=None, selections=(), reveal=False, limits=DEFAULT_LIMITS):
    """Review immutable local hive bytes; selections are (allowlisted path, name).

    PASS means this finite allocation/tree/type profile passed. Source/hive
    identity, Windows runtime behavior and applicant qualification stay OPEN.
    """
    result = {
        "schema_version": 1,
        "status": "OPEN",
        "issues": [],
        "evidence": [],
        "hive_identity": "OPEN",
        "value_authenticity": "OPEN",
        "windows_runtime": "OPEN",
        "unselected_value_content": "NOT_DECODED",
        "security_descriptor_semantics": "OPEN",
        "transaction_recovery": "NOT_IMPLEMENTED",
        "cvp_eligibility": "OPEN",
        "implementation_author": "dhtfish98",
    }
    hive = None
    report_limit = DEFAULT_LIMITS.report_bytes
    try:
        check_limits(limits)
        report_limit = limits.report_bytes
        if type(data) is not bytes or len(data) > limits.file_bytes:
            raise ParseIssue("input_type_or_byte_budget")
        if type(reveal) is not bool:
            raise ParseIssue("reveal_type")
        selections = validate_selection(hive_type, selections, limits)
        result["input_sha256"] = sha256(data).hexdigest()
        result["input_bytes"] = len(data)
        hive = Hive(data, limits)
        hive.parse_header()
        result["header"] = hive.header
        if hive_type is None:
            hive.issue("hive_type_assertion_required")
        elif hive.declared_type != hive_type:
            hive.issue("unknown_or_mismatched_hive_declaration", 0x30)
        hive.allocation()
        hive.traversal()
        result["evidence"] = hive.selected(selections, reveal)
        result["status"] = "OPEN" if hive.issues else "PASS"
    except ParseIssue as error:
        if hive is not None:
            hive.issues = hive.issues[: max(0, limits.issues - 1)]
            hive.issues.append({"code": error.code, "offset": error.offset})
        else:
            result["issues"] = [{"code": error.code, "offset": error.offset}]
        result["evidence"] = []
    if hive is not None:
        result["issues"] = hive.issues
        result["counts"] = {
            "hbins": hive.bins,
            "cells": len(hive.cells),
            "allocated_cells": sum(c.allocated for c in hive.cells.values()),
            "reachable_keys": len(hive.keys),
            "reachable_values": hive.values_count,
            "references": hive.references,
            "types": dict(sorted(hive.types.items())),
        }
    encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
    if len(encoded.encode()) > report_limit:
        return {
            "schema_version": 1,
            "status": "OPEN",
            "issues": [{"code": "report_budget", "offset": None}],
            "evidence": [],
            "hive_identity": "OPEN",
            "cvp_eligibility": "OPEN",
            "implementation_author": "dhtfish98",
        }
    return result

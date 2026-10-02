"""Strict selected value decoding; no expansion, links or execution."""

import struct

from .model import ParseIssue


TYPE_NAMES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}


def utf16(raw, offset):
    if len(raw) % 2:
        raise ParseIssue("utf16_odd_length", offset)
    try:
        return bytes(raw).decode("utf-16le", "strict")
    except UnicodeError:
        raise ParseIssue("utf16_encoding", offset) from None


def decode(kind, raw, offset):
    if kind in (4, 5, 11):
        size = 8 if kind == 11 else 4
        if len(raw) != size:
            raise ParseIssue("integer_size", offset)
        return struct.unpack({4: "<I", 5: ">I", 11: "<Q"}[kind], raw)[0]
    if kind in (1, 2, 7):
        text = utf16(raw, offset)
        if kind == 7:
            if text in ("\0", "\0\0"):
                return []
            if not text.endswith("\0\0"):
                raise ParseIssue("multi_string_termination", offset)
            items = text[:-2].split("\0")
            if any(not item for item in items):
                raise ParseIssue("multi_string_empty_component", offset)
            return items
        if not text.endswith("\0"):
            raise ParseIssue("string_termination", offset)
        text = text[:-1]
        if "\0" in text:
            raise ParseIssue("string_embedded_nul", offset)
        return text
    raise ParseIssue("selected_value_type_not_decoded", offset)

"""Only explicit finite persistence-key and value selections are accepted."""

import re

from .model import ParseIssue


TYPES = {"SOFTWARE": "software", "NTUSER": "ntuser.dat", "USRCLASS": "usrclass.dat"}
BASE = "Microsoft\\Windows\\CurrentVersion\\"
RUN_SUFFIXES = ("Run", "RunOnce", "Policies\\Explorer\\Run")
GUID = re.compile(
    r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}"
)


def permitted(path, hive_type):
    lowered = path.lower()
    prefixes = {"SOFTWARE": ("", "WOW6432Node\\"), "NTUSER": ("Software\\",), "USRCLASS": ()}.get(
        hive_type, ()
    )
    if any(
        lowered == (prefix + BASE + suffix).lower()
        for prefix in prefixes
        for suffix in RUN_SUFFIXES
    ):
        return True
    com_prefix = {
        "SOFTWARE": "Classes\\CLSID\\",
        "NTUSER": "Software\\Classes\\CLSID\\",
        "USRCLASS": "CLSID\\",
    }.get(hive_type)
    if com_prefix and lowered.startswith(com_prefix.lower()):
        pieces = path[len(com_prefix) :].split("\\")
        return (
            len(pieces) == 2
            and GUID.fullmatch(pieces[0]) is not None
            and pieces[1].lower() in ("inprocserver32", "localserver32")
        )
    return False


def validate_selection(hive_type, selections, limits):
    if hive_type is not None and (type(hive_type) is not str or hive_type not in TYPES):
        raise ParseIssue("hive_type_not_supported")
    if type(selections) not in (list, tuple) or len(selections) > limits.selections:
        raise ParseIssue("selection_budget_or_type")
    chosen, seen = [], set()
    for item in selections:
        if type(item) not in (list, tuple) or len(item) != 2:
            raise ParseIssue("selection_shape")
        path, name = item
        if (
            type(path) is not str
            or type(name) is not str
            or not path.isascii()
            or len(path) > 512
            or len(name) > 512
            or any(ord(c) < 32 or ord(c) == 127 for c in path + name)
            or any(0xD800 <= ord(c) <= 0xDFFF for c in name)
        ):
            raise ParseIssue("selection_encoding_or_size")
        # Unicode Windows upcase tables are outside this profile.
        if not name.isascii() or not permitted(path, hive_type):
            raise ParseIssue("selection_outside_allowlist")
        identity = (path.lower(), name.lower())
        if identity in seen:
            raise ParseIssue("duplicate_selection")
        seen.add(identity)
        chosen.append((path, name))
    return chosen

"""Fixed bounds, error locations and integer FILETIME evidence."""

from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone


class ParseIssue(Exception):
    def __init__(self, code, offset=None):
        self.code = code
        self.offset = offset
        super().__init__(code)


@dataclass(frozen=True)
class Limits:
    file_bytes: int = 64 * 1024 * 1024
    cells: int = 100_000
    bins: int = 4096
    keys: int = 10_000
    values: int = 50_000
    references: int = 250_000
    depth: int = 96
    index_depth: int = 32
    value_bytes: int = 1024 * 1024
    selected_bytes: int = 32 * 1024
    selections: int = 16
    issues: int = 64
    report_bytes: int = 1024 * 1024


DEFAULT_LIMITS = Limits()


def check_limits(limits):
    if type(limits) is not Limits:
        raise ParseIssue("limits_type")
    for field in fields(Limits):
        value = getattr(limits, field.name)
        if type(value) is not int or not 0 < value <= getattr(DEFAULT_LIMITS, field.name):
            raise ParseIssue("limits_range")
    if limits.report_bytes < 256:
        raise ParseIssue("minimum_report_budget")


def filetime(ticks, offset):
    if ticks == 0:
        return {"ticks_100ns": 0, "status": "UNSET", "utc": None}
    try:
        stamp = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
    except OverflowError:
        raise ParseIssue("filetime_range", offset) from None
    return {
        "ticks_100ns": ticks,
        "status": "DECODED_UNAUTHENTICATED",
        "utc": stamp.isoformat().replace("+00:00", "Z"),
        "submicrosecond_nanoseconds": (ticks % 10) * 100,
    }

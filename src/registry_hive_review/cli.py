"""Local hive review with sanitized machine-readable diagnostics."""

import argparse
import json

from .files import read_local
from .hive import review
from .model import ParseIssue


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ParseIssue("arguments")


def main(argv=None):
    parser = Parser(
        description="Review a local primary Registry hive and explicit persistence value selections."
    )
    parser.add_argument("file")
    parser.add_argument("--hive-type", choices=("SOFTWARE", "NTUSER", "USRCLASS"))
    parser.add_argument("--select", action="append", default=[], metavar="KEY::VALUE")
    parser.add_argument("--reveal-selected", action="store_true")
    try:
        args = parser.parse_args(argv)
        selections = []
        if len(args.select) > 16:
            raise ParseIssue("selection_budget_or_type")
        for item in args.select:
            path, separator, name = item.partition("::")
            if not separator:
                raise ParseIssue("selection_shape")
            selections.append((path, name))
        result = review(read_local(args.file), args.hive_type, selections, args.reveal_selected)
    except (ParseIssue, OSError, ValueError, UnicodeError) as error:
        code = error.code if isinstance(error, ParseIssue) else "input_error"
        result = {
            "schema_version": 1,
            "status": "OPEN",
            "issues": [{"code": code, "offset": None}],
            "evidence": [],
            "hive_identity": "OPEN",
            "cvp_eligibility": "OPEN",
            "ai_assisted": True,
        }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 2

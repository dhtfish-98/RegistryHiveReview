"""Test-only fixed upstream oracle; never imported by the public library/CLI."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))


def main():
    from fixtures import Builder, RUN, example, multi, string
    from registry_hive_review import review

    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    audit = json.loads((ROOT / "项目文档/SOURCE_AUDIT.json").read_text())
    before = {}
    for row in audit["selected_full_files"]:
        raw = (args.source / row["path"]).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        blob = hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False
        ).hexdigest()
        assert digest == row["sha256"] and blob == row["git_blob"], row["path"]
        before[row["path"]] = digest
    sys.path.insert(0, str(args.source.resolve()))
    from Registry import Registry

    cases = []
    rows = [
        (1, string("Synthetic value")),
        (2, string("%SYNTHETIC%\\app.exe")),
        (7, multi(["alpha", "beta"])),
        (11, struct.pack("<Q", 0xFEDCBA9876543210)),
        (4, struct.pack("<I", 0x12345678)),
        (1, string("")),
        (7, multi([])),
    ]
    for minor in (3, 5):
        for index in ("li", "lf", "lh", "ri"):
            for compressed in (False, True):
                for kind, data in rows:
                    raw, _ = example(
                        kind=kind, data=data, minor=minor, index=index, compressed=compressed
                    )
                    cases.append((raw, "SOFTWARE", RUN, "Demo"))
            raw, _ = example(data=string("A" * 10000), minor=minor, index=index)
            cases.append((raw, "SOFTWARE", RUN, "Demo"))
    for kind, path in [
        ("SOFTWARE", RUN),
        ("NTUSER", "Software\\" + RUN),
        ("USRCLASS", "CLSID\\{01234567-89ab-cdef-0123-456789abcdef}\\InprocServer32"),
    ]:
        builder = Builder(hive_type=kind)
        builder.add(path, "", 1, string("C:\\Synthetic\\component.dll"))
        cases.append((builder.build(), kind, path, ""))
    for raw, kind, path, name in cases:
        digest = hashlib.sha256(raw).hexdigest()
        result = review(raw, kind, [(path, name)], True)
        assert result["status"] == "PASS", result["issues"]
        old = Registry.Registry(io.BytesIO(raw))
        key = old.open(path)
        value = key.value(name if name else "(default)")
        expected = value.value()
        if value.value_type() == 7:
            while expected and expected[-1] == "":
                expected.pop()
        row = result["evidence"][0]
        assert row["value"] == expected, (kind, value.value_type())
        assert row["type_code"] == value.value_type()
        assert row["value_record_offset"] == value._vkrecord.offset()
        assert row["key_record_offset"] == key._nkrecord.offset()
        assert row["key_last_write"]["utc"] == key.timestamp().isoformat() + "Z"
        pending = [old.root()]
        count = 0
        while pending:
            current = pending.pop()
            count += 1
            pending.extend(current.subkeys())
        assert result["counts"]["reachable_keys"] == count
        assert hashlib.sha256(raw).hexdigest() == digest
    assert all(
        hashlib.sha256((args.source / path).read_bytes()).hexdigest() == digest
        for path, digest in before.items()
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "cases": len(cases),
                "upstream_commit": audit["commit"],
                "source_files_unchanged": len(before),
                "fixture_hashes_unchanged": True,
                "compared": ["selected value", "type", "key/value offsets", "time", "tree count"],
                "normalization": "REG_MULTI_SZ terminal separator empty entries only",
                "excluded": "Malformed input, unknown types, external short <=4-byte values including DWORD, all big-endian DWORD source paths, Unicode Windows name casing, log recovery. Independent expected-value tests cover both DWORD storage forms and endian orders.",
            }
        )
    )


if __name__ == "__main__":
    main()

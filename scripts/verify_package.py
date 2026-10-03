"""Verify trusted locally built artifacts; no archive extraction or project execution."""

from email import policy
import argparse
import base64
import csv
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import tomllib
import zipfile


def verify(root, installed=None):
    config = tomllib.loads((root / "pyproject.toml").read_text())
    wheels, sdists = list((root / "dist").glob("*.whl")), list((root / "dist").glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1
    modules = [
        p
        for p in (root / "src").rglob("*")
        if p.is_file()
        and (p.suffix == ".py" or p.name == "py.typed")
        and "__pycache__" not in p.parts
        and not any(x.endswith(".egg-info") for x in p.parts)
    ]
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names))
        record = next(n for n in names if n.endswith(".dist-info/RECORD"))
        rows = list(csv.reader(io.StringIO(archive.read(record).decode())))
        assert set(n for n, _, _ in rows) == set(names)
        for name, expected, size in rows:
            data = archive.read(name)
            if name == record:
                assert not expected and not size
            else:
                encoded = (
                    base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
                )
                assert expected == "sha256=" + encoded and len(data) == int(size), name
        metadata = BytesParser(policy=policy.default).parsebytes(
            archive.read(next(n for n in names if n.endswith(".dist-info/METADATA")))
        )
        assert metadata.get("Name") == config["project"]["name"]
        assert metadata.get("Version") == config["project"]["version"]
        assert metadata.get("License-Expression") == config["project"]["license"]
        assert sorted(metadata.get_all("Requires-Dist", [])) == sorted(
            config["project"].get("dependencies", [])
        )
        for path in modules:
            relative = path.relative_to(root / "src")
            assert archive.read(relative.as_posix()) == path.read_bytes(), relative
            if installed is not None:
                assert (installed / relative).read_bytes() == path.read_bytes(), relative
        licenses = metadata.get_all("License-File", [])
        expected_license_paths = sorted(
            {
                p.relative_to(root).as_posix()
                for pattern in config["project"]["license-files"]
                for p in root.glob(pattern)
                if p.is_file()
            }
        )
        assert expected_license_paths
        assert sorted(licenses) == expected_license_paths
        for relative in licenses:
            suffix = ".dist-info/licenses/" + relative
            name = next(n for n in names if n.endswith(suffix))
            assert archive.read(name) == (root / relative).read_bytes()
    matched = 0
    with tarfile.open(sdists[0], "r:gz") as archive:
        seen = set()
        for member in archive.getmembers():
            parts = PurePosixPath(member.name).parts
            assert parts and not member.name.startswith("/") and ".." not in parts
            assert not any(x in (".git", ".venv", ".consumer", "__pycache__") for x in parts)
            assert member.name not in seen
            seen.add(member.name)
            assert member.isdir() or member.isfile()
            relative = Path(*parts[1:])
            source = root / relative
            if member.isfile() and source.is_file():
                assert archive.extractfile(member).read() == source.read_bytes(), relative
                matched += 1
        for module in modules:
            assert any(n.endswith("/" + module.relative_to(root).as_posix()) for n in seen)
        for license_path in expected_license_paths:
            assert any(n.endswith("/" + license_path) for n in seen)
    return {
        "project": root.name,
        "status": "PASS",
        "wheel_RECORD_rows": len(rows),
        "runtime_files": len(modules),
        "runtime_matches_installed": installed is not None,
        "sdist_local_source_files_matched": matched,
        "license_files_match": licenses,
        "artifacts": [
            {
                "path": str(p),
                "bytes": p.stat().st_size,
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            }
            for p in [wheels[0], sdists[0]]
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--installed", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = verify(args.root, args.installed)
    if args.out:
        args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))

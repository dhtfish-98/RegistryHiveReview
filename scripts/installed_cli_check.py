"""Exercise the installed CLI from a separate working directory, using synthetic hives."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))


def main():
    from fixtures import RUN, example
    import registry_hive_review

    assert ROOT / "src" not in Path(registry_hive_review.__file__).parents
    binary = Path(sys.executable).parent / "registry-hive-review"
    with tempfile.TemporaryDirectory() as name:
        folder = Path(name).resolve()
        sample = folder / "PRIVATE_INPUT_PATH.bin"
        raw, _ = example()
        sample.write_bytes(raw)
        before = hashlib.sha256(sample.read_bytes()).hexdigest()
        cases = [
            ([str(sample), "--hive-type", "SOFTWARE"], 0),
            ([str(sample), "--hive-type", "SOFTWARE", "--select", RUN + "::Demo"], 0),
            (
                [
                    str(sample),
                    "--hive-type",
                    "SOFTWARE",
                    "--select",
                    RUN + "::Demo",
                    "--reveal-selected",
                ],
                0,
            ),
            ([str(sample)], 2),
            ([str(folder / "PRIVATE_INPUT_PATH_MISSING")], 2),
            ([str(sample), "--UNKNOWN_PRIVATE_ARGUMENT"], 2),
        ]
        for args, expected in cases:
            child = subprocess.run(
                [str(binary), *args],
                cwd=folder,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert child.returncode == expected and not child.stderr
            result = json.loads(child.stdout)
            assert "PRIVATE_INPUT_PATH" not in child.stdout and str(folder) not in child.stdout
            assert "UNKNOWN_PRIVATE_ARGUMENT" not in child.stdout
            assert result["status"] == ("PASS" if expected == 0 else "OPEN")
        assert before == hashlib.sha256(sample.read_bytes()).hexdigest()
    print(
        json.dumps(
            {
                "status": "PASS",
                "CLI_cases": len(cases),
                "input_unchanged": True,
                "installed_module": str(registry_hive_review.__file__),
            }
        )
    )


if __name__ == "__main__":
    main()

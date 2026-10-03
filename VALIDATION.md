# Current validation — 0.1.1

The 2026-10-03 attribution update identifies the new implementation author and maintainer as dhtfish98. The final wheel and sdist were rebuilt, and a fresh isolated consumer ran **61 existing and targeted unittest methods successfully**, imported the installed package from site-packages, exercised the declared CLI contract and matched every shipped runtime/notice byte to current source. Wheel metadata records author dhtfish98 and version 0.1.1; RECORD and source-distribution contents were checked. Current runtime identities are in SOURCE_MANIFEST.json; ATTRIBUTION_UPDATE.json records the exact selected validation scope. The matching private build/install/test logs and artifact hashes are retained in the batch validation records, outside this public project.

One functional change in this update rejects missing, non-positive or non-integer safe-file flags before opening input. API/CLI regressions cover missing, None, invalid, zero and boolean flags, plus regular files and symbolic links.

The current safe-file capability gate also requires set/frozenset directory-relative support declarations containing each actually used operation before opening input. Missing, None, empty, malformed or operation-incomplete collections yield the existing controlled unsupported result. Normal set/frozenset declarations and API/CLI rejection-before-open are regression tested.

## Historical validation evidence

The following earlier records retain their original versions, counts and fixed source identities. They are historical observations, not evidence that an old artifact is the current package.

# Validation and boundaries

Local verification uses Python 3.14.6 on macOS. The 56 independent test methods pass;
this includes 16 positive index/version/name-encoding combinations, all three hive
profiles, selected empty/typed strings and both DWORD byte orders/storage forms,
20-KiB multi-HBIN direct/segmented values, and 500 fixed-seed malformed mutations.

Focused negatives cover header signatures/types/versions/checksum/dirty state, HBIN
extent, signed cell size/allocation, out-of-bound/free/nonboundary references, cycles,
DAG/duplicate names/values, LI/LF/LH/RI hints and counts, SK envelopes/list reciprocity/
reference counts/orphan neighbors, value inline/direct/DB storage, strict UTF-16/NUL/
termination rules, timestamps and every declared budget. File/CLI tests exercise held
no-follow parents and leaf, directory/FIFO/socket/device rejection, sparse size refusal,
short read, all observed identity fields, missing paths, unknown arguments and privacy.
No network socket or subprocess is required by public runtime review.

```sh
python -m pip install -r requirements-dev.txt
PYTHONPATH=src python -m unittest discover -s tests -v
ruff check src tests scripts
ruff format --check src tests scripts
python -m build --no-isolation
python -m venv .install-check
.install-check/bin/python -m pip install --no-index --no-deps dist/registry_hive_review-0.1.0-py3-none-any.whl
.install-check/bin/python -m pip check
# Run from a separate directory, with these absolute project/tool paths:
/path/to/.install-check/bin/python -I -m unittest discover -s /path/to/RegistryHiveReview/tests -v
/path/to/.install-check/bin/python -I /path/to/RegistryHiveReview/scripts/installed_cli_check.py
/path/to/.install-check/bin/python -I /path/to/RegistryHiveReview/scripts/verify_package.py /path/to/RegistryHiveReview --installed /path/to/consumer/site-packages
```

`scripts/verify_package.py` checks every wheel RECORD row, metadata/dependencies,
complete license file bytes, all runtime files against source and installed files,
and source archive identity/path/regular-file boundaries. Synthetic tests contain no
real hive or identifiers, and local environments/evidence files are excluded.

Test-only upstream differential reproduction:

```sh
PYTHONPATH=src python scripts/differential_check.py /path/to/verified/python-registry
```

It first verifies the 11 exact source SHA256/Git blob identities, then compares 123
complete synthetic hives' selected value, type, key/value byte positions, timestamp
and reachable tree count. It verifies input and fixed source remain unchanged.
MULTI_SZ terminal separator empty entries are the only output normalization. Known
source limitations for external <=4-byte values, big-endian DWORD, malformed inputs,
Unicode Windows name casing, unsupported types and recovery are outside the differential
domain. New endian/storage cases have explicit independent expected-value tests.
Differential agreement does not prove every Windows hive or runtime behavior.

The CI matrix repeats source tests/build and isolated installed tests, CLI and artifact
validation on Python 3.11/3.14, Linux/macOS. Exact-commit remote CI, remote source identity
and publication must be observed separately by the parent publication task. This local
record does not claim those remote gates passed. Real Windows Registry load/access,
real forensic datasets, complete ACL or Unicode case semantics, source authenticity
and CVP qualification remain OPEN.

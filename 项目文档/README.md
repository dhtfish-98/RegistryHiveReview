> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# RegistryHiveReview

Current implementation author and maintainer: **dhtfish98**. Current package version: **0.1.2**. Upstream authors and reused components retain their original attribution.


An offline, read-only Python library and CLI for a bounded primary Windows Registry hive
profile. It traverses actual REGF, HBIN, allocated/free cells, NK keys, four child-index
forms, VK values, data cells, and version-1.5 segmented large data. It reports checksum,
sequence, graph, type, encoding, FILETIME and numeric byte-offset evidence.

`PASS` means the documented finite structure/type profile completed. It does not prove
that a hive or selected value is authentic, that unselected value content is valid,
that a command is safe, or that Windows would load the hive. Those questions remain
`OPEN`. CVP eligibility and evidence of a human applicant's contribution remain `OPEN`.
Implementation author: dhtfish98; provenance is recorded in [ORIGIN.md](<ORIGIN.md>).

## Use

Python 3.11 or newer, POSIX with directory-relative no-follow file opening; no runtime
dependencies. Install the locally built wheel with `pip install registry_hive_review-0.1.2-py3-none-any.whl`.

```sh
registry-hive-review /trusted/local/SOFTWARE --hive-type SOFTWARE \
  --select 'Microsoft\Windows\CurrentVersion\Run::Demo'
```

The default report redacts the selected value. Add `--reveal-selected` to explicitly
include a supported, selected value after the entire finite review has passed. A
single dirty, damaged, unknown or unsupported structure/selected value suppresses
**all** decoded values. Exit status is 0 for profile PASS and 2 for OPEN. Invalid
arguments and file errors produce fixed JSON issue codes without echoing source
paths, arbitrary hive names, key names, bytes or exception messages.

```python
from registry_hive_review import Limits, review

result = review(
    immutable_bytes,              # exact bytes; the library does not open or alter files
    hive_type="SOFTWARE",          # caller assertion plus untrusted internal header declaration
    selections=[("Microsoft\\Windows\\CurrentVersion\\Run", "Demo")],
    reveal=False,
    limits=Limits(selected_bytes=4096),
)
```

The caller assertion and internal header name are **untrusted declarations**. They
cannot authenticate the hive's type. File naming is never used for classification.
Known SAM/SECURITY declarations or sensitive root markers are refused. An unknown,
missing or mismatched declaration stays OPEN and never enables selected value decoding.

Explicit selections permit only Run, RunOnce, Policies\Explorer\Run paths for SOFTWARE
(and its WOW6432Node alternative) or NTUSER, and a specific GUID beneath the applicable
Classes\CLSID path ending InprocServer32 or LocalServer32. USRCLASS allows the latter
CLSID selection. Value names are explicit bounded ASCII selections; there are no
wildcards, arbitrary paths or full-tree dumps. Reports echo only validated caller
selections and numeric source locations. Revealed strings can contain private data;
only harmless synthetic examples are committed.

See [DEFENSIVE_SCOPE.md](<DEFENSIVE_SCOPE.md>) for the precise parsing profile, input
and privacy limits, [VALIDATION.md](<VALIDATION.md>) for reproducible checks, and
[SOURCE_AUDIT.json](<../SOURCE_AUDIT.json>) for fixed-source identities.

Type and string-termination rules reference Microsoft's
[Registry value types](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types).
FILETIME ticks use the documented [100-nanosecond, 1601 UTC epoch](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime).
The primary independent format reference is libyal's
[REGF format documentation](https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc).
These references are not claims of Windows runtime compatibility or source authenticity.

Safe file input requires positive integer `O_NOFOLLOW`, `O_DIRECTORY` and `O_NONBLOCK` flags and the directory-relative operations used by this reader. A missing, zero or invalid capability returns `OPEN` with `safe_file_platform_not_supported` before input is opened. The supported and tested file-reader platforms are macOS and Linux; native Windows file reading is not validated by these checks.

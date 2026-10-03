# Finite defensive scope

Primary hive versions 1.3 and 1.5 only; declared SOFTWARE, NTUSER.DAT and USRCLASS.DAT.
No SAM/SECURITY, credentials, SYSTEM hive, settings.dat composites, live Registry APIs,
transaction logs, recovery/patching, process launch, environment expansion, linked
key following or any write to the input. A renamed or maliciously labeled hive
cannot be authenticated by static header/root observations; type identity stays OPEN.

The parser checks the primary 4096-byte header, checksum edge cases, sequence state,
format/file type/clustering, declared HBIN extent and whole zero trailing pages.
Each HBIN's relative offset, alignment and size is checked. Every cell is indexed
by its signed, eight-byte-aligned allocation length within one HBIN. References must
target exact allocated cell boundaries with compatible roles and ownership.
NK trees are traversed without recursive key walking. Parent/root flags, duplicate
paths and values, DAG/cycles, volatile/link flags, values lists, LI/LF/LH/RI indexes,
ASCII hints/hashes and counts are checked. Bounded RI recursion handles index lists.
Unreachable allocated cells or SK neighbors without a key reference remain OPEN.

SK list reciprocity, key reference counts, self-relative security-descriptor envelope
and internal offset bounds are checked. SID/ACL layout, access control, permissions
and policy meanings are not interpreted and remain OPEN. Header/record reserved fields
and inactive zero-count pointers are not a complete Windows implementation.

VK metadata and inline/external lengths are checked across the reachable tree. Large
version-1.5 data requires the DB header, exact segment count, list and distinct allocated
segments at the 0x3FD8 boundary; version 1.3 permits bounded direct data. Unselected
raw values are not decoded or reported: `unselected_value_content=NOT_DECODED`.
Only selected REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, DWORD little/big endian and QWORD
can be decoded. Binary, link, resource, unknown and composite selected types stay OPEN.
String termination is required, UTF-16 is strict, and internal NULs/odd bytes/unpaired
surrogates are never repaired. Empty SZ and empty MULTI_SZ are supported. Nonempty
MULTI_SZ requires a double terminator and no empty interior component. Environment
variables and command strings remain literal, unauthenticated evidence.

Compressed names support ASCII only. UTF-16 names are checked structurally; any non-ASCII
name makes the overall profile OPEN because Windows Unicode upcase tables are not
implemented. Some valid Windows hives may contain non-ASCII compressed names, lone
surrogates, permissive strings, unsupported flags or stale allocated records. Such
profile exclusions are not claims that the source is invalid or malicious.

FILETIME uses integer ticks from 1601 UTC; reports retain the sub-microsecond remainder,
zero as UNSET, and reject unrepresentable dates. A valid timestamp is unauthenticated.
Source positions are zero-based byte offsets in the original immutable file; extents
exclude cell size words and represent the exact selected payload pieces.

Default limits, reducible through exact `Limits` values, are 64 MiB input, 4096 HBINs,
100,000 cells, 10,000 keys, 50,000 values, 250,000 references, key depth 96, RI depth
32, 1 MiB per value, 32 KiB per selected value, 16 selections, 64 issues, and 1 MiB
JSON report. The minimum report budget is 256 bytes. Parsing, issues and report exhaustion
produce OPEN without any partial clean result or revealed value.

The CLI requires POSIX O_NOFOLLOW, O_DIRECTORY and true os.open dir_fd support. All
components are opened through held directories; symlinks, dot/dot-dot/empty components,
directories, FIFOs, sockets and devices are refused. Reads are bounded and compare
before/after device, inode, size, mtime, ctime, regular-file state and exact byte count.
This is an observation on held descriptors, not an atomic filesystem snapshot or
proof that a pathname remains unchanged afterward.

Default reports contain SHA256, numeric counts/offsets, fixed issue codes, enum types,
untrusted timestamps and validated caller selectors. Arbitrary source paths, unselected
names/content and exception messages are absent. Explicit reveal can disclose selected
strings and should be used only with authorized local evidence. No real hive data,
identifiers, credentials, private keys, network input or execution are shipped.

PASS applies only to the selected finite structural/type profile; input authenticity,
type identity, ACL semantics, unselected content, Windows behavior, maliciousness,
researcher credentials and CVP qualification remain separate OPEN questions.

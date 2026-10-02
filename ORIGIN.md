# Origin and contribution

The selected design source is [williballenthin/python-registry](https://github.com/williballenthin/python-registry/tree/e649a288b8c62e341eee4a6b95a1337a41c1c163),
commit `e649a288b8c62e341eee4a6b95a1337a41c1c163`. Full selected-file review covers
Registry.py, RegistryParse.py, SettingsParse.py, package initialization, build metadata,
README, original license, RegistryLog.py, and the relevant dump/timeline/transaction
sample tests. The 11 full files' byte sizes, SHA256 and Git blob identities are in
SOURCE_AUDIT.json. This is not a full-repository audit.

The new runtime is independent Python code with no python-registry dependency,
copy of its runtime, or wrapper around its parser. Its contribution is a bounded
allocation ledger and typed reference graph, caller-selected persistence evidence,
strict encodings and data storage checks, stable no-follow regular-file reads,
redaction with whole-review failure propagation, numeric offsets and explicit OPEN
states. Tests construct full synthetic primary hives. Test-only differential checks
load verified fixed upstream files only for a declared supported domain.

The original parser includes permissive string repair, unbounded reads, broad value
and AppContainer decoding, and separate recovery paths. Those behaviors are not
carried into this project. New strict checks are a finite defensive profile, and
profile refusal does not by itself prove a Windows hive is corrupt or malicious.

The original Apache-2.0 text and its named copyright notices are retained. The
complete independent SettingsParse MIT header is retained as well, even though
AppContainer composite types are excluded. libyal's format documentation is a
reference; its prose and implementation are not redistributed.

Implementation, documentation and validation were created with AI assistance.
Human originality, usage history, legitimate research work, safeguards-impact
records, CVP eligibility and approval must be established separately and remain OPEN.

# Protected documents, complex workbook context, inode identity and power lifecycle

**Lifecycle update:** [CHECKPOINT_LIFECYCLE.md](CHECKPOINT_LIFECYCLE.md) describes the separate stopped-restore/explicit-resume API and the 1904 TEXT correction. The earlier withdrawn automatic-continuation experiment below remains a historical boundary, not the new contract. Check the latest release receipt for installed qualification.

This stage extends the local operator implementation; it does not change cloud/workspace/tunnel bindings. The exact implementation, installed artifact, test attempts and qualification limits belong to the dated receipt. Do not infer that a tested S5 shutdown is a removal of AC/battery power, or that a compatible CRIU experiment is an arbitrary application migration service.

## Inode-preserving API versus atomic replacement

`binary_patch_inode` is a separate Linux-only operation: it applies a same-size 1..65536-byte patch under a version/hash-bound transaction identity. Callers must explicitly acknowledge non-atomic visibility. It retains the existing inode, every hard-link alias and already-open descriptors. All aliases see the change; this is not confined to one pathname. Ordinary `binary_write`/upload still provide atomic pathname publication and do not silently split hard links.

A private fsynced recovery record precedes mutation and binds inode/device, old/new patch bytes, metadata and fingerprints. Exact replay returns the verified committed result; status and explicit recovery do not blindly overwrite unrelated later changes. Only existing account authority is used. Owner-controlled special mode bits require the separate `preserve_special_bits` acknowledgement. Immutable flags and executable capability attributes remain refused. Recoverable in-place mutation does not imply atomic visibility to concurrent readers or arbitrary power-loss consistency.

## Protected PDF native tool

`pdf_security` is compiled and registered, with local and explicit configured-host paths. Actions are `inspect`, `encrypt_copy`, `decrypt_copy` and `append_metadata`. Source/output fingerprints are mandatory where applicable. Protection changes use a distinct output and preserve the original source.

Passwords are paths to private, singly linked, owner-controlled files, never raw tool parameters. A remote password file is read only through a bounded private-file transport that checks ownership, mode and link count, and is briefly materialized as a private parser temporary file. It is not included in tool results or audit values. This is trusted-account processing; it is not an assertion that a compromised parser cannot read memory.

AES-256 encrypted copies require explicit output user/owner password files. Decrypted copies of protected PDFs require the owner password; a merely valid user password is sufficient to inspect but not to change protection. Real credentials are never needed for qualification: fixtures use synthetic passwords passed through stdin and removed afterward.

Detached CMS signatures are checked against the actual `/ByteRange` content with a verified gap and OpenSSL cryptographic integrity verification. This does **not** establish certificate trust, revocation status, trusted signing time or DocMDP certification compliance. An explicitly acknowledged unsigned metadata revision uses an incremental append, keeps the entire original byte prefix, and verifies that old signature byte hashes/integrity remain unchanged. The newest revision is reported as unsigned. Certified modifications are refused, as are encryption rewrites that would invalidate signed input. No old signature is represented as signing changed content.

## Complex workbook calculation context

`worksheet_recalculate` now supports static global and worksheet-scoped names, including local-over-global shadowing, nested absolute ranges and constants. Names are expanded only for compilation; source name and formula XML are retained. Relative names without an explicit origin, external references, executable names and cycles are refused.

Shared formula masters and followers are resolved using their declared range and relative/absolute reference rules. Source shared-formula encoding remains untouched. Fixed array formulas with explicit bounded result ranges are supported; dependent cells read calculated array elements, missing output cache cells are created in ordered worksheet XML, and results must match the declared shape. Unbounded dynamic spills, conflicting overlaps and malformed shared masters fail without publication.

The 1904 date system uses isolated date-serial argument/result adapters for supported date functions, with the 1462-day epoch offset applied to serials rather than to durations or text. Compiler bindings are restored afterward so a later 1900 workbook is unaffected. Cross-sheet, named, shared, fixed-array and date cases have independent expected-value tests. The formula engine is not Microsoft Excel, and unsupported features, volatile functions, data tables, external workbooks and macros are not silently evaluated.

## Power lifecycle evidence

The guarded X230 S5 test verifies host identity, absence of business workloads/containers and any existing RTC alarm, and enabled recovery services. Before shutdown it proves a controller-originated magic packet reaches the target wired interface, temporarily arms WOL and an independent RTC alarm, pauses only the idle runner and repeats the workload check. It requests `systemctl poweroff`, observes loss of SSH, then verifies a changed kernel boot ID and automatic recovery services. Original WOL settings and the unused RTC alarm are restored afterward.

This qualifies S5 shutdown/startup on that physical machine, not G3 power removal. No independent mechanism for removing and restoring both AC and battery power has been verified. The main qian-qi controller computer remains in concurrent interactive/business use and has not been physically rebooted in this stage. Neither simulated boot identities nor another host's reboot are substituted for that claim.

## Transparent process-state experiments and shipping boundary

Prior pinned CRIU experiments on X230 genuinely preserved random process memory, unread anonymous-pipe bytes, numeric PID/UID and output offsets without application checkpoint code. A separate external-pipe experiment preserved state while explicitly remapping drained owner-controlled endpoints. These are compatible same-host Linux cases, not arbitrary graphics, network peers or DC's unowned internal buffers.

A new authenticated MCP checkpoint experiment successfully inspected a process, rejected a stale identity, captured real CRIU images and restored the same PID/memory, but its restored process retained the stop state used during capture. Automatic continuation did not pass. A requested lifecycle correction was denied by the session safety check and was not retried through another route. Only the exact disposable restored process was explicitly resumed for cleanup; its original memory and unread-pipe hashes then matched and it exited normally. That cleanup is not reported as a successful automatic native lifecycle.

The unqualified `process_checkpoint` registration was withdrawn from the production tool router and compiled module. Experiment source is retained under `experiments/native_checkpoint/` with the failed native acceptance receipt for review, not enabled in the installed service. No host checkpoint configuration or new sudo entitlement is installed. Do not advertise this as a production arbitrary-PID migration API.

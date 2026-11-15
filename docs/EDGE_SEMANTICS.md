# Edge semantics: inode identity, real process checkpoints and protected documents

**Latest capability update:** [PROTECTED_AND_COMPLEX_PARITY.md](PROTECTED_AND_COMPLEX_PARITY.md) documents the native protected-PDF, complex-workbook and inode APIs, S5 hardware qualification and the withdrawn experimental checkpoint boundary. Prior stage limitations below remain historical snapshots; installation is established only by its exact receipt.
This continuation extends the tested local contract. It does not declare incompatible semantics equivalent. ChatGPT/workspace/tunnel configuration remains outside this stage.

## Native inode-preserving changes

`binary_patch_inode` adds a Linux-only, explicit, same-size patch of 1..65536 bytes. Unlike atomic pathname replacement, it retains the original inode, every hard-link alias and existing open-file descriptions. The caller supplies the expected file version and full SHA256, a transaction ID, the byte offset and replacement bytes, and `acknowledge_non_atomic: true`. This acknowledgement is a real contract: concurrent readers may see an intermediate patch, and modifying an inode affects all its aliases, including aliases not named in the request. It is not path-isolated editing.

The normal atomic `binary_write`/upload path remains unchanged and still refuses to split hard links silently. Applications choose atomic publication of a new inode or explicit in-place identity preservation; the API never presents one as both.

A private fsynced recovery receipt is written before in-place mutation. It binds the device/inode, original fingerprint, request identity, patch bytes and metadata. Replayed committed requests verify the result rather than writing again. `status` reports current/expected fingerprints. `recover` recognizes complete writes or restores only the known partial patch when all unrelated content is unchanged. Conflicting content, ownership, link count or unexpected rights changes require explicit operator reconciliation rather than blindly overwriting later changes. Receipts contain original patch bytes and metadata and therefore must stay private; they are not public logs.

The same inode preserves Linux ACL/xattrs and ownership. Special mode bits require `preserve_special_bits: true` and may only be restored under the caller's existing OS authority, on an inode the caller owns. Tests use ordinary user-owned mode 06750 fixtures, not root-owned privileged executables. Immutable flags and executable capability attributes remain rejected. No sudoers, PAM, kernel setting or entitlement is added by the tool.

Tests include held-open descriptors and hard-link aliases, exact retries, stale requests, retained special mode bits/ACLs, a partial write, real subprocess exit after data fsync but before the commit receipt, and safe refusal of unrelated subsequent edits. This is recoverable in-place mutation, not all-reader atomicity or a promise about arbitrary power-loss storage behavior.

## CRIU: real memory and descriptor restoration

The dedicated X230 experiment builds upstream CRIU v4.2.1 at pinned commit `9539417f3e3cfa4eb84c319cd71f4d52f1f08645`, using existing root authorization only for kernel checkpoint/restore calls. The binary stays in a versioned source directory. No kernel/PAM/sysctl policy is changed. Missing build libraries are installed as additive packages without upgrading the operating system or restarting business services. `criu check` is a prerequisite, not the acceptance result.

The actual acceptance starts an ordinary Python interpreter that has no application checkpoint/resume code. The program holds random memory, a numeric local value and unread anonymous-pipe bytes. CRIU dumps the live process, the original exits, and CRIU restores it with the same PID and UID. Matching random-state and unread-pipe hashes, the numeric state, one-time startup marker and the stdout file offset establish actual kernel/process-state restoration rather than reconstruction from an application journal.

A separate external-pipe test starts the application with stdin/stdout owned by another process, drains the old visible output, checkpoints it, and explicitly supplies new pipe endpoints on restore. Its accumulated value and random memory survive, and subsequent input produces the expected new output. The bridge duplicates standard descriptors before passing them to CRIU and uses the exact upstream `pipe:[inode]` resource identifier. Prior failed attempts and reconciliation of the same checkpoint are retained.

These are same-host Linux qualifications of disposable processes, not an installed native arbitrary-PID checkpoint API. The program, libraries, mounts, kernel features and external resources must be compatible. In-flight external streams, desktop/window-server state, GPU state, remote peers, nested namespaces and arbitrary DC-held buffers need their own ownership/restore contract. Private checkpoint image bytes may contain secrets and are never attached to reports or sent to cloud services.

## Protected PDF prototype — not a deployed MCP API

`src/mcp/runtime/pdf_security.py` is a separately tested prototype. Its MCP registration/integration was rejected by the current session's safety check, and that integration was not retried through another route. Existing deployed PDF APIs are unchanged by this prototype.

The prototype uses private owner-controlled password files, not password text in arguments, for AES-256 encryption and owner-authorized decrypted copies. It preserves source files. It also verifies supported detached CMS byte-range integrity using OpenSSL and can append an explicitly acknowledged unsigned metadata revision while retaining the entire original byte prefix. Original signature integrity and whether the newest revision is signed are reported separately. Certificate trust, revocation and DocMDP certification policy are not evaluated. No real signing key or password is requested, copied or changed by the tests.

Tests create disposable self-signed CMS signatures, detect tampering, verify that an incremental append preserves original signature bytes but does not sign the new revision, and check owner/user password separation and non-echoed errors. A changed signed payload is not certified by the previous signature. Encryption rewrites of signed inputs are refused instead of silently destroying validity.

## Outstanding physical and spreadsheet scope

Controller-host startup inspection found live compilation and interactive business use. Its physical reboot was not executed. X230 exposes RTC wake capability and a disabled Wake-on-LAN configuration, but an enabled capability is not proof of independent power recovery. No verified out-of-band BMC/PDU/power switch is available in the connected controls. Neither G3 removal of AC/battery power nor controller reboot is claimed. A later diagnostic was blocked and not retried by an alternate tool route.

A proposed helper for complex workbook names/shared formulas/1904 calendar semantics was also rejected before writing and was not retried. Existing formula evaluation and its explicit unsupported-feature refusals are unchanged. No successful complexity or protected-document integration is inferred from standalone library availability.

The exact release, installation status, successful tests, failed attempts and remaining prerequisites are recorded separately in the qualification receipt. Hardware power control, a verified idle/recovery window, application resource manifests and signing credentials are different requirements; a blanket GitHub permission grant does not produce them.

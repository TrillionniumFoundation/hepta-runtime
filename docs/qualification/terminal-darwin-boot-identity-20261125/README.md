# Darwin terminal boot identity and retained UTF-8 cursors

The persistent terminal helper previously compared the complete Darwin
`kern.boottime` string. XNU adjusts that timeval when the calendar changes, so
the string cannot establish whether a terminal belongs to the current boot.

## Source contract

Apple XNU commit `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` supplies the relevant
primary implementation:

- [IOPMrootDomain.cpp](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOPMrootDomain.cpp)
  initializes a boot-session UUID at boot and stores its uppercase string.
- [kern_sysctl.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_sysctl.c)
  exports `kern.bootsessionuuid` with `CTLFLAG_RD`.
- [clock.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/clock.c)
  adjusts both boot-time seconds and microseconds in the calendar-setting path.

The helper now records `darwin-boot-session-uuid-v1:` followed by a canonical
lowercase UUID. It accepts exactly the hyphenated UUID format, rejects nil,
extra text and multiple lines, and does not query Darwin sysctls on unsupported
platforms. A different valid UUID means `target_reboot`. Missing or malformed
current identity is unavailable; legacy timeval records are explicitly
unverifiable. Neither old time values nor PID observations migrate a record.

New launch validation precedes owner launch. The daemon captures its identity
before listener creation and `pty.fork`, then stores that same observation.
Write, internal resize and close RPCs share the identity check before socket
creation. Existing final receipts remain readable without a current boot query.
The existing close acknowledgement for a lost owner remains mapped by Rust to
an unknown outcome with `termination_confirmed=false`.

An unverifiable owner does not establish archive EOF. Text reads preserve a
partial UTF-8 cursor for `lost` and `launch_unknown`. Only an explicit `exited`
receipt permits consuming an incomplete final sequence with the lossy flag.
Raw-byte reads retain their existing exact-byte cursor behavior.

## Qualification of these source bytes

| File | SHA-256 |
|---|---|
| `src/mcp/runtime/terminal_host.py` | `6e636560030cde4537420b0484a1b0121a79384f1ce9534dcabf6f3dd475e0d0` |
| `tests/terminal_host_tests.py` | `e4dd106aefe220ca059e95fbd9cb0284ede5153f58e7ba8da80ba4de7ea54a17` |

The unchanged command is `python3 -B tests/terminal_host_tests.py -v`.
Each platform used a new isolated candidate directory and one execution.
Transferred source bytes, post-run bytes and independent file hashes matched.

| Platform | Python | Passed / executed | Controls / real disposable PTYs | Test duration | Raw log SHA-256 |
|---|---|---|---|---|---|
| Linux | 3.12.3 | 22 / 22 | 16 / 6 | 4.507 s | `3bdfc06304783475c0140e3e6104c7fd303e49d4a5d42e0420fbc758c87a6079` |
| Darwin | 3.9.6 | 22 / 22 | 16 / 6 | 2.010 s | `72d9b4c55789f7d306f46a965712a76e38359b31de2fb68f489138ef2fd6b54c` |

These are 22 test identities per platform, with no skips or retries. The 16
controls include strict identity rejection, mutation gating, pre-fork failure,
legacy archive reading, partial-character continuation and explicit final
truncation. The original six PTY tests still exercise real processes, retained
output, reconnection, input deduplication, Unicode, echo handling and changed
boot identity. The changed-identity fixture uses another valid synthetic UUID;
its `target_reboot` assertion is unchanged.

The initial scratch execution failed to create AF_UNIX sockets. Both the
unmodified baseline and candidate reproduced `EPERM` before bind or fork.
Those failures and the earlier 20-case candidate results were retained, not
relabelled as qualification of the final source above. A first collector's
case-regex/newline escaping defect was also retained; independent parsing of
its complete test log verified its scope without rerunning those tests.

Two Darwin UUID observations around the final test run agreed, as did its two
timeval observations. No physical reboot or clock adjustment was induced, and
this does not establish the UUID of any earlier legacy record. No running
service, installed helper, existing session or legacy metadata was changed.
The results qualify isolated candidate execution; they do not claim deployment
or coverage by the repository's general Rust CI.

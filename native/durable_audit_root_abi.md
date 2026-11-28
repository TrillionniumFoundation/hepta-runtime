# Audit configured-root admission, private ABI 1

This HIA actor owns the exact original Unix configuration-root traversal and
hot-directory admission. It receives the actual installed configuration path
from a private runtime capability; public JSON cannot choose this path or
supply descriptors. It exports a retained private directory lease. It does
not acquire the global audit store guard.

Input is `HRAROOT1`, operation, raw path length, zero, then raw path bytes.
Operations are 1 configured-root lease, 2 create/admit hot directory,
3 read-only optional hot directory. The output is 160 bytes, `HRAROOT1`:
diagnostic at 8, errno at 16, exported logical slot at 24 (zero for none),
total length 160 at 32, operation at 40, and the same eleven actual fstat/euid
values as Record I/O at 64. Workspace must hold the original input plus 1024
bytes; no new application path-length limit is introduced. Return codes and
initial/terminal one-shot custody follow the Record I/O actor.

Diagnostics: 10 non-UTF-8, 11 non-absolute or parent component, 12 ancestor
without any search permission, 13 NUL component, 14 unsafe private directory,
23 actual OS error. Their order follows the complete original functions.
Repeated and trailing slashes remain accepted where the original accepts them.
Private directories require original current-euid and exact permission checks;
an existing unsafe directory is not repaired into acceptance.

At workspace 256 the twelve-word `HRARDS01` action record has the same
sequence/shadow/acknowledgement structure as Record I/O. Kind 11 opens the
literal slash root with O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC; kind 1 opens
one captured component relative to the actual held parent; kind 2 returns
fstat/euid; kind 12 mkdirat creates exactly `request-audit` with mode 0700;
kind 5 fsyncs the original parent after successful creation; kind 6 closes
one actual owned slot without replay. O_PATH is retained for intermediate
ancestors and the final admitted directory is opened for reading. Every
ancestor search check occurs in HIA before the next open.

Logical slots 1, 2 and 3 are private owned handles. On success exactly the
declared exported slot survives; the caller closes it after the protected
operation, before releasing its global store guard. All other handles close
before terminal output. Read-only ENOENT returns no lease and creates nothing.
EEXIST after mkdir is followed by full admission of the actual existing
object, with no permission repair.

Qualification preserves ten complete original root/hot functions and compares
92 actual filesystem scenarios, complete outcomes, and post-operation state.
The qualification broker executes actual open/openat/fstat/mkdirat/fsync/close,
then independently checks the exported descriptor's metadata. It closes the
export after inspection. That scaffolding is not the final installed engine.

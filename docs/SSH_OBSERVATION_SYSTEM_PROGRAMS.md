# Fixed system programs in SSH observation profiles

The opt-in SSH observation pool pins its private profile, SSH configuration,
known-hosts file, and required system programs before it acquires reusable
transport authority. This correction supports Linux installations where the
fixed refusal command `/usr/bin/false` is a root-owned symbolic link to a
multicall executable, including uutils layouts with multiple hard links.

## Supported paths and bounds

The alias resolver has a closed two-entry selection: `/bin/sh`, which OpenSSH
uses for its fixed ProxyCommand when `SHELL` is absent, and `/usr/bin/false`,
which remains the exact fixed ProxyCommand value. Neither the profile nor a
caller can supply another alias path. `/usr/bin/ssh` retains its existing
no-symlink, single-link file validation.

Every parent directory in the two alias chains must be root-owned and neither
group-writable nor world-writable. Alias inodes must be root-owned with exactly
one link. Resolution uses held descriptors and `O_NOFOLLOW`, reads each alias
from its opened inode, and checks the inode again before retaining it. At most
eight symbolic links and 64 resolution steps are accepted.

Both resolved targets use the existing 16 MiB system-program ceiling. They must
be regular, root-owned, executable files with no group/other write permissions,
setuid/setgid bits, or Linux file capabilities. The shell target still requires
one hard link. Only the fixed refusal target may start with multiple hard links,
and its initial link count must be positive.

## Continued verification

Loading a profile pins the complete target identity: device, inode, owner,
mode, link count, length, mtime, ctime, and SHA256. A later verification does not
rebase these values. It requires the same alias chain and target path, checks
all directory/alias identities, rechecks the target's exact stamp, and hashes
all target bytes. A changed hard-link count therefore fails even when the
content is unchanged. The owner-side boundary check retains the same complete
identity comparison, and checked byte verification retains cancellation and
deadline checks between chunks.

The general profile/file opener continues to reject symbolic links in any
component. Private account-owned files retain their exact `0600` mode and
single-link requirement. The fixed-program exception cannot be used to admit
private data, choose an executable, or grant authority from an ambient `PATH`.

## Regression coverage

The profile tests retain actual symlink, hard-link, byte, permission, and
replacement rejection cases for private inputs. Fixed-program tests load and
rehash both real system paths, reject wrong content pins, and prove that a
changed expected target link count, inode, ctime, or alias link count is rejected
without modifying the host's root-owned programs. The observation-pool and
file-observation-pool fixture tests exercise complete profile loading on the
actual system layout. This portability correction is independent of the HIA
MCP tool contract.

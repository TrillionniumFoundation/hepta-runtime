// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Optional shared, filesystem-pinned execution-owner admission fence.
//!
//! Deployment requires every controller to configure the SAME private directory.
//! The administrator provisions .owner.lock and .owner.json before enabling.
//! Missing/partial configuration refuses effects; unconfigured installations
//! preserve the legacy mode and are NEVER qualified for owner transfer.
//! A shared flock spans each new-effect request, including durable intent and
//! remote submission; an exclusive transition must wait for every such guard.
//! Old-owner completed job reads are not gated here.
//! This module does NOT by itself implement an administrative transfer protocol.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::Read;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const SCHEMA: &str = "hepta-effect-owner-fence-v1";
const MAX_OWNER_BYTES: u64 = 4096;
const FENCE_DIRECTORY: &str = "HEPTA_EFFECT_OWNER_FENCE_DIR";
const SELF_OWNER: &str = "HEPTA_EFFECT_OWNER_SELF";
const FENCE_REQUIRED: &str = "HEPTA_EFFECT_OWNER_FENCE_REQUIRED";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerDocument {
    schema: String,
    owner: String,
    epoch: u64,
    phase: String,
    state_root: String,
    /// Frozen V4 state used to reject an already-accepted legacy idempotency
    /// binding before V11 can allocate a new job identity.
    #[serde(default)]
    predecessor_state_root: Option<String>,
}

/// Keeps the cross-process SH lock held through the actual effect submission.
/// Disabling a once-configured fence requires a reviewed service redeployment;
/// do not mistake an unconfigured process for a qualified takeover.
#[derive(Debug)]
pub struct AdmissionPermit {
    _locked: Option<File>,
    // Keep the authority and state identities open for the complete admitted
    // submission. Admission requires their pathnames to have remained stable.
    _authority_root: Option<File>,
    _state_root: Option<File>,
    predecessor_state_root: Option<(PathBuf, File)>,
    #[allow(dead_code)]
    epoch: Option<u64>,
}

#[cfg(unix)]
fn open_component(base: &File, name: &std::ffi::OsStr) -> Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let component = CString::new(name.as_bytes()).context("invalid authority directory name")?;
    let fd = unsafe {
        libc::openat(base.as_raw_fd(), component.as_ptr(),
                     libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("authority directory component unavailable");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_root(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        bail!("effect owner fence requires an absolute private directory");
    }
    let mut opened = File::open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => opened = open_component(&opened, name)?,
            _ => bail!("effect owner fence disallows relative/special components"),
        }
    }
    let info = opened.metadata()?;
    if !info.is_dir() || info.uid() != unsafe { libc::geteuid() }
        || info.mode() & 0o777 != 0o700
    {
        bail!("effect owner fence root must be current-UID private mode 0700");
    }
    Ok(opened)
}

#[cfg(unix)]
fn open_record(dir: &File, name: &str, writable: bool) -> Result<File> {
    let part = CString::new(name)?;
    let mode = if writable { libc::O_RDWR } else { libc::O_RDONLY };
    let fd = unsafe {
        libc::openat(dir.as_raw_fd(), part.as_ptr(),
                     mode | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("effect owner authority file absent");
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let info = file.metadata()?;
    if !info.is_file() || info.uid() != unsafe { libc::geteuid() }
        || info.nlink() != 1 || info.mode() & 0o777 != 0o600
    {
        bail!("effect owner authority file must be private regular inode");
    }
    Ok(file)
}

#[cfg(unix)]
fn owner_stamp(info: &std::fs::Metadata) -> (u64, u64, u64, u64, u32, u32, i64, i64, i64, i64) {
    (
        info.dev(), info.ino(), info.len(), info.nlink(), info.mode(), info.uid(),
        info.mtime(), info.mtime_nsec(), info.ctime(), info.ctime_nsec(),
    )
}

#[cfg(unix)]
fn verify_owner_record_stable(
    root_fd: &File,
    original: &File,
    before: &std::fs::Metadata,
) -> Result<()> {
    // An open FD can remain valid after the pathname has been atomically
    // replaced. Re-open under the pinned authority dir to refuse that race.
    let current = open_record(root_fd, ".owner.json", false)?;
    if owner_stamp(before) != owner_stamp(&original.metadata()?)
        || owner_stamp(before) != owner_stamp(&current.metadata()?)
    {
        bail!("effect owner record changed or was replaced during admission");
    }
    Ok(())
}

#[cfg(unix)]
fn verify_root_path_identity(path: &Path, pinned: &File) -> Result<()> {
    let current = open_root(path)?;
    if current.metadata()?.dev() != pinned.metadata()?.dev()
        || current.metadata()?.ino() != pinned.metadata()?.ino()
    {
        bail!("effect owner authority or controller state path was rebound");
    }
    Ok(())
}

#[cfg(unix)]
fn acquire_from_root(root: &Path, self_owner: &str, self_state: &Path) -> Result<AdmissionPermit> {
    if !matches!(self_owner, "v4" | "v11") || !self_state.is_absolute() {
        bail!("invalid owner identity or controller state root");
    }
    let root_fd = open_root(root)?;
    // The configured owner state must actually exist, be private and avoid
    // symlinked ancestors. An unchecked string alone is not an identity pin.
    let state_fd = open_root(self_state)?;
    let lock = open_record(&root_fd, ".owner.lock", true)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH) } != 0 {
        return Err(std::io::Error::last_os_error()).context("effect owner shared lock failed");
    }
    // A different process needs LOCK_EX to replace the durable owner record.
    // Never release this guard before a remote effect submission has completed.
    let owner_file = open_record(&root_fd, ".owner.json", false)?;
    let info = owner_file.metadata()?;
    if info.len() == 0 || info.len() > MAX_OWNER_BYTES {
        bail!("effect owner record has an unsafe length");
    }
    let mut body = Vec::with_capacity(info.len() as usize);
    (&owner_file).take(MAX_OWNER_BYTES + 1).read_to_end(&mut body)?;
    if body.len() as u64 != info.len() {
        bail!("effect owner record changed while reading");
    }
    verify_owner_record_stable(&root_fd, &owner_file, &info)?;
    let record: OwnerDocument =
        serde_json::from_slice(&body).context("effect owner record invalid")?;
    if record.schema != SCHEMA || record.epoch == 0
        || !matches!(record.owner.as_str(), "v4" | "v11")
        || !matches!(record.phase.as_str(), "admitting" | "frozen")
        || !Path::new(&record.state_root).is_absolute()
    {
        bail!("effect owner record is not an admitted schema/epoch");
    }
    if record.phase != "admitting" {
        bail!("effect owner admission frozen; no new effect submitted");
    }
    let predecessor_state_root = match (record.owner.as_str(), record.predecessor_state_root.as_deref()) {
        ("v4", None) => None,
        ("v11", Some(root)) => {
            let path = PathBuf::from(root);
            let prior = open_root(&path).context("V11 predecessor replay state unavailable")?;
            let prior_meta = prior.metadata()?;
            let current_meta = state_fd.metadata()?;
            if (prior_meta.dev(), prior_meta.ino()) == (current_meta.dev(), current_meta.ino()) {
                bail!("V11 predecessor cannot alias current effect state");
            }
            Some((path, prior))
        }
        _ => bail!("V11 owner must bind a trusted previous V4 state root"),
    };
    if record.owner != self_owner || Path::new(&record.state_root) != self_state {
        bail!("effect owner mismatch: refusing new effect");
    }
    // Recheck the pinned lock inode. A removed/replaced lock cannot authorize.
    let check = open_record(&root_fd, ".owner.lock", true)?;
    if check.metadata()?.ino() != lock.metadata()?.ino()
        || check.metadata()?.dev() != lock.metadata()?.dev()
    {
        bail!("effect owner lock inode changed during admission");
    }
    // Confirm the two paths still resolve to the same trusted directory
    // identities before handing the permit to the effect submitter.
    verify_root_path_identity(root, &root_fd)?;
    verify_root_path_identity(self_state, &state_fd)?;
    if let Some((path, prior)) = &predecessor_state_root {
        verify_root_path_identity(path, prior)?;
    }
    Ok(AdmissionPermit {
        _locked: Some(lock),
        _authority_root: Some(root_fd),
        _state_root: Some(state_fd),
        predecessor_state_root,
        epoch: Some(record.epoch),
    })
}

// The successor's native process_start must not recreate an already accepted
// V4 command merely because its own new job registry is initially empty.
// This is intentionally a bounded, conservative read-only scan of the
// predecessor's PRIVATE frozen registry. A faster sealed index can replace
// it only after retaining these same fail-closed identity checks.
#[cfg(unix)]
#[derive(Deserialize)]
struct LegacyJobKey {
    id: String,
    host: String,
    idempotency_key: Option<String>,
    request_digest: Option<String>,
}

impl AdmissionPermit {
    /// Reject any V4 historical process_start retry before V11 allocates its
    /// own durable identity. Missing keys are refused on a V11 owner, since
    /// there is no identity with which to deduplicate cross-generation calls.
    pub fn require_new_process_identity(&self, host: &str, key: Option<&str>) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let Some((predecessor, pinned)) = &self.predecessor_state_root else {
                return Ok(());
            };
            let key = key.context("V11 process_start requires a new idempotency key")?;
            if key.is_empty() || key.len() > 256 {
                bail!("V11 process_start requires a valid idempotency key");
            }
            verify_root_path_identity(predecessor, pinned)?;
            let jobs = open_component(pinned, std::ffi::OsStr::new("jobs"))?;
            let folder_meta = jobs.metadata()?;
            if folder_meta.uid() != unsafe { libc::geteuid() } || folder_meta.mode() & 0o777 != 0o700 {
                bail!("predecessor jobs registry must be owner-private");
            }
            // Linux /proc/self/fd pins the already-open directory, avoiding
            // a second independent traversal of the writable path.
            let fd_path = format!("/proc/self/fd/{}", jobs.as_raw_fd());
            let enumerate = || -> Result<Vec<String>> {
                let mut names = Vec::new();
                for item in fs::read_dir(&fd_path)? {
                    let name = item?.file_name().into_string()
                        .map_err(|_| anyhow!("non-UTF8 old durable job filename"))?;
                    if !name.ends_with(".json") || name.len() > 140 {
                        bail!("uncertain or temporary predecessor job record");
                    }
                    names.push(name);
                    if names.len() > 32768 {
                        bail!("predecessor registry exceeds safe replay scan bound");
                    }
                }
                names.sort();
                Ok(names)
            };
            let names = enumerate()?;
            let mut old_keys = HashSet::with_capacity(names.len());
            let mut is_replay = false;
            for name in &names {
                let file = open_record(&jobs, name, false)?;
                let before = file.metadata()?;
                if before.len() == 0 || before.len() > 1024 * 1024 {
                    bail!("invalid predecessor durable job length");
                }
                let mut content = Vec::with_capacity(before.len() as usize);
                (&file).take(1024 * 1024 + 1).read_to_end(&mut content)?;
                let reopened = open_record(&jobs, name, false)?;
                if content.len() as u64 != before.len()
                    || owner_stamp(&before) != owner_stamp(&file.metadata()?)
                    || owner_stamp(&before) != owner_stamp(&reopened.metadata()?)
                {
                    bail!("predecessor durable record changed during replay inspection");
                }
                let row: LegacyJobKey = serde_json::from_slice(&content)
                    .context("invalid predecessor durable job identity")?;
                if row.id != name.trim_end_matches(".json")
                    || row.host.is_empty() || row.host.len() > 128
                {
                    bail!("predecessor durable identity mismatch");
                }
                if let Some(prior_key) = row.idempotency_key {
                    if prior_key.is_empty() || prior_key.len() > 256
                        || row.request_digest.as_deref().is_none_or(|value|
                            value.len() != 64 || !value.bytes().all(|b|
                                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
                    {
                        bail!("predecessor idempotency binding incomplete");
                    }
                    if !old_keys.insert((row.host.clone(), prior_key.clone())) {
                        bail!("duplicate V4 predecessor idempotency binding");
                    }
                    if row.host == host && prior_key == key {
                        is_replay = true;
                    }
                }
            }
            if enumerate()? != names || owner_stamp(&folder_meta) != owner_stamp(&jobs.metadata()?) {
                bail!("predecessor registry changed while verifying replay namespace");
            }
            verify_root_path_identity(predecessor, pinned)?;
            if is_replay {
                bail!("original V4 has already accepted this host/idempotency identity; resume original job");
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (host, key);
            if self.predecessor_state_root.is_some() {
                bail!("V11 predecessor replay validation requires supported Linux controller");
            }
            Ok(())
        }
    }
}

#[cfg(not(unix))]
fn acquire_from_root(_: &Path, _: &str, _: &Path) -> Result<AdmissionPermit> {
    bail!("effect owner admission requires Unix file locking")
}

/// Each selected new-effect tool calls this before allocating an identity.
/// Startup configuration must be applied to every active V4/V10/V11 controller
/// and every external effect ingress before an administrative transfer is safe.
pub async fn admit_new_effect() -> Result<AdmissionPermit> {
    let root = std::env::var_os(FENCE_DIRECTORY);
    let owner = std::env::var_os(SELF_OWNER);
    let required = match std::env::var_os(FENCE_REQUIRED) {
        None => false,
        Some(value) if value == "1" => true,
        _ => bail!("invalid effect owner fence enforcement switch"),
    };
    let (root, owner) = match (root, owner) {
        (None, None) if !required =>
            return Ok(AdmissionPermit {
                _locked: None, _authority_root: None, _state_root: None,
                predecessor_state_root: None, epoch: None,
            }),
        (Some(root), Some(owner)) => (root, owner),
        _ => bail!("required effect owner fence is not fully configured"),
    };
    let owner = owner.into_string().map_err(|_| anyhow!("invalid owner configuration"))?;
    let state = super::config::runtime_config()?.state_dir.clone();
    tokio::task::spawn_blocking(move || acquire_from_root(&PathBuf::from(root), &owner, &state))
        .await
        .context("effect owner admission worker unavailable")?
}

#[cfg(test)]
#[path = "effect_owner_fence_tests.rs"]
mod tests;

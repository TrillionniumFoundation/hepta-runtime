// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification-only transport; original REA tests call the real HIA policies.
#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static CALL: AtomicU64 = AtomicU64::new(0);
type Entry = unsafe extern "C" fn(*const u8, usize, *mut u8, usize, *mut u8, usize) -> u64;
type Create = unsafe extern "C" fn(*mut u8, usize) -> i64;
type Effect = unsafe extern "C" fn(*mut libc::c_void) -> i64;

fn hex(raw: &[u8]) -> String { raw.iter().map(|b| format!("{b:02x}")).collect() }
fn push(raw: &mut Vec<u8>, value: u64) { raw.extend_from_slice(&value.to_le_bytes()); }
fn get(raw: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(raw.get(at..at + 8).context("short native word")?.try_into()?))
}
fn put(raw: &mut [u8], at: usize, value: u64) { raw[at..at + 8].copy_from_slice(&value.to_le_bytes()); }
fn snapshot(m: &std::fs::Metadata) -> Vec<u8> {
    let mut raw = Vec::new();
    for n in [m.dev(), m.ino(), m.len(), m.mode() as u64, m.uid() as u64,
        m.gid() as u64, m.nlink(), m.mtime() as u64, m.mtime_nsec() as u64,
        m.ctime() as u64, m.ctime_nsec() as u64] { push(&mut raw, n); }
    raw
}

struct Image { address: *mut libc::c_void, size: usize }
impl Image {
    fn map(raw: &[u8]) -> Result<Self> {
        let fd = unsafe { libc::memfd_create(c"hia-rea-qualification".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
        if fd < 0 { return Err(std::io::Error::last_os_error()).context("native code memfd"); }
        use std::os::fd::{AsRawFd, FromRawFd};
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(raw)?;
        if unsafe { libc::fcntl(file.as_raw_fd(), 1033, 15) } != 0
            || unsafe { libc::fcntl(file.as_raw_fd(), 1034) } != 15 {
            bail!("native code seals differ");
        }
        let address = unsafe { libc::mmap(std::ptr::null_mut(), raw.len(), libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE, file.as_raw_fd(), 0) };
        if address == libc::MAP_FAILED { return Err(std::io::Error::last_os_error()).context("sealed native code mapping"); }
        Ok(Self { address, size: raw.len() })
    }
    fn module(role: &str) -> Result<Self> {
        let path = PathBuf::from(std::env::var(format!("HIA_REA_{role}_MANIFEST"))?);
        let raw = std::fs::read(&path)?;
        if hex(&Sha256::digest(&raw)) != std::env::var(format!("HIA_REA_{role}_MANIFEST_SHA256"))? {
            bail!("native manifest changed");
        }
        let m: Value = serde_json::from_slice(&raw)?;
        if m["abi"] != "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
            || m["target"] != "linux-x86_64"
            || m["compiler_commit"] != "d3e2c90173cf733e42b299d0c4274df4b593a12f" {
            bail!("native ABI or compiler differs");
        }
        let mut image = Vec::new();
        for kind in ["source", "image"] {
            let name = m[kind].as_str().context("native member")?;
            if name.is_empty() || name.contains('/') || name.contains('\\') || name == "." || name == ".." {
                bail!("native member must be a basename");
            }
            let bytes = std::fs::read(path.parent().context("manifest parent")?.join(name))?;
            if bytes.is_empty() || bytes.len() > 1 << 20
                || Some(hex(&Sha256::digest(&bytes)).as_str()) != m[format!("{kind}_sha256")].as_str() {
                bail!("native source or code bytes differ");
            }
            if kind == "image" { image = bytes; }
        }
        Self::map(&image)
    }
    fn entry(&self) -> Entry { unsafe { std::mem::transmute(self.address) } }
}
impl Drop for Image { fn drop(&mut self) { unsafe { libc::munmap(self.address, self.size); } } }

struct Engine { image: Image, create: Create, step: Effect, destroy: Effect }
impl Engine {
    fn load() -> Result<Self> {
        let raw = std::fs::read(std::env::var("HIA_REA_ENGINE")?)?;
        if hex(&Sha256::digest(&raw)) != std::env::var("HIA_REA_ENGINE_SHA256")?
            || raw.len() < 64 || &raw[..8] != b"HREAPK01"
            || get(&raw, 8)? != raw.len() as u64 || get(&raw, 16)? + 64 != raw.len() as u64
            || get(&raw, 56)? != 0 { bail!("typed HIA syscall engine differs"); }
        let offsets: Vec<usize> = (3..7).map(|j| get(&raw, j * 8).map(|v| v as usize)).collect::<Result<_>>()?;
        if offsets.windows(2).any(|pair| pair[0] >= pair[1]) || offsets[3] >= raw.len() - 64 {
            bail!("native engine exports differ");
        }
        let image = Image::map(&raw[64..])?;
        let base = image.address as usize;
        Ok(Self { create: unsafe { std::mem::transmute(base + offsets[0]) },
            step: unsafe { std::mem::transmute(base + offsets[1]) },
            destroy: unsafe { std::mem::transmute(base + offsets[3]) }, image })
    }
}
struct Owner<'a> { engine: &'a Engine, context: *mut libc::c_void }
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        if !self.context.is_null() {
            let result = unsafe { (self.engine.destroy)(self.context) };
            assert_eq!(result, 0, "actual native fd owner cleanup");
        }
    }
}

fn error(code: u64, number: u64, maximum: u64, workspace: &[u8]) -> anyhow::Error {
    let io = || std::io::Error::from_raw_os_error(number as i32);
    match code {
        1 => anyhow!("REA native inspection requires an absolute local path"),
        2 => anyhow!("REA inspection denied: no controller workspace roots configured"),
        3 => anyhow!("REA inspection denied: configured workspace root must be absolute"),
        4 => anyhow!("REA inspection denied: parent or non-normal path component"),
        5 => anyhow!("REA inspection path contains NUL"),
        6 => anyhow!("REA inspection requires a regular file, not a workspace root"),
        7 => anyhow!("REA configured root contains NUL"),
        8 => anyhow!("REA inspection denied: path is outside controller workspace roots"),
        9 => anyhow!("REA private preview inode must be owned, single-linked and mode 0600"),
        10 => anyhow!("REA inspection denied: admitted artifact changed during read"),
        11 => {
            let n = get(workspace, 4120).unwrap() as usize;
            let root = PathBuf::from(std::ffi::OsString::from_vec(workspace[4144..4144 + n].to_vec()));
            anyhow::Error::from(io()).context(format!("cannot open configured workspace {}", root.display()))
        },
        12 => anyhow::Error::from(io()).context("REA inspection denied: unsafe or missing directory component"),
        13 => anyhow::Error::from(io()).context("REA inspection denied: unsafe or missing file component"),
        14 => anyhow::Error::from(io()).context("cannot stat admitted artifact"),
        15 => anyhow!("REA inspection requires a regular file"),
        16 => anyhow!("REA inspection file exceeds {maximum} byte limit"),
        17 | 18 => anyhow::Error::from(io()),
        _ => anyhow!("unknown HIA file error {code}"),
    }
}

fn read(path: &Path, roots: &[PathBuf], maximum: u64, mode: u64) -> Result<Vec<u8>> {
    let actor = Image::module("ACTOR")?;
    let engine = Engine::load()?;
    let mut wire = b"HREAFPL1".to_vec();
    push(&mut wire, 1); push(&mut wire, path.as_os_str().as_bytes().len() as u64); push(&mut wire, roots.len() as u64);
    wire.extend_from_slice(path.as_os_str().as_bytes());
    for root in roots { push(&mut wire, root.as_os_str().as_bytes().len() as u64); wire.extend_from_slice(root.as_os_str().as_bytes()); }
    let wcap = 69632_usize.max(wire.len() + 4224);
    let ocap = (wire.len() + 256).max(128).max(usize::try_from(maximum.wrapping_add(1))?.checked_add(128).context("owned output capacity")?);
    let mut output = vec![0; ocap + 16]; output[ocap..].fill(0xA5);
    let mut workspace = vec![0; wcap + 16]; workspace[wcap..].fill(0x5A);
    put(&mut workspace, 144, mode); put(&mut workspace, 152, maximum);
    let context = unsafe { (engine.create)(workspace.as_mut_ptr(), wcap) };
    if context < 0 { bail!("native descriptor context refused {context}"); }
    let owner = Owner { engine: &engine, context: context as *mut libc::c_void };
    let mut log = if let Ok(folder) = std::env::var("HIA_REA_EVIDENCE_DIR") {
        let name = format!("call-{}-{}.jsonl", std::process::id(), CALL.fetch_add(1, Ordering::SeqCst));
        Some(std::fs::OpenOptions::new().write(true).create_new(true).open(PathBuf::from(folder).join(name))?)
    } else { None };
    let original = wire.clone();
    loop {
        let code = unsafe { actor.entry()(wire.as_ptr(), wire.len(), output.as_mut_ptr(), ocap, workspace.as_mut_ptr(), wcap) };
        if wire != original || output[ocap..] != [0xA5; 16] || workspace[wcap..] != [0x5A; 16] {
            bail!("native borrowed-buffer guard changed");
        }
        if let Some(log) = log.as_mut() {
            writeln!(log, "{}", json!({"kind":"actor","code":code,"input_hex":hex(&wire),
                "output_hex":hex(&output[..ocap]),"workspace_hex":hex(&workspace[..wcap])}))?;
        }
        if code == 0xFFFFFFF0 {
            let result = unsafe { (engine.step)(owner.context) };
            if let Some(log) = log.as_mut() {
                writeln!(log, "{}", json!({"kind":"effect","result":result,"action_hex":hex(&workspace[256..352]),
                    "metadata_hex":hex(&workspace[512..600])}))?;
            }
            if result != 0 { bail!("native fd effect refused {result}"); }
            continue;
        }
        if code < 128 || code > ocap as u64 || &output[..8] != b"HRFDRS01" {
            bail!("HIA file terminal extent differs {code}");
        }
        let error_code = get(&output, 16)?;
        if get(&output, 8)? != u64::from(error_code != 0) { bail!("HIA file status differs"); }
        if error_code != 0 { return Err(error(error_code, get(&output, 24)?, maximum, &workspace)); }
        if get(&output, 120)? + 128 != code { bail!("HIA file payload extent differs"); }
        return Ok(output[128..code as usize].to_vec());
    }
}

pub async fn read_bounded(path: &Path, roots: &[PathBuf], maximum: u64) -> Result<Vec<u8>> {
    read(path, roots, maximum, 1)
}
pub(super) async fn read_private_bounded(path: &Path, roots: &[PathBuf], maximum: u64) -> Result<Vec<u8>> {
    read(path, roots, maximum, 2)
}
pub(super) fn ensure_unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) -> Result<()> {
    let policy = Image::module("POLICY")?;
    let mut wire = b"HREAFPL1".to_vec(); push(&mut wire, 2);
    wire.extend_from_slice(&snapshot(before)); wire.extend_from_slice(&snapshot(after));
    let mut output = [0_u8; 64]; let mut workspace = [0x5A_u8; 16];
    output[48..].fill(0xA5);
    let code = unsafe { policy.entry()(wire.as_ptr(), wire.len(), output.as_mut_ptr(), 48, workspace.as_mut_ptr(), 0) };
    if code != 48 || &output[..8] != b"HRFPLAN1" || output[48..] != [0xA5; 16] || workspace != [0x5A; 16] {
        bail!("native metadata policy frame differs");
    }
    let error_code = get(&output, 16)?;
    if error_code != 0 { return Err(error(error_code, 0, 0, &[])); }
    Ok(())
}

#[cfg(test)]
#[path = "rea_files_tests.rs"]
mod rea_files_tests;

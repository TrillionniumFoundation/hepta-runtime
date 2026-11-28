// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification-only FFI and descriptor transport. All ZIP decisions run in HIA.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const WORKSPACE: usize = 64 << 20;
const OUTPUT: usize = (1 << 20) + 40;
static CALL: AtomicU64 = AtomicU64::new(0);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn get(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw: [u8; 8] = bytes.get(offset..offset + 8)
        .ok_or_else(|| anyhow!("short native frame"))?.try_into()?;
    Ok(u64::from_le_bytes(raw))
}

fn push(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub fn metadata(file: &File) -> Result<Vec<u8>> {
    let m = file.metadata()?;
    let mut result = Vec::new();
    for word in [m.dev(), m.ino(), m.len(), m.mode() as u64, m.uid() as u64,
        m.gid() as u64, m.nlink(), m.mtime() as u64, m.mtime_nsec() as u64,
        m.ctime() as u64, m.ctime_nsec() as u64] {
        push(&mut result, word);
    }
    Ok(result)
}

struct Image {
    address: *mut libc::c_void,
    length: usize,
}

impl Image {
    fn load() -> Result<Self> {
        let path = PathBuf::from(std::env::var("HIA_ZIP_MANIFEST")?);
        let raw = std::fs::read(&path)?;
        if hex(&Sha256::digest(&raw)) != std::env::var("HIA_ZIP_MANIFEST_SHA256")? {
            bail!("native manifest changed");
        }
        let manifest: Value = serde_json::from_slice(&raw)?;
        if manifest["abi"] != "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
            || manifest["compiler_commit"] != "d3e2c90173cf733e42b299d0c4274df4b593a12f"
            || manifest["target"] != "linux-x86_64" {
            bail!("native image ABI differs");
        }
        let parent = path.parent().context("manifest parent")?;
        let mut image = Vec::new();
        for kind in ["source", "image"] {
            let name = manifest[kind].as_str().context("native member name")?;
            if name.is_empty() || name.contains('/') || name.contains('\\') || name == "." || name == ".." {
                bail!("native member basename required");
            }
            let bytes = std::fs::read(parent.join(name))?;
            if bytes.is_empty() || bytes.len() > 1 << 20
                || Some(hex(&Sha256::digest(&bytes)).as_str()) != manifest[format!("{kind}_sha256")].as_str() {
                bail!("native member bytes differ");
            }
            if kind == "image" {
                image = bytes;
            }
        }
        let address = unsafe { libc::mmap(std::ptr::null_mut(), image.len(),
            libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
        if address == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error()).context("native image mapping");
        }
        unsafe { std::ptr::copy_nonoverlapping(image.as_ptr(), address.cast(), image.len()); }
        if unsafe { libc::mprotect(address, image.len(), libc::PROT_READ | libc::PROT_EXEC) } != 0 {
            unsafe { libc::munmap(address, image.len()); }
            return Err(std::io::Error::last_os_error()).context("native image read-execute protection");
        }
        Ok(Self { address, length: image.len() })
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.address, self.length); }
    }
}

pub fn invoke(wire: Vec<u8>, file: Option<&File>) -> Result<Value> {
    let image = Image::load()?;
    type Entry = unsafe extern "C" fn(*const u8, usize, *mut u8, usize, *mut u8, usize) -> u64;
    let entry: Entry = unsafe { std::mem::transmute(image.address) };
    let original = wire.clone();
    let mut output = vec![0_u8; OUTPUT + 16];
    let mut workspace = vec![0_u8; WORKSPACE + 16];
    output[OUTPUT..].fill(0xa5);
    workspace[WORKSPACE..].fill(0x5a);
    let mut sequence = 0_u64;
    let mut effects = 0_u64;
    let mut log = if let Ok(folder) = std::env::var("HIA_ZIP_EVIDENCE_DIR") {
        let name = format!("call-{}-{}.jsonl", std::process::id(), CALL.fetch_add(1, Ordering::SeqCst));
        Some(OpenOptions::new().write(true).create_new(true).open(PathBuf::from(folder).join(name))?)
    } else { None };
    if let Some(log) = log.as_mut() {
        writeln!(log, "{}", json!({"event":"input","bytes_hex":hex(&wire)}))?;
    }
    for _ in 0..1_000_000 {
        let code = unsafe { entry(wire.as_ptr(), wire.len(), output.as_mut_ptr(), OUTPUT,
            workspace.as_mut_ptr(), WORKSPACE) };
        if wire != original || output[OUTPUT..] != [0xa5; 16] || workspace[WORKSPACE..] != [0x5a; 16] {
            bail!("native borrowed-buffer guard changed");
        }
        if code != 0xfffffff0 {
            if code < 40 || code > OUTPUT as u64 {
                bail!("native returned invalid extent {code}");
            }
            let body = &output[..code as usize];
            if &body[..8] != b"HZIPRS01" || get(body, 24)? + 40 != code {
                bail!("native response frame differs");
            }
            let status = get(body, 8)?;
            let error = get(body, 16)?;
            if status > 1 || (status == 0) != (error == 0) {
                bail!("native response status differs");
            }
            if let Some(log) = log.as_mut() {
                writeln!(log, "{}", json!({"event":"terminal","effects":effects,
                    "native_calls":effects+1,"code":code,"bytes_hex":hex(body)}))?;
            }
            if status == 1 {
                bail!("{}", std::str::from_utf8(&body[40..])?);
            }
            return serde_json::from_slice(&body[40..]).context("native result JSON");
        }
        let request: Vec<u64> = (0..10).map(|j| get(&workspace, 8192 + j * 8)).collect::<Result<_>>()?;
        if request[0] != u64::from_le_bytes(*b"HZIPFX01") || request[1] != sequence + 1
            || !(1..=2).contains(&request[2]) || request[6..] != [0; 4] {
            bail!("native effect continuation differs");
        }
        let action = request[2];
        let offset = request[3];
        let count = usize::try_from(request[4])?;
        let target = usize::try_from(request[5])?;
        if count == 0 || count > 65536 || target > WORKSPACE - count {
            bail!("native effect buffer differs");
        }
        let file = file.context("descriptor required for native effect")?;
        let mut data = vec![0_u8; count];
        let mut read = 0;
        let mut errno = 0;
        if action == 1 {
            while read < count {
                match file.read_at(&mut data[read..], offset + read as u64) {
                    Ok(0) => break,
                    Ok(n) => read += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => { errno = e.raw_os_error().unwrap_or(5) as u64; break; }
                }
            }
            data.truncate(read);
        } else {
            if offset != 0 || count != 88 || target != 9000 {
                bail!("native metadata effect differs");
            }
            match metadata(file) {
                Ok(bytes) => { data = bytes; read = data.len(); }
                Err(_) => { data.clear(); errno = 5; }
            }
        }
        workspace[target..target + read].copy_from_slice(&data);
        for (j, word) in [request[1], read as u64, errno, 0].iter().enumerate() {
            workspace[8240 + j * 8..8248 + j * 8].copy_from_slice(&word.to_le_bytes());
        }
        if let Some(log) = log.as_mut() {
            writeln!(log, "{}", json!({"event":"effect","request":request,
                "bytes_hex":hex(&data),"errno":errno}))?;
        }
        sequence = request[1];
        effects += 1;
    }
    bail!("native qualification continuation guard exceeded")
}

pub fn inspect(file: &File, filter: u64, offset: usize, limit: usize) -> Result<Value> {
    let mut wire = b"HZIPRQ01".to_vec();
    for value in [filter, offset as u64, limit as u64] { push(&mut wire, value); }
    wire.extend_from_slice(&metadata(file)?);
    invoke(wire, Some(file))
}

pub fn field(op: u64, bytes: &[u8], flags: u16, method: u16, payload: u64) -> Result<Value> {
    let mut wire = b"HZIPAT01".to_vec();
    for value in [op, flags as u64, method as u64, payload, bytes.len() as u64] { push(&mut wire, value); }
    wire.extend_from_slice(bytes);
    invoke(wire, None)
}

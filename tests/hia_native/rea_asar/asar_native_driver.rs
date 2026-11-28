// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification-only FFI and descriptor transport. All ASAR decisions run in HIA.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const WORKSPACE: usize = 256 << 20;
const OUTPUT: usize = (4 << 20) + 32;
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
        let path = PathBuf::from(std::env::var("HIA_ASAR_MANIFEST")?);
        let raw = std::fs::read(&path)?;
        if hex(&Sha256::digest(&raw)) != std::env::var("HIA_ASAR_MANIFEST_SHA256")? {
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

pub fn invoke(mut wire: Vec<u8>, file: &File) -> Result<Value> {
    let image = Image::load()?;
    type Entry = unsafe extern "C" fn(*const u8, usize, *mut u8, usize, *mut u8, usize) -> u64;
    let entry: Entry = unsafe { std::mem::transmute(image.address) };
    let mut output = vec![0_u8; OUTPUT + 16];
    let mut workspace = vec![0_u8; WORKSPACE + 16];
    output[OUTPUT..].fill(0xa5);
    workspace[WORKSPACE..].fill(0x5a);
    let mut sequence = 0_u64;
    let mut effects = 0_u64;
    let mut log = if let Ok(folder) = std::env::var("HIA_ASAR_EVIDENCE_DIR") {
        let name = format!("call-{}-{}.jsonl", std::process::id(), CALL.fetch_add(1, Ordering::SeqCst));
        Some(OpenOptions::new().write(true).create_new(true).open(PathBuf::from(folder).join(name))?)
    } else { None };
    for _ in 0..1_000_000 {
        if let Some(log) = log.as_mut() {
            writeln!(log, "{}", json!({"event":"input","bytes_hex":hex(&wire)}))?;
        }
        let original = wire.clone();
        let code = unsafe { entry(wire.as_ptr(), wire.len(), output.as_mut_ptr(), OUTPUT,
            workspace.as_mut_ptr(), WORKSPACE) };
        if wire != original || output[OUTPUT..] != [0xa5; 16] || workspace[WORKSPACE..] != [0x5a; 16] {
            bail!("native borrowed-buffer guard changed");
        }
        if code != 0xfffffff0 {
            if code < 32 || code > OUTPUT as u64 {
                bail!("native returned invalid extent {code}");
            }
            let body = &output[..code as usize];
            if &body[..8] != b"HSARRS01" || get(body, 24)? + 32 != code {
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
                bail!("{}", std::str::from_utf8(&body[32..])?);
            }
            return serde_json::from_slice(&body[32..]).context("native result JSON");
        }
        let request: Vec<u64> = (0..5).map(|j| get(&workspace, 65536 + j * 8)).collect::<Result<_>>()?;
        if request[0] != u64::from_le_bytes(*b"HSARFX01") || request[1] != sequence + 1
            || !(1..=2).contains(&request[2]) {
            bail!("native effect continuation differs");
        }
        let action = request[2];
        let offset = request[3];
        let count = usize::try_from(request[4])?;
        if count == 0 || count > 16 << 20 {
            bail!("native effect buffer differs");
        }
        let mut data = vec![0_u8; count];
        let mut read = 0;
        let mut errno = 0;
        if action == 1 {
            while read < count {
                let end = (read + 65536).min(count);
                match file.read_at(&mut data[read..end], offset + read as u64) {
                    Ok(0) => break,
                    Ok(n) => read += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => { errno = e.raw_os_error().unwrap_or(5) as u64; break; }
                }
            }
            data.truncate(read);
        } else {
            if offset != 0 || count != 88 {
                bail!("native metadata effect differs");
            }
            match metadata(file) {
                Ok(bytes) => data = bytes,
                Err(_) => { data.clear(); errno = 5; }
            }
        }
        if let Some(log) = log.as_mut() {
            writeln!(log, "{}", json!({"event":"effect","request":request,
                "bytes_hex":hex(&data),"errno":errno}))?;
        }
        wire = b"HSARIN01".to_vec();
        for value in [request[1], data.len() as u64, errno] { push(&mut wire,value); }
        wire.extend_from_slice(&data);
        sequence = request[1];
        effects += 1;
    }
    bail!("native qualification continuation guard exceeded")
}

pub fn inspect(file: &File, operation: u64, offset: u64, length: usize, member: &str, complete: bool) -> Result<Value> {
    let mut wire = b"HSARRQ01".to_vec();
    for value in [operation, offset, length as u64, complete as u64, member.len() as u64] {
        push(&mut wire,value);
    }
    wire.extend_from_slice(&metadata(file)?);
    wire.extend_from_slice(member.as_bytes());
    invoke(wire,file)
}

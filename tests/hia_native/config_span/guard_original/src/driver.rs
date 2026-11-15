use anyhow::{anyhow, bail, Context, Result};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// Only the actual absent-configuration projection is exercised. These private
// type holders never initialize application configuration or claim its schema.
struct RuntimeConfig { controller_workspace_roots: Vec<PathBuf> }
struct InstalledRuntimeConfig { config: RuntimeConfig }

// ORIGINAL_DECLARATIONS

fn word(input: &mut impl Read) -> u64 {
    let mut bytes = [0; 8]; input.read_exact(&mut bytes).unwrap(); u64::from_le_bytes(bytes)
}
fn bytes(input: &mut impl Read, len: u64) -> Vec<u8> {
    let mut value = vec![0; usize::try_from(len).unwrap()]; input.read_exact(&mut value).unwrap(); value
}
fn emit_word(output: &mut impl Write, value: u64) { output.write_all(&value.to_le_bytes()).unwrap(); }
fn marker(id: u64, event: u64, operation: u64) {
    let mut raw = Vec::from(b"HFDGMK01".as_slice());
    for value in [id, event, operation] { raw.extend_from_slice(&value.to_le_bytes()); }
    io::stderr().write_all(&raw).unwrap();
}
fn descriptor_count() -> u64 { std::fs::read_dir("/proc/self/fd").unwrap().count() as u64 }
fn main() {
    let mut input = io::stdin().lock(); let mut output = io::BufWriter::new(io::stdout().lock());
    assert_eq!(bytes(&mut input, 8), b"HFDGI001"); let count = word(&mut input);
    output.write_all(b"HFDGO001").unwrap(); emit_word(&mut output, count);
    for _ in 0..count {
        let id = word(&mut input); let operation = word(&mut input); let source_len = word(&mut input);
        let root_count = word(&mut input); assert_eq!(word(&mut input), 0);
        let source = PathBuf::from(OsString::from_vec(bytes(&mut input, source_len)));
        let mut roots = Vec::new();
        for _ in 0..root_count { let len = word(&mut input); roots.push(PathBuf::from(OsString::from_vec(bytes(&mut input, len)))); }
        let before = descriptor_count(); marker(id, 0, operation);
        let result = match operation {
            1 => check_directory_move_against_roots(&source, &roots),
            2 => { assert!(roots.is_empty()); check_directory_move_source(&source) }
            _ => panic!("unknown operation"),
        };
        marker(id, 1, operation); let after = descriptor_count();
        let (status, present, errno, short, chain) = match result {
            Ok(()) => (0, 0, 0, Vec::new(), Vec::new()),
            Err(error) => {
                let errno = error.downcast_ref::<io::Error>().and_then(|value| value.raw_os_error());
                (1, u64::from(errno.is_some()), errno.unwrap_or(0) as u64,
                    error.to_string().into_bytes(), format!("{error:#}").into_bytes())
            }
        };
        for value in [id, operation, status, present, errno, short.len() as u64, chain.len() as u64, before, after] {
            emit_word(&mut output, value);
        }
        output.write_all(&short).unwrap(); output.write_all(&chain).unwrap(); output.flush().unwrap();
    }
    assert_eq!(input.read(&mut [0; 1]).unwrap(), 0); output.flush().unwrap();
}

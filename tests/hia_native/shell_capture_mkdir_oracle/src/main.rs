//! Test transport for the unmodified linked Rust 1.95 blocking directory API.
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const BEGIN: &[u8] = b"HSHMKRUST-BEGIN\n";
const END: &[u8] = b"HSHMKRUST-END\n";

fn word(raw: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap())
}

fn main() -> io::Result<()> {
    if std::env::args_os().count() != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no arguments admitted"));
    }
    let mut request = Vec::new();
    io::stdin().lock().read_to_end(&mut request)?;
    if request.len() < 64 || &request[..8] != b"HSHMKQ01"
        || word(&request, 8) != 1 || word(&request, 16) != 0
        || word(&request, 24) != (request.len() - 64) as u64
        || request[32..64].iter().any(|value| *value != 0)
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid START frame"));
    }
    let path = Path::new(OsStr::from_bytes(&request[64..]));
    let mut markers = io::stderr().lock();
    markers.write_all(BEGIN)?;
    markers.flush()?;
    let result = std::fs::create_dir_all(path);
    markers.write_all(END)?;
    markers.flush()?;
    let (kind, value) = match result {
        Ok(()) => (0u64, 0u64),
        Err(error) => match error.raw_os_error() {
            Some(value) if value > 0 => (1u64, value as u64),
            None if error.kind() == io::ErrorKind::InvalidInput
                && request[64..].contains(&0) => (2u64, 0u64),
            _ => return Err(error),
        },
    };
    let mut response = Vec::with_capacity(24);
    response.extend_from_slice(b"HSHMKO01");
    response.extend_from_slice(&kind.to_le_bytes());
    response.extend_from_slice(&value.to_le_bytes());
    io::stdout().lock().write_all(&response)
}

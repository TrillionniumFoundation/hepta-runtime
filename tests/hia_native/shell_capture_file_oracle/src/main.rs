//! Test transport for the fixed linked Rust blocking file APIs and owned drop.
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const BEGIN: &[u8] = b"HSHCFRUST-BEGIN\n";
const END: &[u8] = b"HSHCFRUST-END\n";
const ABSENT_FD: u64 = u64::MAX;

fn word(raw: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap())
}

fn main() -> io::Result<()> {
    if std::env::args_os().count() != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no arguments admitted"));
    }
    let mut request = Vec::new();
    io::stdin().lock().read_to_end(&mut request)?;
    if request.len() < 64 || &request[..8] != b"HSHCFRQ1"
        || word(&request, 8) != 1
        || !matches!(word(&request, 16), 1 | 2)
        || word(&request, 24) != (request.len() - 64) as u64
        || request[40..64].iter().any(|value| *value != 0)
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid file frame"));
    }
    let operation = word(&request, 16);
    let disposition = word(&request, 32);
    if (operation == 1 && !matches!(disposition, 1 | 2))
        || (operation == 2 && disposition != 0)
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid file disposition"));
    }
    let path = Path::new(OsStr::from_bytes(&request[64..]));
    let mut receiver: Option<File> = None;
    let mut actual_fd = ABSENT_FD;
    let mut applied_disposition = 0;
    let mut markers = io::stderr().lock();
    markers.write_all(BEGIN)?;
    markers.flush()?;
    let result = if operation == 1 {
        match File::create(path) {
            Ok(file) => {
                actual_fd = file.as_raw_fd() as u64;
                applied_disposition = disposition;
                if disposition == 1 {
                    drop(file);
                } else {
                    receiver = Some(file);
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    } else {
        std::fs::remove_file(path)
    };
    markers.write_all(END)?;
    markers.flush()?;
    let (kind, error) = match result {
        Ok(()) => (0u64, 0u64),
        Err(error) => match error.raw_os_error() {
            Some(value) if value > 0 => (1u64, value as u64),
            None if error.kind() == io::ErrorKind::InvalidInput
                && request[64..].contains(&0) => (2u64, 0u64),
            _ => return Err(error),
        },
    };
    if applied_disposition == 2
        && receiver.as_ref().map(|file| file.as_raw_fd() as u64) != Some(actual_fd)
    {
        return Err(io::Error::other("receiver did not retain the same owned descriptor"));
    }
    let mut response = Vec::with_capacity(48);
    response.extend_from_slice(b"HSHCFO01");
    for value in [operation, kind, error, applied_disposition, actual_fd] {
        response.extend_from_slice(&value.to_le_bytes());
    }
    let mut output = io::stdout().lock();
    output.write_all(&response)?;
    output.flush()?;
    // Like the native fixture, the TAKE receiver owns its file until process
    // termination. exit does not run Rust local destructors; the kernel releases
    // that descriptor. This is receiver cleanup, not an additional owned DROP.
    std::process::exit(0)
}

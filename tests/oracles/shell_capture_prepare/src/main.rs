// Test transport for the explicitly recorded blocking projection of prepare.
// The generated projection.rs is reconstructed from the pinned original source.
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct ProjectionError {
    stage: u64,
    error: io::Error,
    message: String,
}

struct Capture {
    dir: PathBuf,
    id: String,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    stdout_file: File,
    stderr_file: File,
}

type Result<T> = std::result::Result<T, ProjectionError>;

// Preserve the original error-format arguments while retaining the real
// io::Error. This test carrier is not the production anyhow type.
macro_rules! anyhow {
    ($format:literal, $error:expr) => {{
        let error = $error;
        let stage = match $format {
            "Failed to create background job dir: {}" => 1,
            "Failed to create shell stdout log: {}" => 2,
            "Failed to create shell stderr log: {}" => 3,
            _ => panic!("unregistered original error carrier"),
        };
        let message = format!($format, error);
        ProjectionError { stage, error, message }
    }};
}

include!("projection.rs");

fn number(bytes: &[u8], index: usize) -> u64 {
    u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())
}

fn push(words: &mut Vec<u8>, value: u64) {
    words.extend_from_slice(&value.to_le_bytes());
}

fn main() -> io::Result<()> {
    if std::env::args_os().count() != 1 {
        std::process::exit(64);
    }
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut errors = io::stderr().lock();
    let pid = u64::from(std::process::id());
    let mut ready = b"HSPPORD1".to_vec();
    push(&mut ready, pid);
    push(&mut ready, 1);
    push(&mut ready, 0);
    output.write_all(&ready)?;
    output.flush()?;

    let mut request = [0u8; 64];
    input.read_exact(&mut request)?;
    if &request[..8] != b"HSPPORQ1" || number(&request, 1) != 1
        || (3..8).any(|index| number(&request, index) != 0)
    {
        std::process::exit(64);
    }
    let seed = number(&request, 2);
    JOB_SEQ.store(seed, Ordering::Relaxed);
    let before = JOB_SEQ.load(Ordering::Relaxed);
    errors.write_all(b"HSPPORUST-BEGIN\n")?;
    errors.flush()?;
    let result = capture_projection();
    errors.write_all(b"HSPPORUST-END\n")?;
    errors.flush()?;
    let after = JOB_SEQ.load(Ordering::Relaxed);
    let observed = after != before;

    let (tag, stage, kind, errno, message, receiver) = match result {
        Ok(capture) => (0u64, 0u64, 0u64, 0u64, String::new(), Some(capture)),
        Err(error) => {
            let (kind, errno) = match error.error.raw_os_error() {
                Some(value) if (1..=4095).contains(&value) => (1, value as u64),
                None if error.error.kind() == io::ErrorKind::InvalidInput => (2, 0),
                _ => std::process::exit(70),
            };
            (1, error.stage, kind, errno, error.message, None)
        }
    };
    let (dir, id, stdout_path, stderr_path, stdout_fd, stderr_fd) = match &receiver {
        Some(capture) => (
            capture.dir.clone(), capture.id.clone(), capture.stdout_path.clone(),
            capture.stderr_path.clone(), capture.stdout_file.as_raw_fd() as u64,
            capture.stderr_file.as_raw_fd() as u64,
        ),
        None => {
            // Reuse only the exact original pure formatting statements for
            // error metadata. This performs no additional filesystem call or
            // fetch_add and is recorded as fixture observation, not prepare.
            let (dir, id, stdout_path, stderr_path) = metadata_projection(before, observed);
            (dir, id, stdout_path, stderr_path, u64::MAX, u64::MAX)
        }
    };
    let payloads: [&[u8]; 5] = [
        dir.as_os_str().as_bytes(), id.as_bytes(), stdout_path.as_os_str().as_bytes(),
        stderr_path.as_os_str().as_bytes(), message.as_bytes(),
    ];
    let total = 160usize + payloads.iter().map(|bytes| bytes.len()).sum::<usize>();
    let mut response = b"HSPPOR01".to_vec();
    for value in [total as u64, tag, stage, kind, errno, u64::from(observed), before,
        after, pid, stdout_fd, stderr_fd, payloads[0].len() as u64, payloads[1].len() as u64,
        payloads[2].len() as u64, payloads[3].len() as u64, payloads[4].len() as u64,
        u64::from(receiver.is_some()), 0, 0]
    {
        push(&mut response, value);
    }
    for bytes in payloads {
        response.extend_from_slice(bytes);
    }
    assert_eq!(response.len(), total);
    output.write_all(&response)?;
    output.flush()?;

    // The controller observes actual descriptor/inode custody before sending
    // this constant acknowledgement. It supplies no descriptor or result.
    let mut acknowledgement = [0u8; 8];
    input.read_exact(&mut acknowledgement)?;
    if &acknowledgement != b"HSPPOEND" {
        std::process::exit(64);
    }
    std::hint::black_box(&receiver);
    // Successful Files remain owned by receiver until kernel process exit.
    // There is deliberately no semantic DROP after successful publication.
    std::process::exit(0);
}

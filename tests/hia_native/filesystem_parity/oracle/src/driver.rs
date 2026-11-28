// Test-only framing, observations, and markers. The full local_linux module is
// prepended unchanged; no policy, SDK, async wrapper or cache is substituted.
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

fn word(input: &mut impl Read) -> u64 {
    let mut raw = [0; 8];
    input.read_exact(&mut raw).unwrap();
    u64::from_le_bytes(raw)
}

fn bytes(input: &mut impl Read, length: u64) -> Vec<u8> {
    let mut raw = vec![0; usize::try_from(length).unwrap()];
    input.read_exact(&mut raw).unwrap();
    raw
}

fn output_word(output: &mut impl Write, value: u64) {
    output.write_all(&value.to_le_bytes()).unwrap();
}

fn descriptors() -> Vec<[u64; 5]> {
    // Drop the observation directory iterator before querying descriptor IDs.
    // Its temporary FD must not be mistaken for a leaked original-operation FD.
    let mut ids = std::fs::read_dir("/proc/self/fd").unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().parse::<i32>().unwrap())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    let mut result = Vec::new();
    for id in ids {
        let flags = unsafe { libc::fcntl(id, libc::F_GETFD) };
        if flags < 0 { continue; }
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        assert_eq!(unsafe { libc::fstat(id, st.as_mut_ptr()) }, 0);
        let st = unsafe { st.assume_init() };
        result.push([id as u64, flags as u64, st.st_dev, st.st_ino, st.st_mode as u64]);
    }
    result
}

fn main() {
    let mut input = io::BufReader::new(io::stdin().lock());
    let mut output = io::BufWriter::new(io::stdout().lock());
    assert_eq!(bytes(&mut input, 8), b"HFPRI001");
    let count = word(&mut input);
    let prior_umask = unsafe { libc::umask(0o022) };
    output.write_all(b"HFPRO001").unwrap();
    for value in [count, unsafe { libc::getuid() } as u64, unsafe { libc::geteuid() } as u64,
                  unsafe { libc::getgid() } as u64, unsafe { libc::getegid() } as u64,
                  prior_umask as u64, 0o022] {
        output_word(&mut output, value);
    }
    output.flush().unwrap();
    for _ in 0..count {
        let case_id = word(&mut input);
        let operation = word(&mut input);
        let first_size = word(&mut input);
        let second_size = word(&mut input);
        let first = PathBuf::from(std::ffi::OsString::from_vec(bytes(&mut input, first_size)));
        let second = PathBuf::from(std::ffi::OsString::from_vec(bytes(&mut input, second_size)));
        assert!((1..=3).contains(&operation));
        if operation == 1 { assert_eq!(second_size, 0); }
        let before = descriptors();
        let marker = -1_700_000_000i32 + 2 * i32::try_from(case_id).unwrap();
        unsafe { libc::getpgid(marker); }
        let result = match operation {
            1 => local_linux::make_directories(&first).map(Some),
            2 => local_linux::move_noreplace(&first, &second).map(|_| None),
            3 => local_linux::move_directory_noreplace(&first, &second).map(|_| None),
            _ => unreachable!(),
        };
        unsafe { libc::getpgid(marker + 1); }
        let after = descriptors();
        let (status, created, errno_present, errno, short, chain) = match result {
            Ok(created) => (0, created.map_or(0, |v| if v { 2 } else { 1 }), 0, 0, Vec::new(), Vec::new()),
            Err(error) => {
                let os_errno = error.downcast_ref::<std::io::Error>().and_then(|e| e.raw_os_error());
                (1, 0, u64::from(os_errno.is_some()), os_errno.unwrap_or(0) as i64 as u64,
                 error.to_string().into_bytes(), format!("{error:#}").into_bytes())
            }
        };
        for value in [case_id, operation, status, created, errno_present, errno,
                      short.len() as u64, chain.len() as u64, before.len() as u64, after.len() as u64] {
            output_word(&mut output, value);
        }
        output.write_all(&short).unwrap();
        output.write_all(&chain).unwrap();
        for row in before.iter().chain(after.iter()) {
            for value in row { output_word(&mut output, *value); }
        }
        output.flush().unwrap();
    }
    let mut trailing = [0u8; 1];
    assert_eq!(input.read(&mut trailing).unwrap(), 0, "trailing oracle input");
}

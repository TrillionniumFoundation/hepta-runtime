"""Extract the unchanged SessionWorkdir and first-tool atomic latch for replay."""
from pathlib import Path
import hashlib

SERVER_BLOB = '90fe15fd6a998e9b165739bc27e6f3854022221d'

HEADER = '''// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original SessionWorkdir; binary framing and poison injection are test-only.
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStringExt, OsStrExt};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::sync::atomic::AtomicBool;
'''

ADAPTER = '''
struct State { workdir: SessionWorkdir, session_applied: AtomicBool }
impl State {
    fn first(&self) -> bool { !self.session_applied.LATCH }
    fn poison(&self) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.workdir.current.write().unwrap();
            panic!("actual original session RwLock poison fixture");
        }));
        assert!(outcome.is_err() && self.workdir.current.is_poisoned());
    }
}
fn word(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}
fn result(tag: u64, scalar: u64, raw: &[u8]) -> Vec<u8> {
    let mut bytes = b"HRSWR001".to_vec();
    for value in [tag, scalar, raw.len() as u64] { bytes.extend_from_slice(&value.to_le_bytes()); }
    bytes.extend_from_slice(raw);
    bytes
}
fn latch_test() {
    let state = Arc::new(State { workdir: SessionWorkdir::new(PathBuf::from("/root")),
        session_applied: AtomicBool::new(false) });
    let mut tasks = Vec::new();
    for _ in 0..64 { let s = state.clone(); tasks.push(std::thread::spawn(move || s.first())); }
    let values: Vec<bool> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(values.iter().filter(|v| **v).count(), 1);
    assert_eq!(values.iter().filter(|v| !**v).count(), 63);
    println!("{{\\"status\\":\\"PASS\\",\\"actual_threads\\":64,\\"first\\":1,\\"later\\":63}}");
}
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--latch-test") { latch_test(); return; }
    std::panic::set_hook(Box::new(|_| {}));
    let mut input = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut states: HashMap<u32, State> = HashMap::new();
    let mut rows = 0u64;
    let mut poisons = 0u64;
    loop {
        let mut header = [0u8; 8];
        match input.read(&mut header[..1]) {
            Ok(0) => break,
            Ok(1) => input.read_exact(&mut header[1..]).unwrap(),
            _ => panic!("original session input"),
        }
        let sid = u32::from_le_bytes(header[..4].try_into().unwrap());
        let n = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
        assert!((32..=(8 << 20) + 32).contains(&n));
        let mut bytes = vec![0u8; n]; input.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes[..8], b"HRSWQ001");
        let op = word(&bytes, 8);
        assert_eq!(word(&bytes, 16) as usize, n - 32);
        assert_eq!(word(&bytes, 24), 0);
        assert!((1..=6).contains(&op) && (op == 1 || op == 3 || n == 32));
        let body = &bytes[32..];
        if op == 1 {
            let state = State { workdir: SessionWorkdir::new(PathBuf::from(OsString::from_vec(body.to_vec()))),
                session_applied: AtomicBool::new(false) };
            assert!(states.insert(sid, state).is_none());
        }
        let state = states.get(&sid).unwrap();
        let response = match op {
            1 => result(0, 0, &[]),
            2 => result(1, 0, state.workdir.get_current().as_os_str().as_bytes()),
            3 => { state.workdir.set_current(PathBuf::from(OsString::from_vec(body.to_vec()))); result(0, 0, &[]) },
            4 => { state.workdir.reset(); result(0, 0, &[]) },
            5 => result(2, u64::from(state.first()), &[]),
            6 => { state.poison(); poisons += 1; result(0, 0, &[]) },
            _ => unreachable!(),
        };
        output.write_all(&(response.len() as u32).to_le_bytes()).unwrap();
        output.write_all(&response).unwrap(); rows += 1;
    }
    output.flush().unwrap();
    eprintln!("{{\\"status\\":\\"PASS\\",\\"rows\\":{rows},\\"sessions\\":{},\\"actual_poison_events\\":{poisons}}}", states.len());
}
'''

def original_parts(runtime: Path):
    raw = (runtime / 'src/mcp/server.rs').read_bytes()
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if blob != SERVER_BLOB:
        raise ValueError('original server differs from the pinned runtime baseline')
    text = raw.decode()
    start = text.index('#[derive(Debug)]\npub struct SessionWorkdir')
    body = text.index('impl SessionWorkdir {', start)
    depth = 1; end = body + len('impl SessionWorkdir {')
    while depth:
        c = text[end]; end += 1
        depth += (c == '{') - (c == '}')
    original = text[start:end]
    marker = '.swap(true, std::sync::atomic::Ordering::SeqCst)'
    context = text[text.index('fn ensure_session_workdir('):text.index('impl Default for OctofsServer')]
    if context.count(marker) != 1 or '.session_applied\n\t\t\t.swap' not in context:
        raise ValueError('original first-tool latch changed')
    return original, marker[1:]

def oracle_source(runtime: Path):
    body, latch = original_parts(runtime)
    return HEADER + body + '\n' + ADAPTER.replace('LATCH', latch)

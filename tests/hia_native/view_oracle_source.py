"""Assemble a test-only Rust harness around unchanged original view owners.

Filesystem and request-scope fixtures are explicit test inputs. The copied
functions below still perform their original calls, including two independent
reads and cache.set before execute_view's result-size refusal.
"""
from pathlib import Path


def function_source(text, name):
    start = text.index('fn ' + name + '(')
    start = text.rfind('\n', 0, start) + 1
    brace = text.index('{', start)
    at, depth = brace + 1, 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[start:at]


def oracle_source(repo: Path):
    core = (repo / 'src/mcp/fs/core.rs').read_text()
    file_ops = (repo / 'src/mcp/fs/file_ops.rs').read_text()
    delta = (repo / 'src/mcp/fs/delta.rs').read_text()
    truncation = (repo / 'src/utils/truncation.rs').read_text()
    line_hash = (repo / 'src/utils/line_hash.rs').read_text()
    server = (repo / 'src/mcp/server.rs').read_text()
    header = delta[:delta.index('//! Delta views')]
    helpers = '\n\n'.join(function_source(line_hash, name) for name in
        ['fnv1a_8', 'line_hash', 'line_id', 'line_id_at', 'resolve_line_index_clamped'])
    endpoint = line_hash[line_hash.index('#[derive(Debug, Clone, PartialEq, Eq)]\npub enum Endpoint'):
                         line_hash.index('/// Parse a JSON value into a line [`Endpoint`].')]
    range_functions = '\n\n'.join(function_source(core, name) for name in
        ['resolve_endpoint_to_line', 'resolve_view_range', 'execute_view'])
    file_functions = '\n\n'.join(function_source(file_ops, name) for name in
        ['format_file_content_with_numbers', 'view_file_spec'])
    original_delta = delta[:delta.index('#[cfg(test)]')]
    return header + r'''
// Test adapter only; every original function body is extracted byte-for-byte.
#![allow(dead_code)]
use std::cell::RefCell;
use std::future::Future;
use std::io::{self, BufRead, Write};
use std::pin::pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll, Wake, Waker};
type Result<T> = std::result::Result<T, String>;
macro_rules! anyhow { ($($arg:tt)*) => { format!($($arg)*) }; }
macro_rules! bail { ($($arg:tt)*) => { return Err(format!($($arg)*)) }; }

#[derive(Default)]
struct State {
    flags: u64, start: i64, end: i64, first: String, current: String,
    first_stat: u64, current_stat: u64, range_phase: bool,
    actual_read: bool, range: Option<(usize, i64)>, hints: Vec<String>,
    rendered: Option<String>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
static CACHE: LazyLock<mcp::fs::delta::ViewCache> = LazyLock::new(Default::default);

mod utils {
    pub mod line_hash {
''' + helpers + '\n' + endpoint + '\n}\npub mod truncation {\n' + truncation + r'''
}}

mod mcp {
    pub mod request_ctx {
        pub fn with_view_cache<F, T>(f: F) -> Option<T>
        where F: FnOnce(&super::fs::delta::ViewCache) -> T {
            if crate::STATE.with(|s| s.borrow().flags & 8 != 0) { Some(f(&crate::CACHE)) }
            else { None }
        }
        pub fn push_hint(text: &str) {
            crate::STATE.with(|s| { let mut s=s.borrow_mut();
                if s.flags & 8 != 0 { s.hints.push(text.to_owned()); }
            });
        }
        pub fn drain_hints() -> Vec<String> {
            crate::STATE.with(|s| std::mem::take(&mut s.borrow_mut().hints))
        }
    }
    pub mod fs {
        #[derive(Clone)] pub struct PathSource;
        pub struct Metadata { pub size: u64 }
        pub mod text_editing {
            pub fn lock_key_for_source(_: &super::PathSource) -> String { "fixture".to_owned() }
        }
        pub async fn io_exists(_: &PathSource) -> crate::Result<bool> { Ok(true) }
        pub async fn io_is_file(_: &PathSource) -> crate::Result<bool> { Ok(true) }
        pub async fn io_metadata(_: &PathSource) -> crate::Result<Metadata> {
            crate::STATE.with(|s| { let s=s.borrow();
                if s.range_phase {
                    if s.flags & 64 == 0 { Err("fixture metadata read failure".to_owned()) }
                    else { Ok(Metadata { size: s.first_stat }) }
                } else { Ok(Metadata { size: s.current_stat }) }
            })
        }
        pub async fn io_read_to_string(_: &PathSource) -> crate::Result<String> {
            crate::STATE.with(|s| { let mut s=s.borrow_mut();
                if s.range_phase {
                    if s.flags & 32 != 0 { Err("fixture first read failure".to_owned()) }
                    else { Ok(s.first.clone()) }
                } else { s.actual_read=true; Ok(s.current.clone()) }
            })
        }
        pub mod delta {
''' + original_delta + r'''
            // Test-only access to the unchanged original cache methods.
            pub fn reset(previous: Option<String>) {
                crate::CACHE.forget_all();
                if let Some(text)=previous { crate::CACHE.set("fixture".to_owned(),text); }
            }
            pub fn cached() -> Option<String> { crate::CACHE.get("fixture") }
        }
        pub mod file_ops {
            use super::{io_exists,io_is_file,io_metadata,io_read_to_string,PathSource};
            use crate::utils::truncation::format_content_with_line_numbers;
            use crate::Result;
            pub(crate) const MAX_VIEW_FILE_BYTES: u64 = 5 * 1024 * 1024;
''' + file_functions + r'''
        }
        pub mod core {
            use super::{file_ops,io_metadata,io_read_to_string,PathSource};
            use crate::utils::line_hash::{Endpoint,resolve_line_index_clamped};
            use crate::utils::truncation::{MAX_RESULT_BYTES,format_megabytes};
            use crate::Result;
            pub struct McpToolCall;
''' + range_functions + r'''
            // The scope of this oracle starts after endpoint parsing and path
            // routing; the actual original range and file functions still run.
            async fn render_view(_: &McpToolCall) -> Result<String> {
                let (flags,start,end)=crate::STATE.with(|s| {
                    let mut s=s.borrow_mut();s.range_phase=true;(s.flags,s.start,s.end)
                });
                let source=PathSource;
                let range=resolve_view_range(
                    if flags & 1 != 0 { Some(Endpoint::Number(start)) } else { None },
                    if flags & 2 != 0 { Some(Endpoint::Number(end)) } else { None },
                    &source).await;
                crate::STATE.with(|s| { let mut s=s.borrow_mut();s.range_phase=false;
                    if let Ok(value)=&range {s.range=*value;}
                });
                let result=file_ops::view_file_spec(&source,range?,flags & 4 != 0).await;
                crate::STATE.with(|s| {s.borrow_mut().rendered=result.as_ref().ok().cloned();});
                result
            }
        }
    }
}
use mcp::request_ctx;
''' + function_source(server, 'append_hints') + r'''

struct NoWake;
impl Wake for NoWake { fn wake(self: Arc<Self>) {} }
fn block_on<F: Future>(future: F) -> F::Output {
    let waker=Waker::from(Arc::new(NoWake));let mut cx=Context::from_waker(&waker);
    let mut future=pin!(future);
    match future.as_mut().poll(&mut cx) { Poll::Ready(result)=>result,
        Poll::Pending=>panic!("test fixture must not suspend") }
}
fn word(s: &[u8], at: usize) -> u64 {u64::from_le_bytes(s[at..at+8].try_into().unwrap())}
fn put(out: &mut Vec<u8>, value: u64) {out.extend_from_slice(&value.to_le_bytes());}
fn hex(raw: &[u8]) -> String {raw.iter().map(|v| format!("{v:02x}")).collect()}
fn unhex(s: &str) -> Vec<u8> {(0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).unwrap()).collect()}
fn apply(raw: &[u8]) -> Vec<u8> {
    assert_eq!(&raw[..8],b"HVIEW001");let operation=word(raw,8);let flags=word(raw,16);
    let a=word(raw,40) as usize;let b=word(raw,48) as usize;
    let first=std::str::from_utf8(&raw[96..96+a]).unwrap().to_owned();
    let current=std::str::from_utf8(&raw[96+a..96+a+b]).unwrap().to_owned();
    let previous=std::str::from_utf8(&raw[96+a+b..]).unwrap().to_owned();
    let first_stat=word(raw,64);let current_stat=word(raw,72);
    STATE.with(|s| *s.borrow_mut()=State {flags,start:word(raw,24) as i64,end:word(raw,32) as i64,
        first:first.clone(),current:current.clone(),first_stat,current_stat,..State::default()});
    mcp::fs::delta::reset(if flags & 16 != 0 {Some(previous.clone())} else {None});
    let result=block_on(mcp::fs::core::execute_view(&mcp::fs::core::McpToolCall));
    let (actual_read,range,hints,rendered)=STATE.with(|s| {let s=s.borrow();
        (s.actual_read,s.range,s.hints.clone(),s.rendered.clone())});
    let first_count=if flags & 3 != 0 && !(flags & 64 != 0 && first_stat > 5*1024*1024) && flags & 32 == 0 {
        first.lines().count() as u64
    } else {0};
    let current_count=if actual_read {current.lines().count() as u64} else {0};
    let normalized=if actual_read {current.replace("\r\n","\n")} else {String::new()};
    let action=if flags & 8 != 0 && actual_read && range.is_none() {
        if normalized.len() <= 1024*1024 {1} else {2}
    } else {0};
    if action==1 {assert_eq!(mcp::fs::delta::cached().as_ref(),Some(&normalized));}
    if action==2 {assert!(mcp::fs::delta::cached().is_none());}
    let mut kind=if !actual_read {
        if result.as_ref().err().unwrap().starts_with("File is too large") {5} else {6}
    } else if range.is_some() {4}
      else if flags & 24 == 24 && flags & 4 == 0 {if normalized==previous {1} else {2}}
      else {0};
    let mut status=if operation==1 {(!actual_read) as u64} else {result.is_err() as u64};
    let mut body=if operation==1 && actual_read {String::new()}
        else {match result {Ok(s)=>s,Err(e)=>e}};
    if operation==2 && actual_read {
        if let Some(text)=rendered {
            if text.len()>8*1024*1024 {kind=7;status=1;}
            else if kind==2 && text.starts_with("[changed since your last view: too many changes") {kind=3;}
        }
    }
    let body_size=body.len();
    let hint_mask=if status==0 {hints.iter().fold(0u64,|mask,h|mask|
        if h.starts_with("start was after end") {1} else {2})} else {0};
    if operation==2 && status==0 {body=append_hints(body);}
    let cached=if action==1 {normalized.as_bytes()} else {&[]};
    let mut out=b"HVIEWR01".to_vec();
    for value in [status,body.len() as u64,action,cached.len() as u64,range.is_some() as u64,
        range.map(|p|p.0 as u64).unwrap_or(0),range.map(|p|p.1 as u64).unwrap_or(0),
        first_count,current_count,hint_mask,kind,normalized.len() as u64,body_size as u64,0,0] {
        put(&mut out,value);
    }
    out.extend_from_slice(body.as_bytes());out.extend_from_slice(cached);out
}
fn main() {
    std::panic::set_hook(Box::new(|_|{}));
    let stdin=io::stdin();let mut out=io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let raw=unhex(&line.unwrap());
        match std::panic::catch_unwind(||apply(&raw)) {
            Ok(bytes)=>writeln!(&mut out,"OK {}",hex(&bytes)).unwrap(),
            Err(_)=>writeln!(&mut out,"PANIC").unwrap(),
        }
    }
}
'''


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    arguments.output.write_text(oracle_source(arguments.repo))

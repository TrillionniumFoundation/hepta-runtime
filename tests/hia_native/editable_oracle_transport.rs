
// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
// Test-only typed transport, appended to the complete unchanged original owner.
use std::io::{self, BufRead, Write};
fn word(raw: &[u8], at: usize) -> u64 { u64::from_le_bytes(raw[at..at+8].try_into().unwrap()) }
fn unhex(text: &str) -> Vec<u8> { (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at+2],16).unwrap()).collect() }
fn hex(raw: &[u8]) -> String { raw.iter().map(|v| format!("{v:02x}")).collect() }
fn apply(raw: &[u8]) -> Vec<u8> {
    assert_eq!(&raw[..8], b"HEDIT001");
    let mode = word(raw,8); let rawlen=word(raw,16) as usize; let count=word(raw,24);
    let mut owner = EditableContent::from_raw(std::str::from_utf8(&raw[48..48+rawlen]).unwrap());
    let mut at=48+rawlen; let mut done=0u64; let mut message=String::new();
    for _ in 0..count {
        let op=word(raw,at);let a=word(raw,at+8) as usize;let b=word(raw,at+16);let size=word(raw,at+24) as usize;
        let text=std::str::from_utf8(&raw[at+32..at+32+size]).unwrap();
        let result = match op {
            1 => owner.insert_lines(a,&incoming_content_lines(text),b!=0),
            2 => owner.replace_normalized_range(a,b as usize,text),
            3 => {owner.preserve_trailing_newline();Ok(())},
            _ => panic!("bad operation")
        };
        match result { Ok(()) => done+=1, Err(error) => {message=error.to_string();break;} }
        at+=32+size;
    }
    let normalized=owner.normalized();let rendered=owner.rendered();
    let body=if mode==0 {rendered.as_bytes()} else {normalized.as_bytes()};
    let mut out=b"HEDRES01".to_vec();
    for value in [(!message.is_empty()) as u64,done,owner.dominant_ending.len() as u64,owner.had_trailing_newline as u64,
        owner.lines.len() as u64,normalized.len() as u64,rendered.len() as u64,body.len() as u64,message.len() as u64] {
        out.extend(value.to_le_bytes());
    }
    out.extend(body);out.extend(message.as_bytes());out
}
fn main() {
    let stdin=io::stdin();let mut out=io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {writeln!(&mut out,"OK {}",hex(&apply(&unhex(&line.unwrap())))).unwrap();}
}

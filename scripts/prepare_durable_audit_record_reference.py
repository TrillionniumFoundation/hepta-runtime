# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Prepare an exact original audit Record oracle, never a runtime fallback."""
from pathlib import Path
import argparse, hashlib, json, re, shutil
SHA=lambda x:hashlib.sha256(x).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--template",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    raw=(a.source/"src/mcp/runtime/request_audit.rs").read_bytes()
    if SHA(raw)!="b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da":
        raise ValueError("fixed original audit source differs")
    text=raw.decode()
    state=text[text.index("#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]"):text.index("\nmod record_schema")]
    schema=text[text.index("mod record_schema {"):text.index("\n/// The private owner")]
    def function(name):
        start=text.index("fn "+name+"(")
        end=text.index("\n}",start)+2
        return text[start:end]
    valid_id=function("valid_id");valid_tool=function("valid_tool")
    body_start=text.index("\tlet record: Record = serde_json::from_slice(&bytes)?;",text.index("fn read_record("))
    body_end=text.index("\n}",body_start)
    tail=text[body_start:body_end]
    harness=RUST.replace("ORIGINAL_ENUM",state).replace("ORIGINAL_SCHEMA",schema).replace("ORIGINAL_VALID_ID",valid_id).replace("ORIGINAL_VALID_TOOL",valid_tool).replace("ORIGINAL_READ_TAIL",tail)
    shutil.copytree(a.template,a.output)
    d=a.output/"audit_record";d.mkdir()
    (d/"oracle.rs").write_text(harness)
    manifest=a.output/"Cargo.toml"
    with manifest.open("a") as stream:stream.write('\n[[bin]]\nname="hia-durable-audit-record-original"\npath="audit_record/oracle.rs"\n')
    blocks=[]
    for label,segment in [("DurableState",state),("Record",schema),("valid_id",valid_id),("valid_tool",valid_tool),("read_record_tail",tail)]:
        assert text.count(segment)==1 and harness.count(segment)==1
        blocks.append(dict(name=label,source_offset=raw.index(segment.encode()),target_offset=harness.encode().index(segment.encode()),bytes=len(segment.encode()),sha256=SHA(segment.encode())))
    original={"path":"src/mcp/runtime/request_audit.rs","sha256":SHA(raw),"bytes":len(raw)}
    (d/"original-request-audit.rs").write_bytes(raw)
    record=dict(schema="hepta.runtime.durable-audit-original-reference.v1",original=original,blocks=blocks,
                original_lock_sha256=SHA((a.template/"Cargo.lock").read_bytes()),
                lock_unchanged=(a.template/"Cargo.lock").read_bytes()==(a.output/"Cargo.lock").read_bytes(),
                oracle_sha256=SHA(harness.encode()),template_manifest_sha256=SHA((a.template/"Cargo.toml").read_bytes()),
                actual_manifest_sha256=SHA(manifest.read_bytes()))
    (a.output/"audit-record-reference.json").write_text(json.dumps(record,sort_keys=True,indent=2)+"\n")
    print(json.dumps(record,sort_keys=True))
RUST=r'''use serde::{Deserialize, Serialize};
use anyhow::{bail, Result};
use std::io::{Read, Write};
ORIGINAL_ENUM
ORIGINAL_SCHEMA
ORIGINAL_VALID_ID
ORIGINAL_VALID_TOOL
fn original_record(filename: &str, bytes: &[u8]) -> Result<Record> {
ORIGINAL_READ_TAIL
}
fn word(raw: &[u8], at: usize) -> u64 {u64::from_le_bytes(raw[at..at+8].try_into().unwrap())}
fn put(raw: &mut [u8], at: usize, value: u64) {raw[at..at+8].copy_from_slice(&value.to_le_bytes());}
fn diagnostic(value: u64) -> Vec<u8> {
 let mut out=vec![0;32];out[..8].copy_from_slice(b"HRAJR001");put(&mut out,8,value);out
}
fn run(frame: &[u8]) -> Vec<u8> {
 assert!(frame.len()>=32 && &frame[..8]==b"HRAJQ001");
 let op=word(frame,8);let size=word(frame,16) as usize;let fsize=word(frame,24) as usize;
 assert!(op==1 || op==2);assert_eq!(fsize,if op==1 {0} else {69});assert_eq!(frame.len(),32+fsize+size);
 let filename=if op==2 {
  let Ok(name)=std::str::from_utf8(&frame[32..32+fsize]) else {return diagnostic(4)};
  let Some(id)=name.strip_suffix(".json") else {return diagnostic(4)};
  if !valid_id(id) {return diagnostic(4)};name
 } else {""};
 if size>2048 {return diagnostic(3)}
 let json=&frame[32+fsize..];
 let parsed: Record=match serde_json::from_slice(json) {Ok(value)=>value,Err(_)=>return diagnostic(1)};
 if op==2 && original_record(filename,json).is_err(){return diagnostic(2)}
 let fields=[parsed.request_id.as_bytes(),parsed.owner.as_bytes(),parsed.tool_name.as_bytes()];
 let mut out=vec![0;128+fields.iter().map(|s|s.len()).sum::<usize>()];
 out[..8].copy_from_slice(b"HRAJR001");
 put(&mut out,16,match parsed.state {DurableState::Unknown=>0,DurableState::Completed=>1,DurableState::Failed=>2});
 put(&mut out,24,parsed.accepted_unix_ms as u64);put(&mut out,32,(parsed.accepted_unix_ms>>64)as u64);
 put(&mut out,40,if parsed.elapsed_ms.is_some(){1}else{0});put(&mut out,48,parsed.elapsed_ms.unwrap_or(0));
 let n=out.len();put(&mut out,56,n as u64);
 let mut at=128;
 for(i,field)in fields.iter().enumerate(){put(&mut out,64+i*16,at as u64);put(&mut out,72+i*16,field.len()as u64);out[at..at+field.len()].copy_from_slice(field);at+=field.len();}
 out
}
fn main() -> std::io::Result<()> {
 let mut input=std::io::stdin().lock();let mut output=std::io::stdout().lock();
 loop {let mut head=[0u8;4];match input.read_exact(&mut head){Ok(())=>{},Err(e)if e.kind()==std::io::ErrorKind::UnexpectedEof=>break,Err(e)=>return Err(e)}
 let size=u32::from_le_bytes(head) as usize;assert!(size<=1<<20);let mut raw=vec![0;size];input.read_exact(&mut raw)?;
 let response=run(&raw);output.write_all(&(response.len()as u32).to_le_bytes())?;output.write_all(&response)?;
 } output.flush()
}
''';
if __name__=="__main__":main()

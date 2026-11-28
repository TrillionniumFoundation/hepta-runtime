# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Freeze complete original audit descriptor functions as an independent oracle."""
from pathlib import Path
import argparse,hashlib,json
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--project",type=Path,required=True);a=p.parse_args()
 raw=(a.source/"src/mcp/runtime/request_audit.rs").read_bytes()
 if SHA(raw)!="b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da":raise ValueError("original audit whole source differs")
 text=raw.decode();parts={}
 parts["enum"]=text[text.index("#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]"):text.index("\nmod record_schema")]
 parts["schema"]=text[text.index("mod record_schema {"):text.index("\n/// The private owner")]
 for name in("valid_id","valid_tool","name","open_at","open_at_component","validate_file","read_record","directory_scan_result","scan_errno","walk_directory","walk_directory_with_inode","cleanup_staging"):
  start=text.index("fn "+name+"(");end=text.index("\n}",start)+2;parts[name]=text[start:end]
 body="\n\n".join(parts.values());oracle=RUST.replace("ORIGINAL_COMPLETE_FUNCTIONS",body)
 d=a.project/"audit_record_io";d.mkdir(exist_ok=False);(d/"oracle.rs").write_text(oracle);(d/"original-request-audit.rs").write_bytes(raw)
 m=a.project/"Cargo.toml";before=m.read_bytes();lock=(a.project/"Cargo.lock").read_bytes()
 with m.open("a")as f:f.write('\n[[bin]]\nname="hia-durable-audit-record-io-original"\npath="audit_record_io/oracle.rs"\n')
 blocks=[]
 for name,value in parts.items():
  assert text.count(value)==1 and oracle.count(value)==1
  blocks.append(dict(name=name,bytes=len(value.encode()),sha256=SHA(value.encode()),source_offset=raw.index(value.encode()),target_offset=oracle.encode().index(value.encode())))
 proof=dict(schema="hepta.runtime.durable-audit-record-io-original.v1",original_sha256=SHA(raw),oracle_sha256=SHA(oracle.encode()),complete_blocks=blocks,lock_sha256=SHA(lock),manifest_before_sha256=SHA(before),manifest_after_sha256=SHA(m.read_bytes()),scope="complete original read_record, cleanup_staging, open/scan/validation and Record functions; supplied held private directory")
 assert(a.project/"Cargo.lock").read_bytes()==lock
 (d/"source-relation.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n");print(json.dumps(proof,sort_keys=True))
RUST=r'''use anyhow::{anyhow,bail,Result};
use serde::{Deserialize,Serialize};
use std::fs::File;
use std::io::{Read,Write,BufRead};
use std::os::fd::AsRawFd;
const MAX_RECORD_BYTES:usize=2048;
ORIGINAL_COMPLETE_FUNCTIONS
fn original_run(value:&serde_json::Value)->Result<Option<Record>> {
 let directory=File::open(value["directory"].as_str().unwrap())?;
 if value["preseek"].as_bool()==Some(true) {
  let mut bytes=[0u8;32768];
  loop {let n=unsafe{libc::syscall(libc::SYS_getdents64,directory.as_raw_fd(),bytes.as_mut_ptr(),bytes.len())};if n==0{break}if n<0{return Err(std::io::Error::last_os_error().into())}}
 }
 let filename=value["filename"].as_str().unwrap();
 if value["operation"].as_u64()==Some(1){read_record(&directory,filename).map(Some)}
 else {cleanup_staging(&directory,filename)?;Ok(None)}
}
fn response(value:&serde_json::Value)->serde_json::Value {
 match original_run(value) {
  Ok(record)=>serde_json::json!({"diagnostic":0,"errno":0,"record_json":record.as_ref().map(|r|serde_json::to_string(r).unwrap())}),
  Err(error)=>{
   let (diagnostic,number)=if let Some(e)=error.downcast_ref::<std::io::Error>(){(23,e.raw_os_error().unwrap_or(0))}
   else if error.downcast_ref::<serde_json::Error>().is_some(){(1,0)}
   else if error.downcast_ref::<std::str::Utf8Error>().is_some(){(25,0)}
   else {let n=match error.to_string().as_str() {
    "invalid request metadata filename"=>4,
    "request audit metadata identity refused"=>2,
    "request audit metadata size refused"=>3,
    "private request audit inode refused"=>16,
    "audit staging inode refused"=>17,
    "audit staging hard-link binding refused"=>18,
    "unexpected private audit staging entry"=>24,
    "unexpected private audit staging identity"=>27,
    _=>panic!("unmapped original error: {error:#}")
   };(n,0)};
   serde_json::json!({"diagnostic":diagnostic,"errno":number,"record_json":null,"original_error":format!("{error:#}")})
  }
 }
}
fn main()->std::io::Result<()> {
 let mut output=std::io::stdout().lock();
 for line in std::io::stdin().lock().lines(){
  let line=line?;let value:serde_json::Value=serde_json::from_str(&line).unwrap();
  let result=response(&value);writeln!(output,"{}",serde_json::to_string(&result).unwrap())?;output.flush()?;
 }
 Ok(())
}
''';
if __name__=="__main__":main()

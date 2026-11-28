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
 for name in("name","open_at","open_at_component","private_directory","private_directory_metadata","open_store","open_existing_store_at","open_named_store","open_named_store_at","audit_root"):
  start=text.index("fn "+name+"(");end=text.index("\n}",start)+2;parts[name]=text[start:end]
 body="\n\n".join(parts.values());oracle=RUST.replace("ORIGINAL_COMPLETE_FUNCTIONS",body)
 d=a.project/"audit_root";d.mkdir(exist_ok=False);(d/"oracle.rs").write_text(oracle);(d/"original-request-audit.rs").write_bytes(raw)
 m=a.project/"Cargo.toml";before=m.read_bytes();lock=(a.project/"Cargo.lock").read_bytes()
 with m.open("a")as f:f.write('\n[[bin]]\nname="hia-durable-audit-root-original"\npath="audit_root/oracle.rs"\n')
 blocks=[]
 for name,value in parts.items():
  assert text.count(value)==1 and oracle.count(value)==1
  blocks.append(dict(name=name,bytes=len(value.encode()),sha256=SHA(value.encode()),source_offset=raw.index(value.encode()),target_offset=oracle.encode().index(value.encode())))
 proof=dict(schema="hepta.runtime.durable-audit-root-original.v1",original_sha256=SHA(raw),oracle_sha256=SHA(oracle.encode()),complete_blocks=blocks,lock_sha256=SHA(lock),manifest_before_sha256=SHA(before),manifest_after_sha256=SHA(m.read_bytes()),scope="complete original audit_root, private directory and hot open/create/readonly functions; root bytes are supplied from the private configuration domain")
 assert(a.project/"Cargo.lock").read_bytes()==lock
 (d/"source-relation.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n");print(json.dumps(proof,sort_keys=True))
RUST=r'''use anyhow::{anyhow,bail,Result};
use std::fs::File;
use std::path::{Path,PathBuf};
use std::io::{Write,BufRead};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
const STORE_NAME:&str="request-audit";
ORIGINAL_COMPLETE_FUNCTIONS
fn original_run(value:&serde_json::Value)->Result<Option<File>> {
 let hex=value["root_hex"].as_str().unwrap();let mut raw=Vec::new();
 for n in(0..hex.len()).step_by(2){raw.push(u8::from_str_radix(&hex[n..n+2],16).unwrap());}
 let root=PathBuf::from(std::ffi::OsString::from_vec(raw));
 match value["operation"].as_u64().unwrap(){
  1=>audit_root(&root).map(Some),
  2=>open_store(&root).map(Some),
  3=>{let base=audit_root(&root)?;open_existing_store_at(&base)},
  _=>panic!("invalid qualification operation")
 }
}
fn response(value:&serde_json::Value)->serde_json::Value {
 match original_run(value) {
  Ok(file)=>{
   let metadata=file.as_ref().map(|f|{
    let s=f.metadata().unwrap();
    vec![s.mode()as u64,s.uid()as u64,unsafe{libc::geteuid()}as u64,s.nlink(),s.len(),s.dev(),s.ino(),s.mtime()as u64,s.mtime_nsec()as u64,s.ctime()as u64,s.ctime_nsec()as u64]
   });
   serde_json::json!({"diagnostic":0,"errno":0,"present":file.is_some(),"metadata":metadata})
  },
  Err(error)=>{
   let(diagnostic,number)=if let Some(e)=error.downcast_ref::<std::io::Error>(){(23,e.raw_os_error().unwrap_or(0))}
   else{let n=match error.to_string().as_str(){
    "request audit root is not UTF-8"=>10,
    "invalid request audit root"=>11,
    "request audit ancestor is not searchable"=>12,
    "invalid private metadata component"=>13,
    "private request audit directory refused"=>14,
    _=>panic!("unmapped original error: {error:#}")
   };(n,0)};
   serde_json::json!({"diagnostic":diagnostic,"errno":number,"present":false,"metadata":null,"original_error":format!("{error:#}")})
  }
 }
}
fn main()->std::io::Result<()>{
 let mut out=std::io::stdout().lock();
 for line in std::io::stdin().lock().lines(){
  let line=line?;let value:serde_json::Value=serde_json::from_str(&line).unwrap();
  writeln!(out,"{}",serde_json::to_string(&response(&value)).unwrap())?;out.flush()?;
 }
 Ok(())
}
''';
if __name__=="__main__":main()

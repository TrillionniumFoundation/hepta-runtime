# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Derive complete original audit page functions for an independent policy oracle."""
from pathlib import Path
import argparse, hashlib, json
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--project",type=Path,required=True);a=p.parse_args()
 raw=(a.source/"src/mcp/runtime/request_audit.rs").read_bytes()
 if SHA(raw)!="b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da":raise ValueError("fixed original audit differs")
 text=raw.decode()
 def fn(name):
  start=text.index("fn "+name+"(");end=text.index("\n}",start)+2;return text[start:end]
 enum=text[text.index("#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]"):text.index("\nmod record_schema")]
 schema=text[text.index("mod record_schema {"):text.index("\n/// The private owner")]
 params=text[text.index("#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]"):text.index("\n#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]")]
 sort_start=text.index("\tresult.sort_by(",text.index("fn entries_bounded("));sort_end=text.index("\n\tOk(result)",sort_start)
 parts={"ENUM":enum,"SCHEMA":schema,"PARAMS":params,"VALID_ID":fn("valid_id"),"HISTORY":fn("history_at"),"ARCHIVE":fn("archive_page_output"),"WIRE_SIZE":fn("wire_size"),"SORT":text[sort_start:sort_end]}
 result=RUST
 for key,value in parts.items():result=result.replace("ORIGINAL_"+key,value)
 d=a.project/"audit_page";d.mkdir(exist_ok=False)
 (d/"oracle.rs").write_text(result);(d/"original-request-audit.rs").write_bytes(raw)
 manifest=a.project/"Cargo.toml";before=manifest.read_bytes();lock=(a.project/"Cargo.lock").read_bytes()
 with manifest.open("a")as stream:stream.write('\n[[bin]]\nname="hia-durable-audit-page-original"\npath="audit_page/oracle.rs"\n')
 proof={"schema":"hepta.runtime.durable-audit-page-original.v1","original_sha256":SHA(raw),"oracle_sha256":SHA(result.encode()),"lock_sha256":SHA(lock),"manifest_before_sha256":SHA(before),"manifest_after_sha256":SHA(manifest.read_bytes()),"scope":"Exact original history_at/archive_page_output/wire_size; fixture providers supply private validated rows and active state; does not qualify filesystem or public routing"}
 proof["complete_blocks"]=[]
 for name,value in parts.items():
  assert text.count(value)==1 and result.count(value)==1
  proof["complete_blocks"].append(dict(name=name,source_offset=raw.index(value.encode()),target_offset=result.encode().index(value.encode()),bytes=len(value.encode()),sha256=SHA(value.encode())))
 (d/"source-relation.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
 assert (a.project/"Cargo.lock").read_bytes()==lock
 print(json.dumps(proof,sort_keys=True))
RUST=r'''use anyhow::{anyhow,bail,Result};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use rmcp::schemars;
use std::{path::Path,time::{Instant,Duration},collections::HashSet,cell::RefCell,io::{Read,Write}};
const MAX_GLOBAL:usize=512;
const MAX_OWNER:usize=128;
const MAX_PAGE_BYTES:usize=64*1024;
ORIGINAL_ENUM
ORIGINAL_SCHEMA
ORIGINAL_PARAMS
ORIGINAL_VALID_ID
thread_local! {static ROWS:RefCell<Vec<Record>>=const{RefCell::new(Vec::new())};static ACTIVE:RefCell<HashSet<String>>=RefCell::new(HashSet::new());}
fn store_lock()->Result<()>{Ok(())}
fn open_store(_root:&Path)->Result<()>{Ok(())}
fn entries(_directory:&())->Result<Vec<Record>>{
 let mut result=ROWS.with(|r|r.borrow().clone());
ORIGINAL_SORT
 Ok(result)
}
fn is_dispatch_active(id:&str)->Result<bool>{Ok(ACTIVE.with(|r|r.borrow().contains(id)))}
#[derive(Debug)]struct MetadataQueryDeadline;
impl std::fmt::Display for MetadataQueryDeadline {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{write!(f,"archive metadata query total deadline exceeded")}}
impl std::error::Error for MetadataQueryDeadline{}
ORIGINAL_WIRE_SIZE
ORIGINAL_HISTORY
ORIGINAL_ARCHIVE
fn word(raw:&[u8],at:usize)->u64{u64::from_le_bytes(raw[at..at+8].try_into().unwrap())}
fn string(raw:&[u8],at:usize,len:usize)->String{std::str::from_utf8(&raw[at..at+len]).unwrap().to_owned()}
fn response(diag:u64,value:&[u8])->Vec<u8>{
 let mut out=vec![0;32+value.len()];out[..8].copy_from_slice(b"HRAQR001");out[8..16].copy_from_slice(&diag.to_le_bytes());
 if diag==0 {out[16..24].copy_from_slice(&(value.len()as u64).to_le_bytes());let n=out.len()as u64;out[24..32].copy_from_slice(&n.to_le_bytes());out[32..].copy_from_slice(value)}
 out
}
fn run(frame:&[u8])->Vec<u8>{
 assert!(frame.len()>=192&&&frame[..8]==b"HRAQP001");
 let op=word(frame,8);let n=word(frame,16)as usize;let limit=word(frame,24);let after=word(frame,32);
 assert!(op==1||op==2);assert_eq!(frame.len(),192+256*n);
 let owner=string(frame,64,64);let cursor=if after==1{Some(string(frame,128,64))}else{None};
 let mut records=Vec::new();let mut active=HashSet::new();
 for i in 0..n {let at=192+i*256;let id=string(frame,at,64);
 if word(frame,at+240)==1{active.insert(id.clone());}
 records.push(Record{request_id:id,owner:string(frame,at+64,64),tool_name:string(frame,at+128,word(frame,at+192)as usize),state:match word(frame,at+200){0=>DurableState::Unknown,1=>DurableState::Completed,2=>DurableState::Failed,_=>panic!("private state")},accepted_unix_ms:word(frame,at+208)as u128|((word(frame,at+216)as u128)<<64),elapsed_ms:if word(frame,at+224)==1{Some(word(frame,at+232))}else{None}});
 }
 ROWS.with(|r|*r.borrow_mut()=records.clone());ACTIVE.with(|r|*r.borrow_mut()=active);
 let value=std::panic::catch_unwind(||{
  if op==1{history_at(Path::new("private-fixture-not-opened"),&owner,RequestHistoryParams{after_id:cursor,limit:Some(limit.try_into().unwrap())})}
  else{let deadline=if word(frame,48)>=word(frame,56){Instant::now()-Duration::from_nanos(1)}else{Instant::now()+Duration::from_secs(3)};archive_page_output(records,word(frame,40),limit as usize,deadline)}
 });
 match value{
  Ok(Ok(text))=>response(0,text.as_bytes()),
  Ok(Err(e))=>response(if e.is::<MetadataQueryDeadline>(){4}else if e.to_string()=="request history cursor expired or unavailable to this session"{2}else{1},&[]),
  Err(_)=>response(3,&[])
 }
}
fn main()->std::io::Result<()>{
 let mut input=std::io::stdin().lock();let mut output=std::io::stdout().lock();
 loop{let mut prefix=[0;4];match input.read_exact(&mut prefix){Ok(())=>{},Err(e)if e.kind()==std::io::ErrorKind::UnexpectedEof=>break,Err(e)=>return Err(e)}
 let n=u32::from_le_bytes(prefix)as usize;assert!(n<=192+512*256);let mut raw=vec![0;n];input.read_exact(&mut raw)?;let result=run(&raw);
 output.write_all(&(result.len()as u32).to_le_bytes())?;output.write_all(&result)?;}output.flush()
}
''';
if __name__=="__main__":main()

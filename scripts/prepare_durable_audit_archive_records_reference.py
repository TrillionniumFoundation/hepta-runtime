# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Append observation-only anchor type reachability to the verified full abc9 graph."""
from pathlib import Path
import argparse,ast,hashlib,json
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
PINS={"Cargo.toml":"9d95c6f534a0a5cd1b21dde659ebe2ed02c0ba7d52d5bc792118ec32d615ff14",
"Cargo.lock":"b868d2529f17dfb78ba390e078eb281a98d9850e4eaa12245739fec43ec97823",
"src/mcp/runtime/request_audit.rs":"b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da",
"src/mcp/runtime/request_archive_store.rs":"efecc499d8032f06230e5048dfe2daf65d74560ab171aed707c187653e511c48"}
STORE_APPEND=r'''
// Qualification only: original derives parse the original byte slice directly.
fn __hia_anchor_wire(kind:u64, format:u32, root:Identity, legacy:Identity,
 archive:Option<Identity>, shards:&[Identity])->Vec<u8>{
 let mut words=vec![u64::from_le_bytes(*b"HRAATR01"),0,kind,128+16*shards.len()as u64,
  format as u64,root[0],root[1],legacy[0],legacy[1],archive.is_some()as u64,
  archive.unwrap_or([0,0])[0],archive.unwrap_or([0,0])[1],shards.len()as u64,0,0,0];
 for item in shards {words.extend_from_slice(item);}
 words.into_iter().flat_map(u64::to_le_bytes).collect()
}
fn __hia_anchor_hex(bytes:&[u8])->String{
 bytes.iter().map(|b|format!("{b:02x}")).collect()
}
fn __hia_anchor_error(diagnostic:u64,error:String)->serde_json::Value{
 let mut words=vec![u64::from_le_bytes(*b"HRAATR01"),diagnostic,0,0];
 let wire:Vec<u8>=words.drain(..).flat_map(u64::to_le_bytes).collect();
 serde_json::json!({"diagnostic":diagnostic,"wire_hex":__hia_anchor_hex(&wire),"original_error":error})
}
pub(super) fn __hia_archive_anchor_original(kind:u64, raw:&[u8])->serde_json::Value{
 if raw.len()>if kind==1{MAX_RECORD_BYTES}else{MAX_ANCHOR_BYTES}{
  return __hia_anchor_error(2,"outside unchanged original file read bound".into());
 }
 match kind {
  1=>match serde_json::from_slice::<ArchiveAnchor>(raw){
   Ok(value)=>{
    let wire=__hia_anchor_wire(kind,0,[value.root_device,value.root_inode],
     [value.archive_device,value.archive_inode],None,&[]);
    serde_json::json!({"diagnostic":0,"wire_hex":__hia_anchor_hex(&wire),"canonical":serde_json::to_string(&value).unwrap()})
   },
   Err(error)=>__hia_anchor_error(1,error.to_string()),
  },
  2=>match serde_json::from_slice::<ShardAnchor>(raw){
   Ok(value)=>{
    let wire=__hia_anchor_wire(kind,value.format,value.root,value.legacy,Some(value.archive),&value.shards);
    serde_json::json!({"diagnostic":0,"wire_hex":__hia_anchor_hex(&wire),"canonical":serde_json::to_string(&value).unwrap()})
   },
   Err(error)=>__hia_anchor_error(1,error.to_string()),
  },
  3=>match serde_json::from_slice::<InitIntent>(raw){
   Ok(value)=>{
    let wire=__hia_anchor_wire(kind,value.format,value.root,value.legacy,value.archive,&value.shards);
    serde_json::json!({"diagnostic":0,"wire_hex":__hia_anchor_hex(&wire),"canonical":serde_json::to_string(&value).unwrap()})
   },
   Err(error)=>__hia_anchor_error(1,error.to_string()),
  },
  _=>panic!("qualification supplied an unknown kind"),
 }
}
'''
AUDIT_APPEND=r'''
// Observation-only public reachability; no original policy function is changed.
#[doc(hidden)]
pub fn __hia_durable_archive_records_original(value:&serde_json::Value)->serde_json::Value{
 let encoded=value["raw_hex"].as_str().unwrap();
 let raw:Vec<u8>=(0..encoded.len()).step_by(2).map(|i|u8::from_str_radix(&encoded[i..i+2],16).unwrap()).collect();
 archive_store::__hia_archive_anchor_original(value["kind"].as_u64().unwrap(),&raw)
}
'''
BIN=r'''use std::io::{BufRead,Write};
fn main()->std::io::Result<()>{
 let mut output=std::io::stdout().lock();
 for line in std::io::stdin().lock().lines(){
  let line=line?;
  let value:serde_json::Value=serde_json::from_str(&line).unwrap();
  let result=hepta_runtime::mcp::runtime::request_audit::__hia_durable_archive_records_original(&value);
  writeln!(output,"{}",serde_json::to_string(&result).unwrap())?;
  output.flush()?;
 }
 Ok(())
}
'''
def main():
 p=argparse.ArgumentParser();p.add_argument("--project",type=Path,required=True);p.add_argument("--history-preparer",type=Path,required=True);a=p.parse_args();root=a.project
 prior=root/"audit_current_history"
 originals={n:(prior/("original-"+n.replace("/","__"))).read_bytes()for n in list(PINS)[:3]}
 originals["src/mcp/runtime/request_archive_store.rs"]=(root/"src/mcp/runtime/request_archive_store.rs").read_bytes()
 for n,raw in originals.items():assert SHA(raw)==PINS[n],n
 history=a.history_preparer.read_bytes();assert SHA(history)=="844713331bb1b0ea0713cfc57622f0f363767f38dcb986b408c2d01cf35892ae"
 appends=[ast.literal_eval(n.value)for n in ast.parse(history).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=="APPEND"for t in n.targets)]
 assert len(appends)==1
 expected_manifest=originals["Cargo.toml"]+b'\n[[bin]]\nname = "hia-durable-audit-history-original"\npath = "audit_current_history/oracle.rs"\n'
 assert(root/"Cargo.toml").read_bytes()==expected_manifest
 assert(root/"src/mcp/runtime/request_audit.rs").read_bytes()==originals["src/mcp/runtime/request_audit.rs"]+appends[0].encode()
 assert(root/"Cargo.lock").read_bytes()==originals["Cargo.lock"]
 q=root/"audit_archive_records";q.mkdir(exist_ok=False)
 before={n:(root/n).read_bytes()for n in PINS}
 for n,raw in before.items():(q/("before-"+n.replace("/","__"))).write_bytes(raw)
 (q/"oracle.rs").write_text(BIN)
 for n,append in [("src/mcp/runtime/request_archive_store.rs",STORE_APPEND),("src/mcp/runtime/request_audit.rs",AUDIT_APPEND)]:
  with(root/n).open("ab")as f:f.write(append.encode())
 with(root/"Cargo.toml").open("ab")as f:f.write(b'\n[[bin]]\nname = "hia-durable-archive-records-original"\npath = "audit_archive_records/oracle.rs"\n')
 for n,raw in before.items():assert(root/n).read_bytes().startswith(raw),n
 assert(root/"Cargo.lock").read_bytes()==originals["Cargo.lock"]
 report=dict(schema="hepta.runtime.durable-archive-original-types.v1",original_commit="abc9ecb95ee9538518ec3f36c47b881974107021",
 original=PINS,before={n:dict(bytes=len(raw),sha256=SHA(raw))for n,raw in before.items()},
 after={n:dict(bytes=len(raw),sha256=SHA(raw))for n in PINS for raw in[(root/n).read_bytes()]},
 original_functions_whole_bytes_preserved=True,original_derive_macros_used=True,graph_profile_default_features_unchanged=True,
 append_sha256={"audit":SHA(AUDIT_APPEND.encode()),"store":SHA(STORE_APPEND.encode()),"bin":SHA(BIN.encode())},
 scope="raw JSON bytes parsed by original ArchiveAnchor, ShardAnchor and InitIntent in complete original library; original bounded file lengths applied separately; no filesystem or v12 admission policy replacement")
 (q/"source-relation.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":main()

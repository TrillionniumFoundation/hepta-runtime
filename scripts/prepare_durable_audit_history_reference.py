# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Append an observation-only bin to the complete original locked Runtime tree.

No original Rust function, dependency, feature or release profile is replaced.
The additional private-root/active-marker fixture calls original history_at.
"""
from pathlib import Path
import argparse,hashlib,json
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
AUDIT="b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da"
MANIFEST="9d95c6f534a0a5cd1b21dde659ebe2ed02c0ba7d52d5bc792118ec32d615ff14"
LOCK="b868d2529f17dfb78ba390e078eb281a98d9850e4eaa12245739fec43ec97823"
APPEND=r'''
// Qualification-only reachability into the unchanged original private function.
// The fixture creates real Arc/Weak/AtomicBool values, never replacement policy.
#[doc(hidden)]
pub fn __hia_durable_history_original(value: &serde_json::Value) -> serde_json::Value {
 use std::os::unix::ffi::OsStringExt;
 let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
 let parameters: RequestHistoryParams = match serde_json::from_value(value["params"].clone()) {
  Ok(value)=>value,
  Err(error)=>return serde_json::json!({"parameter_error":error.to_string()}),
 };
 let encoded=value["root_hex"].as_str().unwrap();
 let bytes:Vec<u8>=(0..encoded.len()).step_by(2).map(|i|u8::from_str_radix(&encoded[i..i+2],16).unwrap()).collect();
 let root=std::path::PathBuf::from(std::ffi::OsString::from_vec(bytes));
 let mut keep_alive=Vec::new();
 {
  let mut registry=active_registry().unwrap();
  registry.clear();
  for item in value["active"].as_array().unwrap() {
   let id=item["id"].as_str().unwrap().to_owned();
   let marker=Arc::new(AtomicBool::new(item["value"].as_bool().unwrap()));
   registry.insert(id,Arc::downgrade(&marker));
   if item["alive"].as_bool().unwrap(){keep_alive.push(marker);}
  }
 }
 let result=history_at(&root,value["owner"].as_str().unwrap(),parameters);
 // Original public history only preserves the cursor diagnostic. This output
 // retains the original private error as independent qualification evidence.
 let response=match result {
  Ok(text)=>serde_json::json!({"diagnostic":0,"output":text}),
  Err(error)=>{
   let text=error.to_string();
   let diagnostic=if text=="request history cursor expired or unavailable to this session"{2}else{1};
   serde_json::json!({"diagnostic":diagnostic,"output":null,"original_error":text})
  }
 };
 let registry=active_registry().unwrap();
 let mut remaining:Vec<_>=registry.iter().map(|(id,marker)|(id.clone(),marker.strong_count())).collect();
 remaining.sort();
 drop(registry);
 drop(keep_alive);
 let after=std::fs::read_dir("/proc/self/fd").unwrap().count();
 serde_json::json!({"result":response,"remaining_active_entries":remaining,"fd_count_before":before,"fd_count_after":after})
}
'''
BIN=r'''use std::io::{BufRead,Write};
fn main()->std::io::Result<()> {
 let mut output=std::io::stdout().lock();
 for line in std::io::stdin().lock().lines(){
  let line=line?;
  let value:serde_json::Value=serde_json::from_str(&line).unwrap();
  let response=hepta_runtime::mcp::runtime::request_audit::__hia_durable_history_original(&value);
  writeln!(output,"{}",serde_json::to_string(&response).unwrap())?;
  output.flush()?;
 }
 Ok(())
}
'''
def main():
 p=argparse.ArgumentParser();p.add_argument("--project",type=Path,required=True);a=p.parse_args();root=a.project
 paths={"Cargo.toml":MANIFEST,"Cargo.lock":LOCK,"src/mcp/runtime/request_audit.rs":AUDIT}
 originals={n:(root/n).read_bytes()for n in paths}
 for n,raw in originals.items():assert SHA(raw)==paths[n],n
 q=root/"audit_current_history";q.mkdir(exist_ok=False)
 for n,raw in originals.items():
  dest=q/("original-"+n.replace("/","__"));dest.write_bytes(raw)
 (q/"oracle.rs").write_text(BIN)
 with(root/"src/mcp/runtime/request_audit.rs").open("ab")as f:f.write(APPEND.encode())
 with(root/"Cargo.toml").open("ab")as f:
  f.write(b'\n[[bin]]\nname = "hia-durable-audit-history-original"\npath = "audit_current_history/oracle.rs"\n')
 for n in("Cargo.toml","src/mcp/runtime/request_audit.rs"):
  assert(root/n).read_bytes().startswith(originals[n]),n
 assert(root/"Cargo.lock").read_bytes()==originals["Cargo.lock"]
 report=dict(schema="hepta.runtime.durable-history-full-original-graph.v1",
  source_commit="abc9ecb95ee9538518ec3f36c47b881974107021",
  original=paths,append_only={n:dict(original_bytes=len(originals[n]),current_bytes=(root/n).stat().st_size,
   current_sha256=SHA((root/n).read_bytes()))for n in("Cargo.toml","src/mcp/runtime/request_audit.rs")},
  oracle_sha256=SHA(BIN.encode()),fixture_sha256=SHA(APPEND.encode()),original_functions_unchanged=True,
  dependency_graph_profile_features_unchanged=True,scope="complete original Runtime library and Cargo graph; original history_at on actual private directories and Arc/Weak/AtomicBool registry; public transport not invoked")
 (q/"source-relation.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()

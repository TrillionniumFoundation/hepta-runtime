# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Expose the unchanged v12 metadata routines in the original full Cargo graph."""
from pathlib import Path
import argparse,ast,hashlib,json
SHA=lambda v:hashlib.sha256(v).hexdigest()
PINS={"Cargo.toml":"9d95c6f534a0a5cd1b21dde659ebe2ed02c0ba7d52d5bc792118ec32d615ff14","Cargo.lock":"b868d2529f17dfb78ba390e078eb281a98d9850e4eaa12245739fec43ec97823","src/mcp/runtime/request_audit.rs":"b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da","src/mcp/runtime/request_archive_store.rs":"efecc499d8032f06230e5048dfe2daf65d74560ab171aed707c187653e511c48","src/mcp/runtime/request_archive_store_tests.rs":"95d6ebd4a7a8eede5f254b051a8447e98735cd38a9882248228e24574c7308a7"}
STORE_APPEND="\n// Qualification-only reachability to unchanged v12 metadata routines.\npub(super) fn __hia_archive_metadata_original(value:&serde_json::Value)->serde_json::Value {\n let path=std::path::Path::new(value[\"root\"].as_str().unwrap());\n let operation=value[\"operation\"].as_str().unwrap();\n let result=(||->Result<serde_json::Value>{\n  let root=File::open(path)?;\n  match operation {\n   \"read_intent\"=>Ok(match read_intent(&root)? {\n    Some(record)=>serde_json::json!({\"present\":true,\"record\":serde_json::to_value(record)?}),\n    None=>serde_json::json!({\"present\":false})\n   }),\n   \"read_anchor\"=>{\n    let(record,stamp)=read_anchor(&root)?;\n    Ok(serde_json::json!({\"present\":true,\"record\":serde_json::to_value(record)?,\"stamp\":stamp}))\n   },\n   \"persist_initial\"|\"persist_next\"=>{\n    let record:InitIntent=serde_json::from_value(value[\"record\"].clone())?;\n    persist_intent(&root,&record,operation==\"persist_initial\")?;\n    Ok(serde_json::json!({\"written\":true}))\n   },\n   \"publish_anchor\"=>{\n    let record:ShardAnchor=serde_json::from_value(value[\"record\"].clone())?;\n    publish_anchor(&root,&record)?;\n    Ok(serde_json::json!({\"written\":true}))\n   },\n   _=>bail!(\"unknown qualification operation\"),\n  }\n })();\n match result{\n  Ok(value)=>serde_json::json!({\"accepted\":true,\"value\":value}),\n  Err(error)=>serde_json::json!({\"accepted\":false,\"error\":{\n   \"text\":format!(\"{error:#}\"),\n   \"io_errno\":error.downcast_ref::<std::io::Error>().and_then(std::io::Error::raw_os_error),\n   \"io_kind\":error.downcast_ref::<std::io::Error>().map(|v|format!(\"{:?}\",v.kind()))\n  }})\n }\n}\n"
AUDIT_APPEND="\n// Qualification-only forwarding; original audit policy and public API are unchanged.\n#[doc(hidden)]\npub fn __hia_durable_archive_metadata_original(value:&serde_json::Value)->serde_json::Value {\n archive_store::__hia_archive_metadata_original(value)\n}\n"
BIN="use std::io::{BufRead,Write};\nfn main()->std::io::Result<()>{\n let mut output=std::io::stdout().lock();\n for line in std::io::stdin().lock().lines(){\n  let value:serde_json::Value=serde_json::from_str(&line?).unwrap();\n  let result=hepta_runtime::mcp::runtime::request_audit::__hia_durable_archive_metadata_original(&value);\n  writeln!(output,\"{}\",serde_json::to_string(&result).unwrap())?;output.flush()?;\n }\n Ok(())\n}\n"
def literals(path,pin):
 raw=path.read_bytes();assert SHA(raw)==pin
 return {t.id:ast.literal_eval(n.value)for n in ast.parse(raw).body if isinstance(n,ast.Assign)for t in n.targets if isinstance(t,ast.Name)and t.id in{"APPEND","STORE_APPEND","AUDIT_APPEND","BIN"}}
def main():
 p=argparse.ArgumentParser();p.add_argument("--project",type=Path,required=True);p.add_argument("--history-preparer",type=Path,required=True);p.add_argument("--records-preparer",type=Path,required=True);p.add_argument("--anchor-preparer",type=Path,required=True);a=p.parse_args();root=a.project
 history=literals(a.history_preparer,"844713331bb1b0ea0713cfc57622f0f363767f38dcb986b408c2d01cf35892ae")
 records=literals(a.records_preparer,"f94091c91999da81d28178a79697aa87a0f7453bf8b3c0aa6bd145773bf2277a")
 anchor=literals(a.anchor_preparer,"5ce30c05fa506c822ad96ec3a6cb4f275c62bd9ab9bf63d7fee6e33f3f9ac0d5")
 originals={n:(root/"audit_current_history"/("original-"+n.replace("/","__"))).read_bytes()for n in list(PINS)[:3]}
 originals["src/mcp/runtime/request_archive_store.rs"]=(root/"audit_archive_records/before-src__mcp__runtime__request_archive_store.rs").read_bytes()
 originals["src/mcp/runtime/request_archive_store_tests.rs"]=(root/"src/mcp/runtime/request_archive_store_tests.rs").read_bytes()
 for n,v in originals.items():assert SHA(v)==PINS[n],n
 expected=dict(originals)
 for name,path in[("hia-durable-audit-history-original","audit_current_history/oracle.rs"),("hia-durable-archive-records-original","audit_archive_records/oracle.rs"),("hia-durable-archive-anchor-original","audit_anchor_fs/oracle.rs")]:
  expected["Cargo.toml"]+=("\n[[bin]]\nname = "+json.dumps(name)+"\npath = "+json.dumps(path)+"\n").encode()
 expected["src/mcp/runtime/request_audit.rs"]+=history["APPEND"].encode()+records["AUDIT_APPEND"].encode()+anchor["AUDIT_APPEND"].encode()
 expected["src/mcp/runtime/request_archive_store.rs"]+=records["STORE_APPEND"].encode()+anchor["STORE_APPEND"].encode()
 before={n:(root/n).read_bytes()for n in PINS};assert before==expected
 q=root/"audit_archive_metadata";q.mkdir(exist_ok=False)
 for n,v in before.items():(q/("before-"+n.replace("/","__"))).write_bytes(v)
 (q/"oracle.rs").write_text(BIN)
 for n,v in[("src/mcp/runtime/request_audit.rs",AUDIT_APPEND),("src/mcp/runtime/request_archive_store.rs",STORE_APPEND)]:
  with(root/n).open("ab")as f:f.write(v.encode())
 with(root/"Cargo.toml").open("ab")as f:f.write(b'\n[[bin]]\nname = "hia-durable-archive-metadata-original"\npath = "audit_archive_metadata/oracle.rs"\n')
 for n,v in before.items():assert(root/n).read_bytes().startswith(v),n
 assert(root/"Cargo.lock").read_bytes()==originals["Cargo.lock"]and(root/"src/mcp/runtime/request_archive_store_tests.rs").read_bytes()==originals["src/mcp/runtime/request_archive_store_tests.rs"]
 report=dict(schema="hepta.runtime.durable-archive-metadata-original.v1",original_commit="abc9ecb95ee9538518ec3f36c47b881974107021",original=PINS,
 before={n:dict(bytes=len(v),sha256=SHA(v))for n,v in before.items()},after={n:dict(bytes=len(v),sha256=SHA(v))for n in PINS for v in[(root/n).read_bytes()]},
 original_functions_whole_bytes_preserved=True,original_tests_whole_bytes_preserved=True,graph_profile_default_features_unchanged=True,
 append_sha256={"audit":SHA(AUDIT_APPEND.encode()),"store":SHA(STORE_APPEND.encode()),"bin":SHA(BIN.encode())},
 scope="original read_intent/read_anchor/persist_intent/publish_anchor reachability only; no policy replacement or public handler claim")
 (q/"source-relation.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n");print(json.dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":main()

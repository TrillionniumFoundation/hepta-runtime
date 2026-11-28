# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Keep the nine complete original FIFO/thread tests unchanged for both implementations."""
from pathlib import Path
import argparse,hashlib,json
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--project",type=Path,required=True);a=p.parse_args()
 names=("request_audit.rs","request_audit_tests.rs","request_archive_index_tests.rs")
 raw={n:(a.source/"src/mcp/runtime"/n).read_bytes()for n in names}
 if SHA(raw["request_audit.rs"])!="b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da":raise ValueError("fixed audit differs")
 text={n:value.decode()for n,value in raw.items()}
 core=text[names[0]];begin=core.index("#[derive(Clone, Copy, PartialEq, Eq)]",core.index("// Writers and recovery"))
 end=core.index("\nfn store_lock()",begin);body=core[begin:end]
 t=text[names[1]];begin=t.index("fn wait_for_shared_gate_queue(");end=t.index("\n#[test]\nfn shared_hot_preflight",begin);shared=t[begin:end]
 t=text[names[2]];begin=t.index("fn wait_for_audit_store_waiters(");end=t.index("\n#[test]\nfn interrupted_checkpoint",begin);writers=t[begin:end]
 tests=shared+"\n"+writers
 if tests.count("#[test]")!=9:raise ValueError("original complete nine methods differ")
 native=(a.source/"scripts/durable_audit_fifo_native_fixture.rs.txt").read_text()
 original="use std::collections::VecDeque;\nuse std::sync::{Arc,Mutex};\nuse std::time::{Instant,Duration};\n"+body
 d=a.project/"audit_fifo";d.mkdir(exist_ok=False)
 (d/"original.rs").write_text(original+"\n"+tests)
 (d/"native.rs").write_text(native+"\n"+tests)
 for name,value in raw.items():(d/("complete-"+name)).write_bytes(value)
 proof={"schema":"hepta.runtime.durable-fifo-original-tests.v1","methods":9,"test_body_identical":True,"source":{n:{"bytes":len(v),"sha256":SHA(v)}for n,v in raw.items()},"complete_test_blocks":[],"original_fifo_sha256":SHA(body.encode()),"native_adapter_sha256":SHA(native.encode())}
 for name,value in ((names[1],shared),(names[2],writers)):
  assert text[name].count(value)==1
  proof["complete_test_blocks"].append({"name":name,"offset":raw[name].index(value.encode()),"bytes":len(value.encode()),"sha256":SHA(value.encode())})
 lock=(a.project/"Cargo.lock").read_bytes();manifest=a.project/"Cargo.toml";before=manifest.read_bytes()
 with manifest.open("a")as stream:
  for kind in ("original","native"):stream.write(f'\n[[test]]\nname="hia-durable-audit-fifo-{kind}"\npath="audit_fifo/{kind}.rs"\n')
 proof.update(lock_sha256=SHA(lock),manifest_before_sha256=SHA(before),manifest_after_sha256=SHA(manifest.read_bytes()))
 assert (a.project/"Cargo.lock").read_bytes()==lock
 (d/"source-relation.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
 print(json.dumps(proof,sort_keys=True))
if __name__=="__main__":main()

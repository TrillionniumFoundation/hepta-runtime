# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Private dispatch liveness state owner. The caller supplies the one runtime mutex."""
from pathlib import Path
import argparse,hashlib,json
from author_durable_common import compile_source
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
_SELF=Path(__file__).read_bytes()
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--runtime",type=Path,default=Path(__file__).resolve().parents[1]);a=p.parse_args()
 root=a.runtime.resolve(strict=True);source=root/"scripts/durable_audit_activity_source.py.txt"
 before={str(path):path.read_bytes()for path in(Path(__file__).resolve(),source,root/"src/mcp/runtime/request_audit.rs",root/"scripts/author_durable_common.py")}
 assert before[str(Path(__file__).resolve())]==_SELF and Path(__file__).resolve()==root/"scripts/author_durable_audit_activity.py"
 assert SHA(before[str(root/"src/mcp/runtime/request_audit.rs")])=="b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da"
 constants=dict(INVALID=0xffffffff,CAPACITY=0xfffffffe,MAXWORD=2**64-1,MAX_REFS=2**63-1,
  REQUEST=int.from_bytes(b"HRAACTQ1","little"),RESPONSE=int.from_bytes(b"HRAACTR1","little"),STATE=int.from_bytes(b"HRAACTS1","little"))
 result=compile_source(root,a.hepta,"durable_audit_activity",before[str(source)].decode(),constants,[
 ("native/durable_audit_record_io.hepta","0e7e9dcb4f77b2f31ce64c85e3bd765995c79d0e6b8bb7c6da17ed0fc05bfbdf",
  dict(get="f23",put="f24",read64="f25",zeros="f16",valid_id="f19"))])
 for name,raw in before.items():assert Path(name).read_bytes()==raw,name
 result.update(domain="private actual RequestTicket dispatch liveness; closed 64-hex request IDs, strong holder tokens and weak map, mapped dead entries removed only during query; one runtime-wide mechanical critical section required",
  source_inputs={name:dict(bytes=len(raw),sha256=SHA(raw))for name,raw in before.items()},
  public_routing_qualified=False,concurrent_runtime_integration_qualified=False)
 (root/"native/durable_audit_activity_composition.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()

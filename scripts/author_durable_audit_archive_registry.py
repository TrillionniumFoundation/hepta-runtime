# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the shared Archive weak registry, preserving the original scope."""
from pathlib import Path
import argparse,hashlib,json
SELF=Path(__file__).resolve(strict=True);EXECUTED=SELF.read_bytes();SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--runtime",type=Path,default=SELF.parents[1]);a=p.parse_args();root=a.runtime.resolve(strict=True)
 names=["scripts/author_durable_audit_archive_registry.py","scripts/durable_audit_archive_registry_source.py.txt","scripts/author_durable_common.py","native/durable_audit_record_io.hepta","src/mcp/runtime/request_archive_store.rs","src/mcp/runtime/request_audit.rs"]
 before={n:(root/n).read_bytes()for n in names};assert before[names[0]]==EXECUTED
 assert SHA(before[names[4]])=="efecc499d8032f06230e5048dfe2daf65d74560ab171aed707c187653e511c48"
 assert SHA(before[names[5]])=="b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da"
 cp=root/names[2];common={"__file__":str(cp),"__name__":"_captured_durable_archive_registry_author"};exec(compile(before[names[2]],str(cp),"exec"),common)
 constants=dict(INVALID=0xffffffff,CAPACITY=0xfffffffe,FATAL=0xfffffffd,MAXWORD=2**64-1,MAX_REFS=2**63-1)
 for key,value in[("REQUEST",b"HRAARQ01"),("RESPONSE",b"HRAARR01"),("STATE",b"HRAARW01")]:constants[key]=int.from_bytes(value,"little")
 result=common["compile_source"](root,a.hepta,"durable_audit_archive_registry",before[names[1]].decode(),constants,[
  ("native/durable_audit_record_io.hepta","0e7e9dcb4f77b2f31ce64c85e3bd765995c79d0e6b8bb7c6da17ed0fc05bfbdf",dict(get="f23",put="f24",read64="f25"))])
 for n,value in before.items():assert(root/n).read_bytes()==value,n
 result["actual_sources"]={n:dict(bytes=len(value),sha256=SHA(value))for n,value in before.items()}
 result["domain"]="Same-runtime global Weak<Inner> registry keyed by actual root/legacy device+inode; reservations span actual open/load/fence; reference drops retire the exact physical owner and dead weak entries are pruned only on later open"
 result["workspace_bytes"]="128+64*N; grow zeroed storage when requested, no application entry cap"
 result["output_bytes"]=112
 result["requires_mechanical_binding"]=["actual directory identity acquisition before registry lock","one global instance across sessions","exclusive open gate across layout child","atomic reference operations and exact final owner retirement","actual allocator growth and sticky poison"]
 result["public_archive_qualified"]=False
 (root/"native/durable_audit_archive_registry_composition.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");print(json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()

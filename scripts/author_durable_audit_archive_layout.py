# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the exact v12 physical-layout construction and recovery domain."""
from pathlib import Path
import argparse,hashlib,json
SELF=Path(__file__).resolve(strict=True);EXECUTED=SELF.read_bytes();SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--runtime",type=Path,default=SELF.parents[1]);a=p.parse_args();root=a.runtime.resolve(strict=True)
 names=["scripts/author_durable_audit_archive_layout.py","scripts/durable_audit_archive_layout_source.py.txt","scripts/author_durable_common.py","native/durable_audit_record_io.hepta","native/durable_audit_archive_metadata.hepta","native/durable_audit_archive_publication.hepta","native/durable_audit_anchor.hepta","src/mcp/runtime/request_archive_store.rs","src/mcp/runtime/request_audit.rs"]
 before={n:(root/n).read_bytes()for n in names};assert before[names[0]]==EXECUTED
 for name,pin in {
  "src/mcp/runtime/request_archive_store.rs":"efecc499d8032f06230e5048dfe2daf65d74560ab171aed707c187653e511c48",
  "src/mcp/runtime/request_audit.rs":"b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da",
  "native/durable_audit_archive_metadata.hepta":"02b4c9104c90e755bd058af7848d789e40a1a144eaf9e61d04da34b6b66216a1",
  "native/durable_audit_archive_publication.hepta":"3d9a374680558789265961c029a1db7006c07223a86e12bd457f3650f093ae49"
 }.items():assert SHA(before[name])==pin,name
 cp=root/"scripts/author_durable_common.py";common={"__file__":str(cp),"__name__":"_captured_durable_archive_layout_author"};exec(compile(before["scripts/author_durable_common.py"],str(cp),"exec"),common)
 source=before[names[1]].decode()
 source+="\ndef fixed_names(w:mutbuf) -> u64:\n"
 for offset,value in [(2048,b"request-archive-v12\0"),(2112,b".request-archive-v12-anchor.json\0"),(2176,b".request-archive-v12-init.json\0"),(2240,b"request-archive-v11\0"),(2368,b".\0")]:
  for i,ch in enumerate(value):source+=f"    store(w, {offset+i}, {ch})\n"
 source+="    return 0\n"
 constants=dict(INVALID=0xffffffff,CAPACITY=0xfffffffe,YIELD=0xffffffe0,MAXWORD=2**64-1,DIR_FLAGS=0xb0000,FILE_FLAGS=0xa0800)
 for key,value in[("REQUEST",b"HRAALQ01"),("RESPONSE",b"HRAALR01"),("STATE",b"HRAALW01"),("ACTION",b"HRAALA01"),("RECORD_RESPONSE",b"HRAATR01"),("METADATA_REQUEST",b"HRAAMQ01"),("METADATA_RESPONSE",b"HRAAMR01"),("PUBLICATION_REQUEST",b"HRAAWQ01"),("PUBLICATION_RESPONSE",b"HRAAWR01"),("PIN_REQUEST",b"HRAANQ01"),("PIN_RESPONSE",b"HRAANR01")]:constants[key]=int.from_bytes(value,"little")
 result=common["compile_source"](root,a.hepta,"durable_audit_archive_layout",source,constants,[
  ("native/durable_audit_record_io.hepta","0e7e9dcb4f77b2f31ce64c85e3bd765995c79d0e6b8bb7c6da17ed0fc05bfbdf",dict(get="f23",put="f24",read64="f25",zeros="f16",equal="f17",equal_inputs="f18"))])
 for n,value in before.items():assert(root/n).read_bytes()==value,n
 result["actual_sources"]={n:dict(bytes=len(value),sha256=SHA(value))for n,value in before.items()}
 result["domain"]="Private physical v12 layout load/initialize/restart/fence and exclusive-open probe with same retained root/legacy and pinned anchor; original exact 256-shard topology, all durable checkpoints and metadata publication children"
 result["workspace_bytes"]=1048576;result["output_bytes"]=4480
 result["not_implemented_here"]=["global archive registry and reference lifecycle","content-watch cache generation","redb persistent index","public durable-request routing"]
 result["public_archive_qualified"]=False
 (root/"native/durable_audit_archive_layout_composition.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");print(json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()

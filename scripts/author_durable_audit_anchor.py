# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the original Audit legacy anchor's retained-FD open/fence lifecycle."""
from pathlib import Path
import argparse,hashlib,json
SELF=Path(__file__).resolve(strict=True);EXECUTED=SELF.read_bytes();SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--runtime",type=Path,default=SELF.parents[1]);a=p.parse_args();root=a.runtime.resolve(strict=True)
 names=["scripts/author_durable_audit_anchor.py","scripts/durable_audit_anchor_source.py.txt","scripts/author_durable_common.py","native/durable_audit_record_io.hepta","native/durable_audit_archive_records.hepta","src/mcp/runtime/request_archive_store.rs"]
 before={n:(root/n).read_bytes()for n in names}
 assert before[names[0]]==EXECUTED
 assert SHA(before["src/mcp/runtime/request_archive_store.rs"])=="efecc499d8032f06230e5048dfe2daf65d74560ab171aed707c187653e511c48"
 assert SHA(before["native/durable_audit_archive_records.hepta"])=="729c1b695584bc88a36bbbde7cdb0c1069743c1b355e189e14e55b74da4b3ec0"
 cp=root/"scripts/author_durable_common.py";common={"__file__":str(cp),"__name__":"_captured_audit_anchor_author"};exec(compile(before["scripts/author_durable_common.py"],str(cp),"exec"),common)
 source=before[names[1]].decode();name=b".request-archive-v11-anchor.json"
 source+="\ndef set_name(w:mutbuf) -> u64:\n"
 for i,ch in enumerate(name+b"\0"):source+=f"    store(w, {896+i}, {ch})\n"
 source+="    return 0\n"
 constants=dict(INVALID=0xffffffff,CAPACITY=0xfffffffe,YIELD=0xffffffe0,MAXWORD=2**64-1,OPEN_FLAGS=0x80000|0x20000|0x800,NAME_LENGTH=len(name))
 for key,value in[("REQUEST",b"HRAANQ01"),("RESPONSE",b"HRAANR01"),("STATE",b"HRAANW01"),("ACTION",b"HRAANA01"),("RECORD_REQUEST",b"HRAATQ01"),("RECORD_RESPONSE",b"HRAATR01")]:constants[key]=int.from_bytes(value,"little")
 result=common["compile_source"](root,a.hepta,"durable_audit_anchor",source,constants,[
  ("native/durable_audit_record_io.hepta","0e7e9dcb4f77b2f31ce64c85e3bd765995c79d0e6b8bb7c6da17ed0fc05bfbdf",dict(get="f23",put="f24",read64="f25",zeros="f16",equal="f17",equal_inputs="f18"))])
 for n,value in before.items():assert(root/n).read_bytes()==value,n
 result["actual_sources"]={n:dict(bytes=len(value),sha256=SHA(value))for n,value in before.items()}
 result["domain"]="original PinnedAnchor::open/fence, including full 11-field gid stamp and every positional byte reread; caller retains same actual root and anchor descriptors"
 result["workspace_bytes"]=16384;result["output_bytes"]=192
 result["public_archive_qualified"]=False
 (root/"native/durable_audit_anchor_composition.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the fixed syscall engine's HIA emitter; as/ld are independent QA only."""
from pathlib import Path
import argparse,hashlib,json,struct
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
_SELF=Path(__file__).read_bytes()
CODE="d31421523de93476059b9f9a788ce6f1dec08f765177e7d8d9a45f9ebe5d5a91"
ENGINE="c5e87641d3fe8ff322d0a325396decdf8f6685856b4ab7b94f9c09198b680b3d"
FLAT="4fd8764b4f023defca8ad7f6271590450a167dd12cc5857486f5a4d5bf330984"
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--runtime",type=Path,default=Path(__file__).resolve().parents[1]);a=p.parse_args()
 root=a.runtime.resolve(strict=True)
 paths=[Path(__file__).resolve(),root/"scripts/durable_audit_anchor_code.json",root/"scripts/durable_audit_anchor_engine.S",root/"scripts/author_durable_common.py",root/"native/durable_audit_record_io.hepta"]
 before={str(path):path.read_bytes()for path in paths}
 assert paths[0]==root/"scripts/author_durable_audit_anchor_packer.py"and before[str(paths[0])]==_SELF
 assert SHA(before[str(paths[1])])==CODE and SHA(before[str(paths[2])])==ENGINE
 record=json.loads(before[str(paths[1])]);code=bytes.fromhex(record["flat_hex"])
 assert type(record["flat_bytes"])is int and len(code)==record["flat_bytes"]==2150 and SHA(code)==FLAT==record["flat_sha256"]
 entries={"create":0,"step":162,"child_ack":1758,"take":1950,"destroy":1958}
 assert set(record["exports"])==set(entries)
 assert all(type(record["exports"][name])is int and record["exports"][name]==offset for name,offset in entries.items())
 assert record["source_sha256"]==ENGINE and record["source_path"]=="scripts/durable_audit_anchor_engine.S"
 header=b"HRAAPK01"+struct.pack("<7Q",64+len(code),len(code),*(entries[name]for name in entries))
 output=header+code;assert len(output)==2214
 chunks=[]
 for start in range(0,len(output),512):
  lines=["def part_"+str(len(chunks))+"(o:mutbuf) -> u64:"]
  end=min(start+512,len(output));at=start
  while at+8<=end:
   lines.append("    put(o, "+str(at)+", "+str(int.from_bytes(output[at:at+8],"little"))+")");at+=8
  while at<end:
   lines.append("    store(o, "+str(at)+", "+str(output[at])+")");at+=1
  lines.append("    return 0");chunks.append("\n".join(lines))
 entry="""def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 24:
        return 4294967295
    if read64(s, 0) != """+str(int.from_bytes(b"HRAAPQ01","little"))+""" or read64(s, 8) != 1 or read64(s, 16) != 0:
        return 4294967295
    if length(o) < 2214:
        return 4294967294
"""
 for index in range(len(chunks)):entry+="    part_"+str(index)+"(o)\n"
 entry+="    return 2214\n"
 text=entry+"\n\n"+"\n\n".join(chunks)+"\n"
 cp=root/"scripts/author_durable_common.py";common={"__file__":str(cp),"__name__":"_captured_anchor_packer_author"};exec(compile(before[str(cp)],str(cp),"exec"),common)
 result=common["compile_source"](root,a.hepta,"durable_audit_anchor_packer",text,{},[
  ("native/durable_audit_record_io.hepta","0e7e9dcb4f77b2f31ce64c85e3bd765995c79d0e6b8bb7c6da17ed0fc05bfbdf",dict(put="f24",read64="f25"))])
 for name,value in before.items():assert Path(name).read_bytes()==value,name
 result.update(schema="hepta.runtime.audit-anchor-hia-packer.v1",engine_source_sha256=ENGINE,
  fixed_code_record_sha256=CODE,expected_flat_sha256=FLAT,exports=entries,
  expected_output_bytes=len(output),expected_output_sha256=SHA(output),request_hex=(b"HRAAPQ01"+struct.pack("<QQ",1,0)).hex(),
  authoring_inputs={name:dict(bytes=len(value),sha256=SHA(value))for name,value in before.items()},
  installed_assembler_required=False,public_routing_qualified=False)
 (root/"native/durable_audit_anchor_packer_composition.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 (root/"scripts/durable_audit_anchor_packer_source.py.txt").write_text(text)
 print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()

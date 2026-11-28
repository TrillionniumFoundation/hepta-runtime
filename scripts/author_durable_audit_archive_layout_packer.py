# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the fixed syscall engine's HIA emitter; as/ld are independent QA only."""
from pathlib import Path
import argparse,hashlib,json,struct
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
_SELF=Path(__file__).read_bytes()
CODE="9a5783e8e3a68cad8120410932dee9311b7a4ab792adbd86a334639c068e4152"
ENGINE="e4b75d8377478b2bf96d61afbbfce9895c19ad61767248de125112c12707ab99"
FLAT="336125e75c3eb8007cbe775571df4c66d1699e008268aed51615e62b8290b0b7"
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--runtime",type=Path,default=Path(__file__).resolve().parents[1]);a=p.parse_args()
 root=a.runtime.resolve(strict=True)
 paths=[Path(__file__).resolve(),root/"scripts/durable_audit_archive_layout_code.json",root/"scripts/durable_audit_archive_layout_engine.S",root/"scripts/author_durable_common.py",root/"native/durable_audit_record_io.hepta"]
 before={str(path):path.read_bytes()for path in paths}
 assert paths[0]==root/"scripts/author_durable_audit_archive_layout_packer.py"and before[str(paths[0])]==_SELF
 assert SHA(before[str(paths[1])])==CODE and SHA(before[str(paths[2])])==ENGINE
 record=json.loads(before[str(paths[1])]);code=bytes.fromhex(record["flat_hex"])
 assert type(record["flat_bytes"])is int and len(code)==record["flat_bytes"]==3719 and SHA(code)==FLAT==record["flat_sha256"]
 entries={"create":0,"step":211,"child_ack":3222,"take":3456,"destroy":3464}
 assert set(record["exports"])==set(entries)
 assert all(type(record["exports"][name])is int and record["exports"][name]==offset for name,offset in entries.items())
 assert record["source_sha256"]==ENGINE and record["source_path"]=="scripts/durable_audit_archive_layout_engine.S"
 header=b"HRALPK01"+struct.pack("<7Q",64+len(code),len(code),*(entries[name]for name in entries))
 output=header+code;assert len(output)==3783
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
    if read64(s, 0) != """+str(int.from_bytes(b"HRALPQ01","little"))+""" or read64(s, 8) != 1 or read64(s, 16) != 0:
        return 4294967295
    if length(o) < 3783:
        return 4294967294
"""
 for index in range(len(chunks)):entry+="    part_"+str(index)+"(o)\n"
 entry+="    return 3783\n"
 text=entry+"\n\n"+"\n\n".join(chunks)+"\n"
 cp=root/"scripts/author_durable_common.py";common={"__file__":str(cp),"__name__":"_captured_anchor_packer_author"};exec(compile(before[str(cp)],str(cp),"exec"),common)
 result=common["compile_source"](root,a.hepta,"durable_audit_archive_layout_packer",text,{},[
  ("native/durable_audit_record_io.hepta","0e7e9dcb4f77b2f31ce64c85e3bd765995c79d0e6b8bb7c6da17ed0fc05bfbdf",dict(put="f24",read64="f25"))])
 for name,value in before.items():assert Path(name).read_bytes()==value,name
 result.update(schema="hepta.runtime.audit-archive-layout-hia-packer.v1",engine_source_sha256=ENGINE,
  fixed_code_record_sha256=CODE,expected_flat_sha256=FLAT,exports=entries,
  expected_output_bytes=len(output),expected_output_sha256=SHA(output),request_hex=(b"HRALPQ01"+struct.pack("<QQ",1,0)).hex(),
  authoring_inputs={name:dict(bytes=len(value),sha256=SHA(value))for name,value in before.items()},
  installed_assembler_required=False,public_routing_qualified=False)
 (root/"native/durable_audit_archive_layout_packer_composition.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 (root/"scripts/durable_audit_archive_layout_packer_source.py.txt").write_text(text)
 print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()

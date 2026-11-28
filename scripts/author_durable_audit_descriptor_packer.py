# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the fixed syscall engine's HIA emitter; as/ld are independent QA only."""
from pathlib import Path
import argparse,hashlib,json,struct
from author_durable_common import compile_source
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
_SELF=Path(__file__).read_bytes()
CODE="d9ed7274bc05a2a1a2aa198dbc19256946b0d6031ad0e6feb6207ca438409028"
ENGINE="990a1dbd3a90d6a0a6154e9d0031b860b58b178b12201e7d382b8196ca715a8c"
FLAT="d8aafa16374d1ba86085b84c3e54496a6d8bace2d06099a8b18e04255727914b"
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--runtime",type=Path,default=Path(__file__).resolve().parents[1]);a=p.parse_args()
 root=a.runtime.resolve(strict=True)
 paths=[Path(__file__).resolve(),root/"scripts/durable_audit_descriptor_code.json",root/"scripts/durable_audit_descriptor_engine.S",root/"scripts/author_durable_common.py"]
 before={str(path):path.read_bytes()for path in paths}
 assert paths[0]==root/"scripts/author_durable_audit_descriptor_packer.py"and before[str(paths[0])]==_SELF
 assert SHA(before[str(paths[1])])==CODE and SHA(before[str(paths[2])])==ENGINE
 record=json.loads(before[str(paths[1])]);code=bytes.fromhex(record["flat_hex"])
 assert type(record["flat_bytes"])is int and len(code)==record["flat_bytes"]==3423 and SHA(code)==FLAT==record["flat_sha256"]
 entries={"create":0,"step":245,"child_ack":2874,"take":3066,"destroy":3184}
 assert set(record["exports"])==set(entries)
 assert all(type(record["exports"][name])is int and record["exports"][name]==offset for name,offset in entries.items())
 assert record["source_sha256"]==ENGINE and record["source_path"]=="scripts/durable_audit_descriptor_engine.S"
 header=b"HRAEPK01"+struct.pack("<7Q",64+len(code),len(code),*(entries[name]for name in entries))
 output=header+code;assert len(output)==3487
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
    if read64(s, 0) != """+str(int.from_bytes(b"HRAEPQ01","little"))+""" or read64(s, 8) != 1 or read64(s, 16) != 0:
        return 4294967295
    if length(o) < 3487:
        return 4294967294
"""
 for index in range(len(chunks)):entry+="    part_"+str(index)+"(o)\n"
 entry+="    return 3487\n"
 text=entry+"\n\n"+"\n\n".join(chunks)+"\n"
 result=compile_source(root,a.hepta,"durable_audit_descriptor_packer",text,{},[
  ("native/durable_audit_record_io.hepta","0e7e9dcb4f77b2f31ce64c85e3bd765995c79d0e6b8bb7c6da17ed0fc05bfbdf",dict(put="f24",read64="f25"))])
 for name,value in before.items():assert Path(name).read_bytes()==value,name
 result.update(schema="hepta.runtime.audit-descriptor-hia-packer.v1",engine_source_sha256=ENGINE,
  fixed_code_record_sha256=CODE,expected_flat_sha256=FLAT,exports=entries,
  expected_output_bytes=len(output),expected_output_sha256=SHA(output),request_hex=(b"HRAEPQ01"+struct.pack("<QQ",1,0)).hex(),
  authoring_inputs={name:dict(bytes=len(value),sha256=SHA(value))for name,value in before.items()},
  installed_assembler_required=False,public_routing_qualified=False)
 (root/"native/durable_audit_descriptor_packer_composition.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 (root/"scripts/durable_audit_descriptor_packer_source.py.txt").write_text(text)
 print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()

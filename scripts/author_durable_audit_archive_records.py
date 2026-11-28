# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Generate the three original Audit archive metadata types without filesystem authority."""
from pathlib import Path
import argparse,hashlib,json
SELF=Path(__file__).resolve(strict=True)
EXECUTED=SELF.read_bytes()
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
EXPECTED={
 "src/mcp/runtime/request_audit.rs":"b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da",
 "src/mcp/runtime/request_archive_store.rs":"efecc499d8032f06230e5048dfe2daf65d74560ab171aed707c187653e511c48",
 "native/request_storage_json.hepta":"3dca192460879ca124649f17bfa753f8aabf76a734b0560e9096f1c723007128",
}
NAMES=[b"root_device",b"root_inode",b"archive_device",b"archive_inode",b"format",b"root",b"legacy",b"archive",b"shards"]
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--runtime",type=Path,default=SELF.parents[1]);a=p.parse_args()
 root=a.runtime.resolve(strict=True)
 names=[*EXPECTED,"scripts/author_durable_common.py","scripts/durable_audit_archive_records_source.py.txt","scripts/author_durable_audit_archive_records.py"]
 captured={n:(root/n).read_bytes()for n in names}
 assert captured["scripts/author_durable_audit_archive_records.py"]==EXECUTED
 for n,pin in EXPECTED.items():assert SHA(captured[n])==pin,n
 common_path=root/"scripts/author_durable_common.py"
 common={"__file__":str(common_path),"__name__":"_durable_archive_captured_author"}
 exec(compile(captured["scripts/author_durable_common.py"],str(common_path),"exec"),common)
 source=captured["scripts/durable_audit_archive_records_source.py.txt"].decode()
 source+="\ndef name_length(code:u64) -> u64:\n"
 for i,raw in enumerate(NAMES,1):source+=f"    if code == {i}:\n        return {len(raw)}\n"
 source+="    return 0\n\ndef name_byte(code:u64, index:u64) -> u64:\n"
 for i,raw in enumerate(NAMES,1):
  source+=f"    if code == {i}:\n"
  for j,ch in enumerate(raw):source+=f"        if index == {j}:\n            return {ch}\n"
  source+="        return 0\n"
 source+="    return 0\n"
 imports=[("native/request_storage_json.hepta",EXPECTED["native/request_storage_json.hepta"],
  dict(string_info="f22",decoded="f28",whitespace="f25",unsigned="f7",null="f6",read64="f31",get="f29",put="f30"))]
 record=common["compile_source"](root,a.hepta,"durable_audit_archive_records",source,
  dict(INVALID=0xffffffff,CAPACITY=0xfffffffe,REQUEST=int.from_bytes(b"HRAATQ01","little"),RESPONSE=int.from_bytes(b"HRAATR01","little")),imports)
 for n,raw in captured.items():assert (root/n).read_bytes()==raw,n
 record["actual_sources"]={n:dict(bytes=len(raw),sha256=SHA(raw))for n,raw in captured.items()}
 record["domain"]="original ArchiveAnchor, ShardAnchor and InitIntent typed JSON only; filesystem and v12 admission remain separate"
 record["limits"]={"legacy_raw":2048,"sharded_raw":65536,"no_vector_policy_cap":True}
 (root/"native/durable_audit_archive_records_composition.json").write_text(json.dumps(record,sort_keys=True,indent=2)+"\n")
 print(json.dumps(record,sort_keys=True),flush=True)
if __name__=="__main__":main()

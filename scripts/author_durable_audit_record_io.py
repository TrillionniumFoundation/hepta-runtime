# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author private audit record I/O policy; all emitted decisions are HIA."""
from pathlib import Path
import argparse,hashlib,json
from author_durable_common import compile_source
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--runtime",type=Path,default=Path(__file__).resolve().parents[1]);a=p.parse_args()
 root=a.runtime.resolve(strict=True);raw=(root/"scripts/durable_audit_record_io_source.py.txt").read_text()
 constants={"INVALID":0xffffffff,"CAPACITY":0xfffffffe,"YIELD":0xffffffe0,"MAXWORD":2**64-1,
 "REQUEST":int.from_bytes(b"HRAIO001","little"),"RESPONSE":int.from_bytes(b"HRADIO01","little"),
 "STATE":int.from_bytes(b"HRAIOS01","little"),"ACTION":int.from_bytes(b"HRADAS01","little"),
 "RECORD_REQUEST":int.from_bytes(b"HRAJQ001","little"),"RECORD_RESPONSE":int.from_bytes(b"HRAJR001","little"),
 "FILEFLAGS":0x20000|0x80000|0x800,"DIRFLAGS":0x20000|0x80000|0x10000}
 result=compile_source(root,a.hepta,"durable_audit_record_io",raw,constants,[
 ("native/request_storage_json.hepta","3dca192460879ca124649f17bfa753f8aabf76a734b0560e9096f1c723007128",dict(get="f29",put="f30",read64="f31"))])
 result["domain"]="Linux retained private directory, exact read_record and cleanup_staging; not root admission or public routing"
 result["original_source"]={"path":"src/mcp/runtime/request_audit.rs","sha256":hashlib.sha256((root/"src/mcp/runtime/request_audit.rs").read_bytes()).hexdigest()}
 (root/"native/durable_audit_record_io_composition.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()

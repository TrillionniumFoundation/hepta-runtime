# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author descriptor-bound audit root/hot policy; emitted production is HIA."""
from pathlib import Path
import argparse,hashlib,json
from author_durable_common import compile_source
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--runtime",type=Path,default=Path(__file__).resolve().parents[1]);a=p.parse_args()
 root=a.runtime.resolve(strict=True);raw=(root/"scripts/durable_audit_hot_source.py.txt").read_text()
 constants=dict(INVALID=0xffffffff,CAPACITY=0xfffffffe,YIELD=0xffffffe0,MAXWORD=2**64-1,
 REQUEST=int.from_bytes(b"HRAHOT01","little"),RESPONSE=int.from_bytes(b"HRAHOTR1","little"),
 STATE=int.from_bytes(b"HRAHST01","little"),ACTION=int.from_bytes(b"HRAHAS01","little"),
 IO_REQUEST=int.from_bytes(b"HRAIO001","little"),IO_RESPONSE=int.from_bytes(b"HRADIO01","little"),RECORD_RESPONSE=int.from_bytes(b"HRAJR001","little"),
 PATHFLAGS=0x200000|0x20000|0x80000|0x10000,DIRFLAGS=0x20000|0x80000|0x10000)
 result=compile_source(root,a.hepta,"durable_audit_hot",raw,constants,[
 ("native/durable_audit_record_io.hepta","0e7e9dcb4f77b2f31ce64c85e3bd765995c79d0e6b8bb7c6da17ed0fc05bfbdf",
 dict(get="f23",put="f24",read64="f25",zeros="f16",equal="f17",utf8="f22",valid_id="f19",suffix="f20"))])
 result["domain"]="Linux hot directory complete member capture, staging cleanup before all records, and full timestamp/ID sort; borrowed directory and real global FIFO guard are caller capabilities"
 result["original_source"]={"path":"src/mcp/runtime/request_audit.rs","sha256":hashlib.sha256((root/"src/mcp/runtime/request_audit.rs").read_bytes()).hexdigest()}
 (root/"native/durable_audit_hot_composition.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()

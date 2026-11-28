# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author actual FIFO ownership decisions, independent of mechanical synchronization."""
from pathlib import Path
import argparse,hashlib,json
from author_durable_common import compile_source
def main():
 p=argparse.ArgumentParser();p.add_argument("--runtime",type=Path,default=Path(__file__).resolve().parents[1]);p.add_argument("--hepta",type=Path,required=True);a=p.parse_args()
 record=compile_source(a.runtime,a.hepta,"durable_audit_fifo",(a.runtime/"scripts/durable_audit_fifo_source.py.txt").read_text(),{
 "REQUEST":int.from_bytes(b"HRAFL001","little"),"RESPONSE":int.from_bytes(b"HRAFO001","little"),
 "STATE":int.from_bytes(b"HRQST001","little"),"MAXWORD":2**64-1,"INVALID":0xffffffff,"CAPACITY":0xfffffffe},
 [("native/request_storage_json.hepta","3dca192460879ca124649f17bfa753f8aabf76a734b0560e9096f1c723007128",dict(get="f29",put="f30",read64="f31"))])
 record["original_source"]={"path":"src/mcp/runtime/request_audit.rs","sha256":hashlib.sha256((a.runtime/"src/mcp/runtime/request_audit.rs").read_bytes()).hexdigest()}
 record["domain"]="Original FIFO access/reader ownership/poison/finish transitions. Mutex, condition variable, clock and actual writer inner mutex are closed mechanical capabilities; no application queue cap."
 (a.runtime/"native/durable_audit_fifo_composition.json").write_text(json.dumps(record,sort_keys=True,indent=2)+"\n")
 print(json.dumps(record,sort_keys=True))
if __name__=="__main__":main()

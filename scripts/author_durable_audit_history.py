# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author private audit history composition; policy is emitted as HIA."""
from pathlib import Path
import argparse,hashlib,json
from author_durable_common import compile_source
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--runtime",type=Path,default=Path(__file__).resolve().parents[1]);a=p.parse_args()
 root=a.runtime.resolve(strict=True);raw=(root/"scripts/durable_audit_history_source.py.txt").read_text()
 constants=dict(INVALID=0xffffffff,CAPACITY=0xfffffffe,YIELD=0xffffffe0,MAXWORD=2**64-1,
 REQUEST=int.from_bytes(b"HRAHIS01","little"),RESPONSE=int.from_bytes(b"HRAHYR01","little"),
 STATE=int.from_bytes(b"HRAHYS01","little"),ACTION=int.from_bytes(b"HRAHYA01","little"),
 ROOT_REQUEST=int.from_bytes(b"HRAROOT1","little"),ROOT_RESPONSE=int.from_bytes(b"HRAROOT1","little"),
 HOT_REQUEST=int.from_bytes(b"HRAHOT01","little"),HOT_RESPONSE=int.from_bytes(b"HRAHOTR1","little"),
 PAGE_REQUEST=int.from_bytes(b"HRAQP001","little"),PAGE_RESPONSE=int.from_bytes(b"HRAQR001","little"))
 result=compile_source(root,a.hepta,"durable_audit_history",raw,constants,[
 ("native/durable_audit_record_io.hepta","0e7e9dcb4f77b2f31ce64c85e3bd765995c79d0e6b8bb7c6da17ed0fc05bfbdf",
 dict(get="f23",put="f24",read64="f25",zeros="f16",equal="f17",equal_inputs="f18",valid_id="f19")),
 ("native/durable_audit_page.hepta","7981a5c0bdbfe53252f55d441ea90cd536a3b056a2c9de492b0ebcb29cd90c17",
 dict(valid_row="f5",row_less="f6"))])
 result["domain"]="private same-session history composition: real global FIFO writer lease, configured root lease, complete hot capture, selected unknown dispatch checks, fixed page owner; public routing remains separately qualified"
 result["history_outcomes"]={"0":"exact original history JSON","1":"ordinary unavailable metadata error","2":"original session cursor error","3":"original release-profile numeric-conversion panic; fatal, no public JSON response"}
 result["fatal_public_mapping_qualified"]=False
 result["original_source"]={"path":"src/mcp/runtime/request_audit.rs","sha256":hashlib.sha256((root/"src/mcp/runtime/request_audit.rs").read_bytes()).hexdigest()}
 (root/"native/durable_audit_history_composition.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()

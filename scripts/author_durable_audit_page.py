# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author original audit history selection and archive page rendering in HIA."""
from pathlib import Path
import argparse, hashlib, json
from author_durable_common import compile_source
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
LITERALS={
1:b'{"automatic_operation_retry":false,"cross_session_resume":false,"history_is_live":true,"next_after_id":',
2:b'{"archive_retention":"no_automatic_metadata_eviction","automatic_operation_retry":false,"contains_parameters_or_output":false,"coverage":"metadata_retained_at_archive_introduction_and_subsequent_admitted_requests","history_is_live":true,"next_after_id":',
3:b',"requests":[',
4:b'],"retention":{"global":512,"per_session":128},"session_scope":"native_mcp_session_only","status_semantics":"native_request_dispatch_observation_not_side_effect_delivery_or_business_success"}',
5:b'],"total":',
11:b'{"accepted_unix_ms":',12:b',"elapsed_ms":',13:b',"request_id":',14:b',"state":',15:b',"tool_name":',
20:b'null',21:b'"unknown"',22:b'"accepted"',23:b'"completed"',24:b'"failed"'}
def main():
 p=argparse.ArgumentParser();p.add_argument("--runtime",type=Path,default=Path(__file__).resolve().parents[1]);p.add_argument("--hepta",type=Path,required=True);a=p.parse_args()
 source=(a.runtime/"scripts/durable_audit_page_source.py.txt").read_text()
 source+='\ndef literal(o:mutbuf, w:mutbuf, code:u64) -> u64:\n'
 for code,raw in LITERALS.items():
  source+=f"    if code == {code}:\n"
  full=len(raw)//8*8
  for at in range(0,full,8):source+=f"        emit_word(o, w, {int.from_bytes(raw[at:at+8],'little')})\n"
  for ch in raw[full:]:source+=f"        emit(o, w, {ch})\n"
  source+="        return 0\n"
 source+="    return 0\n"
 record=compile_source(a.runtime,a.hepta,"durable_audit_page",source,{
 "REQUEST":int.from_bytes(b"HRAQP001","little"),"RESPONSE":int.from_bytes(b"HRAQR001","little"),
 "INVALID":0xffffffff,"CAPACITY":0xfffffffe},[
 ("native/request_storage_json.hepta","3dca192460879ca124649f17bfa753f8aabf76a734b0560e9096f1c723007128",dict(get="f29",put="f30",read64="f31"))])
 record["original_source"]={"path":"src/mcp/runtime/request_audit.rs","sha256":SHA((a.runtime/"src/mcp/runtime/request_audit.rs").read_bytes())}
 record["domain"]="Complete history selection and archive_page_output rendering over private validated rows; no filesystem or public scope authority"
 (a.runtime/"native/durable_audit_page_composition.json").write_text(json.dumps(record,sort_keys=True,indent=2)+"\n")
 print(json.dumps(record,sort_keys=True))
if __name__=="__main__":main()

#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author public direct SSH output/error formatting with exact retained HIA text owners."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
def main():
    p=argparse.ArgumentParser()
    for name in ("source","hepta"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();root=a.source.resolve(strict=True)
    sys.path.insert(0,str(root/"authoring/public_publication_v1"))
    import source_support as support
    api=support.tools(a.hepta.resolve(strict=True))
    constants={"INVALID":0xffffffff,**{name:support.WORD(value) for name,value in {
        "REQUEST":"HRTRQ001","RESPONSE":"HRTRR001","CAPTURE":"HRSCAP01",
        "GROW":"HGRWS002","DIAGNOSTIC_RESULT":"HSJERR01","VALUE_QUERY":"HJSVS002","VALUE_RESULT":"HJSVR002"}.items()}}
    source=(root/"native/canonical_path.hepta").read_bytes()
    raw,names,proof=support.compile_new(api,source,
       {"load":"f18","get":"f19","put":"f20","lossy_size":"f13","lossy_copy":"f14",
        "next_lossy":"f21","errno_text":"f23","decimal":"f22"},
       (root/"authoring/public_read/result.pseudo").read_text(),constants,"runtime_public_read_transport_result")
    proof.update(schema="hepta.runtime.public-read.transport-result-author.v1",aliases=names,
       retained_lossy_and_os_errors=True,original_remote_exit_display=True,actual_value_parser_required=True,
       public_route_qualified=False)
    (root/"native/public_read_transport_result.hepta").write_bytes(raw)
    (root/"native/public_read_transport_result_composition.json").write_bytes(support.ENCODE(proof))
    print(json.dumps({"bytes":len(raw),"sha256":support.SHA(raw),"functions":proof["functions"]},sort_keys=True))
if __name__=="__main__":main()

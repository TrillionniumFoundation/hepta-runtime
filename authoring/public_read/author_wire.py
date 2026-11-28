#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author configured SSH argv and fixed remote read packets in HIA."""
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
      "WIRE_REQUEST":"HRWRQ001","WIRE_RESULT":"HRWRR001","SSH_REQUEST":"HRSSQ001",
      "BOOTSTRAP_RESULT":"HSSBR001","COMMAND_MAGIC":"HSDCMD01",
      "READ_PACKET":"HBRDQ001","INFO_PACKET":"HFRDQ001",
      "MULTI_PACKET":"HMRDQ001","MULTI_TYPED":"HMRPR001"}.items()}}
    raw,names,proof=support.compile_new(api,(root/"native/binary_call_plan.hepta").read_bytes(),
       {"load":"f1","get":"f2","put":"f3","grow":"f4","valid_typed":"f10","utf8":"f34"},
       (root/"authoring/public_read/wire.pseudo").read_text(),constants,"runtime_public_read_wire")
    proof.update(schema="hepta.runtime.public-read.wire-author.v1",aliases=names,
       environment_bytes_inherited=True,ssh_executable="ssh",native_path_search=True,
       public_target_only_from_installed_config=True,original_ssh_arguments=True,
       one_shot_remote_read_packet=True,public_route_qualified=False)
    (root/"native/public_read_wire.hepta").write_bytes(raw)
    (root/"native/public_read_wire_composition.json").write_bytes(support.ENCODE(proof))
    print(json.dumps({"bytes":len(raw),"sha256":support.SHA(raw),"functions":len(names)},sort_keys=True))
if __name__=="__main__":main()

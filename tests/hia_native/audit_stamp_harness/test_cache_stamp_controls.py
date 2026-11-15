# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Admission and private-inspection controls for the actual-file cache composition."""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import struct
import sys

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
OUT=266432
WORK=8388608
INVALID=0xffffffff
STATE=0xfffffff9
EFFECT=0xfffffff0


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('manifest','runtime','output'):parser.add_argument('--'+key,type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    sys.path[:0]=[str(Path(__file__).resolve().parent),str(args.runtime.resolve(strict=True)/'scripts')]
    from hia_native_loader import NativeModule
    from cache_stamp_cases import command,inspect,wire,record,put,stamp,records_wire
    manifest=args.manifest.read_bytes();rows=[];rejects=0
    def rejected(name,code,out,state,expected,outcap=OUT):
        nonlocal rejects
        assert code==expected and out==bytes([0xa7])*outcap,(name,code,expected)
        rows.append(dict(name=name,code=code,output_untouched=True,state_sha256=SHA(state)));rejects+=1
    request=wire(inspect(),{});before=stamp();values=[record(0),record(1,state='completed',elapsed_ms=0)]
    def populate(session):
        raw=wire(put(values),{});assert session.invoke_raw(raw)[0]==EFFECT
        reply=struct.pack('<8s5Q',b'HRACC001',0,0,0,112,0)+before
        ctypes.memmove(ctypes.addressof(session._workspace)+524288,reply,len(reply))
        sequence=struct.unpack_from('<Q',session._workspace,264)[0]
        struct.pack_into('<2Q',session._workspace,320,sequence,len(reply))
        assert session.invoke_raw(raw)[0]==64
    with NativeModule(args.manifest,manifest_sha256=SHA(manifest)) as module:
        bad=[('inspection-output',request,OUT-1,WORK,0xfffffffe),('inspection-workspace',request,OUT,WORK-1,0xfffffffe),
            ('inspection-short',request[:-1],OUT,WORK,INVALID),('inspection-long',request+b'\0',OUT,WORK,INVALID),
            ('inspection-index',wire(inspect(16),{}),OUT,WORK,INVALID),('cold-not-admitted',wire(command(3),{}),OUT,WORK,INVALID),
            ('unknown-op',wire(command(7),{}),OUT,WORK,INVALID)]
        for op in (1,2,4):
            for directory in (0,18,(1<<64)-1):
                bad.append((f'borrowed-directory-{op}-{directory}',wire(command(op,directory),{}),OUT,WORK,INVALID))
        for at in (24,32,40,48,56):
            changed=bytearray(request);struct.pack_into('<Q',changed,at,1)
            bad.append(('inspection-field-'+str(at),bytes(changed),OUT,WORK,INVALID))
        for name,raw,outcap,workcap,expected in bad:
            code,out,state=module.invoke_raw(raw,output_capacity=outcap,workspace_capacity=workcap,output_fill=0xa7)
            rejected(name,code,out,state,expected,outcap)
        for name,at,value in (('count',3145728+112,513),('length',3145728+128,513),
            ('projection-magic',3145728+136,0),('projection-kind',3145728+144,2),
            ('projection-reserved',3145728+136+112,1)):
            with module.session(output_capacity=OUT,workspace_capacity=WORK) as session:
                populate(session);struct.pack_into('<Q',session._workspace,at,value);ctypes.memset(session._output,0xa7,OUT)
                code,out,state=session.invoke_raw(request);rejected('owned-record-'+name,code,out,state,STATE)
        with module.session(output_capacity=OUT,workspace_capacity=WORK) as session:
            raw=wire(put(values),{});assert session.invoke_raw(raw)[0]==EFFECT;previous=bytes(session._workspace)[:WORK]
            ctypes.memset(session._output,0xa7,OUT);code,out,state=session.invoke_raw(request)
            rejected('inspection-during-pending-stamp',code,out,state,INVALID);assert state==previous
        with module.session(output_capacity=OUT,workspace_capacity=WORK) as session:
            populate(session);code,out,state=session.invoke_raw(request)
            assert code==176+len(records_wire(values)) and out[:8]==b'HRACR001' and out[64:176]==before and out[176:code]==records_wire(values)
            assert struct.unpack_from('<4Q',out,32)==(112,2,1,1)
            rows.append(dict(name='synthetic-complete-private-inspection',code=code,exact_record_vector=True))
            code,out,state=session.invoke_raw(wire(command(5),{}));assert code==64
            code,out,state=session.invoke_raw(request);assert code==64 and struct.unpack_from('<7Q',out,8)==(43,0,0,0,0,1,1)
            rows.append(dict(name='synthetic-poison-inspection',code=code))
        with module.session(output_capacity=OUT,workspace_capacity=WORK) as session:
            code,out,state=session.invoke_raw(request);assert code==64 and struct.unpack_from('<7Q',out,8)==(0,0,0,0,0,0,0)
            rows.append(dict(name='synthetic-uninitialized-inspection',code=code))
    assert args.manifest.read_bytes()==manifest
    report=dict(schema='hepta.request-audit.cache-stamp-controls.v1',status='PASS',checks=len(rows),rejection_controls=rejects,
        synthetic_completion_controls=len(rows)-rejects,cases=rows,manifest_sha256=SHA(manifest),
        original_executed=False,real_filesystem_effects=False,cold_snapshot_admitted=False,
        whole_runtime_replaced=False,production_activated=False)
    (args.output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},sort_keys=True))


if __name__=='__main__':main()

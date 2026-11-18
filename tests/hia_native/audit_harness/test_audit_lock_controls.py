"""Raw HIA buffer contracts and synthetic clock boundaries; no thread claims."""
from pathlib import Path
import argparse,ctypes,hashlib,json,struct,sys
SHA=lambda b:hashlib.sha256(b).hexdigest()
def wire(operation=0,token=0,flags=0,fields=None):
    raw=bytearray(128);raw[:8]=b'HRALQ001';struct.pack_into('<3Q',raw,8,operation,token,flags)
    for at,value in (fields or {}).items():struct.pack_into('<Q',raw,at,value)
    return bytes(raw)
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('manifest','runtime','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(mode=0o700,parents=True)
    sys.path.insert(0,str(args.runtime.resolve(strict=True)/'scripts'))
    from hia_native_loader import NativeModule
    raw_manifest=args.manifest.read_bytes();rows=[];rejections=0
    with NativeModule(args.manifest,manifest_sha256=SHA(raw_manifest)) as module:
        bad=[('short',wire()[:-1],64,256,0xffffffff),('long',wire()+b'\0',64,256,0xffffffff),
            ('magic',b'BADMAGIC'+wire()[8:],64,256,0xffffffff),('output',wire(),63,256,0xfffffffe),
            ('workspace',wire(),64,255,0xfffffffe),('operation',wire(14),64,256,0xffffffff),
            ('exclusive-flags',wire(1,flags=2),64,256,0xffffffff),('shared-needs-deadline',wire(2),64,256,0xffffffff),
            ('initial-token',wire(token=1),64,256,0xffffffff),('missing-guard',wire(4,flags=1),64,256,0xffffffff),
            ('unexpected-deadline',wire(8,fields={32:1}),64,256,0xffffffff),
            ('unknown-private-role',wire(4,token=1),64,256,0xffffffff),
            ('unknown-preflight-role',wire(13,token=3),64,256,0xffffffff),
            ('bad-drop-reason',wire(12,token=1,flags=1,fields={32:2}),64,256,0xffffffff)]
        for at in (40,56,72,88):bad.append(('invalid-nanoseconds-'+str(at),wire(fields={at:1000000000}),64,256,0xffffffff))
        for at,value in ((96,2),(104,2),(104,1),(112,1),(120,1)):
            bad.append(('invalid-field-'+str(at)+'-'+str(value),wire(fields={at:value}),64,256,0xffffffff))
        for name,raw,outcap,workcap,expected in bad:
            code,received,state=module.invoke_raw(raw,output_capacity=outcap,workspace_capacity=workcap,output_fill=0xa7)
            assert code==expected and received==b'\xa7'*outcap,(name,code,expected)
            rows.append(dict(name=name,code=code,output_untouched=True,state_sha256=SHA(state)));rejections+=1
        for name,at,value in [('magic',0,0),('version',8,2),('extent-short',16,255),('extent-past',16,272),
                ('reader-poison',72,2),('inner-poison',80,2),('queue-poison',88,2),('live-bound',104,257),('wait-bound',120,1)]:
            with module.session(output_capacity=64,workspace_capacity=256) as session:
                assert session.invoke_raw(wire())[0]==64
                struct.pack_into('<Q',session._workspace,at,value);ctypes.memset(session._output,0xa7,64)
                code,received,state=session.invoke_raw(wire(8));assert code==0xfffffff9 and received==b'\xa7'*64,name
                rows.append(dict(name='state-'+name,code=code,output_untouched=True,state_sha256=SHA(state)));rejections+=1
        with module.session(output_capacity=64,workspace_capacity=256) as session:
            initialized=session.invoke_raw(wire());assert initialized[0]==64;before=initialized[2]
            code,received,state=session.invoke_raw(wire(1));assert code==64
            assert struct.unpack_from('<3Q',received,16)==(2,0,352) and state==before
            rows.append(dict(name='growth-before-ticket-reservation',code=code,status=2,required=352,state_unchanged=True))
        clocks=[]
        for role in (1,2):
            for now in (99,100,101):clocks.append((f'post-turn-{role}-{now}',wire(4,1,role,{32:100,64:now,104:1}),6 if now>=100 else (4 if role==1 else 5)))
        for result in (0,1,2):
            for poison in (0,1):
                for now in (99,100):clocks.append((f'post-inner-{result}-{poison}-{now}',wire(5,1,result,{32:100,64:now,96:poison,104:1}),7 if result or poison else (6 if now>=100 else 5)))
        for role in (1,2):
            for panicking in (0,1):clocks.append((f'private-drop-{role}-{panicking}',wire(12,1,role,{32:panicking}),8 if role==1 else 0))
            for now in (99,100):clocks.append((f'pre-queue-{role}-{now}',wire(13,role,1,{32:100,48:now}),6 if now>=100 else 0))
        for name,raw,status in clocks:
            with module.session(output_capacity=64,workspace_capacity=256) as session:
                ctypes.memset(session._workspace,0xa7,256)
                code,received,state=session.invoke_raw(raw)
                assert code==64 and state==b'\xa7'*256,(name,code)
                assert struct.unpack_from('<Q',received,16)[0]==status,(name,received.hex(),status)
                assert received[40:64]==bytes(24)
                rows.append(dict(name=name,code=code,status=status,private_workspace_untouched=True))
    assert args.manifest.read_bytes()==raw_manifest
    report=dict(schema='hepta.request-audit.lock-controls.v1',status='PASS',checks=len(rows),rejection_controls=rejections,
        synthetic_controls=len(rows)-rejections,cases=rows,manifest_sha256=SHA(raw_manifest),original_executed=False,
        real_threads_executed=False,real_clock_readings=False,whole_runtime_replaced=False,production_activated=False)
    (args.output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},sort_keys=True))
if __name__=='__main__':main()

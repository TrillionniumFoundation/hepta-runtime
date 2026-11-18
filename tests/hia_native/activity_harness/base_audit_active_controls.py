"""Borrowed buffers, private arena growth and invalid lease-state controls."""
from pathlib import Path
import argparse,ctypes,hashlib,json,struct,sys
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def wire(op=0,token=0,id=b'',flag=0):
    return b'HRAAQ001'+struct.pack('<7Q',op,token,len(id),flag,0,0,0)+id
def setq(raw,at,value):
    raw=bytearray(raw);struct.pack_into('<Q',raw,at,value);return bytes(raw)
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('manifest','runtime','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(parents=True,mode=0o700)
    sys.path.insert(0,str(args.runtime.resolve(strict=True)/'scripts'));from hia_native_loader import NativeModule
    raw_manifest=args.manifest.read_bytes();rows=[];rejections=0
    with NativeModule(args.manifest,manifest_sha256=SHA(raw_manifest)) as module:
        bad=[('short',wire()[:-1],64,256,0xffffffff),('long',wire()+bytes(257),64,256,0xffffffff),
            ('magic',b'BADMAGIC'+wire()[8:],64,256,0xffffffff),('output',wire(),63,256,0xfffffffe),
            ('workspace',wire(),64,255,0xfffffffe),('operation',wire(15),64,256,0xffffffff),
            ('unused-token',wire(token=1),64,256,0xffffffff),('unused-id',wire(id=b'a'),64,256,0xffffffff),
            ('unused-flag',wire(flag=1),64,256,0xffffffff),('pin-flag',wire(2,flag=1),64,256,0xffffffff),
            ('bool',wire(1,flag=2),64,256,0xffffffff),('utf8',wire(1,id=b'\xff'),64,256,0xffffffff),
            ('id-too-long',wire(1,id=b'x'*257),64,256,0xffffffff),('id-size',setq(wire(1,id=b'x'),24,2),64,256,0xffffffff)]
        for op in (3,4,5,11):bad.append(('required-token-'+str(op),wire(op),64,256,0xffffffff))
        for at in (40,48,56):bad.append(('reserved-'+str(at),setq(wire(),at,1),64,256,0xffffffff))
        for name,raw,outcap,workcap,expected in bad:
            code,received,state=module.invoke_raw(raw,output_capacity=outcap,workspace_capacity=workcap,output_fill=0xa7)
            assert code==expected and received==b'\xa7'*outcap,(name,code)
            rows.append(dict(name=name,code=code,output_untouched=True,state_sha256=SHA(state)));rejections+=1
        for at,value in ((0,1),(8,255),(8,4097),(16,0),(24,8),(32,2),(40,2),(48,1),(56,1),(64,1),(72,1)):
            with module.session(output_capacity=64,workspace_capacity=4096) as session:
                assert session.invoke_raw(wire())[0]==64
                struct.pack_into('<Q',session._workspace,at,value);ctypes.memset(session._output,0xa7,64)
                code,received,state=session.invoke_raw(wire(8));assert code==0xfffffff9 and received==b'\xa7'*64,(at,value,code)
                rows.append(dict(name=f'header-{at}-{value}',code=code,output_untouched=True,state_sha256=SHA(state)));rejections+=1
        changes=[('kind',256,4),('object-id-zero',264,0),('object-id-future',264,2),('refcount',272,2),
            ('linked',280,2),('atomic-bool',288,2),('id-length',296,257),('handle-target-low',784,0),
            ('handle-target-alignment',784,257),('handle-target-past',784,1280),('handle-generation',800,2),
            ('missing-object',256,0),('dead-object-with-live-handle',272,0)]
        for name,at,value in changes:
            with module.session(output_capacity=64,workspace_capacity=4096) as session:
                assert session.invoke_raw(wire(1,id=b'x',flag=1))[0]==64
                struct.pack_into('<Q',session._workspace,at,value);ctypes.memset(session._output,0xa7,64)
                code,received,state=session.invoke_raw(wire(8));assert code==0xfffffff9 and received==b'\xa7'*64,(name,code)
                rows.append(dict(name=name,code=code,output_untouched=True,state_sha256=SHA(state)));rejections+=1
        with module.session(output_capacity=64,workspace_capacity=256) as session:
            assert session.invoke_raw(wire())[0]==64;before=bytes(session._workspace)[:256]
            code,received,state=session.invoke_raw(wire(1,id=b'x',flag=1))
            assert code==64 and struct.unpack_from('<2Q',received,8)==(2,1280) and state==before
            rows.append(dict(name='create-growth-before-publishing',required=1280,state_unchanged=True))
        with module.session(output_capacity=64,workspace_capacity=1280) as session:
            assert session.invoke_raw(wire(1,id=b'x',flag=1))[0]==64;before=bytes(session._workspace)[:1280]
            code,received,state=session.invoke_raw(wire(3,token=1))
            assert code==64 and struct.unpack_from('<2Q',received,8)==(2,1792) and state==before
            rows.append(dict(name='clone-growth-before-refcount',required=1792,state_unchanged=True))
        with module.session(output_capacity=64,workspace_capacity=2048) as session:
            ctypes.memmove(ctypes.addressof(session._workspace),before,len(before))
            code,received,state=session.invoke_raw(wire(3,token=1))
            assert code==64 and struct.unpack_from('<3Q',received,8)==(0,2,1) and struct.unpack_from('<Q',received,56)[0]==2
            assert struct.unpack_from('<Q',state,8)[0]==2048
            rows.append(dict(name='relocated-clone-replay',generation=1,new_handle=2,handles=2))
        for op in (1,3):
            with module.session(output_capacity=64,workspace_capacity=4096) as session:
                assert session.invoke_raw(wire(1,id=b'x',flag=1))[0]==64
                struct.pack_into('<Q',session._workspace,16,(1<<64)-1);before=bytes(session._workspace)[:4096]
                raw=wire(1,id=b'y',flag=1) if op==1 else wire(3,token=1)
                code,received,state=session.invoke_raw(raw)
                assert code==64 and struct.unpack_from('<3Q',received,8)==(41,0,0) and state==before
                rows.append(dict(name='synthetic-private-counter-'+str(op),state_unchanged=True,diagnostic=41))
    assert args.manifest.read_bytes()==raw_manifest
    report=dict(schema='hepta.request-audit.active-controls.v1',status='PASS',checks=len(rows),rejection_controls=rejections,
        synthetic_growth_and_counter_controls=len(rows)-rejections,cases=rows,manifest_sha256=SHA(raw_manifest),
        original_executed=False,real_threads_executed=False,native_language_unwind_qualified=False,whole_runtime_replaced=False,production_activated=False)
    (args.output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='cases'},sort_keys=True))
if __name__=='__main__':main()

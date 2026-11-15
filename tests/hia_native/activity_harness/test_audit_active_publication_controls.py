"""Extend the unchanged active-owner controls for detached publication inputs."""
from pathlib import Path
import argparse,contextlib,ctypes,hashlib,io,json,struct,sys
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('manifest','runtime','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(parents=True,mode=0o700)
    sys.path[:0]=[str(Path(__file__).resolve().parent),str(args.runtime.resolve(strict=True)/'scripts')]
    import base_audit_active_controls as base
    saved=sys.argv;sys.argv=[saved[0],'--manifest',str(args.manifest),'--runtime',str(args.runtime),'--output',str(args.output/'base')]
    try:
        capture=io.StringIO()
        with contextlib.redirect_stdout(capture):base.main()
    finally:sys.argv=saved
    previous=json.loads(capture.getvalue());assert previous['checks']==50 and previous['status']=='PASS'
    from hia_native_loader import NativeModule
    wire,setq=base.wire,base.setq;manifest=args.manifest.read_bytes();rows=[];rejects=0
    with NativeModule(args.manifest,manifest_sha256=SHA(manifest)) as module:
        bad=[('detached-token',wire(13,token=1),64,256,0xffffffff),('detached-id',wire(13,id=b'x'),64,256,0xffffffff),
            ('detached-flag',wire(13,flag=2),64,256,0xffffffff),('detached-extra',wire(13)+b'x',64,256,0xffffffff),
            ('detached-output',wire(13),63,256,0xfffffffe),('detached-workspace',wire(13),64,255,0xfffffffe),
            ('publish-token',wire(14),64,256,0xffffffff),('publish-flag',wire(14,token=1,flag=1),64,256,0xffffffff),
            ('publish-id',wire(14,token=1,id=b'x'*257),64,256,0xffffffff),('publish-utf8',wire(14,token=1,id=b'\xff'),64,256,0xffffffff),
            ('publish-short',wire(14,token=1)[:-1],64,256,0xffffffff),('publish-output',wire(14,token=1),63,256,0xfffffffe),
            ('publish-workspace',wire(14,token=1),64,255,0xfffffffe)]
        for op in (13,14):
            for at in (40,48,56):bad.append((f'reserved-{op}-{at}',setq(wire(op,token=int(op==14)),at,1),64,256,0xffffffff))
        for name,raw,outcap,workcap,expected in bad:
            code,received,state=module.invoke_raw(raw,output_capacity=outcap,workspace_capacity=workcap,output_fill=0xa7)
            assert code==expected and received==b'\xa7'*outcap,(name,code)
            rows.append(dict(name=name,code=code,output_untouched=True,state_sha256=SHA(state)));rejects+=1
        for at in (560,568):
            with module.session(output_capacity=64,workspace_capacity=4096) as session:
                assert session.invoke_raw(wire(13,flag=1))[0]==64
                struct.pack_into('<Q',session._workspace,at,2);ctypes.memset(session._output,0xa7,64)
                code,received,state=session.invoke_raw(wire(14,token=1,id=b'x'))
                assert code==0xfffffff9 and received==b'\xa7'*64
                rows.append(dict(name='publication-state-'+str(at),code=code,output_untouched=True,state_sha256=SHA(state)));rejects+=1
        with module.session(output_capacity=64,workspace_capacity=256) as session:
            assert session.invoke_raw(wire())[0]==64;before=bytes(session._workspace)[:256]
            code,received,state=session.invoke_raw(wire(13,flag=1))
            assert code==64 and struct.unpack_from('<2Q',received,8)==(2,1280) and state==before
            rows.append(dict(name='detached-growth',required=1280,state_unchanged=True))
        with module.session(output_capacity=64,workspace_capacity=4096) as session:
            assert session.invoke_raw(wire(9))[0]==64
            code,received,state=session.invoke_raw(wire(13,flag=1))
            assert code==64 and struct.unpack_from('<3Q',received,8)==(0,1,1) and received[32:56]==bytes(24)
            before=state;code,received,state=session.invoke_raw(wire(14,token=1,id=b'x'))
            assert code==64 and struct.unpack_from('<3Q',received,8)==(38,0,0) and state==before
            rows.append(dict(name='detached-before-registry-availability',state_unchanged_on_publish_error=True))
        with module.session(output_capacity=64,workspace_capacity=256) as session:
            assert session.invoke_raw(wire())[0]==64
            struct.pack_into('<Q',session._workspace,16,(1<<64)-1);before=bytes(session._workspace)[:256]
            code,received,state=session.invoke_raw(wire(13,flag=1))
            assert code==64 and struct.unpack_from('<3Q',received,8)==(41,0,0) and state==before
            rows.append(dict(name='synthetic-detached-counter-exhaustion',diagnostic=41,state_unchanged=True))
    assert args.manifest.read_bytes()==manifest
    result=dict(schema='hepta.request-audit.active-publication-controls.v1',status='PASS',checks=previous['checks']+len(rows),
        rejection_controls=previous['rejection_controls']+rejects,synthetic_controls=previous['synthetic_growth_and_counter_controls']+len(rows)-rejects,
        base_controls=previous,extension_cases=rows,manifest_sha256=SHA(manifest),
        baseline_control_delta='Only unknown op 13 becomes 15 because 13 and 14 are newly admitted.',
        original_executed=False,real_threads_executed=False,native_language_unwind_qualified=False,
        whole_runtime_replaced=False,production_activated=False)
    (args.output/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('base_controls','extension_cases')},sort_keys=True))
if __name__=='__main__':main()

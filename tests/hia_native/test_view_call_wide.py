#!/usr/bin/env python3
"""Capture real Value → typed projection → caller for one wide endpoint case.

No expected diagnostic is generated here. The separate locked Rust replay
checks the complete error, observations and cache against the original input.
"""
from __future__ import annotations
import ctypes,gzip,hashlib,importlib.util,json,os,struct,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module
sync=load('_view_wide_sync',Path(__file__).with_name('test_view_call_sync.py'))
wide=load('_view_wide_inputs',Path(__file__).with_name('view_call_oracle')/'wide_endpoint_case.py')
loader=load('_view_wide_loader',ROOT/'scripts/hia_native_loader.py')

def module_inputs(manifest,pins):
    meta=json.loads(manifest.read_text())
    for path in (manifest,manifest.parent/meta['source'],manifest.parent/meta['image']):
        pins[str(path)]=sync.identity(path)
    return loader.NativeModule(manifest,manifest_sha256=sync.identity(manifest)['sha256'])

def native_call(module,number,wire,output,workspace,capacity):
    name=f'owner-{number}';started=time.monotonic();code=None;failure=None;result=b''
    with module.session(workspace_capacity=workspace,output_capacity=capacity) as session:
        ctypes.memset(session._output,0xa5,capacity)
        try:result=session.invoke(wire);code=len(result)
        except (loader.NativeRejected,loader.NativeCapacityError) as error:
            code=error.code;failure=repr(error)
        assert code is not None
        path=output/(name+'.raw.bin.gz')
        with path.open('xb') as underlying,gzip.GzipFile(filename='',fileobj=underlying,mode='wb',mtime=0) as stream:
            stream.write(struct.pack('<8s6Q',b'HVWDR001',number,len(wire),capacity,workspace,code,len(result)))
            stream.write(wire)
            for buffer,length in ((session._output,capacity),(session._workspace,workspace)):
                address=ctypes.addressof(buffer)
                for at in range(0,length,65536):stream.write(ctypes.string_at(address+at,min(65536,length-at)))
        record=dict(number=number,code=code,workspace=workspace,output_capacity=capacity,
            input=sync.support.save_gzip(output,name+'.input.bin.gz',wire),
            output=sync.support.save_gzip(output,name+'.output.bin.gz',result),
            raw_path=path.name,raw_compressed=sync.identity(path),elapsed_seconds=time.monotonic()-started,error=failure)
        sync.write_json(output/(name+'.json'),record)
    if failure:raise AssertionError(record)
    return result,record

def main():
    output=Path(os.environ['HIA_VIEW_WIDE_CAPTURE_DIR']).resolve();output.mkdir(parents=True,exist_ok=False)
    manifest=Path(os.environ['HIA_VIEW_CALL_FIXTURE_MANIFEST']).resolve();elf,pins=sync.build_inputs(manifest)
    for path in (Path(__file__),Path(sync.__file__),Path(sync.support.__file__),Path(wide.__file__),Path(loader.__file__)):
        pins[str(path.resolve())]=sync.identity(path)
    calls=[];process=None;row=None;failure=None;arguments_artifact=None;canonical_bytes=None
    try:
        raw=wide.arguments();assert len(raw)<8<<20
        arguments_artifact=sync.support.save_gzip(output,'arguments.bin.gz',raw)
        value_manifest=Path(os.environ['HIA_VIEW_PARAMS_VALUE_MANIFEST']).resolve()
        with module_inputs(value_manifest,pins) as module:
            canonical,record=native_call(module,1,b'HSJVAL01'+struct.pack('<2Q',1,len(raw))+raw,
                output,128<<20,32<<20);calls.append(record)
        assert len(canonical)>16<<20
        projection_manifest=Path(os.environ['HIA_VIEW_PARAMS_MANIFEST']).resolve()
        with module_inputs(projection_manifest,pins) as module:
            projection,record=native_call(module,2,b'HVPRQ001'+struct.pack('<2Q',len(canonical),0)+canonical,
                output,65536,32<<20);calls.append(record)
        canonical_bytes=len(canonical);del canonical,raw
        assert projection[:8]==b'HVPRR001' and len(projection)>=96
        status,flags,pathlen,startlen,endlen,patternlen,contentlen,context,depth,presence,errorlen=struct.unpack_from('<11Q',projection,8)
        assert (status,flags,pathlen,endlen,patternlen,contentlen,context,depth,presence,errorlen)==(0,0,4,0,0,0,0,0,0,0)
        assert len(projection)==96+pathlen+startlen and projection[96:100]==b'file'
        start=projection[100:];assert start[:8]==b'HIAEP001'
        kind,length,scalar=struct.unpack_from('<3Q',start,8);assert kind==3 and scalar==0 and length==len(start)-32
        wire=struct.pack('<8s7Q',b'HVCLQ001',0,4,4,len(start),0,0,0)+b'filefile'+start
        del projection,start
        directory=output/'files';directory.mkdir();case=wide.case()
        filesystem=sync.support.CaseFilesystem(directory,case);filesystem.setup()
        process=sync.support.RecordedElf([elf,'--sync'],directory,output,'wide-endpoint',timeout=90)
        row=sync.execute_case(process,case,filesystem,output,wire_override=wire,original_input_override=wide.original_input())
        row['domain']='additional_public_prelude_wide_endpoint'
        assert row['case_id']==wide.CASE_ID and row['cancelled'] is False and row['ok'] is False
        assert row['body_bytes']>16<<20 and row['after_render_status']==1
        assert [item['event'] for item in row['io']]==['exists','is_dir']
        assert all(not item['present'] for name in ('cache_before','cache_after') for item in row[name])
        (output/'native-cases.jsonl').write_text(json.dumps(row,sort_keys=True,ensure_ascii=False)+'\n')
        receipt=process.finish();receipt['observed_kernel_receipts']=sync.receipt_counts(bytes(process.stderr))
        sync.write_json(output/'processes.json',[receipt]);assert receipt['observed_kernel_receipts']['read_attempts']==0
        assert {path:sync.identity(path) for path in pins}==pins
    except BaseException as error:
        failure=dict(error=repr(error),traceback=traceback.format_exc())
    finally:
        if process is not None and not process.closed:
            try:process.finish()
            except BaseException as error:
                if failure is None:failure=dict(error=repr(error),traceback=traceback.format_exc())
                else:failure['cleanup_error']=repr(error)
            sync.write_json(output/'processes.json',[process.receipt])
    summary=dict(schema='hepta.runtime.view-call-wide-native.v1',
        status='FAIL' if failure else 'NATIVE_COMPLETE_RUST_REPLAY_REQUIRED',
        groups=1,additional_wide_cases=1,ordinary_58_cases_counted=0,case_id=wide.CASE_ID,
        arguments=arguments_artifact,canonical_bytes=canonical_bytes,owner_calls=calls,
        actual_elf_processes=1 if process else 0,complete_error_bytes=row['body_bytes'] if row else None,
        ordinary_file_reads=0 if row is not None and [item['event'] for item in row['io']]==['exists','is_dir'] else None,
        pinned_inputs=pins,failure=failure,original_reference_comparison=False,
        public_mcp_route_replaced=False,whole_view_replaced=False,whole_runtime_replaced=False)
    sync.write_json(output/'result.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
    return failure is not None

if __name__=='__main__':raise SystemExit(main())

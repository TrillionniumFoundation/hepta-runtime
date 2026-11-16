"""CI-only complete unchanged target Deserialize and asynchronous plan observations."""
from __future__ import annotations
import argparse,hashlib,io,json,os,shutil,struct,sys,tarfile,tomllib
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'reference/params'))
from cases import all_cases
from process_capture import run,put,sha
ORIGINAL_SHA='254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'
def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert os.environ.get('GITHUB_ACTIONS')=='true','original Rust execution is restricted to CI'
    output=a.output.absolute();output.mkdir();source=json.loads((ROOT/'package-manifest.json').read_bytes())
    for name,expected in source['files'].items():assert pin((ROOT/name).read_bytes())==expected,name
    assert sha((ROOT/'reference/weight_bellman.rs').read_bytes())==ORIGINAL_SHA
    shutil.copytree(ROOT/'reference',output/'reference')
    shutil.copytree(ROOT,output/'recipe-source')
    put(output/'package-manifest.json',(ROOT/'package-manifest.json').read_bytes())
    env=dict(os.environ)
    for key in list(env):
        if key in {'RUSTFLAGS','RUSTDOCFLAGS','RUSTC','RUSTDOC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_TARGET',
            'CARGO_BUILD_RUSTC','CARGO_BUILD_RUSTDOC','CARGO_BUILD_RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_TARGET_DIR'} or (
            key.startswith('CARGO_') and (key.endswith('RUSTFLAGS') or key.endswith('RUSTDOCFLAGS') or key.endswith('_LINKER') or key.endswith('_RUNNER'))):del env[key]
    work=output.parent.parent/(output.parent.name+'-'+output.name+'-build-work');work.mkdir(mode=0o700)
    env.update(RUSTUP_TOOLCHAIN='1.95.0',CARGO_HOME=str(work/'cargo-home'),CARGO_TARGET_DIR=str(work/'target'),
        CARGO_ENCODED_RUSTFLAGS='',CARGO_ENCODED_RUSTDOCFLAGS='',PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED='0')
    run(output,'rustc-version',['rustc','--version','--verbose'],env,limit=30)
    assert (output/'processes/rustc-version.stdout').read_bytes().startswith(b'rustc 1.95.0 ')
    run(output,'cargo-version',['cargo','--version'],env,limit=30)
    manifest=output/'reference/full_plan/Cargo.toml';lock=manifest.with_name('Cargo.lock');lock_raw=lock.read_bytes()
    run(output,'cargo-build',['cargo','build','--locked','--manifest-path',str(manifest)],env,limit=300)
    assert lock.read_bytes()==lock_raw
    run(output,'cargo-metadata',['cargo','metadata','--locked','--format-version','1','--manifest-path',str(manifest)],env,limit=120)
    metadata=json.loads((output/'processes/cargo-metadata.stdout').read_bytes())
    locked={(p['name'],p['version']):p for p in tomllib.loads(lock_raw.decode())['package'] if 'source' in p};registry={}
    for package in metadata['packages']:
        if package['source'] is None:assert package['name']=='hia-bellman-call-reference';continue
        name=package['name']+'-'+package['version'];identity=locked[(package['name'],package['version'])]
        candidates=list((work/'cargo-home/registry/cache').glob('*/'+name+'.crate'));assert len(candidates)==1
        raw=candidates[0].read_bytes();assert sha(raw)==identity['checksum'] and package['source']==identity['source']
        actual=Path(package['manifest_path']).parent;rows={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as tar:
            for member in tar:
                if member.isdir():continue
                assert member.isfile() and member.name.startswith(name+'/')
                relative=member.name[len(name)+1:];assert '..' not in Path(relative).parts and relative not in rows
                data=tar.extractfile(member).read();assert (actual/relative).read_bytes()==data
                rows[relative]=pin(data)
        put(output/'registry'/(name+'.crate'),raw);put(output/'registry'/(name+'.source.json'),rows)
        registry[name]=dict(archive=pin(raw),actual_source_files=len(rows))
    assert set(registry)=={n+'-'+v for n,v in locked}
    put(output/'registry.json',registry)
    binary=work/'target/debug/hia-bellman-call-reference';target=output/'original-plan';put(target,binary.read_bytes());target.chmod(0o500)
    public_binary=work/'target/debug/hia-bellman-public-reference';public_target=output/'original-public';put(public_target,public_binary.read_bytes());public_target.chmod(0o500)
    cases=list(all_cases(ROOT/'reference/qualify_bellman.py'));assert len(cases)==683
    request=b''.join(struct.pack('<Q',len(raw))+raw for _,_,raw in cases);put(output/'original.stdin',request)
    # The second binary imports the same unchanged target types directly.
    # Its compact wire encoder is byte-identical to the qualified old observer.
    typed_binary=work/'target/debug/hia-bellman-params-reference'
    typed_target=output/'original-params';put(typed_target,typed_binary.read_bytes());typed_target.chmod(0o500)
    run(output,'params-original',[str(typed_target)],env,limit=60,stdin=request)
    typed=(output/'processes/params-original.stdout').read_bytes()
    domain=json.loads((ROOT/'domain.json').read_bytes());assert pin(typed)==domain['original_output']
    at=0;typed_rows=[]
    for (group,name,raw),declared in zip(cases,domain['cases']):
        assert len(typed)-at>=8;size=struct.unpack_from('<Q',typed,at)[0];at+=8
        frame=typed[at:at+size];at+=size
        assert len(frame)==size and size>=64 and frame[:8]==b'HBPOR001'
        status,canonical_length,body_length,count,r0,r1,r2=struct.unpack_from('<7Q',frame,8)
        assert status in (0,1) and (r0,r1,r2)==(0,0,0) and size==64+canonical_length+body_length
        canonical=frame[64:64+canonical_length];body=frame[64+canonical_length:]
        assert (group,name)==(declared['group'],declared['name'])
        assert pin(canonical)==declared['canonical'] and pin(body)==declared['body'] and status==declared['status'] and count==declared['states']
        typed_rows.append(dict(group=group,name=name,raw=pin(raw),canonical=pin(canonical),body=pin(body),status=status,states=count))
    assert at==len(typed) and len(typed_rows)==683
    put(output/'typed/original.stdout',typed);put(output/'typed/original.stdin',request)
    put(output/'typed/original.json',dict(status='ORIGINAL_OBSERVED_NATIVE_REQUIRED',cases=typed_rows,case_count=683,
        successful_typed=401,typed_errors=282,complete_input=pin(request),complete_output=pin(typed),binary=pin(typed_target.read_bytes()),
        original_source_sha256=ORIGINAL_SHA,source_manifest=pin((ROOT/'package-manifest.json').read_bytes()),
        native_qualified=False,whole_runtime_replaced=False,public_handler_qualified=False))
    run(output,'original',[str(target)],env,limit=60,stdin=request)
    data=(output/'processes/original.stdout').read_bytes();at=0;results=[]
    domain=json.loads((ROOT/'domain.json').read_bytes())
    for index,((group,name,raw),declared) in enumerate(zip(cases,domain['cases'])):
        assert (group,name)==(declared['group'],declared['name'])
        assert len(data)-at>=8;size=struct.unpack_from('<Q',data,at)[0];at+=8
        record=data[at:at+size];at+=size;assert len(record)==size and record[:8]==b'HBCOR001'
        status,canonical_length,text_length,before,after,position,reserved=struct.unpack_from('<7Q',record,8)
        assert size==64+canonical_length+text_length and position==index and reserved==0 and before<=after
        canonical=record[64:64+canonical_length];text=record[64+canonical_length:]
        assert pin(canonical)==declared['canonical'] and status in (0,1,2)
        assert (status==1)==(declared['status']==1)
        if status==0:
            value=json.loads(text);assert len(value)==36
            assert 0<=value['native_operation_wall_seconds']<=(after-before)/1e9
        else:text.decode('utf-8')
        results.append(dict(index=index,group=group,name=name,status=status,canonical=pin(canonical),text=pin(text),before_ns=before,after_ns=after))
    assert at==len(data)
    put(output/'original.json',dict(status='ACTUAL_ORIGINAL_HANDLER_OBSERVED',cases=results,case_count=683,
        complete_input=pin(request),complete_output=pin(data),binary=pin(target.read_bytes()),registry_packages=len(registry),
        original_source_sha256=ORIGINAL_SHA,source_manifest=pin((ROOT/'package-manifest.json').read_bytes()),
        whole_runtime_replaced=False,public_handler_qualified=False,native_executed=False))
    print(json.dumps(dict(status='ACTUAL_ORIGINAL_HANDLER_OBSERVED',cases=683,registry_packages=len(registry),output_bytes=len(data)),sort_keys=True))
if __name__=='__main__':main()

"""Independently read the entire retained build, all source, and physical controls.

No HIA, native, Rust, compiler, assembler, or shell process is executed. The
complete producer archive is immutable. Physical control clones are derived
only from already retained bytes and retired only after full byte/mode checks.
"""
from pathlib import Path
import argparse,codecs,gzip,hashlib,importlib,json,os,shutil,stat,sys,traceback,zipfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import archive_stream as stream
import read_only_guard as guard
IDENTITY={'artifact':14293655303,'run':44002477899,'source':'b149a6ffb01d140b9182a9834bb8dedbb6e1c762',
    'bytes':787671157,'sha256':'490c0260a2a8f2d5b293781efd6e5248533044508e56164643422e05fbdaa1df'}
BUILD_PROFILE='2e5cf893eeb0068465801c9f6f5e43a347c95d75c9d830878b899e9eb9710370'
BINDING='8016acfef110430ce56aaac1b956fc56a27463fd3362d29280620f185013573d'
CHUNK=384<<20
def put(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as f:json.dump(value,f,sort_keys=True,indent=2,allow_nan=False);f.write('\n')
def inventory(root):
    root=Path(root);result={}
    for path in sorted(root.rglob('*')):
        info=path.lstat();assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
        if stat.S_ISREG(info.st_mode):result[path.relative_to(root).as_posix()]={**stream.pin(path),'mode':stat.S_IMODE(info.st_mode)}
    return result
def equal_files(first,second):
    assert stat.S_IMODE(first.stat().st_mode)==stat.S_IMODE(second.stat().st_mode)
    with first.open('rb') as one,second.open('rb') as two:
        while True:
            a=one.read(1<<20);b=two.read(1<<20);assert a==b
            if not a:break
def qualify_controls(capture,package,reader,controls,output):
    output.mkdir();declared=controls.build_inventory(capture)
    # The new source-reproduction prerequisite must be in every physical clone.
    for rel,row in inventory(capture/'source-reproduction').items():
        declared['source-reproduction/'+rel]={k:row[k] for k in ('bytes','sha256')}
    for suffix in ('json','stdout','stderr'):
        name='processes/source-reproduction.'+suffix;declared[name]=stream.pin(capture/name)
    original={n:{**r,'mode':stat.S_IMODE((capture/n).stat().st_mode)} for n,r in declared.items()}
    put(output/'FULL_SOURCE_INVENTORY.json',original);cases=[];baseline_guard=None
    for index,(name,relative,kind) in enumerate(controls.CASES):
        clone=output/(name+'.clone');clone.mkdir()
        for rel,row in original.items():
            dst=clone/rel;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(capture/rel,dst);dst.chmod(row['mode'])
        assert inventory(clone)==original
        if index==0:
            baseline_guard=guard.guarded(lambda:reader.verify_build(package,clone,BUILD_PROFILE),roots=[clone,package,ROOT],foreign_path=Path('/dev/null'))
            assert baseline_guard['before']==baseline_guard['after'] and len(baseline_guard['probes'])==11
            put(output/'BASELINE_GUARD.json',baseline_guard)
        changed=clone/relative;raw=changed.read_bytes();mutated=controls.mutation(raw,kind)
        assert mutated!=raw;mode=original[relative]['mode'];changed.chmod(mode|stat.S_IWUSR);changed.write_bytes(mutated);changed.chmod(mode)
        expected=dict(original);expected[relative]={**stream.pin(changed),'mode':mode};assert inventory(clone)==expected
        def reject():
            assert inventory(clone)==expected
            try:reader.verify_build(package,clone,BUILD_PROFILE)
            except (ValueError,AssertionError) as error:return {'rejected':True,'type':type(error).__name__,'message':str(error)}
            raise ValueError('physical corruption accepted')
        checked=guard.guarded(reject,roots=[clone,package,ROOT],foreign_path=Path('/dev/null'))
        assert checked['before']==checked['after'] and len(checked['probes'])==11 and checked['reader_writes']==checked['native_or_rust_executions']==0 and checked['evidence']['rejected']
        saved=output/name;saved.mkdir();target=saved/'changed'/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(changed,target);target.chmod(mode)
        equal_files(changed,target);put(saved/'GUARD.json',checked)
        for rel in expected:equal_files(clone/rel,target if rel==relative else capture/rel)
        assert inventory(clone)==expected
        row={'case':name,'changed_path':relative,'before':original[relative],'after':expected[relative],
            'rejection':checked['evidence'],'guard':stream.pin(saved/'GUARD.json'),'complete_clone_files':len(original),
            'complete_unchanged_bytes_and_modes_verified_before_retirement':True,'native_or_rust_executed':False}
        put(saved/'CONTROL.json',row);cases.append(row);shutil.rmtree(clone)
    report={'status':'COMPLETE_PHYSICAL_BUILD_READER_CONTROLS_PASS','refusals':4,'guard_probes':44,
        'complete_baseline_guard_probes':11,'complete_source_inventory':stream.pin(output/'FULL_SOURCE_INVENTORY.json'),
        'baseline_guard':stream.pin(output/'BASELINE_GUARD.json'),'cases':cases,
        'original_controls_preserved':True,'added_source_reproduction_prerequisite':True,
        'semantic_executions':0,'complete_mutated_bytes_retained':True}
    put(output/'REPORT.json',report);return report
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--profile',required=True);a=p.parse_args()
    out=a.output.absolute();assert not out.exists();proof=out/'proof';proof.mkdir(parents=True)
    try:
        assert stream.pin(ROOT/'PROFILE.json')['sha256']==a.profile;profile=json.loads((ROOT/'PROFILE.json').read_bytes())
        assert {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(profile['files'])|{'PROFILE.json'}
        for name,row in profile['files'].items():assert stream.pin(ROOT/name)==row and stat.S_IMODE((ROOT/name).stat().st_mode)==0o644
        meta=json.loads((a.input.parent/'artifact.json').read_bytes())
        assert meta['id']==IDENTITY['artifact'] and meta['digest']=='sha256:'+IDENTITY['sha256'] and meta['workflow_run']['id']==IDENTITY['run'] and meta['workflow_run']['head_sha']==IDENTITY['source']
        for encoding in ('ascii','utf-8','utf-8-sig','cp437'):codecs.lookup(encoding)
        assert gzip.decompress(gzip.compress(b'',mtime=0))==b''
        capture=out/'complete-capture';selected=stream.archive(a.input,IDENTITY,lambda name:True,output=capture)
        package=capture/'ci-package';assert stream.pin(package/'PACKAGE.json')['sha256']==BUILD_PROFILE
        assert stream.pin(package/'graph/source/native/runtime_mcp_sources.json')['sha256']==BINDING
        sys.path.insert(0,str(package/'ci'))
        reader=importlib.import_module('read_build');controls=importlib.import_module('build_controls')
        assert Path(reader.__file__).resolve()==package/'ci/read_build.py' and Path(controls.__file__).resolve()==package/'ci/build_controls.py'
        reader.prepare(package)
        def verify():
            archive=stream.archive(a.input,IDENTITY,lambda name:True,verify_root=capture)
            assert archive==selected
            result=reader.verify_build(package,capture,BUILD_PROFILE)
            old_controls=controls.verify_controls(package,capture,BUILD_PROFILE)
            recorded=json.loads((capture/'processes/read-build.stdout').read_bytes())
            relocated=json.loads(json.dumps(result));origin=json.loads((capture/'BUILD_ORIGIN.json').read_bytes());path_bindings=[]
            # descriptor() reports the current evidence location. Bind exactly
            # these eight paths to the unchanged original capture-relative path.
            for label in ('production','journal','trace','instances'):
                for kind in ('elf','manifest'):
                    actual=Path(result['entries'][label][kind]['path']);relative=actual.relative_to(capture)
                    expected=str(Path(origin['output'])/relative)
                    assert recorded['entries'][label][kind]['path']==expected
                    relocated['entries'][label][kind]['path']=expected
                    path_bindings.append({'entry':label,'kind':kind,'actual':str(actual),'producer':expected,'relative':relative.as_posix()})
            assert len(path_bindings)==8 and relocated==recorded
            assert old_controls['refusals']==4 and result['runtime_hia_images']==118 and result['fresh_direct_members']==110
            return {'status':'COMPLETE_PUBLIC118_ARCHIVE_STREAM_READ_PASS','source':IDENTITY['source'],'run':IDENTITY['run'],
                'artifact':IDENTITY['artifact'],'zip':{k:IDENTITY[k] for k in ('bytes','sha256')},'archive':archive,
                'build_qualification':result,'complete_report_relocation':path_bindings,'original_physical_controls':old_controls,'all_regular_members_read':True,
                'all_original_modes_checked':True,'native_executed':False,'rust_executed':False}
        checked=guard.guarded(verify,roots=[capture,ROOT,a.input.absolute().parent],foreign_path=Path('/dev/null'))
        assert checked['before']==checked['after'] and len(checked['probes'])==11 and checked['reader_writes']==checked['native_or_rust_executions']==0
        put(proof/'READONLY.json',checked)
        repaired=qualify_controls(capture,package,reader,controls,proof/'complete-physical-controls')
        shutil.copytree(ROOT,proof/'reader-source')
        for name in ('BUILD_PASS.json','BUILD_ORIGIN.json','production/BUILD.json','reader-controls/report.json',
                'processes/read-build.stdout','processes/physical-controls.stdout','processes/shape-admission-controls.stdout','processes/source-reproduction.stdout'):
            target=proof/'selected'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(capture/name,target);equal_files(capture/name,target)
        parts=[];whole=hashlib.sha256();count=0
        with a.input.open('rb') as src:
            for index in range(2):
                folder=out/('part-'+str(index));folder.mkdir();target=folder/'part.bin';remaining=min(CHUNK,IDENTITY['bytes']-count)
                with target.open('xb') as dst:
                    while remaining:
                        raw=src.read(min(1<<20,remaining));assert raw;dst.write(raw);whole.update(raw);count+=len(raw);remaining-=len(raw)
                parts.append({'index':index,**stream.pin(target)})
            assert src.read(1)==b'' and {'bytes':count,'sha256':whole.hexdigest()}=={k:IDENTITY[k] for k in ('bytes','sha256')}
        transport={'schema':'hepta.runtime.complete-artifact-chunks.v1','status':'COMPLETE_UNCHANGED_ZIP_SPLIT_PASS',
            'original_artifact':IDENTITY['artifact'],'original_run':IDENTITY['run'],'original_source':IDENTITY['source'],
            'original_zip':{k:IDENTITY[k] for k in ('bytes','sha256')},'parts':parts,'chunk_size':CHUNK,
            'archive_readback':stream.pin(proof/'READONLY.json'),'complete_physical_controls':stream.pin(proof/'complete-physical-controls/REPORT.json'),
            'source_profile_sha256':a.profile,'native_or_rust_executed':False,'qualified_semantics_replayed':False}
        put(proof/'TRANSPORT.json',transport)
        for row in parts:put(out/('part-'+str(row['index']))/'TRANSPORT.json',transport)
        print(json.dumps(transport,sort_keys=True))
    except BaseException as error:
        put(proof/'FAILURE.json',{'status':'FAIL','error':repr(error),'traceback':traceback.format_exc(),'native_or_rust_executed':False});raise
if __name__=='__main__':main()

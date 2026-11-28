"""Qualify exact historical58 source materialization; never run Rust or HIA."""
# Copyright 2026 Muvon Un Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from pathlib import Path
import argparse, ast, contextlib, hashlib, importlib.util, io, json, os, shutil, stat, subprocess, sys, tarfile
sys.dont_write_bytecode=True
P=Path('tests/hia_native/historical_public58')
BASE='3072822ad1f7e6e0caa680225ffadd3bacff4718'
HEAD='208ff61db1da78aadfeb8d7913af7ddf4b59d461'
TREE='7d50c61f02704e3ce3afd82568c50db960b08a9a'
OLD_PROFILE='967681ea10302228904f72a83b85e996cf57f008'
OLD_MATERIALIZER='f8c5f1e47e68b4a45a6dd35f17a67204145fd987'
NEW={'PROFILE.json':'817652c6f11fed3035ea902fc54cedb16f931876','materialize.py':'c24d5798eedca8177cb3189ce7a7bd14e2b1e2b7','README.md':'c9383d2751cb644e50ad58b1906ca485e2e3453b'}
FIXES={'scripts/hia_native_shell_process_reference.py':'048ed71646399e92e4f8bcc465cf09043ccc53e3',
       'scripts/compare_hia_runtime_rust.py':'178b411e1fc15d21240d2588f62ebc61f1dfba99',
       'tests/hia_native/test_qualification_reporting.py':'64587aa4bac8cffd8e9fbe2119a9e8fcf2f925be'}
REPLACEMENTS=[('"authoring","vendor")','"authoring","vendor","runtime_support")',1),('source-profile.v3','source-profile.v4',1),('==102','==111',2),('==218','==390',1),('==75','==247',1),('current_default_images=102','current_default_images=111',2),('CURRENT102_AND_HISTORICAL58','CURRENT111_AND_HISTORICAL58',1),('current_graph_files=218','current_graph_files=390',1),('default_current_images=102','default_current_images=111',1)]

def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())

def dump(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def files(root):
    result={}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink(),str(path)
        if path.is_dir():continue
        assert stat.S_ISREG(path.stat().st_mode)
        result[path.relative_to(root).as_posix()]={**pin(path.read_bytes()),'mode':stat.S_IMODE(path.stat().st_mode)}
    return result

def snapshot(root):
    result={}
    for path in [root,*sorted(root.rglob('*'))]:
        s=path.lstat();assert not stat.S_ISLNK(s.st_mode)
        result[path.relative_to(root).as_posix()]=(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns,
            pin(path.read_bytes()) if stat.S_ISREG(s.st_mode) else None)
    return result

def load_materializer(path):
    spec=importlib.util.spec_from_file_location('historical58_materializer',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def check_sources(current,baseline,old_text):
    raw=(current/P/'PROFILE.json').read_bytes();profile=json.loads(raw)
    assert pin(json.dumps(baseline,sort_keys=True,indent=2).encode()+b'\n')['git_blob']==OLD_PROFILE
    for name,sha in NEW.items():assert pin((current/P/name).read_bytes())['git_blob']==sha,name
    assert len(profile['current_graph_files'])==390 and len(profile['current_authority_profile_files'])==6
    assert profile['restore']==baseline['restore'] and len(profile['restore'])==119
    assert profile['historical_authority_restore']==baseline['historical_authority_restore']
    assert profile['current_authority_profile_files']==baseline['current_authority_profile_files']
    added=set(profile['current_graph_files'])-set(baseline['current_graph_files'])
    assert len(added)==172 and not added.intersection(profile['restore'])
    assert profile['remove_current_public_only']==sorted(set(baseline['remove_current_public_only'])|added)
    assert len(profile['remove_current_public_only'])==247
    stable=set(baseline)-{'schema','current_default_images','current_default_graph_binding_sha256','current_graph_files','remove_current_public_only'}
    assert all(profile[k]==baseline[k] for k in stable)
    reconstructed=(current/P/'materialize.py').read_text()
    for before,after,count in reversed(REPLACEMENTS):
        assert reconstructed.count(after)==count
        reconstructed=reconstructed.replace(after,before)
    assert reconstructed==old_text
    assert ast.dump(ast.parse(reconstructed),include_attributes=False)==ast.dump(ast.parse(old_text),include_attributes=False)
    for path,sha in FIXES.items():assert pin((current/path).read_bytes())['git_blob']==sha,path
    module=load_materializer(current/P/'materialize.py')
    checked,sha=module.check(current);assert checked==profile
    return module,profile,sha

def read(capture):
    proof=json.loads((capture/'proof.json').read_bytes())
    baseline_raw=(capture/'baseline-profile.json').read_bytes()
    assert pin(baseline_raw)['git_blob']==OLD_PROFILE
    old_raw=(capture/'baseline-materialize.py').read_bytes()
    assert pin(old_raw)['git_blob']==OLD_MATERIALIZER
    current=capture/'current-source';historical=capture/'historical-source'
    module,profile,profile_sha=check_sources(current,json.loads(baseline_raw),old_raw.decode())
    actual_current={k:pin(p.read_bytes()) for k,p in module.selected(current).items()}
    actual_historical={k:pin(p.read_bytes()) for k,p in module.selected(historical).items()}
    receipt=json.loads((historical/'HISTORICAL_PUBLIC_SOURCE.json').read_bytes())
    assert receipt['status']=='SOURCE_PROFILE_MATERIALIZED'
    assert receipt['profile_sha256']==profile_sha
    assert receipt['historical_public_images']==58 and receipt['current_default_images']==111
    assert receipt['restored_paths']==sorted(profile['restore'])
    assert receipt['excluded_current_only_paths']==profile['remove_current_public_only']
    assert receipt['files']==actual_historical
    expected=dict(actual_current)
    for name in profile['remove_current_public_only']:
        assert expected.pop(name)==profile['current_graph_files'][name]
        assert not (historical/name).exists()
    expected.update(profile['restore'])
    assert actual_historical==expected
    for name,value in profile['restore'].items():assert actual_historical[name]==value
    assert proof['source_files']==len(actual_current)==3270
    assert proof['historical_files']==len(actual_historical)==3023
    assert proof['source_commit']==HEAD and proof['source_tree']==TREE
    assert proof['producer_source_unchanged'] and proof['materialized_reader_passed']
    assert proof['rust_or_hia_executed'] is False and proof['prior_local_session_status']=='UNKNOWN_NOT_REPLAYED'
    controls=json.loads((capture/'controls.json').read_bytes())
    assert [c['name'] for c in controls]==['current-frontend','current-packed-worker','historical-restore']
    assert all(c['refused'] and c['check_wrote_nothing'] for c in controls)
    for c in controls:
        raw=(capture/'mutations'/c['name']).read_bytes()
        assert pin(raw)==c['changed_bytes']
        assert c['target_path'] in c['assertion']
    index=json.loads((capture/'FILE_INDEX.json').read_bytes())
    actual=files(capture);actual.pop('FILE_INDEX.json')
    assert actual==index
    return {'status':'EXACT_CURRENT111_TO_HISTORICAL58_COMPLETE_SOURCE_PASS',
        'source_commit':HEAD,'source_tree':TREE,'current_bound_files':390,'authority_files':6,
        'all_current_files':3270,'historical_files':3023,'historical_restore_files':119,
        'historical_restore_bytes_unchanged':True,'current_only_excluded':247,
        'physical_pin_refusals':3,'materializer_full_inverse_bytes_and_ast_equal':True,
        'retained_7afd_08ce':True,'native_or_rust_executed':False,
        'semantic_ci_replayed':False,'archive_files':len(actual)+1}

def guarded(capture):
    # Preload the exact Python source module before installing the no-effect reader guard.
    load_materializer(capture/'current-source'/P/'materialize.py')
    before=snapshot(capture);active=[True];blocked=[]
    def audit(event,args):
        if not active[0]:return
        if event.startswith(('subprocess.','os.exec','os.spawn','ctypes.','mmap.')) or event in ('os.system','os.posix_spawn'):
            blocked.append(event);raise PermissionError(event)
        if event=='open':
            mode,flags=args[1:3]
            if (isinstance(mode,str) and any(c in mode for c in 'wax+')) or (isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)):
                blocked.append(event);raise PermissionError('write open')
        if event in ('os.mkdir','os.remove','os.rename','os.rmdir','os.chmod','os.utime','os.link','os.symlink','os.truncate'):
            blocked.append(event);raise PermissionError(event)
    sys.addaudithook(audit)
    try:
        evidence=read(capture);assert not blocked
        after=snapshot(capture);assert before==after
    finally:active[0]=False
    return {'status':'READONLY_COMPLETE_SOURCE_PASS','evidence':evidence,'unchanged_entries':len(before),
            'writes':0,'child_processes':0,'native_or_rust_executed':False}

def capture_source(source,output):
    assert not output.exists();output.mkdir(parents=True)
    def git(*args):return subprocess.check_output(['git','-C',str(source),*args])
    assert git('rev-parse','HEAD').decode().strip()==HEAD
    assert git('rev-parse','HEAD^{tree}').decode().strip()==TREE
    changed=git('diff','--name-only',BASE,HEAD).decode().splitlines()
    assert set(changed)=={(P/name).as_posix() for name in NEW}
    baseline_raw=git('cat-file','blob',OLD_PROFILE);old_raw=git('cat-file','blob',OLD_MATERIALIZER)
    assert pin(baseline_raw)['git_blob']==OLD_PROFILE and pin(old_raw)['git_blob']==OLD_MATERIALIZER
    module,profile,profile_sha=check_sources(source,json.loads(baseline_raw),old_raw.decode())
    original=module.selected(source)
    before={k:(pin(p.read_bytes()),p.stat().st_mode,p.stat().st_mtime_ns,p.stat().st_ctime_ns) for k,p in original.items()}
    capture=output/'capture';capture.mkdir();current=capture/'current-source';current.mkdir()
    for name,path in original.items():
        target=current/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,target)
    historical=capture/'historical-source'
    prior=sys.argv[:];sys.argv=[str(source/P/'materialize.py'),'--source',str(source),'--output',str(historical)]
    stream=io.StringIO()
    try:
        with contextlib.redirect_stdout(stream):module.main()
    finally:sys.argv=prior
    (capture/'materialize.stdout').write_text(stream.getvalue())
    verified=module.verify_materialized(historical)
    (capture/'baseline-profile.json').write_bytes(baseline_raw);(capture/'baseline-materialize.py').write_bytes(old_raw)
    (capture/'mutations').mkdir();controls=[]
    packed=next(name for name in sorted(profile['current_graph_files']) if name.startswith('runtime_support/') and name.endswith('.hepta'))
    for name,target in [('current-frontend','native/runtime_mcp.hepta'),('current-packed-worker',packed),('historical-restore',(P/'source/native/runtime_mcp.hepta').as_posix())]:
        clone=output/('control-'+name);shutil.copytree(current,clone)
        raw=(clone/target).read_bytes()+b'\n';(clone/target).write_bytes(raw)
        before_control=files(clone);error=None
        try:module.check(clone)
        except AssertionError as failure:error=str(failure)
        assert error is not None and target.removeprefix(str(P/'source')+'/') in error
        assert before_control==files(clone)
        (capture/'mutations'/name).write_bytes(raw)
        reported_target=target.removeprefix(str(P/'source')+'/') if name=='historical-restore' else target
        controls.append({'name':name,'target_path':reported_target,'changed_bytes':pin(raw),'assertion':error,'refused':True,'check_wrote_nothing':True})
        shutil.rmtree(clone)
    dump(capture/'controls.json',controls)
    after={k:(pin(p.read_bytes()),p.stat().st_mode,p.stat().st_mtime_ns,p.stat().st_ctime_ns) for k,p in module.selected(source).items()}
    assert before==after
    proof={'source_commit':HEAD,'source_tree':TREE,'source_files':len(before),'historical_files':verified['files'],
           'producer_source_unchanged':True,'materialized_reader_passed':True,
           'rust_or_hia_executed':False,'prior_local_session_status':'UNKNOWN_NOT_REPLAYED',
           'prior_local_session':13338,'prior_verify_create_process':'REJECTED_NOT_EXECUTED',
           'preserved_failures':[{'run':43997250789,'job':133752232343},{'run':43997250856,'job':133752233452},{'run':43997250790,'job':133752232588}],
           'historical_graph_binding_sha256':profile['historical_graph_binding_sha256'],
           'materialized_result':verified,'source_delta':changed}
    dump(capture/'proof.json',proof)
    dump(capture/'FILE_INDEX.json',files(capture))
    gate=guarded(capture);dump(output/'GATE.json',gate)
    archive=output/'source-proof.tar.gz';entries=[]
    with tarfile.open(archive,'w:gz',compresslevel=1) as tar:
        for path in sorted(capture.rglob('*')):
            if not path.is_file():continue
            raw=path.read_bytes();name='capture/'+path.relative_to(capture).as_posix()
            item=tarfile.TarInfo(name);item.size=len(raw);item.mode=stat.S_IMODE(path.stat().st_mode);item.mtime=0
            tar.addfile(item,io.BytesIO(raw));entries.append({'path':name,'mode':item.mode,**pin(raw)})
        raw=(output/'GATE.json').read_bytes();item=tarfile.TarInfo('GATE.json');item.size=len(raw);item.mode=0o644;item.mtime=0
        tar.addfile(item,io.BytesIO(raw));entries.append({'path':'GATE.json','mode':0o644,**pin(raw)})
    with tarfile.open(archive,'r:gz') as tar:
        seen=[]
        for member in tar:
            assert member.isfile();raw=tar.extractfile(member).read();seen.append({'path':member.name,'mode':member.mode,**pin(raw)})
        assert seen==entries
    dump(output/'ARCHIVE.json',{'archive':pin(archive.read_bytes()),'files':entries,'complete_tar_bytes_reread':True,
          'native_or_rust_executed':False})
    print(json.dumps(gate,sort_keys=True))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path);parser.add_argument('--output',type=Path);parser.add_argument('--read-only',type=Path)
    args=parser.parse_args()
    if args.read_only:print(json.dumps(guarded(args.read_only.resolve()),sort_keys=True));return
    assert args.source and args.output;capture_source(args.source.resolve(),args.output.absolute())

if __name__=='__main__':main()

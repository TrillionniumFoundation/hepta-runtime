"""Rebuild only a diagnostic transport prefix around the retained 118-image graph."""
from pathlib import Path
import argparse,copy,hashlib,json,os,shutil,signal,stat,sys,time,traceback
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'retained'))
import restore
def sha(b):return hashlib.sha256(b).hexdigest()
def put(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
def fail_alarm(signum,frame):raise TimeoutError('unchanged diagnostic domain deadline')
def exactly(text,before,after):
    assert text.count(before)==1,('source anchor',before)
    return text.replace(before,after,1)
def source_admit():
    raw=(ROOT/'PACKAGE.json').read_bytes();rows=json.loads(raw)['files']
    assert os.environ['PACKAGE_SHA256']==sha(raw)
    actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}
    assert actual==set(rows)|{'PACKAGE.json'}
    for name,row in rows.items():
        p=ROOT/name;b=p.read_bytes();assert not p.is_symlink() and stat.S_IMODE(p.stat().st_mode)==int(row['mode'],8)&0o777
        assert len(b)==row['bytes'] and sha(b)==row['sha256']
        assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==row['git_blob']
    return {'files':len(rows),'manifest_sha256':sha(raw)}
def instrument(root,out):
    p=root/'scripts/runtime_extract_body_bridge.S';before=p.read_text();text=before
    text=exactly(text,'    call local_extract_lines_run\n','    call local_extract_lines_run\n    call extract_diagnostic_terminal\n')
    text=exactly(text,'    mov r12, rdi\n    mov [rsp], rsi\n','    mov r12, rdi\n    mov qword ptr [r12 + 232], 1\n    mov [rsp], rsi\n')
    text=exactly(text,'    add rdx, 64\n','    mov qword ptr [r12 + 232], 2\n    add rdx, 64\n')
    text=exactly(text,'    call view_scope_invoke\n','    mov qword ptr [r12 + 232], 3\n    call view_scope_invoke\n    mov [r12 + 240], rax\n    mov qword ptr [r12 + 232], 4\n')
    text=exactly(text,'    mov eax, 32\n    jmp rexh_hint_done\n','    mov qword ptr [r12 + 232], 5\n    inc qword ptr [r12 + 248]\n    mov eax, 32\n    jmp rexh_hint_done\n')
    text+='\n'+(ROOT/'diagnostic.S').read_text()
    p.write_text(text)
    proof={'schema':'extract.public118.native-diagnostic-overlay.v1','base_source':'a521066dfa07db38e6a22bd2f03d1dae3c203cc2','before':{'bytes':len(before.encode()),'sha256':sha(before.encode())},'after':{'bytes':len(text.encode()),'sha256':sha(text.encode())},'changes':['after callable return, observe existing contexts without changing return or any admission','hint callback stores stage and actual return in previously unused opaque bytes232..255'],'diagnostic_only':True,'production_candidate':False,'semantic_checks_removed':False}
    put(out/'DIAGNOSTIC_OVERLAY.json',proof)
    cache=root/'scripts/runtime_extract_cache_bridge.S';cache_before=cache.read_text()
    old='    cmp qword ptr [rsi + 8], 3\n    jne rec_cache_invalid\n'
    new='    cmp qword ptr [rsi + 8], 3\n    je rec_cache_operation\n    cmp qword ptr [rsi + 8], 7\n    jne rec_cache_invalid\n'
    cache_after=exactly(cache_before,old,new);cache.write_text(cache_after)
    cache_proof={'before':{'bytes':len(cache_before.encode()),'sha256':sha(cache_before.encode())},'after':{'bytes':len(cache_after.encode()),'sha256':sha(cache_after.encode())},'operation':7,'reason':'source-owned invalidate-local-variants request after the real extract file edit','HIA_payload_validation_unchanged':True}
    put(out/'CACHE_OPERATION7_FIX.json',cache_proof)
    binding=root/'native/runtime_mcp_sources.json';old=binding.read_bytes()
    assert sha(old)=='2c423747b2827c3a6d0993b89583c47691640ea44fcf5f77e6c0ed2aaaf0dc70'
    v=json.loads(old);assert v['sources']['scripts/runtime_extract_body_bridge.S']==proof['before']
    v['sources']['scripts/runtime_extract_body_bridge.S']=proof['after']
    assert v['sources']['scripts/runtime_extract_cache_bridge.S']==cache_proof['before']
    v['sources']['scripts/runtime_extract_cache_bridge.S']=cache_proof['after'];put(binding,v)
    put(out/'DIAGNOSTIC_BINDING.json',{'old_sha256':sha(old),'new_sha256':sha(binding.read_bytes())})
def main():
    assert os.environ.get('GITHUB_ACTIONS')=='true'
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--retained',type=Path,required=True);p.add_argument('--source',type=Path,required=True);p.add_argument('--compiler',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve();out.mkdir();report={'status':'RUNNING','source_admission':source_admit(),'diagnostic_only':True,'public_handler_qualified':False,'original_reference_executed':False,'passed_native_build_replayed':False,'run':os.environ['GITHUB_RUN_ID'],'source':os.environ['GITHUB_SHA']}
    put(out/'RUN.json',report)
    try:
        z=a.input.resolve();assert restore.pin_file(z)=={k:restore.PINS['native'][k] for k in ('bytes','sha256')}
        base=a.retained.resolve();assert not base.exists();base.mkdir()
        restore.selected=lambda role,name:True
        read=restore.archive('native',z,base);put(out/'RETAINED_ARCHIVE_READ.json',read)
        origin=json.loads((base/'BUILD_ORIGIN.json').read_bytes())
        assert str(base)==origin['output'],'use original producer path without rewriting captured manifests'
        root=a.source.resolve();assert not root.exists();shutil.copytree(base/'ci-package/graph/source',root)
        original_hia={p.relative_to(root).as_posix():sha(p.read_bytes()) for p in root.rglob('*.hepta')}
        instrument(root,out)
        assert original_hia=={p.relative_to(root).as_posix():sha(p.read_bytes()) for p in root.rglob('*.hepta')}
        put(out/'UNCHANGED_HIA_SOURCES.json',original_hia)
        shutil.copytree(root,out/'source')
        sys.path.insert(0,str(root/'scripts'))
        import public_nine_build as build
        candidate=out/'candidate';candidate.mkdir();shutil.copytree(base/'instances/bootstrap',candidate/'bootstrap')
        md=json.loads((base/'production/build/public-task-batch-extract/manifest.json').read_bytes());manifests={r['name']:r['manifest'] for r in md['members']}
        assert len(manifests)==110 and all(Path(v).is_relative_to(base) for v in manifests.values())
        signal.signal(signal.SIGALRM,fail_alarm);signal.alarm(900)
        try:
            manifest=build.build_runtime_mcp(a.compiler.resolve(strict=True),candidate,name='diagnostic-private',source_root=root,manifests=manifests,private_fixture=True,bellman_port_build=base/'production/port/build-v3',bellman_port_package=root/'runtime_support/bellman_port',bellman_worker_build=base/'production/worker')
        finally:signal.alarm(0)
        value=json.loads(Path(manifest).read_bytes());assert len(value['members'])==110 and all(not x['fresh_compile'] for x in value['members'])
        put(out/'DIAGNOSTIC_BUILD.json',{'manifest':str(manifest),'binary':{'bytes':value['elf_bytes'],'sha256':value['elf_sha256']},'unchanged_hia_images':118,'retained_direct_members':110,'retained_packed_members':8,'source':'a521066dfa07db38e6a22bd2f03d1dae3c203cc2','diagnostic_only':True})
        import qualify_public as q
        real_plan=q.cases.plan
        def one_case(domain,fixture,case_index=None):
            v=real_plan(domain,fixture,case_index);v['rows']=v['rows'][:1];return v
        q.cases.plan=one_case
        fixture=out/'workspace';trial=out/'trial';signal.alarm(180)
        try:q.execute('native',Path(manifest).parent/value['elf'],fixture,trial,'typed-modern')
        except BaseException as error:put(out/'TRIAL_FAILURE.json',{'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc(),'original_first_failure_retained':True})
        finally:signal.alarm(0)
        vault=out/'full-fixture-blobs';vault.mkdir()
        put(out/'FINAL_FILESYSTEM.json',q.body_fixture.tree_snapshot(fixture,vault))
        report['status']='DIAGNOSTIC_CAPTURE_COMPLETE';report['qualification_claimed']=False
    except BaseException as error:
        report['status']='FAIL';report['error']={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()};raise
    finally:put(out/'RUN.json',report)
if __name__=='__main__':main()

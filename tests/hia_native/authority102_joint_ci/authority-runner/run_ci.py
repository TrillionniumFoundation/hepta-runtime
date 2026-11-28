"""Fresh public102, retained authority domains, and unchanged current Rust originals."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from check_source import check,check_runner
from verify_complete import FALSE_FLAGS
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True)
    for name in ('sdk-source','hepta','rust-bin','get-info-reference','output'):p.add_argument('--'+name,type=Path)
    p.add_argument('--check-only',action='store_true');a=p.parse_args()
    source=a.source.resolve(strict=True);closure=check(source);runner=check_runner(HERE)
    if a.check_only:
        print(json.dumps(dict(status='SOURCE_CLOSURE_PASS',source=closure,runner=runner,native_or_rust_executed=False),sort_keys=True));return
    assert os.environ.get('CI')=='true','Fresh Rust is executed only in CI.'
    assert all(getattr(a,name) for name in ('sdk_source','hepta','rust_bin','get_info_reference','output'))
    reference=a.get_info_reference.resolve(strict=True);raw=reference.read_bytes()
    assert len(raw)==1236951 and SHA(raw)=='c9ff4c9282e406de911119c2287093165d3829c333be43da06ac14f75edf295d'
    out=a.output.absolute();assert not out.exists() and not out.is_relative_to(source)
    out.mkdir(parents=True);(out/'processes').mkdir();start=time.monotonic()
    report=dict(schema='hepta.public-authority102.recipe.v1',status='RUNNING',processes=[],
        source_manifest_sha256=closure['source_manifest_sha256'],fresh_retained_62=False,fresh_public_102=False,
        fresh_current_owner_v4=False,fresh_exact_transport_original=False,fresh_exact_handshake_original=False,
        current_public_owner_replay=False,existing_binary_inputs=False,rust_executed=False,
        **{name:False for name in FALSE_FLAGS})
    report['producer_identity']=dict(source=str(source),output=str(out),runner=str(HERE),
        sdk_source=str(a.sdk_source.resolve(strict=True)),hepta=str(a.hepta.resolve(strict=True)),
        rust_bin=str(a.rust_bin.resolve(strict=True)),get_info_reference=str(reference),
        python=sys.executable,cwd=os.getcwd())
    def checkpoint():report['elapsed_seconds']=time.monotonic()-start;put(out/'RECIPE.json',report)
    def run(label,script,args):
        command=[sys.executable,'-I','-B',str(script),*map(str,args)];begin=time.monotonic()
        with (out/'processes'/(label+'.stdout')).open('xb') as stdout,(out/'processes'/(label+'.stderr')).open('xb') as stderr:
            process=subprocess.Popen(command,stdout=stdout,stderr=stderr);code=process.wait()
        row=dict(label=label,command=command,exit_code=code,elapsed_seconds=time.monotonic()-begin,
            outer_timeout_seconds=None,pid=process.pid,cwd=os.getcwd())
        for key in ('stdout','stderr'):
            data=(out/'processes'/(label+'.'+key)).read_bytes();row[key]=dict(bytes=len(data),sha256=SHA(data))
        report['processes'].append(row);checkpoint();assert code==0,label
    checkpoint();drivers=source/'drivers';graph=source/'source'
    try:
        run('author-frontend',source/'authoring/author_frontend.py',['--hepta',a.hepta,'--baseline',source/'baseline-source','--source',source/'authority-before','--check'])
        run('author-mechanical',source/'authoring/author_mechanical.py',['--baseline',source/'baseline-source','--source',source/'authority-before','--check'])
        run('author-batch-union',source/'composition/check_union.py',['--source',source,'--hepta',a.hepta])
        run('fresh-retained62',source/'transport-reference/drivers/build_retained_eight.py',
            ['--sdk-source',a.sdk_source,'--hepta',a.hepta,'--output',out/'retained-eight'])
        baseline=json.loads((out/'retained-eight/BUILD.json').read_bytes())
        assert baseline['fresh_members']==62 and baseline['existing_binary_inputs'] is False
        report['fresh_retained_62']=True;checkpoint()
        run('fresh-public102',graph/'scripts/hia_native_runtime_mcp_build.py',
            ['--hepta',a.hepta,'--output',out/'public','--bootstrap',out/'retained-eight/build/bootstrap'])
        public=json.loads((out/'public/BUILD.json').read_bytes())
        assert public['fresh_member_compiles']==102 and public['checked_reused_members']==0 and public['default_public_entrypoint'] is True
        report['fresh_public_102']=True;checkpoint()
        run('private-pack102',drivers/'build_private_binding.py',['--source',graph,'--public',out/'public','--hepta',a.hepta,'--output',out/'private'])
        private=json.loads((out/'private/BUILD.json').read_bytes());private_manifest=out/'private'/private['manifest']
        mapping={}
        for manifest in (Path(public['manifest']),private_manifest):
            data=json.loads(manifest.read_bytes())
            for row in [*data['members'],data['link'],data['pack']]:
                path=Path(row['manifest']).resolve(strict=True);assert path.is_relative_to(out)
                mapping[str(path)]=path.relative_to(out).as_posix()
        put(out/'module-map.json',dict(schema='hepta.public-authority.portable-module-map.v1',modules=mapping))
        run('native-private-binding',drivers/'capture_private_binding.py',['--source',graph,'--manifest',private_manifest,'--output',out/'private-binding'])
        run('private-readonly',drivers/'verify_private_readonly.py',['--source',graph,'--manifest',private_manifest,
            '--capture',out/'private-binding','--module-map',out/'module-map.json'])
        run('current-profile-build',drivers/'build_authority_retained.py',['--source',source/'authority-retained','--hepta',a.hepta,
            '--bootstrap',out/'public/build/bootstrap','--output',out/'current-profile-build'])
        run('current-profile23',drivers/'run_authority_retained.py',['--source',source/'authority-retained','--hepta',a.hepta,
            '--manifests',out/'current-profile-build/MANIFESTS.json','--output',out/'current-profile'])
        run('historical-profile-build',drivers/'build_authority_retained.py',['--source',source/'authority-historical','--hepta',a.hepta,
            '--bootstrap',out/'public/build/bootstrap','--output',out/'historical-profile-build'])
        run('historical-profile7',drivers/'run_authority_historical.py',['--source',source/'authority-historical',
            '--manifests',out/'historical-profile-build/MANIFESTS.json','--output',out/'historical-profile'])
        finish(a,source,out,graph,drivers,private_manifest,public,baseline,reference,run,report,checkpoint)
        assert check(source)==closure and check_runner(HERE)==runner
    except BaseException:report.update(status='FAIL',failure=traceback.format_exc());raise
    finally:checkpoint()
    print(json.dumps({k:v for k,v in report.items() if k!='processes'},sort_keys=True))

def finish(a,source,out,graph,drivers,private_manifest,public,baseline,reference,run,report,checkpoint):
    owner=source/'owner-reference'
    run('fresh-owner-v4-current243',owner/'tests/hia_native/caller_owner_export/qualify.py',
        ['--phase','all','--source-root',owner,'--hepta',a.hepta,'--output',out/'owner-v4'])
    original=json.loads((out/'owner-v4/QUALIFICATION.json').read_bytes())
    assert original['status']=='PASS' and original['evidence']['original']['rows']==243
    report.update(fresh_current_owner_v4=True,rust_executed=True);checkpoint()
    run('current-public-owner16',drivers/'public_owner_reference.py',['--source',graph,'--manifest',private_manifest,
        '--capture',out/'private-binding','--owner-output',out/'owner-v4','--output',out/'public-owner-reference',
        '--module-map',out/'module-map.json'])
    report['current_public_owner_replay']=True;checkpoint()
    run('normal-corpus',drivers/'transport_cases.py',['--output',out/'transport-inputs'])
    run('native-framing24',drivers/'capture_transport_native.py',['--build',out/'public','--cases',out/'transport-inputs','--output',out/'native-framing'])
    run('fresh-original28',source/'transport-reference/drivers/run_transport_reference.py',
        ['--source',source/'transport-reference','--cases',out/'transport-inputs','--native',out/'native-framing',
         '--rust-bin',a.rust_bin,'--output',out/'transport-reference'])
    assert json.loads((out/'transport-reference/SUMMARY.json').read_bytes())['status']=='ACTUAL_TARGET_TRANSPORT_REFERENCE_PASS'
    report['fresh_exact_transport_original']=True;checkpoint()
    run('fresh-original54',source/'handshake-reference/scripts/run_reference.py',
        ['--source',source/'handshake-reference','--rust-bin',a.rust_bin,'--output',out/'handshake-reference'])
    assert json.loads((out/'handshake-reference/SUMMARY.json').read_bytes())['status']=='PASS'
    report['fresh_exact_handshake_original']=True;checkpoint()
    run('native-handshake54',drivers/'capture_handshake.py',
        ['--source',source/'handshake-reference','--build',out/'public','--output',out/'native-handshake'])
    run('retained-public90',drivers/'qualify_public.py',['--source',graph,'--manifest',public['manifest'],
        '--baseline-elf',baseline['elf'],'--get-info-reference',reference,'--output',out/'public-loop'])
    run('readonly-complete',HERE/'verify_complete.py',['--source',source,'--run',out,'--require-fresh'])
    guarded=json.loads((out/'processes/readonly-complete.stdout').read_bytes());gate=guarded['evidence']
    assert gate['status']=='READONLY_PUBLIC102_AUTHORITY259_HANDSHAKE324_PUBLIC90_TRANSPORT24_PASS'
    assert guarded['readonly']['before']==guarded['readonly']['after'] and len(guarded['readonly']['probes'])==11
    put(out/'verification.json',gate)
    report.update(status='PASS',sessions=54,handshake_responses=324,serial_public_wire_cases=24,
        codec_eof_reference_only_cases=4,public_counts=gate['public']['counts'],
        private_counts=gate['private_binding']['counts'],current_owner_original_rows=243,current_public_owner_rows=16,
        current_profile_native_groups=23,historical_receipt_groups=7,candidate_elf_sha256=gate['candidate_elf_sha256'])

if __name__=='__main__':main()

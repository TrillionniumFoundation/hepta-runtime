"""Read the complete public102/authority/current-original qualification."""
from pathlib import Path
import argparse
from contextlib import contextmanager
from functools import lru_cache
import hashlib
import importlib.util
import json
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from check_source import check,check_runner
from retained_baseline_reader import baseline
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
FALSE_FLAGS=('full_sdk_qualified','full_136_route_qualified','full_async_runtime_qualified',
    'service_task_or_future_lifecycle_qualified','cancellation_timing_qualified',
    'target_general_response_owner_integrated','request_audit_integrated','annotation_integrated',
    'public_http_qualified','concurrent_binding_qualified','paired_random_generators_compared',
    'production_activated','old_path_removed','independent_cold_qualified')
LABELS=('author-frontend','author-mechanical','author-batch-union','fresh-retained62','fresh-public102','private-pack102',
    'native-private-binding','private-readonly','current-profile-build','current-profile23',
    'historical-profile-build','historical-profile7','fresh-owner-v4-current243','current-public-owner16',
    'normal-corpus','native-framing24','fresh-original28','fresh-original54','native-handshake54',
    'retained-public90','readonly-complete')
ISOLATED=('cases','common','reader','custody','controls','prepare_reference','verify_readonly',
    'hia_native_owner_export_reference','hia_native_build','hia_native_loader',
    'hia_native_authority_layout','hia_native_entropy_qualification')
def doc(path):return json.loads(path.read_bytes())
@lru_cache(maxsize=None)
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
@contextmanager
def isolated():
    saved={name:sys.modules.pop(name,None) for name in ISOLATED};paths=list(sys.path)
    try:yield
    finally:
        sys.path[:]=paths
        for name,prior in saved.items():
            sys.modules.pop(name,None)
            if prior is not None:sys.modules[name]=prior
@contextmanager
def selected(modules):
    with isolated():
        sys.modules.update(modules)
        yield

@lru_cache(maxsize=None)
def preload(source):
    drivers=source/'drivers';sys.path.insert(0,str(drivers))
    # Import before the exact-file guard; importlib probes a non-admitted pyc path.
    load('_authority102_composition_summary',source/'composition/check_union.py')
    load('_authority_private_reader',drivers/'verify_private_binding.py')
    load('_authority_public_reader',drivers/'verify_public.py')
    load('_authority_transport_reader',drivers/'verify_transport_reference.py')
    load('_authority_bridge_reference_reader',drivers/'public_owner_reference.py')
    guard=load('_authority_complete_guard',drivers/'read_only_guard.py')
    sys.path.insert(0,str(source/'transport-reference/drivers'))
    import transport_cases
    with isolated():
        handshake=load('_authority_handshake_reader',drivers/'verify_handshake.py')
        handshake.original_module=lru_cache(maxsize=None)(handshake.original_module)
        handshake.original_module(source/'handshake-reference')
    with isolated():
        owner=load('_authority_owner_qualifier',source/'owner-reference/tests/hia_native/caller_owner_export/qualify.py')
        import controls
        owner.source_evidence(source/'owner-reference')
        owner_modules={name:sys.modules[name] for name in ISOLATED if name in sys.modules}
    retained=load('_authority_retained_reader',drivers/'verify_authority_retained.py')
    retained.load_reader=lru_cache(maxsize=None)(retained.load_reader)
    with isolated():
        retained.load_reader(source/'authority-retained')
        retained.load_reader(source/'authority-historical')
    return dict(guard=guard,owner=owner,owner_modules=owner_modules)

def verify(source,run,*,require_fresh=False,require_recipe_pass=False):
    prepared=preload(source)
    closure=check(source);runner=check_runner(HERE);graph=source/'source';drivers=source/'drivers'
    module_map=run/'module-map.json';old=baseline(run/'retained-eight')
    public=load('_authority_public_reader',drivers/'verify_public.py').verify(graph,run/'public',run/'public-loop',module_map)
    with isolated():
        handshake=load('_authority_handshake_reader',drivers/'verify_handshake.py').verify(
            source/'handshake-reference',run/'handshake-reference',run/'native-handshake',run/'public')
    transport=load('_authority_transport_reader',drivers/'verify_transport_reference.py').verify(
        source/'transport-reference',run/'transport-reference',run/'native-framing',run/'transport-inputs')
    built=doc(run/'public/BUILD.json');md=doc(run/'public/build/public-authority-batch/manifest.json')
    assert public['elf_sha256']==handshake['candidate_elf_sha256']==transport['actual_native_elf_sha256']==built['elf_sha256']
    assert public['physical_images']==102 and handshake['sessions']==54 and handshake['responses']==324
    assert transport['serial_public_wire_cases']==24 and transport['codec_eof_reference_only_cases']==4
    if require_fresh:assert public['fresh_member_compiles']==102 and public['checked_reused_members']==0
    assert built['default_public_entrypoint'] is True and md['authority_slot']==56
    assert md['private_descriptor_base']==8192 and md['private_engine_bytes']==16384
    private_build=doc(run/'private/BUILD.json');private_manifest=run/'private'/private_build['manifest']
    assert private_build['status']=='PASS' and private_build['checked_public_members']==102
    assert private_build['public_manifest_sha256']==built['manifest_sha256']
    assert private_build['manifest_sha256']==SHA(private_manifest.read_bytes())
    pmd=doc(private_manifest)
    assert pmd['source_binding']==md['source_binding']
    for actual,expected in zip(pmd['members'],md['members'],strict=True):
        for key in ('name','source','source_sha256','image_sha256','image_bytes','manifest','manifest_sha256'):
            assert actual[key]==expected[key]
    private=load('_authority_private_reader',drivers/'verify_private_binding.py').verify(graph,private_manifest,run/'private-binding',module_map)
    guarded=doc(run/'processes/private-readonly.stdout')
    assert guarded['evidence']==private and guarded['before']==guarded['after']
    assert guarded['reader_writes']==guarded['native_or_rust_executions']==0 and len(guarded['probes'])==11
    retained_reader=load('_authority_retained_reader',drivers/'verify_authority_retained.py')
    with isolated():retained=retained_reader.verify(source/'authority-retained',run/'current-profile-build',run/'current-profile')
    with isolated():historical=retained_reader.verify(source/'authority-historical',run/'historical-profile-build',run/'historical-profile',historical=True)
    assert retained['test_groups']==23 and historical['test_groups']==7
    with selected(prepared['owner_modules']):
        owner_root=source/'owner-reference'
        owner=prepared['owner']
        owner_source=owner.source_evidence(owner_root)
        current=owner.qualification(run/'owner-v4',owner_source['pins_sha256'])
        assert owner.encoded(current)==(run/'owner-v4/QUALIFICATION.json').read_bytes()
    assert current['evidence']['original']['rows']==243 and current['reader_refusals']==16
    bridge=load('_authority_bridge_reference_reader',drivers/'public_owner_reference.py').verify(run/'owner-v4',private,run/'public-owner-reference')
    assert bridge==doc(run/'public-owner-reference/REFERENCE.json') and bridge['rows']==16
    result=dict(schema='hepta.public-authority102.complete-readonly.v1',status='READONLY_PUBLIC102_AUTHORITY259_HANDSHAKE324_PUBLIC90_TRANSPORT24_PASS',
        source=closure,runner=runner,retained_eight=old,public=public,handshake=handshake,transport=transport,
        private_binding=private,current_profile_retained=retained,historical_profile_retained=historical,
        current_owner_v4=current,current_public_owner=bridge,candidate_elf_sha256=built['elf_sha256'],physical_images=102,
        fresh_member_compiles=public['fresh_member_compiles'],checked_reused_members=public['checked_reused_members'],
        default_public_entrypoint_verified=True,configured_serial_owner_admission_verified=True,
        peer_info_is_authority=False,target_original_public_handler_comparison=False,
        native_or_rust_executed_by_reader=False,source_or_evidence_written_by_reader=False,
        **{name:False for name in FALSE_FLAGS})
    verify_recipe(source,run,closure,result,require_recipe_pass)
    return result

def verify_recipe(source,run,closure,result,require_pass):
    recipe=doc(run/'RECIPE.json')
    assert recipe['schema']=='hepta.public-authority102.recipe.v1'
    assert recipe['status'] in (('PASS',) if require_pass else ('RUNNING','PASS'))
    assert recipe['source_manifest_sha256']==closure['source_manifest_sha256']
    assert recipe['existing_binary_inputs'] is False and recipe['rust_executed'] is True
    for key in ('fresh_retained_62','fresh_public_102','fresh_current_owner_v4',
                'fresh_exact_transport_original','fresh_exact_handshake_original','current_public_owner_replay'):
        assert recipe[key] is True
    for key in FALSE_FLAGS:assert recipe[key] is False
    labels=LABELS if recipe['status']=='PASS' else LABELS[:-1]
    assert [row['label'] for row in recipe['processes']]==list(labels)
    expected=expected_commands(recipe['producer_identity'],doc(run/'public/BUILD.json'),doc(run/'retained-eight/BUILD.json'))
    for row in recipe['processes']:
        assert row['exit_code']==0 and row['outer_timeout_seconds'] is None
        assert type(row['pid']) is int and row['pid']>0
        assert row['command']==expected[row['label']] and row['cwd']==recipe['producer_identity']['cwd']
        for stream in ('stdout','stderr'):
            raw=(run/'processes'/(row['label']+'.'+stream)).read_bytes()
            assert row[stream]==dict(bytes=len(raw),sha256=SHA(raw))
    composition=load('_authority102_composition_summary',source/'composition/check_union.py')
    assert doc(run/'processes/author-batch-union.stdout')==composition.summary(source)
    assert (run/'processes/author-batch-union.stderr').read_bytes()==b''
    assert doc(run/'current-profile/SUMMARY.json')['runner_source_sha256']==SHA((source/'drivers/run_authority_retained.py').read_bytes())
    assert doc(run/'historical-profile/SUMMARY.json')['runner_source_sha256']==SHA((source/'drivers/run_authority_historical.py').read_bytes())
    if recipe['status']=='PASS':assert doc(run/'verification.json')==result

def expected_commands(identity,public,baseline):
    assert set(identity)=={'source','output','runner','sdk_source','hepta','rust_bin','get_info_reference','python','cwd'}
    assert all(type(value) is str and Path(value).is_absolute() for value in identity.values())
    source=Path(identity['source']);out=Path(identity['output']);runner=Path(identity['runner'])
    graph=source/'source';drivers=source/'drivers';owner=source/'owner-reference'
    hepta=identity['hepta'];private=out/'private/build/authority-private/manifest.json'
    rows={}
    def add(label,script,args):rows[label]=[identity['python'],'-I','-B',str(script),*map(str,args)]
    add('author-frontend',source/'authoring/author_frontend.py',['--hepta',hepta,'--baseline',source/'baseline-source','--source',source/'authority-before','--check'])
    add('author-mechanical',source/'authoring/author_mechanical.py',['--baseline',source/'baseline-source','--source',source/'authority-before','--check'])
    add('author-batch-union',source/'composition/check_union.py',['--source',source,'--hepta',hepta])
    add('fresh-retained62',source/'transport-reference/drivers/build_retained_eight.py',['--sdk-source',identity['sdk_source'],'--hepta',hepta,'--output',out/'retained-eight'])
    add('fresh-public102',graph/'scripts/hia_native_runtime_mcp_build.py',['--hepta',hepta,'--output',out/'public','--bootstrap',out/'retained-eight/build/bootstrap'])
    add('private-pack102',drivers/'build_private_binding.py',['--source',graph,'--public',out/'public','--hepta',hepta,'--output',out/'private'])
    add('native-private-binding',drivers/'capture_private_binding.py',['--source',graph,'--manifest',private,'--output',out/'private-binding'])
    add('private-readonly',drivers/'verify_private_readonly.py',['--source',graph,'--manifest',private,'--capture',out/'private-binding','--module-map',out/'module-map.json'])
    add('current-profile-build',drivers/'build_authority_retained.py',['--source',source/'authority-retained','--hepta',hepta,'--bootstrap',out/'public/build/bootstrap','--output',out/'current-profile-build'])
    add('current-profile23',drivers/'run_authority_retained.py',['--source',source/'authority-retained','--hepta',hepta,'--manifests',out/'current-profile-build/MANIFESTS.json','--output',out/'current-profile'])
    add('historical-profile-build',drivers/'build_authority_retained.py',['--source',source/'authority-historical','--hepta',hepta,'--bootstrap',out/'public/build/bootstrap','--output',out/'historical-profile-build'])
    add('historical-profile7',drivers/'run_authority_historical.py',['--source',source/'authority-historical','--manifests',out/'historical-profile-build/MANIFESTS.json','--output',out/'historical-profile'])
    add('fresh-owner-v4-current243',owner/'tests/hia_native/caller_owner_export/qualify.py',['--phase','all','--source-root',owner,'--hepta',hepta,'--output',out/'owner-v4'])
    add('current-public-owner16',drivers/'public_owner_reference.py',['--source',graph,'--manifest',private,'--capture',out/'private-binding','--owner-output',out/'owner-v4','--output',out/'public-owner-reference','--module-map',out/'module-map.json'])
    add('normal-corpus',drivers/'transport_cases.py',['--output',out/'transport-inputs'])
    add('native-framing24',drivers/'capture_transport_native.py',['--build',out/'public','--cases',out/'transport-inputs','--output',out/'native-framing'])
    add('fresh-original28',source/'transport-reference/drivers/run_transport_reference.py',['--source',source/'transport-reference','--cases',out/'transport-inputs','--native',out/'native-framing','--rust-bin',identity['rust_bin'],'--output',out/'transport-reference'])
    add('fresh-original54',source/'handshake-reference/scripts/run_reference.py',['--source',source/'handshake-reference','--rust-bin',identity['rust_bin'],'--output',out/'handshake-reference'])
    add('native-handshake54',drivers/'capture_handshake.py',['--source',source/'handshake-reference','--build',out/'public','--output',out/'native-handshake'])
    add('retained-public90',drivers/'qualify_public.py',['--source',graph,'--manifest',public['manifest'],'--baseline-elf',baseline['elf'],'--get-info-reference',identity['get_info_reference'],'--output',out/'public-loop'])
    add('readonly-complete',runner/'verify_complete.py',['--source',source,'--run',out,'--require-fresh'])
    assert tuple(rows)==LABELS
    return rows

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--run',type=Path,required=True)
    p.add_argument('--require-fresh',action='store_true');p.add_argument('--require-recipe-pass',action='store_true')
    a=p.parse_args();source=a.source.resolve(strict=True);run=a.run.resolve(strict=True)
    check(source);check_runner(HERE);guard=preload(source)['guard']
    report=guard.guarded(lambda:verify(source,run,require_fresh=a.require_fresh,require_recipe_pass=a.require_recipe_pass),
        roots=[source,run,HERE],foreign_path='/dev/null')
    print(json.dumps(dict(status=report['evidence']['status'],evidence=report['evidence'],readonly=report),sort_keys=True))

if __name__=='__main__':main()

"""Admit one new native build and the unchanged successful original public lane.

All archive members are read. Original semantics are never rerun. The old full
ZIP and both original build proofs remain part of the new retained evidence.
"""
from pathlib import Path
import hashlib,json,os,shutil,stat,zipfile
import archive_stream,legacy_ready,legacy_restore
from receipt_support import PIN,regular,require
ROOT=Path(__file__).resolve().parent
CONFIG=json.loads((ROOT/'RETAINED.json').read_bytes())
BINARIES=CONFIG['binaries']
def native_selected(name):
    return name.startswith('ci-package/') or name in {r['path'] for r in BINARIES.values() if r['source']=='native'} or name in {
        'artifact-manifest.json','BUILD_PASS.json','BUILD_ORIGIN.json','production/BUILD.json',
        'production/build/public-task-batch-extract/manifest.json','instances/task-pump/manifest.json',
        'processes/read-build.stdout','processes/physical-controls.stdout','processes/shape-admission-controls.stdout',
        'processes/source-reproduction.stdout','reader-controls/report.json','CI_SOURCE_DECLARATION.json'}
def prior_selected(name):
    return name.startswith(('retained/','original/','source/')) or name in {
        'artifact-manifest.json','original.lane.json','original.lane.stdout','original.lane.stderr','RUN.json','LANE_FAILURES.json','READONLY.json','CONTROLS.json','CI_SOURCE_DECLARATION.json'}
def artifact_meta(folder,role,identity):
    meta=json.loads(regular(Path(folder)/(role+'.json')))
    require(meta['id']==identity['artifact'] and meta['digest']=='sha256:'+identity['sha256'] and meta['workflow_run']['id']==identity['run'] and meta['workflow_run']['head_sha']==identity['source'],'immutable '+role+' artifact identity')
    require(archive_stream.pin(Path(folder)/(role+'.zip'))=={k:identity[k] for k in ('bytes','sha256')},'complete '+role+' input ZIP')
    return meta
def proof_extract(path,output):
    output=Path(output);require(not output.exists(),'proof output exists');output.mkdir()
    with zipfile.ZipFile(path) as z:
        require(z.testzip() is None,'proof full ZIP CRC');seen=set()
        for info in z.infolist():
            archive_stream.safe(info.filename);require(info.filename not in seen and not info.is_dir() and not stat.S_ISLNK(info.external_attr>>16),'unique regular proof file');seen.add(info.filename)
            target=output/info.filename;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(info.filename));target.chmod((info.external_attr>>16)&0o777 or 0o644)
def proof_verify(path,folder):
    folder=Path(folder)
    with zipfile.ZipFile(path) as z:
        require(z.testzip() is None and set(z.namelist())=={p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()},'complete proof member inventory')
        for info in z.infolist():require(regular(folder/info.filename)==z.read(info.filename),'complete proof bytes')
    guards=list(folder.rglob('READONLY.json'));require(len(guards)==1,'one independent full native read')
    g=json.loads(regular(guards[0]));require(g['before']==g['after'] and len(g['probes'])==11 and g['reader_writes']==g['native_or_rust_executions']==0 and g['source_bound_guard'] is True,'complete native guarded read')
    e=g['evidence'];pin=CONFIG['native'];require(e['status']=='COMPLETE_PUBLIC118_ARCHIVE_STREAM_READ_PASS' and e['artifact']==pin['artifact'] and e['source']==pin['source'] and e['run']==pin['run'] and e['zip']=={k:pin[k] for k in ('bytes','sha256')},'exact repaired native build read')
    q=e['build_qualification'];require(q['status']=='FRESH_PUMP_GRAPH_BUILD_READBACK_PASS' and q['source']['graph_source_binding']==CONFIG['source_binding'] and q['runtime_hia_images']==118 and q['fresh_direct_members']==110 and q['packed_hia_members']==8,'full actual native source/build qualification')
    reports=list(folder.rglob('complete-physical-controls/REPORT.json'));require(len(reports)==1,'complete physical prerequisite gate');control_root=reports[0].parent;report=json.loads(regular(reports[0]))
    require(report['status']=='COMPLETE_PHYSICAL_BUILD_READER_CONTROLS_PASS' and report['refusals']==4 and report['guard_probes']==44 and report['complete_baseline_guard_probes']==11 and report['semantic_executions']==0 and report['complete_mutated_bytes_retained'] is True,'full physical read controls')
    require(PIN(regular(control_root/'FULL_SOURCE_INVENTORY.json'))==report['complete_source_inventory'] and PIN(regular(control_root/'BASELINE_GUARD.json'))==report['baseline_guard'],'full baseline identities')
    baseline=json.loads(regular(control_root/'BASELINE_GUARD.json'));require(baseline['before']==baseline['after'] and len(baseline['probes'])==11 and baseline['reader_writes']==baseline['native_or_rust_executions']==0,'complete unmutated clone gate')
    for row in report['cases']:
        case=control_root/row['case'];require(json.loads(regular(case/'CONTROL.json'))==row and PIN(regular(case/'GUARD.json'))==row['guard'],'complete physical case identity');cg=json.loads(regular(case/'GUARD.json'))
        require(cg['before']==cg['after'] and len(cg['probes'])==11 and cg['reader_writes']==cg['native_or_rust_executions']==0 and cg['evidence']==row['rejection'] and row['rejection']['rejected'] is True,'actual physical refusal')
        changed=case/'changed'/row['changed_path'];node=cg['before']['0:'+row['changed_path']]
        require(PIN(regular(changed))=={k:row['after'][k] for k in ('bytes','sha256')} and {k:node[k] for k in ('bytes','sha256')}=={k:row['after'][k] for k in ('bytes','sha256')} and stat.S_IMODE(node['mode'])==row['after']['mode'] and row['before']!=row['after'],'full physical mutation bytes and original guarded mode')
    return {'build':q,'controls':report,'native_or_rust_executions':0}
def copied_inventory(source,target):
    source,target=Path(source),Path(target);first={p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file()};second={p.relative_to(target).as_posix() for p in target.rglob('*') if p.is_file()};require(first==second,'complete original lane copy inventory');rows={}
    for name in sorted(first):
        one,two=source/name,target/name;require(regular(one)==regular(two) and stat.S_IMODE(one.stat().st_mode)==stat.S_IMODE(two.stat().st_mode),'original captured byte or mode changed')
        rows[name]={**PIN(regular(one)),'mode':stat.S_IMODE(one.stat().st_mode)}
    return rows
def prepare(inputs,output,domain):
    inputs,output=Path(inputs),Path(output);require(domain in CONFIG['prior_artifacts'] and not output.exists(),'fixed new retained lane');output.mkdir(parents=True)
    identities={'native':CONFIG['native'],'prior':CONFIG['prior_artifacts'][domain],'native-proof':CONFIG['native-proof']}
    reports={}
    for role,identity in identities.items():
        artifact_meta(inputs,role,identity);shutil.copy2(inputs/(role+'.json'),output/(role+'.artifact.json'))
        if role=='native-proof':
            shutil.copy2(inputs/(role+'.zip'),output/(role+'.zip'));proof_extract(inputs/(role+'.zip'),output/role);reports[role]=proof_verify(output/(role+'.zip'),output/role)
        else:
            reports[role]=archive_stream.archive(inputs/(role+'.zip'),identity,native_selected if role=='native' else prior_selected,output=output/role)
            if role=='prior':shutil.copy2(inputs/(role+'.zip'),output/(role+'.zip'))
    previous=legacy_ready.ready(output/'prior/retained');require(previous['original_build_source']==CONFIG['original_build_source'],'original build identity unchanged')
    original=json.loads(regular(output/'prior/RUN.json'));require(original['source_commit']==CONFIG['prior_source'] and original['source_profile']==CONFIG['prior_profile'] and original['domain']==domain and original['status']=='FAIL','original producer and genuine prior failure retained')
    binaries={}
    for name,row in BINARIES.items():
        target=output/('native' if row['source']=='native' else 'prior/retained/original')/row['path'];require(PIN(regular(target))=={k:row[k] for k in ('bytes','sha256')},'exact retained executable '+name);binaries[name]={'path':str(target.resolve()),**PIN(regular(target))}
    result={'status':'REPAIRED_NATIVE118_WITH_UNCHANGED_ORIGINAL_LANE_READY','domain':domain,'producer_root':str(output.resolve()),'binaries':binaries,
        'native_source_binding':CONFIG['source_binding'],'native_build_source':CONFIG['native']['source'],'original_build_source':CONFIG['original_build_source'],
        'prior_semantic_source':CONFIG['prior_source'],'prior_semantic_run':CONFIG['prior_run'],'prior_producer_status':'FAIL',
        'runtime_recompiled':False,'original_semantics_replayed':False,'native_or_rust_executions':0,'runtime_hia_images':118,'physical_images':111,'installed_handlers':10}
    (output/'READY.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');return result
def install_original(retained,capture):
    retained,capture=Path(retained),Path(capture);prior=retained/'prior';require(not (capture/'original').exists(),'original output already exists');shutil.copytree(prior/'original',capture/'original');files=copied_inventory(prior/'original',capture/'original')
    for suffix in ('json','stdout','stderr'):
        name='original.lane.'+suffix;shutil.copy2(prior/name,capture/name);require(regular(prior/name)==regular(capture/name),'original lane receipt bytes')
    result={'schema':'hepta.runtime.unchanged-original-lane-copy.v1','files':files,'original_replayed':False,'source_artifact':CONFIG['prior_artifacts'][json.loads(regular(prior/'RUN.json'))['domain']]}
    (capture/'ORIGINAL_REUSE.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');return result
def verify_ready(root,domain):
    root=Path(root);r=json.loads(regular(root/'READY.json'));require(r['status']=='REPAIRED_NATIVE118_WITH_UNCHANGED_ORIGINAL_LANE_READY' and r['domain']==domain and r['runtime_recompiled'] is False and r['original_semantics_replayed'] is False and r['native_or_rust_executions']==0 and (r['runtime_hia_images'],r['physical_images'],r['installed_handlers'])==(118,111,10),'complete retained lane identity')
    identities={'native':CONFIG['native'],'prior':CONFIG['prior_artifacts'][domain],'native-proof':CONFIG['native-proof']}
    for role,identity in identities.items():
        meta=json.loads(regular(root/(role+'.artifact.json')));require(meta['id']==identity['artifact'] and meta['digest']=='sha256:'+identity['sha256'] and meta['workflow_run']['id']==identity['run'] and meta['workflow_run']['head_sha']==identity['source'],'immutable retained artifact')
        if role!='native-proof':archive_stream.verify_selection(root/role,identity,native_selected if role=='native' else prior_selected)
    reread=archive_stream.archive(root/'prior.zip',identities['prior'],prior_selected,verify_root=root/'prior');require(reread==json.loads(regular(root/'prior/SELECTION.json')),'complete retained original domain ZIP')
    require(PIN(regular(root/'native-proof.zip'))=={k:identities['native-proof'][k] for k in ('bytes','sha256')},'full native proof ZIP');proof_verify(root/'native-proof.zip',root/'native-proof')
    previous=legacy_ready.ready(root/'prior/retained');require(previous['original_build_source']==CONFIG['original_build_source'],'exact retained original reference')
    require(PIN(regular(root/'native/ci-package/graph/source/native/runtime_mcp_sources.json'))['sha256']==CONFIG['source_binding'] and PIN(regular(root/'native/ci-package/PACKAGE.json'))['sha256']==CONFIG['native_build_profile'],'exact repaired graph and build source')
    origin=Path(r['producer_root']);require(origin.is_absolute(),'absolute producer retained root')
    for name,row in BINARIES.items():
        rel=('native/' if row['source']=='native' else 'prior/retained/original/')+row['path'];require(PIN(regular(root/rel))=={k:row[k] for k in ('bytes','sha256')} and r['binaries'][name]=={'path':str(origin/rel),**{k:row[k] for k in ('bytes','sha256')}},'complete binary custody')
    return r

"""Read the exact complete retained raw-stdio reference build without rebuilding."""
from pathlib import Path
import hashlib,json,stat
import archive_stream,read_only_guard
IDENTITY={'artifact':14289717989,'run':43996932889,'source':'eed44ba83628cf8d3223c9f54d62684eb0d4e5f5','bytes':484575168,'sha256':'e2f5ab921ead324994dec0f11f51708cced434c68e49f8bb5b8e0f11f5e81265'}
BINARY={'bytes':5703600,'sha256':'58ad36258a3bc96bb9844e97d009291711ee10fc8770dda1c02a36e50f6145b0'}
BINARY_PATH='original/bin/hepta-batch-sdk-current-original-oracle'
PROFILE='625113df9a0a26d11440d75377c09e3d4792c209195de564d6cec13ef546fa91'
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def choose(name):
    return name.startswith(('ci-package/','original/project/')) or name in {BINARY_PATH,'original/target/release/hepta-batch-sdk-current-original-oracle','original/BUILD.json','QUALIFICATION.json','CORE_READY.json','ORIGIN.json','processes/guarded-read.stdout','CI_SOURCE_DECLARATION.json'}
def verify(folder):
    folder=Path(folder);full=archive_stream.verify_selection(folder,IDENTITY,choose);source=folder/'ci-package'
    assert archive_stream.pin(source/'PACKAGE.json')['sha256']==PROFILE
    rows=json.loads((source/'PACKAGE.json').read_bytes())['files']
    assert {p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file()}==set(rows)|{'PACKAGE.json'}
    for name,row in rows.items():assert archive_stream.pin(source/name)=={k:row[k] for k in ('bytes','sha256')}
    report=json.loads((folder/'original/BUILD.json').read_bytes())
    assert report['status']=='PASS' and report['fresh_original_build'] is True and report['actual_reference_executions']==0
    assert report['target_commit']=='d3d75c30719db966b004756f610007a7c723729e' and report['actual_target_sdk']=='3.9.0' and report['actual_target_tokio']=='1.53.3'
    for name,row in report['source_inputs']['files'].items():assert archive_stream.pin(source/'reference'/name)==row
    project=json.loads((source/'reference/project/SOURCE.json').read_bytes())
    for name,row in project['files'].items():
        left=source/'reference/project'/name;right=folder/'original/project'/name
        assert left.read_bytes()==right.read_bytes() and archive_stream.pin(left)=={k:row[k] for k in ('bytes','sha256')}
    assert (source/'reference/project/src/stdio_bridge.rs').read_bytes()==(folder/'original/project/src/stdio_bridge.rs').read_bytes()
    original=archive_stream.pin(folder/BINARY_PATH);assert original==BINARY and archive_stream.pin(folder/'original/target/release/hepta-batch-sdk-current-original-oracle')==BINARY
    guard=json.loads((folder/'processes/guarded-read.stdout').read_bytes());qualification=json.loads((folder/'QUALIFICATION.json').read_bytes())
    assert guard['before']==guard['after'] and len(guard['probes'])==11 and guard['reader_writes']==guard['native_or_rust_executions']==0 and guard['source_bound_guard'] is True
    assert guard['evidence']==qualification and qualification['status']=='FRESH_EXTRACT_REFERENCE_COMPLETE_BUILD_READ_PASS'
    assert qualification['controls']['refusals']==4 and qualification['original']['fresh_original_build'] is True and qualification['original']['extract_original_spans']==13
    assert qualification['original']['binaries']['hepta-batch-sdk-current-original-oracle']=={'path':'bin/hepta-batch-sdk-current-original-oracle',**BINARY}
    return {'status':'RETAINED_STDIO_REFERENCE_FULL_CUSTODY_PASS','producer':IDENTITY,'archive_files':full['files'],'complete_source_files':len(rows)+1,'binary':original,'prior_guard_probes':11,'prior_physical_controls':4,'native_or_rust_executions':0,'successful_original_domains_replayed':False}
def prepare(inputs,out):
    inputs,out=Path(inputs),Path(out);meta=json.loads((inputs/'reference.json').read_bytes())
    assert meta['id']==IDENTITY['artifact'] and meta['digest']=='sha256:'+IDENTITY['sha256'] and meta['workflow_run']['id']==IDENTITY['run'] and meta['workflow_run']['head_sha']==IDENTITY['source']
    full=archive_stream.archive(inputs/'reference.zip',IDENTITY,choose,output=out/'reference');put(out/'FULL_REFERENCE_READ.json',full);put(out/'reference.artifact.json',meta)
    guard=read_only_guard.guarded(lambda:verify(out/'reference'),roots=[out/'reference'],foreign_path='/proc/self/status');put(out/'REFERENCE_READONLY.json',guard)
    return out/'reference'/BINARY_PATH

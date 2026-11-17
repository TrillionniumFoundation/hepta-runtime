#!/usr/bin/env python3
"""Recompute the history recovery's proof joins without running its readers.

Inputs are the complete, independently hash-checked recovery archive, the
original full index ZIP, and the unchanged original failed report. No captured
qualification module, NativeModule, subprocess or Rust code is imported.
"""
from __future__ import annotations
import argparse,gzip,hashlib,json,stat,time,zipfile
from pathlib import Path

REPORT={'bytes':94614535,'sha256':'6159169d8c0763d2418c8f625e5cd67099a06179f69927f7a1e62972a1eafa41'}
INDEX={'bytes':90869688,'sha256':'a0f581904dba96b2959da711542fded9f716e03c54d71ff924e737fbb5ae2a37'}
INDEX_MEMBER='history-aggregate-index/tar-index.jsonl.gz'
INDEX_MEMBER_SHA='ad4d01ef4fa926526bc0483a6160d0d9453e8529b8b2c770fe03d2345c3edf40'
OLD_CONTROLS=['result-values-evidence-controls','public-registry-evidence-controls','result-storage-evidence-controls']
FS_LABELS=['native_deadline_not_180','native_claimed_as_original_phase','original_claimed_as_native_phase',
 'duplicate_private_summary_field','resigned_private_return_mismatch','resigned_private_refusal_mutation',
 'retirement_binds_other_native_evidence','reintroduced_live_fixture','another_declared_compiler_than_actual_build',
 'unchanged_original_module_changed','missing_original_retirement']
REGEX_LABELS=['missing-complete-nfa-half','duplicated-actual-suite','sigkill-cannot-be-pass','timeout-cannot-be-pass',
 'changed-completed-stdout','extended-suite-budget','changed-actual-suite-command','changed-native-source',
 'changed-real-embedded-image','changed-actual-native-corpus','rehash-does-not-admit-duplicated-case',
 'missing-full-original-match-replay','changed-full-original-output','missing-original-startup-refusal-side']
SOURCE='/home/runner/work/_temp/hia-historical-public58'
CAPTURE='/home/runner/work/_temp/hia-runtime-native'
REBUILT_FILES=['Cargo.toml','Cargo.lock','src/main.rs','src/bin/view_call_sdk.rs',
 'src/bin/view_call_router_sdk.rs','src/bin/view_call_public_schema.rs','src/bin/view_call_info_sdk.rs']
REBUILT_DIRS=['.','src','src/bin']
REBUILT_OPS=[('mkdir','.'),('mkdir','src'),('copyfile','Cargo.toml'),('copyfile','Cargo.lock'),
 ('write_text','src/main.rs'),('mkdir','src/bin'),('write_text','src/bin/view_call_sdk.rs'),
 ('write_text','src/bin/view_call_router_sdk.rs'),('write_text','src/bin/view_call_public_schema.rs'),
 ('write_text','src/bin/view_call_info_sdk.rs')]
REBUILT_CALLERS=(('scripts/hia_native_view_call_qualification.py','_original_evidence','view-original-materialization-'),
 ('scripts/hia_native_runtime_mcp_original.py','view_reference','runtime-mcp-original-source-'))
REBUILT_SOURCES={
 'scripts/hia_native_runtime_mcp_original.py':(13097,'b051ed49dba6dfa33cdc17b812caa9ff395746905aba1bc395f99cc00ce60ec9'),
 'scripts/hia_native_view_call_qualification.py':(87273,'6797db0667a828bd38ad27784cf7d17e1414b9bb1a7ed7a5891ed3938f78b85d'),
 'tests/hia_native/view_call_oracle/verify_sources.py':(14395,'2118c3d91971887451bd3d72f468dfcfeb8e74f853c54f9273829fa676e4356c'),
 'tests/hia_native/view_call_oracle/run.py':(13903,'19ed876d121a1c917c667ccc3ead4dae1ed25c4a5b7cf1744625773c921ca33b')}
REBUILD_REFUSALS=['changed-bound-source','extra-crate-member','missing-crate-member','wrong-temporary-prefix',
 'undeclared-temporary-caller','nested-reconstruction','write-outside-reconstruction','wrong-copy-source',
 'wrong-operation-order','omitted-materialization','write-text-options','changed-captured-copy',
 'changed-captured-generated','aliased-crate-member','wrong-public-temporary-prefix',
 'public-prefix-on-view-caller','undeclared-public-caller','changed-public-bound-source']

SCHEMA_INPUT='public-schema.stdout'
SCHEMA_OUTPUTS=('raw-input-schema.json','public-input-schema.json')
SCHEMA_CALLER=('tests/hia_native/view_call_oracle/run.py','additional_reference_summary')
SCHEMA_PARENT=('scripts/hia_native_runtime_mcp_original.py','view_reference')
SCHEMA_PINS={key:REBUILT_SOURCES[key] for key in (SCHEMA_CALLER[0],SCHEMA_PARENT[0])}
SCHEMA_REFUSALS=['undeclared-summary-writer','undeclared-summary-caller','summary-wrong-root',
 'summary-wrong-order','summary-changed-argument','summary-changed-target','summary-changed-input',
 'summary-omitted-second-write','summary-nonbytes','changed-summary-source']

def need(value,label):
    if not value:raise ValueError(label)
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(path):
    with path.open('rb') as f:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest()}
def rawjson(path):return json.loads(path.read_bytes())
def packedjson(path):
    with gzip.open(path,'rb') as f:return json.load(f)
def semantic(value):
    return {key:{k:row[k] for k in (('mode','sha256','bytes') if row['sha256'] is not None else ('mode','sha256'))} for key,row in value.items()}

LIBRARY_SOURCES={
 'scripts/hia_native_shell_foreground_build.py':(51691,'7c82a36902c7d4ae2f9649080a381416ef4679816a1ed3ec66c756a668a9d723'),
 'scripts/hia_native_shell_process_build.py':(29502,'f3e282104f02006d7d54e41fe120ee95ec6523e55aa23da6f47ab28f9d21c036')}
LIBRARY_REFUSALS=['changed-library-reader-source','changed-module-owner','changed-manifest-bytes',
 'changed-recorded-root','nonabsolute-library-path','wrong-library-basename','host-library-symlink',
 'retained-library-symlink','changed-current-library-byte','changed-retained-library-byte',
 'boolean-library-size','changed-retained-library-pin','unlisted-external-file']
LIBRARY_ROLES=(('allocator','allocator-libc.so.6','libc.so.6'),
 ('interpreter','interpreter.bin','ld-linux-x86-64.so.2'))

def runtime_libraries(readback,preflight,original,before,external,final):
    binding=readback['runtime_libraries'];controls=preflight['runtime_library_controls']
    need(binding['schema']=='hepta.history.runtime-library-admission.v1' and binding['status']=='PASS'
     and binding['source']==SOURCE and binding['output']==CAPTURE
     and binding['manifest_path']=='build/shell-foreground/manifest.json'
     and binding['manifest_identity']==before['0:'+binding['manifest_path']]
     and binding['current_files_read_completely']==binding['retained_files_read_completely']==2
     and binding['paths_rewritten'] is False and binding['original_build_reader_modified'] is False
     and binding['library_loads']==binding['native_or_rust_executions']==0,
     'complete exact two-library admission without path substitution or loading')
    manifest=binding['manifest_path'];module=original['modules']['shell_foreground']
    need(module=={'builder':'shell_foreground','manifest':manifest,
      'sha256':binding['manifest_identity']['sha256'],'source':'native/shell_foreground_controller.hepta'}
     and original['shell_foreground_evidence']['artifact_sha256'][manifest]==module['sha256'],
     'original module and retained manifest pins both bind current admission')
    need(set(binding['source_files'])==set(LIBRARY_SOURCES),'exact source set for library admission')
    for name,(size,digest) in LIBRARY_SOURCES.items():
        need(binding['source_files'][name]=={'bytes':size,'sha256':digest}
         and original['source_sha256'][name]==digest and before['1:'+name]['bytes']==size
         and before['1:'+name]['sha256']==digest,'unchanged complete foreground/process reader source')
    need(type(binding['files'])is list and len(binding['files'])==2,'two complete library rows')
    original_dynamic=original['original_rust_comparisons']['shell_capture_file']['reference_build']['dynamic_binding']
    historical_by_name={row['listing']['name']:row['file'] for row in original_dynamic['libraries']}
    identities=[]
    for row,(role,retained_name,basename) in zip(binding['files'],LIBRARY_ROLES):
        old=historical_by_name[basename];target=row['current_identity'];saved=row['retained_identity']
        expected={'size':old['bytes'],'sha256':old['sha256']}
        need(row['role']==role and row['path']==old['resolved_path']
         and row['retained_path']=='build/shell-foreground/'+retained_name and row['pin']==expected
         and type(row['pin']['size'])is int and row['pin']['size']>0,
         'actual source-declared roles and original fully captured runtime-library identities')
        snap=before['0:'+row['retained_path']];current=external[row['path']]
        need(saved==snap and current['absent'] is False and current['resolved']==row['path']
         and current['logical']==current['target']
         and target=={**{key:current['target'][key] for key in ('mode','inode','device','bytes','mtime_ns','ctime_ns')},
                        'sha256':current['sha256']},
         'all complete captured and current library bytes and metadata join the unchanged snapshots')
        need(stat.S_ISREG(target['mode']) and stat.S_ISREG(saved['mode'])
         and target['bytes']==saved['bytes']==expected['size']
         and target['sha256']==saved['sha256']==expected['sha256']
         and original['shell_foreground_evidence']['artifact_sha256'][row['retained_path']]==expected['sha256'],
         'entire original/current/retained library extents match')
        identities.append({'role':role,'path':row['path'],'retained_path':row['retained_path'],'pin':expected})
    need(len({row['path'] for row in binding['files']})==2,'two distinct original library paths')
    need(controls['status']=='PASS' and controls['complete_admissions']==2
     and controls['complete_library_files_per_admission']==2 and len(controls['admissions'])==2
     and [row['name'] for row in controls['refusals']]==LIBRARY_REFUSALS
     and controls['execution_attempts']==[] and controls['library_loads']==controls['native_or_rust_executions']==0
     and controls['test_owned_library_bytes_not_executed'] is True,'all thirteen physical library admission refusals')
    for admission in controls['admissions']:
        g=admission['guard']
        need(g['reader_writes']==g['native_or_rust_executions']==0 and len(g['probes'])==12
         and g['before']==g['after'] and g['external_before']==g['external_after']
         and g['evidence']==admission['binding'],'complete control before/after bytes and original twelve guard probes')
    need(final['current_runtime_library_files']==2 and final['runtime_library_refusals']==13
     and final['library_loads']==0,'final exact library admission scope')
    return identities


REFERENCE_SOURCES={
 'scripts/hia_native_shell_capture_path_reference.py':(17202,'9e780c452c2430b1fe6e01d4494380a1f2d29609e97e79e4905fa2f4202e89c8'),
 'scripts/hia_native_shell_capture_file_reference.py':(33082,'034e3ffa8af009de87215c8f9ad7b0178f2507ed802cc81119e15ee4b6196621'),
 'scripts/hia_native_shell_capture_mkdir_reference.py':(30678,'c16a41acdd136c3fd37d9bf29dee81ebd04bcee8bff96af1dfbb6205d1958e5c'),
 'scripts/hia_native_shell_capture_prepare_reference.py':(35983,'8d2f2ac7735def1be5c4c163fed1e635b9421ffc05e9502762d51cb551b233c4'),
 'scripts/hia_native_shell_process_reference.py':(61723,'d825520f8edc3dafb01abe86426c3fa4cf476eeb0e6c2dd1f105c970261240cc')}
REFERENCE_KEYS=('shell_capture_path','shell_capture_file','shell_capture_mkdir','shell_capture_prepare')
ENVIRONMENT_REFUSALS=['changed-bound-reference-source','changed-reference-report-bytes',
 'mismatched-reference-report-dual-pin','unexpected-tool-role','changed-fixed-sysroot',
 'missing-original-target-library','extra-current-target-library','aliased-target-library',
 'changed-current-library','changed-retained-loader-cache','conflicting-external-identity',
 'boolean-dependency-size','wrong-original-loader-cache-path','unexpected-preload-file',
 'changed-current-dependency-mode','unlisted-external-file']
RUST_SYSROOT='/home/runner/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu'

def reference_environment(root,readback,preflight,original,before,external,final):
    env=readback['reference_environment'];controls=preflight['reference_environment_controls']
    need(env['schema']=='hepta.history.reference-environment-admission.v1' and env['status']=='PASS'
     and env['source']==SOURCE and env['output']==CAPTURE and env['paths_rewritten'] is False
     and env['library_loads']==env['native_or_rust_executions']==0
     and env['original_reference_readers_modified'] is False and env['qualification_summary_cached'] is False,
     'exact reference dependency admission scope, no qualification summary replacement')
    need(set(env['source_files'])==set(REFERENCE_SOURCES),'five exact original reference source inputs')
    for name,(size,digest) in REFERENCE_SOURCES.items():
        need(env['source_files'][name]=={'bytes':size,'sha256':digest}
         and before['1:'+name]['bytes']==size and before['1:'+name]['sha256']==digest
         and original['source_sha256'][name]==digest,'complete unchanged original reference helper')
    copies=readback['retained_dependency_reports']
    expected_paths={'build/shell-foreground/manifest.json'}
    expected_paths.update(key.replace('_','-')+'-original/build/result.json' for key in REFERENCE_KEYS)
    need(set(copies)==expected_paths,'exact five original dependency reports')
    documents={}
    for rel,row in copies.items():
        need(row['path']=='retained-input-reports/'+rel,'source-derived report copy path')
        file=root/'reader'/row['path'];raw=file.read_bytes();snap=before['0:'+rel]
        need(row['pin']==pin(file)=={'bytes':snap['bytes'],'sha256':snap['sha256']},
             'entire unchanged original dependency report bytes')
        documents[rel]=json.loads(raw)
    manifest=documents['build/shell-foreground/manifest.json']
    need(manifest['recorded_directory']==CAPTURE+'/build/shell-foreground'
     and manifest['recorded_source_root']==SOURCE,'complete original foreground manifest roots')
    for row in readback['runtime_libraries']['files']:
        need(manifest[row['role']]=={'path':row['path'],'pin':row['pin']},
             'actual complete manifest binds both exact runtime library descriptors')
    need([row['key'] for row in env['reports']]==list(REFERENCE_KEYS),'all original reference reports once')
    claims={};retained=[];absent=set()
    def claim(identity,role,executable=False):
        fields={'launch_path','resolved_path','bytes','sha256'}
        need(type(identity)is dict and set(identity) in (fields,fields|{'mode'}),'exact original dependency fields')
        expected={key:identity[key] for key in ('bytes','sha256')}
        need(type(expected['bytes'])is int and expected['bytes']>=0
         and type(expected['sha256'])is str and len(expected['sha256'])==64
         and all(c in '0123456789abcdef' for c in expected['sha256']),'complete original dependency pin')
        for path in (identity['launch_path'],identity['resolved_path']):
            need(type(path)is str and path.startswith('/') and str(Path(path))==path,
                 'original canonical absolute dependency name')
            old=claims.get(path)
            row={'path':path,'resolved_path':identity['resolved_path'],'pin':expected,
                 'mode':identity.get('mode'),'executable':executable}
            if old is not None:
                need(old['resolved_path']==row['resolved_path'] and old['pin']==expected,
                     'same recorded dependency path has one identity')
                if old['mode'] is not None and row['mode'] is not None:
                    need(old['mode']==row['mode'],'recorded dependency mode agrees across reports')
                if row['mode'] is None:row['mode']=old['mode']
                row['executable']|=old['executable'];row['roles']=old['roles']+[role]
            else:row['roles']=[role]
            claims[path]=row
    for entry in env['reports']:
        key=entry['key'];folder=key.replace('_','-')+'-original/build';rel=folder+'/result.json'
        report=documents[rel];comparison=original['original_rust_comparisons'][key]
        need(entry['path']==rel and entry['pin']==copies[rel]['pin']
         and entry['pin']['sha256']==comparison['reference_build']['report_sha256']
         and comparison['retained_files_sha256'][rel]==entry['pin']['sha256']
         and report['status']=='PASS' and report['error'] is None,'complete original report dual receipt bindings')
        tools=report['tools'];tool_roles={'rustc','linker','ld'}|({'interpreter'} if key!='shell_capture_path' else set())
        need(entry['tools']==tools and set(tools)==tool_roles
         and report['sysroot']==RUST_SYSROOT and tools['rustc']['resolved_path']==RUST_SYSROOT+'/bin/rustc',
         'actual original fixed Rust and linker identities')
        for role,identity in sorted(tools.items()):claim(identity,key+':'+role,True)
        target=report['target_libraries'];libdir=RUST_SYSROOT+'/lib/rustlib/x86_64-unknown-linux-gnu/lib'
        need(entry['target_libraries']==target and set(target)=={'path','files','file_count'}
         and target['path']==libdir and type(target['file_count'])is int
         and target['file_count']==len(target['files'])==comparison['reference_build']['target_library_files']>0,
         'entire original standard-library file set')
        for name,p in sorted(target['files'].items()):
            need(type(name)is str and name and not name.startswith('/') and '\\' not in name
             and all(part not in ('','.','..') for part in name.split('/')),'relative original target library name')
            path=libdir+'/'+name
            claim({'launch_path':path,'resolved_path':path,**p},key+':target-library')
        if key!='shell_capture_path':
            dynamic=report['dynamic_binding']
            need(entry['dynamic_binding']==dynamic==comparison['reference_build']['dynamic_binding'],
                 'complete original dynamic-library report and original summary agree')
            claim(dynamic['interpreter'],key+':dynamic-interpreter',True)
            configuration=dynamic['configuration']
            need(set(configuration)=={'cache','preload'}
             and configuration['cache']['launch_path']=='/etc/ld.so.cache','exact original loader configuration')
            claim(configuration['cache'],key+':loader-cache')
            rel=folder+'/loader-configuration/ld.so.cache'
            retained.append({'path':rel,'current_path':'/etc/ld.so.cache','pin':{
                'bytes':configuration['cache']['bytes'],'sha256':comparison['retained_files_sha256'][rel]}})
            preload=configuration['preload']
            need(type(preload['present'])is bool,'exact original preload presence type')
            if preload['present']:
                need(set(preload)=={'present','file'} and preload['file']['launch_path']=='/etc/ld.so.preload',
                     'exact original preload identity')
                claim(preload['file'],key+':loader-preload')
                rel=folder+'/loader-configuration/ld.so.preload'
                retained.append({'path':rel,'current_path':'/etc/ld.so.preload','pin':{
                    'bytes':preload['file']['bytes'],'sha256':comparison['retained_files_sha256'][rel]}})
            else:
                need(set(preload)=={'present'},'no invented absent preload data')
                absent.add('/etc/ld.so.preload')
            need(type(dynamic['library_count'])is int and dynamic['library_count']==len(dynamic['libraries'])>0,
                 'complete original dynamic library count')
            for row in dynamic['libraries']:
                identity=row['file'];claim(identity,key+':dynamic-library')
                rel=folder+'/'+row['retained']['path']
                need({k:identity[k] for k in ('bytes','sha256')}=={k:row['retained'][k] for k in ('bytes','sha256')},
                     'complete retained dynamic library pin')
                retained.append({'path':rel,'current_path':identity['launch_path'],'pin':{
                    'bytes':identity['bytes'],'sha256':comparison['retained_files_sha256'][rel]}})
    need(env['external_files']==sorted(claims)==[row['path'] for row in env['files']]
     and len(env['files'])==len(claims),'every external dependency path derives from the complete original reports')
    for row in env['files']:
        expected=claims[row['path']]
        need({key:row[key] for key in expected}==expected,'all dependency claims derive from original reports')
        saved=external[row['path']]
        need(saved['absent'] is False and saved['resolved']==row['resolved_path']
         and saved['logical']==row['logical'] and saved['target']==row['target']
         and row['pin']=={'bytes':saved['target']['bytes'],'sha256':saved['sha256']}
         and stat.S_ISREG(saved['target']['mode']),'complete current dependency bytes and all metadata were unchanged')
        if row['mode'] is not None:
            need(type(row['mode'])is int and stat.S_IMODE(row['target']['mode'])==row['mode'],'original mode identity')
        if row['executable']:need(row['target']['mode']&0o111,'recorded tool executable bits')
    need(env['retained_files']==retained and env['absent_paths']==sorted(absent),'complete retained library/config correspondence')
    for row in retained:
        saved=before['0:'+row['path']];current=external[row['current_path']]
        need(row['pin']=={'bytes':saved['bytes'],'sha256':saved['sha256']}
         and row['pin']=={'bytes':current['target']['bytes'],'sha256':current['sha256']},
         'complete original/current/retained dynamic library and loader config bytes')
    need(controls['schema']=='hepta.history.reference-environment-controls.v1' and controls['status']=='PASS'
     and controls['complete_admissions']==len(controls['admissions'])==2
     and controls['complete_reference_reports_per_admission']==4
     and [row['name'] for row in controls['refusals']]==ENVIRONMENT_REFUSALS
     and controls['test_owned_dependency_bytes_not_executed'] is True
     and controls['library_loads']==controls['native_or_rust_executions']==0,'all sixteen exact dependency controls')
    for admission in controls['admissions']:
        g=admission['guard']
        need(g['before']==g['after'] and g['external_before']==g['external_after']
         and g['evidence']==admission['binding'] and len(g['probes'])==12
         and g['reader_writes']==g['native_or_rust_executions']==0,'complete dependency control guarded reads')
    need(final['reference_environment_files']==len(claims) and final['reference_environment_reports']==4
     and final['reference_environment_refusals']==16 and final['reference_environment_report_copies']==5,
     'honest final reference dependency scope')
    return {'files':len(claims),'reports':4,'whole_original_report_copies':5,'refusals':16,'library_loads':0}


def guard_diagnostics(root,complete,readback,preflight,final):
    path=root/'reader/GUARD_DIAGNOSTICS.json'
    evidence=rawjson(path)
    source={k:complete['source_files']['read_only_guard.py'][k] for k in ('bytes','sha256')}
    need(pin(path)==readback['guard_diagnostics']
     and evidence['schema']=='hepta.history.guard-denial-diagnostics.v1'
     and evidence['status']=='RECORDED' and evidence['guard_source']==source
     and evidence['completed_guarded_read'] is True and evidence['permissions_changed'] is False
     and type(evidence['reader_denials'])is int and evidence['reader_denials']==0
     and type(evidence['probe_denials'])is int and evidence['probe_denials']==12
     and evidence['native_or_rust_executions']==0,'full zero-denial guarded-read diagnostics')
    events=evidence['events']
    need(len(events)==12 and all(row['phase']=='probes' and row['frames'] for row in events)
     and [row['kind'] for row in events]==[row['guard_event'] for row in readback['probes']],
     'all actual original guard probes and no caught reader denial')
    controls=preflight['guard_diagnostic_controls']
    need(controls['schema']=='hepta.history.guard-diagnostic-controls.v1' and controls['status']=='PASS'
     and controls['complete_admissions']==1 and controls['refusals']==2
     and controls['original_guard_probes']==36 and controls['permissions_changed'] is False
     and controls['native_or_rust_executions']==0
     and controls['source']=={'original_guard_sha256':
      '989cc4f469b490031f3953284a9983311137badf6f6ecb1baf92d4d80747fb98',
      'current_guard_sha256':source['sha256'],'complete_original_source_reproduced':True},
     'diagnostic source inverse and all original permissions retained')
    need([row['name'] for row in controls['cases']]==[
     'complete-read-with-diagnostics','swallowed-foreign-read','uncaught-native-load'],
     'complete diagnostic control domain')
    for number,row in enumerate(controls['cases']):
        probe=[event for event in row['events'] if event['phase']=='probes']
        reader=[event for event in row['events'] if event['phase']=='reader']
        need(row['before']==row['after'] and row['cleanup_restored'] is True
         and row['native_or_rust_executions']==0 and len(probe)==12
         and len(row['events'])==len(probe)+len(reader),'complete diagnostic control snapshots')
        need([event['kind'] for event in probe]==[event['kind'] for event in events],
         'all original refusal kinds remain in each diagnostic control')
        for event in row['events']:
            need(event['frames'] and all(type(frame['file'])is str and type(frame['function'])is str
             and type(frame['line'])is int and frame['line']>0 for frame in event['frames']),
             'entire metadata-only denial stack')
        if number==0:
            need(row['outcome'] is None and reader==[],'positive full read has no refusal')
        else:
            need(len(reader)==1,'one exact refused operation')
            expected={'type':'ValueError','message':'reader attempted a forbidden operation'} if number==1 else {
             'type':'PermissionError','message':'history-aggregate read-only guard: native-mapping'}
            kind='foreign-read' if number==1 else 'native-mapping'
            name='swallowed_read' if number==1 else 'native_load'
            need(row['outcome']==expected and reader[0]['kind']==kind
             and any(frame['function']==name for frame in reader[0]['frames']),
             'caught/uncaught diagnostic failures retained')
            frames=[frame for frame in reader[0]['frames']
             if frame['function']=='audit' and 'arguments' in frame and 'event' in frame['arguments']]
            need(len(frames)==1 and frames[0]['arguments']['event']==('open' if number==1 else 'ctypes.dlopen'),
             'actual rejected audit event captured')
            if number==1:
                foreign=[frame for frame in probe[10]['frames']
                 if frame['function']=='audit' and 'arguments' in frame and 'event' in frame['arguments']]
                need(len(foreign)==1 and frames[0]['arguments']['args'][0]==foreign[0]['arguments']['args'][0],
                 'same fully retained foreign-path argument')
    need(final['guard_reader_denials']==0 and final['guard_diagnostic_refusals']==2
     and final['guard_diagnostic_probe_count']==36,'final diagnostic count binding')
    return {'reader_denials':0,'original_guard_probes':12,'diagnostic_refusals':2,
     'diagnostic_guard_probes':36,'guard_source':source,'permissions_changed':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('--readback',type=Path,required=True)
    p.add_argument('--original-report',type=Path,required=True);p.add_argument('--original-index',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();start=time.monotonic_ns()
    root=a.readback/'proof/recovery';complete=rawjson(a.readback/'COMPLETE_READBACK.json')
    members=rawjson(a.readback/'COMPLETE_MEMBER_PINS.json')
    need(complete['status']=='COMPLETE_ARCHIVE_BYTES_AND_GIT_SOURCES_PASS' and complete['aggregate_recovery_pass'] is True,'complete successful proof archive first')
    member_files={r['path'][len('recovery/'):]:{k:r[k] for k in ('bytes','sha256')} for r in members if r['type']=='file'}
    # Reopen all proof files from the independently verified extraction. No
    # archive-only receipt can substitute for these complete file reads.
    for name,expected in member_files.items():need(pin(root/name)==expected,'proof file changed after extraction: '+name)
    final=rawjson(root/'FINAL.json');readback=rawjson(root/'reader/READBACK.json')
    restoration=rawjson(root/'RESTORATION.json');preflight=rawjson(root/'PREFLIGHT.json')
    need(pin(a.original_report)==REPORT and pin(a.original_index)==INDEX,'entire original report and index bytes')
    original=rawjson(a.original_report)
    need(original['status']=='FAIL' and original['phase']=='original_collect'
     and original['error']=={'type':'ValueError','message':'public evidence controls did not observe the complete prior process set'},'original failure remains exact')
    need(len(original['checks'])==405 and len(original['original_rust_comparisons'])==81 and len(original['source_sha256'])==2111,'full original process/recipe/source sets')
    need([x['name'] for x in original['checks'][-3:]]==OLD_CONTROLS and all(x['exit_code']==0 and x['timed_out'] is False and x['timeout_seconds']==180 for x in original['checks'][-3:]),'three previously completed original controls')
    need(restoration['status']=='COMPLETE_RESTORED_BYTES_AND_MODES_PASS' and restoration['files']==151622 and restoration['directories']==26653 and restoration['logical_bytes']==26910012457,'whole original restoration counts')
    ev=readback['evidence']
    need(ev['status']=='COMPLETE_RETAINED_AGGREGATE_READBACK_PASS' and ev['original_status']=='FAIL'
     and ev['original_report_sha256']==REPORT['sha256'] and ev['actual_checks']==405 and ev['recipes']==81
     and ev['preserved_controls']==OLD_CONTROLS and ev['old_prefix_refusal_reproduced'] is True
     and ev['changed_function']=='public_registry_control_evidence' and ev['all_other_comparator_ast_identical'] is True
     and ev['source_pins_rebound'] is False and ev['original_failure_reclassified_as_pass'] is False
     and ev['native_or_rust_executions']==0 and ev['new_executable_mappings']==0
     and ev['current_kernel_mapping_and_seals_retested'] is False,'exact narrow aggregate recovery scope')
    need(readback['reader_writes']==readback['native_or_rust_executions']==0 and len(readback['probes'])==12
     and readback['source_after']==original['source_sha256'] and readback['original_report']==REPORT,'actual guarded source/process proof')
    before=packedjson(root/'reader/before.json.gz');after=packedjson(root/'reader/after.json.gz')
    need(before==after and len(before)==readback['full_snapshot_entries'],'complete actual before/after bytes and metadata')
    del after
    external=packedjson(root/'reader/external_before.json.gz');external_after=packedjson(root/'reader/external_after.json.gz')
    need(external==external_after and len(external)==readback['external_snapshot_entries'],'complete external bytes/absence/metadata')
    del external_after
    for name,digest in original['source_sha256'].items():need(before['1:'+name]['sha256']==digest,'complete source before-snapshot pin: '+name)
    code=rawjson(root/'reader/STATIC_CODE_ADMISSION.json')
    need(pin(root/'reader/STATIC_CODE_ADMISSION.json')==readback['static_code_admission'],'entire static admission receipt')
    need(code['source']==SOURCE and code['output']==CAPTURE and code['execution_attempts']==[]
     and code['new_executable_mappings']==code['native_or_rust_executions']==0
     and code['kernel_mapping_and_seals_retested'] is False,'no mapping or execution by static adapter')
    prefix=code['prefix'];controls=preflight['static_code_controls']
    need(prefix==controls['prefix'] and prefix['loader_sha256']=='58e2fe0492379340d7471a7857e1aa5de1a9a5d1e37a118852278b131bb1fe06','exact historical loader prefix')
    need(controls['status']=='PASS' and controls['complete_static_admissions']==1 and len(controls['refusals'])==25
     and len({r['name'] for r in controls['refusals']})==25 and controls['early_and_late_alias_restoration'] is True,'all new static admission controls')
    table=[]
    for key,row in sorted(original['modules'].items()):
        item=before['0:'+row['manifest']];need(item['sha256']==row['sha256'],'original registered manifest')
        table.append({'key':key,'manifest':row['manifest'],'bytes':item['bytes'],'sha256':item['sha256']})
    need(len(table)==87 and table==code['registered_modules'],'all original 87 modules bound')
    need(len(code['admissions'])==ev['static_code_admissions']>0,'actual static constructor admission set')
    for row in code['admissions']:
        need(row['new_executable_mapping'] is False,'constructor never mapped code')
        for field in ('manifest','source','image'):
            item=before['0:'+row[field]]
            need(item['bytes']==row[field+'_bytes'] and item['sha256']==row[field+'_sha256'],'complete static admission file extent')
        need(row['source_sha256']==row['metadata']['source_sha256'] and row['image_sha256']==row['metadata']['image_sha256'],'module source/image metadata')
    rebuilt=rawjson(root/'reader/SOURCE_RECONSTRUCTION.json');rebuild_controls=preflight['source_reconstruction_controls']
    need(pin(root/'reader/SOURCE_RECONSTRUCTION.json')==readback['source_reconstruction'],'complete source reconstruction receipt')
    need(rebuilt['source']==SOURCE and rebuilt['output']==CAPTURE and rebuilt['crate']==CAPTURE+'/view-call-original/crate'
     and rebuilt['expected_files']==REBUILT_FILES and rebuilt['expected_directories']==REBUILT_DIRS
     and rebuilt['expected_callers']==[list(row) for row in REBUILT_CALLERS]
     and rebuilt['violations']==[] and rebuilt['active_reconstruction'] is False
     and rebuilt['new_file_writes']==rebuilt['native_or_rust_executions']==0
     and rebuilt['original_materialize_function_modified'] is False and rebuilt['materialization_summary_cached'] is False,
     'exact source generation without cached summary or writes')
    need(set(rebuilt['source_files'])==set(REBUILT_SOURCES),'all four source-regeneration input bindings')
    for name,(size,digest) in REBUILT_SOURCES.items():
        item=rebuilt['source_files'][name];snap=before['1:'+name]
        need(item=={'bytes':size,'sha256':digest} and item=={'bytes':snap['bytes'],'sha256':snap['sha256']},'full unchanged materializer/caller sources')
    need(set(rebuilt['initial_inventory'])==set(REBUILT_FILES)|set(REBUILT_DIRS),'exact independent seven-file inventory')
    for name,row in rebuilt['initial_inventory'].items():
        suffix='' if name=='.' else '/'+name
        need(row==before['0:view-call-original/crate'+suffix],'all captured crate bytes and metadata')
    need(len(rebuilt['records'])==ev['source_reconstructions']>0,'all actual source reconstruction contexts')
    need(ev['source_reconstruction_file_writes']==0 and ev['original_materialize_function_modified'] is False
     and ev['materialization_summary_cached'] is False,'unchanged source generator scope in aggregate result')
    need({(row['caller_source'],row['caller_function'],row['temporary_prefix']) for row in rebuilt['records']}==set(REBUILT_CALLERS),
     'both actual caller/prefix source bindings observed')
    for row in rebuilt['records']:
        need(row['status']=='PASS' and row['error'] is None and row['crate']==rebuilt['crate']
         and row['temporary_path']==CAPTURE+'/view-call-original'
         and (row['caller_source'],row['caller_function'],row['temporary_prefix']) in REBUILT_CALLERS
         and [(item['operation'],item['path']) for item in row['operations']]==REBUILT_OPS,'all original materializer operations')
        for item in row['operations']:
            need(item['physical_writes']==0,'no generated file writes')
            if item['operation']!='mkdir':
                snap=before['0:view-call-original/crate/'+item['path']]
                need(item['complete_bytes']=={'bytes':snap['bytes'],'sha256':snap['sha256']},'full regenerated/copied bytes')
                if item['operation']=='copyfile':
                    source_name='tests/hia_native/view_call_oracle/'+item['path'];source_pin=before['1:'+source_name]
                    need(item['source']==SOURCE+'/'+source_name and item['complete_bytes']=={'bytes':source_pin['bytes'],'sha256':source_pin['sha256']},'unchanged complete Cargo source')
    need(rebuild_controls['status']=='PASS' and rebuild_controls['complete_generator_admissions']==4
     and rebuild_controls['exact_caller_prefix_pairs']==[list(row) for row in REBUILT_CALLERS]
     and rebuild_controls['generated_files_per_admission']==7 and rebuild_controls['operations_per_admission']==10
     and [row['name'] for row in rebuild_controls['refusals']]==REBUILD_REFUSALS
     and rebuild_controls['early_and_late_alias_restoration'] is True
     and rebuild_controls['native_or_rust_executions']==0 and rebuild_controls['execution_attempts']==[]
     and rebuild_controls['original_materialize_function_modified'] is False,'all source-reconstruction controls')
    schemas=rawjson(root/"reader/RETAINED_SCHEMA_WRITES.json");schema_controls=preflight["retained_schema_controls"]
    need(pin(root/"reader/RETAINED_SCHEMA_WRITES.json")==readback["retained_schema_writes"]
     and schemas["source"]==SOURCE and schemas["output"]==str(CAPTURE)
     and schemas["folder"]==CAPTURE+"/view-call-original"
     and schemas["input_name"]==SCHEMA_INPUT and schemas["output_names"]==list(SCHEMA_OUTPUTS)
     and schemas["physical_writes"]==schemas["native_or_rust_executions"]==0
     and schemas["pending_operations"]==[] and schemas["pending_frame"] is False and schemas["violations"]==[]
     and schemas["original_summary_function_modified"] is False and schemas["summary_result_cached"] is False,
     "complete unchanged summary with only retained schema comparisons")
    need(set(schemas["source_files"])==set(SCHEMA_PINS),"all retained summary source bindings")
    for name,row in schemas["source_files"].items():
     expected=before["1:"+name]
     need(row=={"bytes":expected["bytes"],"sha256":expected["sha256"]}
      and (row["bytes"],row["sha256"])==SCHEMA_PINS[name],"exact unchanged summary source")
    need(set(schemas["initial_inventory"])=={SCHEMA_INPUT,*SCHEMA_OUTPUTS},"complete schema input/output inventory")
    for name,row in schemas["initial_inventory"].items():
     need(row==before["0:view-call-original/"+name],"complete schema input/output bytes and metadata")
    need(len(schemas["records"])==readback["evidence"]["retained_schema_pairs"]>0,"actual retained schema comparison pairs")
    for row in schemas["records"]:
     need(row["status"]=="PASS" and row["folder"]==schemas["folder"]
      and (row["caller_source"],row["caller_function"])==SCHEMA_CALLER
      and (row["parent_source"],row["parent_function"])==SCHEMA_PARENT
      and [item["path"] for item in row["operations"]]==list(SCHEMA_OUTPUTS),"exact original summary write order/callers")
     for item in row["operations"]:
      expected=before["0:view-call-original/"+item["path"]];incoming=before["0:view-call-original/"+SCHEMA_INPUT]
      need(item["operation"]=="write_bytes" and item["physical_writes"]==0
       and item["complete_bytes"]=={"bytes":expected["bytes"],"sha256":expected["sha256"]}
       and item["input_stream"]=={"bytes":incoming["bytes"],"sha256":incoming["sha256"]},"full original schema input/output spans")
    need(schema_controls["status"]=="PASS" and schema_controls["complete_pair_admissions"]==2
     and schema_controls["complete_files_per_pair"]==2 and [row["name"] for row in schema_controls["refusals"]]==SCHEMA_REFUSALS
     and schema_controls["early_and_late_alias_restoration"] is True and schema_controls["execution_attempts"]==[]
     and schema_controls["native_or_rust_executions"]==0 and schema_controls["original_summary_function_modified"] is False,
     "all retained schema comparison controls")
    diagnostics=guard_diagnostics(root,complete,readback,preflight,final)
    libraries=runtime_libraries(readback,preflight,original,before,external,final)
    environment=reference_environment(root,readback,preflight,original,before,external,final)
    mechanical=rawjson(root/'reader/MECHANICAL_READS.json')
    need(mechanical['violations']==[] and mechanical['native_or_rust_executions']==0 and mechanical['actual_git_metadata_only'] is True,'only declared Git metadata replay')
    need(len(mechanical['records'])==readback['metadata_actual_calls'] and len(mechanical['replayed_metadata'])==readback['metadata_replayed_calls']
     and len(mechanical['existing_directory_noops'])==readback['existing_directory_noops'],'complete mechanical call counts')
    skipped=rawjson(root/'skipped/SKIPPED_CONTROLS.json')
    need(skipped['status']=='PASS' and skipped['original_completed_controls_rerun'] is False
     and skipped['original_failed_report_preserved'] is True and skipped['native_or_rust_executions']==0,'only two originally skipped controls')
    control_custody={}
    for kind in ('filesystem','regex'):
        item=skipped[kind];process=rawjson(root/'skipped'/f'{kind}.process.json');audit=rawjson(root/'skipped'/f'{kind}.audit.json')
        stdout=(root/'skipped'/f'{kind}.stdout').read_bytes();stderr=(root/'skipped'/f'{kind}.stderr').read_bytes()
        need(item['process']==process and item['audit']==audit and json.loads(stdout)==item['original_summary'] and stderr==b'','complete actual control streams')
        need(pin(root/'skipped'/f'{kind}.stdout')==process['stdout'] and pin(root/'skipped'/f'{kind}.stderr')==process['stderr'],'actual stream identities')
        need(type(process['pid'])is int and process['pid']>0 and type(process['parent_pid'])is int and process['parent_pid']>0
         and type(process['elapsed_ns'])is int and 0<process['elapsed_ns']<=180000000000
         and process['pgid']==process['pid'] and type(process['timeout_seconds'])is int and process['timeout_seconds']==180
         and type(process['exit_code'])is int and process['exit_code']==0 and process['timed_out'] is False and process['start_error'] is None,'owned process deadline and completion')
        need(audit['status']=='PASS' and audit['kind']==kind and audit['pid']==process['pid'] and audit['parent_pid']==process['parent_pid']
         and audit['pgid']==process['pgid'] and audit['argv']==process['command'][9:]
         and audit['native_or_rust_executions']==0 and audit['guard_probes']==['process','native-map','native-library']
         and len(audit['execution_attempts'])==3 and all(x['probe'] is True for x in audit['execution_attempts']),'actual no-execution control audit')
        control_custody[kind]={k:process[k] for k in ('pid','pgid','parent_pid','elapsed_ns','timeout_seconds','exit_code','stdout','stderr')}
    fs=skipped['filesystem']['original_summary'];regex=skipped['regex']['original_summary']
    need(fs['controls']==11 and [r['name'] for r in fs['events']]==FS_LABELS and all(r['status']=='REJECTED' for r in fs['events'])
     and fs['actual_foreign_path_refusals']==12 and fs['physical_relocations']==2 and fs['all_source_and_artifacts_unchanged'] is True
     and fs['new_native_calls']==fs['new_rust_processes']==fs['new_processes']==0,'complete original filesystem domains')
    need(regex['negative_control_count']==14 and [r['name'] for r in regex['negative_controls']]==REGEX_LABELS
     and all(r['rejected'] is True for r in regex['negative_controls']) and regex['actual_baseline_admissions']==6
     and regex['source_and_artifacts_restored'] is True and regex['native_calls_added']==regex['original_processes_added']==0
     and regex['actual_process_report_sha256']==REPORT['sha256'],'complete original configuration/regex domains')
    need(preflight['status']=='PASS' and preflight['prefix_regressions']==8 and len(preflight['mechanical_refusals'])==6
     and len(preflight['guard_refusals'])==12 and preflight['descriptor_complete_reads']==2 and len(preflight['descriptor_refusals'])==6,'all retained source controls')
    post=packedjson(root/'POST_CONTROLS_COMPLETE_SNAPSHOT.json.gz')
    need(semantic(before)==semantic(post),'complete bytes and modes restored after negative controls')
    changes=sorted(k for k in before if before[k]!=post[k])
    need(changes==sorted(final['negative_control_phase_metadata_differences']),'all expected metadata differences explicitly retained')
    count=total=0
    with zipfile.ZipFile(a.original_index) as z:
        packed=z.read(INDEX_MEMBER);need(hashlib.sha256(packed).hexdigest()==INDEX_MEMBER_SHA,'full original index member')
        for line in gzip.decompress(packed).splitlines():
            row=json.loads(line);actual=post['0:'+row['path']]
            need(stat.S_IMODE(actual['mode'])==row['mode'],'all original file and directory modes')
            if row['type']=='0':
                need(actual['bytes']==row['data']['bytes'] and actual['sha256']==row['data']['sha256'],'all original retained bytes')
                total+=actual['bytes']
            else:need(row['type']=='5' and stat.S_ISDIR(actual['mode']),'original directory type')
            count+=1
    need(count==178275 and total==26910012457,'entire original index domain')
    actual_proofs={k:v for k,v in member_files.items() if k!='FINAL.json' and not k.startswith('recovery-source/')}
    need(actual_proofs==final['proof_files'],'all final proof members bound, without missing/extra files')
    need(final['status']=='RETAINED_AGGREGATE_AND_SKIPPED_CONTROLS_PASS' and final['original_aggregate_status']=='FAILURE'
     and final['original_failure_reclassified_as_pass'] is False and final['source_pins_rebound'] is False
     and final['retained_actual_checks']==405 and final['retained_original_recipes']==81 and final['retained_source_pins']==2111
     and final['retained_aggregate_controls_rerun'] is False and final['previously_skipped_control_processes']==2
     and final['native_or_rust_executions']==0 and final['new_executable_mappings']==0
     and final['current_kernel_mapping_and_seals_retested'] is False
     and final['source_reconstructions']==len(rebuilt['records']) and final['source_reconstruction_refusals']==18
     and final['source_reconstruction_file_writes']==0 and final['original_materialize_function_modified'] is False
     and final['retained_schema_pairs']==len(schemas['records']) and final['retained_schema_refusals']==10
     and final['retained_schema_physical_writes']==0 and final['original_summary_function_modified'] is False
     and final['whole_runtime_replaced'] is final['production_activated'] is final['old_stack_removal_qualified'] is False,'honest final scope')
    result={'schema':'hepta.history.independent-retained-proof-join.v7','status':'COMPLETE_RETAINED_PROOF_JOIN_PASS',
     'archive':complete['zip'],'archive_files':complete['files'],'archive_logical_bytes':complete['logical_bytes'],
     'all_proof_file_bytes_reopened':len(member_files),'original_report':REPORT,'original_index':INDEX,
     'original_index_entries':count,'original_logical_bytes':total,'original_status':'FAIL',
     'source_pins':2111,'registered_modules':87,'actual_static_admissions':len(code['admissions']),
     'source_reconstructions':len(rebuilt['records']),'source_reconstruction_refusals':18,
     'source_reconstruction_file_writes':0,'original_materialize_function_modified':False,
     'retained_schema_pairs':len(schemas['records']),'retained_schema_refusals':10,
     'retained_schema_physical_writes':0,'original_summary_function_modified':False,
     'runtime_libraries':libraries,'runtime_library_refusals':13,'library_loads':0,
     'reference_environment':environment,'guard_diagnostics':diagnostics,
     'read_only_snapshot_entries':len(before),'external_snapshot_entries':len(external),
     'read_only_full_metadata_equal':True,'post_control_original_bytes_and_modes_equal':True,
     'post_control_metadata_differences':len(changes),'skipped_controls':control_custody,
     'native_or_rust_executions':0,'original_failure_reclassified_as_pass':False,
     'new_executable_mappings':0,'current_kernel_mapping_and_seals_retested':False,
     'elapsed_ns':time.monotonic_ns()-start,'reader_source':pin(Path(__file__))}
    with a.output.open('xb') as f:f.write(encoded(result))
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()

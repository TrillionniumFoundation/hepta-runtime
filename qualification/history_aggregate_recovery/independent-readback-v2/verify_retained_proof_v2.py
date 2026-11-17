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
REBUILT_SOURCES={
 'scripts/hia_native_view_call_qualification.py':(87273,'6797db0667a828bd38ad27784cf7d17e1414b9bb1a7ed7a5891ed3938f78b85d'),
 'tests/hia_native/view_call_oracle/verify_sources.py':(14395,'2118c3d91971887451bd3d72f468dfcfeb8e74f853c54f9273829fa676e4356c'),
 'tests/hia_native/view_call_oracle/run.py':(13903,'19ed876d121a1c917c667ccc3ead4dae1ed25c4a5b7cf1744625773c921ca33b')}
REBUILD_REFUSALS=['changed-bound-source','extra-crate-member','missing-crate-member','wrong-temporary-prefix',
 'undeclared-temporary-caller','nested-reconstruction','write-outside-reconstruction','wrong-copy-source',
 'wrong-operation-order','omitted-materialization','write-text-options','changed-captured-copy',
 'changed-captured-generated','aliased-crate-member']

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
     and rebuilt['violations']==[] and rebuilt['active_reconstruction'] is False
     and rebuilt['new_file_writes']==rebuilt['native_or_rust_executions']==0
     and rebuilt['original_materialize_function_modified'] is False and rebuilt['materialization_summary_cached'] is False,
     'exact source generation without cached summary or writes')
    need(set(rebuilt['source_files'])==set(REBUILT_SOURCES),'all three source-regeneration input bindings')
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
    for row in rebuilt['records']:
        need(row['status']=='PASS' and row['error'] is None and row['crate']==rebuilt['crate']
         and row['temporary_path']==CAPTURE+'/view-call-original' and row['temporary_prefix']=='view-original-materialization-'
         and [(item['operation'],item['path']) for item in row['operations']]==REBUILT_OPS,'all original materializer operations')
        for item in row['operations']:
            need(item['physical_writes']==0,'no generated file writes')
            if item['operation']!='mkdir':
                snap=before['0:view-call-original/crate/'+item['path']]
                need(item['complete_bytes']=={'bytes':snap['bytes'],'sha256':snap['sha256']},'full regenerated/copied bytes')
                if item['operation']=='copyfile':
                    source_name='tests/hia_native/view_call_oracle/'+item['path'];source_pin=before['1:'+source_name]
                    need(item['source']==SOURCE+'/'+source_name and item['complete_bytes']=={'bytes':source_pin['bytes'],'sha256':source_pin['sha256']},'unchanged complete Cargo source')
    need(rebuild_controls['status']=='PASS' and rebuild_controls['complete_generator_admissions']==2
     and rebuild_controls['generated_files_per_admission']==7 and rebuild_controls['operations_per_admission']==10
     and [row['name'] for row in rebuild_controls['refusals']]==REBUILD_REFUSALS
     and rebuild_controls['early_and_late_alias_restoration'] is True
     and rebuild_controls['native_or_rust_executions']==0 and rebuild_controls['execution_attempts']==[]
     and rebuild_controls['original_materialize_function_modified'] is False,'all source-reconstruction controls')
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
     and final['source_reconstructions']==len(rebuilt['records']) and final['source_reconstruction_refusals']==14
     and final['source_reconstruction_file_writes']==0 and final['original_materialize_function_modified'] is False
     and final['whole_runtime_replaced'] is final['production_activated'] is final['old_stack_removal_qualified'] is False,'honest final scope')
    result={'schema':'hepta.history.independent-retained-proof-join.v2','status':'COMPLETE_RETAINED_PROOF_JOIN_PASS',
     'archive':complete['zip'],'archive_files':complete['files'],'archive_logical_bytes':complete['logical_bytes'],
     'all_proof_file_bytes_reopened':len(member_files),'original_report':REPORT,'original_index':INDEX,
     'original_index_entries':count,'original_logical_bytes':total,'original_status':'FAIL',
     'source_pins':2111,'registered_modules':87,'actual_static_admissions':len(code['admissions']),
     'source_reconstructions':len(rebuilt['records']),'source_reconstruction_refusals':14,
     'source_reconstruction_file_writes':0,'original_materialize_function_modified':False,
     'read_only_snapshot_entries':len(before),'external_snapshot_entries':len(external),
     'read_only_full_metadata_equal':True,'post_control_original_bytes_and_modes_equal':True,
     'post_control_metadata_differences':len(changes),'skipped_controls':control_custody,
     'native_or_rust_executions':0,'original_failure_reclassified_as_pass':False,
     'new_executable_mappings':0,'current_kernel_mapping_and_seals_retested':False,
     'elapsed_ns':time.monotonic_ns()-start,'reader_source':pin(Path(__file__))}
    with a.output.open('xb') as f:f.write(encoded(result))
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()

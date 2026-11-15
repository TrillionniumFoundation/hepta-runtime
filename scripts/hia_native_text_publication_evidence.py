"""Consume the complete native read gate and its actual refusal/absence receipts.

This is a read-only consumer, including when origins have moved. It never
restores fixtures and never reruns a producer or original implementation.
"""
from pathlib import Path
import argparse,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import hia_native_text_publication_qualification as q

def qualification_evidence(*,native,boundary,faults,corpus,handoff,controls,relocations,origins=None):
    roots=dict(native=native,boundary=boundary,faults=faults,corpus=corpus,handoff=handoff)
    admitted=q.native_evidence(**roots,origins=origins)
    f=q.Files(roots,origins)
    f.roots.update(controls=str(Path(controls).absolute()),relocations=str(Path(relocations).absolute()))
    test=Path(q.ROOT)/'tests/hia_native/test_text_publication_evidence.py'
    sources=dict(admitted['reader_sources']);sources['tests/hia_native/'+test.name]=q.pin(test.read_bytes())
    expected_controls=[(g,n,r) for g,n,_,r in q.pure_function(test.read_bytes(),'controls')()]
    q.same(len(expected_controls),33,'fixed complete refusal domain')
    totals={}
    for group,folder,mode in [('controls','controls','refusals'),('relocations','relocations','relocations')]:
        config=f.obj(group,'CONFIG.json');q.same(config,roots,'actual gate original roots')
        q.same(f.obj(group,folder+'/CONFIG.json'),roots,'actual suite original roots')
        table=f.obj(group,'SOURCE-FILES.json')
        q.same(table,{k:v['sha256'] for k,v in sources.items()},'all three actually executed read-gate sources')
        for name,pin in sources.items():f.read(group,'source/'+name,pin,source=True)
        q.same(f.obj(group,folder+'/SOURCE-FILES.json'),sources,'suite exact source pins')
        proc=f.obj(group,'PROCESS.json')
        command=['/usr/bin/python3','-I','-B',f.absolute(group,'source/tests/hia_native/'+test.name),
                 '--config',f.absolute(group,'CONFIG.json'),'--output',f.absolute(group,folder)]
        if mode=='relocations':command.append('--relocations-only')
        q.same(proc['command'],command,'actual source-owned read suite command')
        q.same(proc['cwd'],f.absolute(group,'source'),'actual read suite cwd');q.clocks(proc,180)
        q.same(proc['source_before'],table,'wrapper source before');q.same(proc['source_after'],table,'wrapper source after')
        stdout=f.read(group,'stdout',proc['stdout']);stderr=f.read(group,'stderr',proc['stderr'])
        q.same(stderr,b'','complete read suite stderr')
        result=f.obj(group,folder+'/RESULT.json');q.same(result['status'],'PASS','actual read qualification success')
        q.same(result['schema'],'hepta.runtime.text-publication-read-controls.v1','read controls schema')
        q.same(result['mode'],mode,'actual read suite mode');q.same(result['source_pins'],sources,'executed exact suite source')
        for field in ('native_cases_added','rust_cases_added','native_processes','rust_processes','skipped','errors','failures'):
            q.same(result[field],0,'read replay adds no execution or skipped checks: '+field)
        q.same(result['original_comparison_complete'],False,'original qualification is separate')
        q.require(q.number(result['elapsed_seconds']) and result['elapsed_seconds']<=proc['elapsed_seconds'],'actual read suite duration')
        baseline=f.obj(group,folder+'/BASELINE.json',result['baseline']);q.same(baseline,admitted,'whole native evidence baseline')
        messages=[q.decode(x) for x in stdout.splitlines()]
        if mode=='refusals':
            q.same(result['groups'],6,'all six independent refusal groups');q.same(result['controls'],33,'all physical refusal controls')
            q.same(result['physical_controls'],4,'raw physical changes');q.same(result['resigned_controls'],29,'re-signed semantic refusals')
            q.same(result['baseline_unchanged'],True,'full original baseline unchanged');q.same(result['snapshot_restored'],True,'private snapshot restored')
            q.same(len(result['cases']),33,'complete actual refusal receipts');q.same(len(messages),34,'full actual refusal stdout')
            for index,(row,(expected_group,name,resigned)) in enumerate(zip(result['cases'],expected_controls),1):
                q.same((row['index'],row['group'],row['name'],row['resigned_surrounding_indices']),
                       (index,expected_group,name,resigned),'source-owned exact control identity')
                q.same(row['status'],'PASS','physical mutation was rejected')
                q.same(row['native_cases_added'],0,'no new native case');q.same(row['rust_cases_added'],0,'no new original case')
                q.require(q.number(row['elapsed_seconds']) and row['elapsed_seconds']<=180,'actual rejection duration')
                rejection=row['rejection'];q.require(type(rejection) is dict and rejection['type'] in
                    ('ValueError','FileNotFoundError','OSError','KeyError','UnicodeDecodeError','error')
                    and type(rejection['message']) is str and rejection['message'],'actual refusal result')
                case=folder+'/cases/'+('%02d-'%index)+name
                q.same(f.obj(group,case+'/result.json'),row,'complete per-control receipt')
                q.same(messages[index-1],{k:row[k] for k in ('index','group','name','status','rejection')},'actual refusal stdout receipt')
                changes=row['actual_physical_changes'];q.require(type(changes) is dict and changes,'actual changed files retained')
                changed=False
                for key,item in changes.items():
                    q.relative(key)
                    q.same(item['before'],admitted['artifact_sha256'].get(key),'physical mutation began at admitted bytes')
                    if item['after'] is None:q.same(item['file'],None,'actual missing artifact control')
                    else:
                        q.same(item['file'],'changed/'+key,'only private exact changed artifact path')
                        raw=f.read(group,case+'/'+item['file'],item['after'])
                    changed=changed or item['after']!=item['before']
                q.require(changed,'physical control actually changes at least one admitted artifact')
            totals[group]={'groups':6,'controls':33,'physical':4,'resigned':29,'baseline_unchanged':True}
        else:
            q.same(len(messages),1,'complete relocation stdout');q.same(result['positive_relocations'],2,'two actual absent-origin replays')
            q.same(result['directory_identity_before'],result['directory_identity_restored'],'same original directory inodes restored')
            q.same(set(result['directory_identity_before']),set(roots),'all five original roots moved')
            for identity in result['directory_identity_before'].values():
                q.same(set(identity),{'dev','ino','mode','uid','gid'},'complete actual directory identity')
                q.require(all(q.integer(v) for v in identity.values()) and identity['ino']>0,'actual directory metadata')
            q.same(result['complete_original_evidence_unchanged'],True,'complete originals preserved')
            q.same(len(result['reads']),2,'two complete relocated read processes')
            for number,row in enumerate(result['reads'],1):
                base=folder+'/new-root-'+str(number)
                q.same(f.obj(group,base+'/RESULT.json'),row,'actual positive relocation result')
                q.same(row['new_source'],f.absolute(group,base+'/source'),'actual independent new source')
                q.same(row['new_output'],f.absolute(group,base+'/output'),'actual independent new output')
                q.same(row['original_roots_absent'],{k:True for k in roots},'actual old outputs absent')
                q.same(row['original_source_roots_absent'],{k:True for k in ('native','boundary','faults','corpus')},'actual old producer sources absent')
                for flag in ('original_fixture_roots_absent','complete_object_equal'):q.same(row[flag],True,'relocation assertion '+flag)
                q.same(row['native_processes'],0,'no native execution during relocation');q.same(row['rust_processes'],0,'no original execution during relocation')
                mapping={v:f.absolute(group,base+'/output/'+k) for k,v in roots.items()}
                q.same(f.obj(group,base+'/CONFIG.json'),dict(roots,origins=mapping),'explicit complete new-root mapping')
                for name,pin in admitted['reader_sources'].items():f.read(group,base+'/source/'+name,pin,source=True)
                child=f.obj(group,base+'/read/PROCESS.json');q.same(child,row['process'],'actual relocated reader child')
                q.same(child['command'],['/usr/bin/python3','-I','-B',f.absolute(group,base+'/source/scripts/hia_native_text_publication_qualification.py'),
                    '--config',f.absolute(group,base+'/CONFIG.json'),'--output',f.absolute(group,base+'/read/EVIDENCE.json')],'actual relocated read command')
                q.same(child['cwd'],row['new_source'],'actual relocated source cwd');q.clocks(child,180)
                q.same(child['native_processes'],0,'relocated no native');q.same(child['rust_processes'],0,'relocated no Rust')
                child_out=f.read(group,base+'/read/stdout',child['stdout']);q.same(f.read(group,base+'/read/stderr',child['stderr']),b'','complete relocated stderr')
                moved=f.obj(group,base+'/read/EVIDENCE.json',row['evidence']);q.same(moved,admitted,'full positive moved evidence equality')
                summary=q.decode(child_out)
                q.same(summary,{'status':'PASS','artifacts':len(admitted['artifacts']),'sources':len(admitted['sources']),
                                'cases':144,'native_executed':0,'rust_executed':0,'output':row['evidence']},'actual relocated complete stdout')
            totals[group]={'positive_relocations':2,'original_source_and_output_absent':True,'same_original_inodes_restored':True,'whole_objects_equal':True}
        expected_summary={k:v for k,v in result.items() if k not in ('cases','reads','source_pins','traceback')}
        q.same(messages[-1],expected_summary,'complete actual suite final stdout')
    artifacts=dict(admitted['artifact_sha256']);artifacts.update(f.artifacts)
    closure=dict(admitted['sources']);closure.update(f.sources)
    source_pins=dict(sources);source_pins['scripts/'+Path(__file__).name]=q.pin(Path(__file__).read_bytes())
    return {'schema':'hepta.runtime.text-publication-qualified-native-evidence.v1','status':'PASS',
            'native':admitted,'read_controls':totals,'artifact_sha256':dict(sorted(artifacts.items())),
            'artifacts':sorted(artifacts),'sources':dict(sorted(closure.items())),'reader_sources':source_pins,
            'new_native_execution':0,'new_rust_execution':0,'original_reference_executed':False,
            'original_reference_status':'SEPARATE_REFERENCE_ADMISSION_REQUIRED','public_handler_replaced':False,'whole_runtime_replaced':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    args=p.parse_args();result=qualification_evidence(**q.decode(args.config.read_bytes()))
    raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
    with args.output.open('xb') as stream:stream.write(raw)
    print(json.dumps({'status':'PASS','artifacts':len(result['artifacts']),'bytes':len(raw),'sha256':q.sha(raw),
                      'groups':6,'refusals':33,'relocations':2,'new_native_execution':0,'new_rust_execution':0},sort_keys=True),flush=True)

if __name__=='__main__':main()

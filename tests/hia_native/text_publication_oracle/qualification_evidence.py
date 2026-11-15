"""Complete retained original and physical-refusal evidence, without live fixtures."""
from pathlib import Path
import ast,os,stat
from common import Files,require,pin,integer,same,encoded,loads
from strict_races import evidence as race_evidence
SOURCE_PINS={'ordinary/Cargo.lock': {'bytes': 5070, 'sha256': 'b7e3bd136133883bff99d542ae984ca7ae7c35a0dd1186d1c1808be98f03c2d5'}, 'ordinary/common.py': {'bytes': 6132, 'sha256': 'dbcc268859c10b39aadbafda3196cfd47265673db409ee5a2ed8661ebb605fd5'}, 'ordinary/driver.rs': {'bytes': 3128, 'sha256': '4bcc65aa7006d76444c2eef0fa58aa5221f2219244d67a813df9b2709db698f3'}, 'ordinary/hia_native_text_publication_fixtures.py': {'bytes': 15120, 'sha256': '444145bdbb842da038d18d04f18484782fad7d5e50b213ef6dd78a8ac0e8b1b1'}, 'ordinary/native_predecessor.py': {'bytes': 12205, 'sha256': 'c8dedc99f6334d580dff1063f28c21cc264d78f465258257b10471e2b672665d'}, 'ordinary/original/Cargo.lock': {'bytes': 90148, 'sha256': '7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43'}, 'ordinary/original/text_file_write.rs': {'bytes': 13948, 'sha256': 'f502197e7409c5d565b1c3328816dceb9cacac8031fb4fbadd20b473286facfc'}, 'ordinary/run.py': {'bytes': 14247, 'sha256': '25c7d7e8bc1c7d85372ed539f4c85126f6ef562fb6a8446ac4faeda8b1dc71a0'}, 'ordinary/verify_sources.py': {'bytes': 5000, 'sha256': '0adba009fd7aec00e3c6be59ce84e354988006425400c06eaf7c43971b9ee096'}, 'races/GENERATOR-SOURCE.json': {'bytes': 396, 'sha256': 'ec858f8d91e6353db0b0b0494e2e71c69e81d5202eae7e764f3ff07d978902a0'}, 'races/original/native_races.py': {'bytes': 19050, 'sha256': '550cf160469171fda477dc5f7fdae070a094727a04f7ce6085d0fff3e190a421'}, 'races/ptrace_capture.py': {'bytes': 11988, 'sha256': 'fd796b8ffca32c6a94eec53d8ea9869a63f57b90df73c9c890386fbc3dc1fe18'}, 'races/race_cases.py': {'bytes': 3374, 'sha256': '337aebcf57b9f7998813f3c1b154722083397a660172c477875988037c0f32cc'}, 'races/race_native_predecessor.py': {'bytes': 6327, 'sha256': 'a7af1aeec6d94121dd256f3c15cb7553f099af0d86a9f3ae425ed56c177942a9'}, 'races/run_races.py': {'bytes': 17119, 'sha256': '2e89ff4e0c656691f3e9531ee28078ab23195dfb15ae34dac551912744e56aa9'}, 'readers/ptrace_evidence.py': {'bytes': 9686, 'sha256': 'bb361884992816492075c6b71d83253463ae01503416b130cf90faa3652c6b9d'}, 'readers/strict_races.py': {'bytes': 26776, 'sha256': 'eb99ace0649ff2e747b221d26d88f7599d9375f2224100c6e4d5e1f989552418'}, 'readers/strict_reference.py': {'bytes': 22488, 'sha256': 'f797b9e1e7e1e337adf33367d7f76391930adce36b71bf7674fa601a10d2b81b'}, 'readers/trace_evidence.py': {'bytes': 10447, 'sha256': '01586d600bd23761c08141c80912e80184859484a2147aaeb6f5bd99a8ee4407'}, 'test_original_evidence.py': {'bytes': 16097, 'sha256': '154a886643457367e45f7cb90de7949e41fd12e953ab79e04bc8e96ee2ed547d'}, 'test_race_evidence.py': {'bytes': 13645, 'sha256': '3d494a0fa451ca93494415dc66444a4b8baca4abb34c65b747476839d1ba51fe'}}
def mapped(files,origin):
    origin=Path(origin);require(origin.is_absolute() and '..' not in origin.parts,'safe explicit artifact origin')
    pairs=[(a,b) for a,b in files.origins if origin==a or a in origin.parents];require(pairs,'unmapped artifact origin')
    a,b=max(pairs,key=lambda p:len(p[0].parts));path=b/origin.relative_to(a)
    for parent in reversed(path.parents):require(not parent.is_symlink(),'symlink in artifact parent')
    return path
def _controls(f,source,out,receipt,request_path,baseline,test):
    source=Path(source);out=Path(out);receipt=Path(receipt);request_path=Path(request_path)
    result=f.json(out/'RESULT.json');test_raw=f.raw(source/test,SOURCE_PINS[test]);syntax=ast.parse(test_raw)
    controls=[(n.args[0].value,n.args[1].value) for n in ast.walk(syntax) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='control' and len(n.args)>=2 and all(isinstance(x,ast.Constant) and type(x.value) is str for x in n.args[:2])]
    count=42 if test=='test_original_evidence.py' else 36
    require(len(controls)==count and len(set(controls))==count,'fixed complete actual refusal source')
    require(result['status']=='PASS' and type(result['groups']) is int and result['groups']==6 and type(result['controls']) is int and result['controls']==count,'complete typed refusal domain')
    require(result['new_original_processes']==result['new_native_calls']==0 and type(result['new_original_processes']) is int and type(result['new_native_calls']) is int and result['unchanged_whole_evidence_after_controls'] is True,'no new semantic calls in retained refusals')
    same(f.json(out/'BASELINE.json',result['baseline']),baseline,'entire admitted refusal baseline')
    request=f.json(request_path);same(f.json(out/'REQUEST.json'),request,'complete actual refusal selection')
    raw_request=f.raw(request_path)
    src=f.json(out/'SOURCE.json');same(src,result['source'],'full actual refusal producer source record')
    dirs=[source/'readers',source/'ordinary'] if count==42 else [source/'readers',source/'races',source/'ordinary']
    wanted={str(source/n):p for n,p in SOURCE_PINS.items() if any(Path(n).parts[0]==d.name for d in dirs)}
    wanted[str(source/test)]=SOURCE_PINS[test]
    if count==36:wanted[str(request_path)]=pin(raw_request)
    same(src,wanted,'all and only actual refusal source inputs')
    for path,expected in src.items():f.raw(path,expected)
    p=f.json(receipt)
    require(set(p)=={'command','cwd','pid','timeout_seconds','timed_out','start_error','exit_code','started_monotonic_ns','finished_monotonic_ns','elapsed_seconds','stdout','stderr'},'complete real refusal process')
    cmd=[p['command'][0],'-I','-B',str(source/test),'--request',str(request_path),'--output',str(out)]
    for d in dirs:cmd+=['--reader',str(d)]
    same(p['command'],cmd,'actual complete refusal command');require(p['cwd']==str(source),'actual refusal cwd')
    integer(p['pid'],'actual refusal PID',1)
    require(type(p['timeout_seconds']) is int and p['timeout_seconds']==180 and p['timed_out'] is False and p['start_error'] is None and type(p['exit_code']) is int and p['exit_code']==0,'actual successful unchanged refusal budget')
    a=integer(p['started_monotonic_ns'],'refusal start',1);b=integer(p['finished_monotonic_ns'],'refusal finish',a+1)
    require(type(p['elapsed_seconds']) in (int,float) and 0<p['elapsed_seconds']<180 and abs(p['elapsed_seconds']-(b-a)/1e9)<1e-9,'real refusal elapsed interval')
    same(loads(f.raw(receipt.parent/'stdout',p['stdout'])),{k:v for k,v in result.items() if k not in ('rows','source')},'entire actual refusal stdout')
    require(f.raw(receipt.parent/'stderr',p['stderr'])==b'','complete actual refusal stderr')
    require([(r['group'],r['name']) for r in result['rows']]==controls,'every physical refusal in source order')
    mutated=0;links=0
    for row in result['rows']:
        d=out/'controls'/row['name'];same(f.json(d/'RESULT.json'),row,'complete per-control actual receipt')
        require(row['status']=='REJECTED' and row['exception'] in ('ValueError','KeyError','FileNotFoundError','UnicodeDecodeError','error','StopIteration') and type(row['message']) is str and row['message'],'actual refusal exception')
        require(type(row['elapsed_seconds']) in (int,float) and 0<row['elapsed_seconds']<180,'actual refusal interval')
        mutations=f.json(d/'MUTATIONS.json');same(mutations,row['mutations'],'all complete physical mutations')
        require(mutations,'nonempty actual physical refusal')
        retired=f.json(d/'LINK-RETIREMENT.json');same(retired,row['retired_links'],'actual owned negative-test link retirement')
        require(type(retired) is list and len({r['path'] for r in retired})==len(retired),'unique retired links')
        bypath={r['path']:r for r in retired};seen=set()
        for old,e in mutations.items():
            path=Path(e['path']);require(path.parent==d and path.is_absolute(),'private owned mutation location')
            if 'bytes' in e:
                require(set(e)=={'path','bytes','sha256'},'whole controlled mutation bytes')
                f.raw(path,{k:e[k] for k in ('bytes','sha256')});mutated+=1
            elif e.get('absent') is True:
                require(set(e)=={'path','absent'} and path.name.startswith('absent-') and not os.path.lexists(mapped(f,path)),'real absent mapped corruption')
            else:
                require(set(e)=={'path','symlink_target'} and path.name.startswith('symlink-'),'exact private link refusal')
                require(str(path) in bypath and not os.path.lexists(mapped(f,path)),'only admitted negative-test link retired')
                r=bypath[str(path)];require(set(r)=={'path','target','identity','removed'} and r['target']==e['symlink_target'] and r['removed'] is True,'same actual link retirement')
                require(set(r['identity'])=={'dev','ino','mode','uid','gid'} and stat.S_ISLNK(r['identity']['mode']),'actual retired symlink identity')
                for value in r['identity'].values():integer(value,'actual retired link stat')
                seen.add(str(path));links+=1
        require(seen==set(bypath),'all and only actual controlled symlinks retired')
    return {'groups':6,'controls':count,'baseline':result['baseline'],'test_source':SOURCE_PINS[test],'physical_regular_mutations':mutated,'retired_private_symlinks':links,'process':p,'rows':result['rows']}
def qualification_evidence(*,source,ordinary_request,race_request,ordinary_controls,race_controls,ordinary_receipt,race_receipt,origins):
    f=Files(origins);source=Path(source)
    for name,expected in SOURCE_PINS.items():f.raw(source/name,expected)
    ordinary=f.json(ordinary_request);race=f.json(race_request)
    require(ordinary['source']==str(source/'ordinary') and race['source']==str(source/'races'),'same selected frozen original source')
    same(ordinary,f.json(Path(race['output'])/'ORDINARY-REQUEST.json'),'same actual ordinary predecessor selection')
    proof=race_evidence(**{**race,'origins':origins});f.artifacts.update(proof['artifact_sha256'])
    first=_controls(f,source,ordinary_controls,ordinary_receipt,ordinary_request,proof['ordinary_reference'],'test_original_evidence.py')
    second=_controls(f,source,race_controls,race_receipt,race_request,proof,'test_race_evidence.py')
    fixtures=proof['ordinary_reference']['transient_fixture_directories']+proof['transient_fixture_directories']
    require(len(fixtures)==len(set(fixtures))==119,'all independent original fixture directories')
    return {'schema':'hepta.runtime.text-publication-original-qualification.v1','status':'PASS',
      'ordinary_cases':99,'external_writer_cases':20,'actual_fresh_locked_builds':1,
      'actual_version_processes':3,'actual_original_replay_processes':5,'actual_original_child_processes':9,
      'physical_refusal_groups':12,'physical_refusals':78,'refusal_processes':2,
      'new_original_processes':0,'new_native_calls':0,'original_reference':proof,
      'ordinary_refusals':first,'race_refusals':second,'source_sha256':SOURCE_PINS,
      'transient_fixture_directories':fixtures,'public_handler_complete':False,
      'whole_runtime_replaced':False,'artifact_sha256':f.artifacts}

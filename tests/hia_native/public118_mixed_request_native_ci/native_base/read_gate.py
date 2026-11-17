"""Read one repaired native lane against the exact retained original public lane."""
from pathlib import Path
import argparse,ast,codecs,gzip,json,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import read_public,source_check,restore,legacy_ready,read_only_guard
from receipt_support import PIN,regular,require
def admit_original(capture,package,domain):
    capture,package=Path(capture),Path(package);prior=capture/'retained/prior'
    original_source=source_check.check(prior/'source',restore.CONFIG['prior_profile'])
    for name in read_public.DRIVER_FILES:require(regular(prior/'source'/name)==regular(package/name),'recording driver or inputs changed since original execution: '+name)
    # Bind the exact complete historical ready reader by source and AST.
    old=regular(package/'retained/public-v1/read_gate.py').decode();new=regular(package/'legacy_ready.py').decode()
    a=next(n for n in ast.parse(old).body if isinstance(n,ast.FunctionDef) and n.name=='ready');b=next(n for n in ast.parse(new).body if isinstance(n,ast.FunctionDef) and n.name=='ready')
    require(ast.dump(a,include_attributes=False)==ast.dump(b,include_attributes=False) and ''.join(old.splitlines(keepends=True)[a.lineno-1:a.end_lineno])==''.join(new.splitlines(keepends=True)[b.lineno-1:b.end_lineno]),'original full build reader changed')
    require(regular(package/'legacy_restore.py')==regular(package/'retained/public-v1/restore.py'),'original complete build/archive reader changed')
    producer=json.loads(regular(prior/'RUN.json'));require(producer['status']=='FAIL' and producer['source_commit']==restore.CONFIG['prior_source'] and producer['run_id']==str(restore.CONFIG['prior_run']) and producer['domain']==domain,'genuine original producer status')
    reuse=json.loads(regular(capture/'ORIGINAL_REUSE.json'));require(reuse['original_replayed'] is False and reuse['source_artifact']==restore.CONFIG['prior_artifacts'][domain] and reuse['files']==restore.copied_inventory(prior/'original',capture/'original'),'unchanged original complete capture')
    for suffix in ('json','stdout','stderr'):require(regular(prior/('original.lane.'+suffix))==regular(capture/('original.lane.'+suffix)),'original lane receipt changed')
    binary={k:restore.BINARIES['original'][k] for k in ('bytes','sha256')}
    if domain.startswith('body-'):
        folder=capture/'original';lane=json.loads(regular(folder/'lane.json'));specs=read_public.cases.body_specs()
        require(lane['status']=='PASS' and lane['role']=='original' and lane['domain']==domain and lane['case_count']==153 and lane['operation_count']==175 and lane['outer_lane_deadline_seconds']==180 and read_public.number(lane['elapsed_seconds'],180),'complete retained body lane')
        require(len(lane['cases'])==len(specs)==153,'all body ordinals retained');results=[]
        for index,(row,spec) in enumerate(zip(lane['cases'],specs,strict=True)):
            case=folder/'cases'/f'{index:03d}';require(row=={'index':index,'name':spec['name'],'operations':len(spec['operations']),'result':PIN(regular(case/'result.json'))},'complete retained body case binding');results.append(read_public.inspect(case,package,expected_binary=binary))
    else:results=[read_public.inspect(capture/'original',package,expected_binary=binary)]
    return {'status':'UNCHANGED_ORIGINAL_PUBLIC_LANE_READ_PASS','domain':domain,'source':original_source,'complete_captures':results,'original_semantics_replayed':False,'native_or_rust_executions':0}
def verify(capture,package,profile):
    capture,package=Path(capture),Path(package);source=source_check.check(package,profile);require(source_check.check(capture/'source',profile)==source,'complete executed source snapshot');r=json.loads(regular(capture/'RUN.json'));domain=r['domain']
    require(r['status'] in ('VERIFYING','PASS') and r['source_profile']==profile and domain in read_public.capture.DOMAINS and r['original_semantics_replayed'] is False and r['native_build_replayed'] is False,'fixed complete native-only domain')
    build=restore.verify_ready(capture/'retained',domain);original=admit_original(capture,package,domain);require(json.loads(regular(capture/'ORIGINAL_ADMISSION.json'))==original,'full prior original admission')
    prior=json.loads(regular(capture/'retained/prior/RUN.json'));producer=Path(r['producer_root']);require(producer.is_absolute() and prior['producer_root']==r['producer_root'] and r['fixture']==prior['fixture']==str(producer/'workspaces'/domain),'same actual absolute fixture input')
    previous=legacy_ready.ready(capture/'retained/prior/retained')
    for role in ('native','original'):
        folder=capture/role;lane=json.loads(regular(capture/(role+'.lane.json')));summary=json.loads(regular(folder/('lane.json' if domain.startswith('body-') else 'result.json')))
        binary=build['binaries']['native-private'] if role=='native' else previous['binaries']['original']
        require(lane['status']=='PASS' and lane['schema']=='hepta.runtime.extract-public-lane-guard.v1' and lane['role']==role and lane['domain']==domain and lane['fixture']==r['fixture'] and lane['output']==str(producer/role) and lane['binary']==binary['path'] and lane['kind']=='private','actual lane identity')
        require(lane['driver']=='qualify_public.py' and lane['driver_pin']==PIN(regular(package/'qualify_public.py')) and lane['outer_lane_deadline_seconds']==180 and lane['per_exchange_deadline_seconds']==60 and lane['alarm_fired'] is False and lane['cleanup_in_recording_driver'] is True and read_public.number(lane['elapsed_seconds'],180) and lane['elapsed_seconds']<180 and summary['elapsed_seconds']<=lane['elapsed_seconds'] and lane['capture']==PIN(regular(folder/('lane.json' if domain.startswith('body-') else 'result.json'))),'actual unchanged lane budget and recording source')
        for stream in ('stdout','stderr'):
            raw=regular(capture/(role+'.lane.'+stream));require(lane[stream]=={'path':role+'.lane.'+stream,**PIN(raw)} and raw==b'','complete recording-driver stream')
    result=read_public.compare_lane(capture/'native',capture/'original',capture/'source',native_binary={k:restore.BINARIES['native-private'][k] for k in ('bytes','sha256')},original_binary={k:restore.BINARIES['original'][k] for k in ('bytes','sha256')},domain=domain)
    require(not (capture/'workspaces'/domain).exists(),'mutable completed fixture remains')
    return {'status':'COMPLETE_PUBLIC_EXTRACT_DOMAIN_PASS','domain':domain,'source':source,'comparison':result,'original_semantics_replayed':False,'native_or_rust_executions':0,'runtime_hia_images':118,'installed_handlers':10,'full_async_cancellation_qualified':False,'remote_sftp_qualified':False,'whole_runtime_replaced':False}
def guarded(capture,package,profile):
    for encoding in ('ascii','utf-8','utf-8-sig','cp437'):codecs.lookup(encoding)
    require(gzip.decompress(gzip.compress(b'',mtime=0))==b'','gzip warmup');source_check.check(package,profile)
    result=read_only_guard.guarded(lambda:verify(capture,package,profile),roots=[Path(capture),Path(package)],foreign_path=Path('/dev/null'))
    require(result['before']==result['after'] and len(result['probes'])==11 and result['reader_writes']==result['native_or_rust_executions']==0,'strict complete read-only gate');return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--capture',type=Path,required=True);p.add_argument('--package',type=Path,required=True);p.add_argument('--profile',required=True);a=p.parse_args();print(json.dumps(guarded(a.capture,a.package,a.profile),sort_keys=True,allow_nan=False))

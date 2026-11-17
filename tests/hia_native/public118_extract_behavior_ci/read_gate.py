"""Full source, retained build custody, actual streams, state and filesystem comparison."""
from pathlib import Path
import argparse,codecs,gzip,hashlib,json,stat,sys,zipfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import read_public,source_check,restore,read_only_guard
from receipt_support import PIN,regular,require
def ready(root):
    root=Path(root);r=json.loads(regular(root/'READY.json'));require(r['status']=='RETAINED_NATIVE118_AND_ORIGINAL_REFERENCE_READY' and r['runtime_recompiled'] is False and r['native_or_rust_executions']==0 and (r['runtime_hia_images'],r['physical_images'],r['installed_handlers'])==(118,111,10),'retained actual graph identity')
    for role,pin in restore.PINS.items():
        meta=json.loads(regular(root/(role+'.artifact.json')));require(meta['id']==pin['artifact'] and meta['digest']=='sha256:'+pin['sha256'] and meta['workflow_run']['id']==pin['run'] and meta['workflow_run']['head_sha']==pin['source'],'immutable input artifact identity')
        if role in ('native','original'):
            folder=root/role;selection=json.loads(regular(folder/'SELECTION.json'));require(selection['status']=='COMPLETE_RETAINED_ARCHIVE_STREAM_READ_PASS' and selection['zip']=={k:pin[k] for k in ('bytes','sha256')} and selection['native_or_rust_executions']==0,'complete prior archive read identity');receipt=selection['archive_receipt'];manifest_raw=regular(folder/'artifact-manifest.json');manifest=json.loads(manifest_raw);require(PIN(manifest_raw)==receipt['manifest'] and receipt['git_head']==pin['source'] and receipt['run_id']==str(pin['run']),'complete prior member inventory')
            allrows=dict(manifest['files']);allrows['artifact-manifest.json']={**receipt['manifest'],'mode':0o600};selected={n:v for n,v in allrows.items() if restore.selected(role,n)};require(selection['selected']==selected and selection['files']==len(allrows),'exact full selector inventory')
            require({p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}==set(selected)|{'SELECTION.json'},'selected retained file closure')
            for name,row in selected.items():
                path=folder/name;require(PIN(regular(path))=={k:row[k] for k in ('bytes','sha256')} and stat.S_IMODE(path.stat().st_mode)==row['mode'],'complete retained member bytes/mode '+name)
            if role=='native':require(hashlib.sha256(regular(folder/'ci-package/graph/source/native/runtime_mcp_sources.json')).hexdigest()=='2c423747b2827c3a6d0993b89583c47691640ea44fcf5f77e6c0ed2aaaf0dc70','exact 425-source public graph binding')
            else:require(PIN(regular(folder/'ci-package/PACKAGE.json'))['sha256']=='fec98075c21e5761ae344d786d457144c5fb01aa48ab7427bb65748b26ea9e22','exact original reference source')
        else:
            archive=root/(role+'.zip');require(PIN(regular(archive))=={k:pin[k] for k in ('bytes','sha256')},'complete independent proof ZIP');folder=root/role
            with zipfile.ZipFile(archive) as z:
                require(z.testzip() is None and set(z.namelist())=={p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()},'complete proof member set/CRC')
                for info in z.infolist():require(regular(folder/info.filename)==z.read(info.filename),'complete independently retained proof file')
            names=list(folder.rglob('READONLY.json')) if role=='native-proof' else list(folder.rglob('extract-reference-retained-read.stdout'));require(len(names)==1,'one original guarded proof');g=json.loads(regular(names[0]));require(g['before']==g['after'] and len(g['probes'])==11 and g['reader_writes']==g['native_or_rust_executions']==0 and g['source_bound_guard'] is True,'complete prior independent guarded read')
            if role=='native-proof':require(g['evidence']['status']=='COMPLETE_PUBLIC118_ARCHIVE_STREAM_READ_PASS' and g['evidence']['artifact']==14286335670,'actual native producer proof')
            else:require(g['evidence']['status']=='RETAINED_EXTRACT_REFERENCE_COMPLETE_READ_PASS' and g['evidence']['producer_conclusion_retained']=='FAIL' and g['evidence']['qualification']['controls']['refusals']==4,'actual recovered reference and original failure')
    for name,row in restore.BINARIES.items():require(PIN(regular(root/row['source']/row['path']))=={k:row[k] for k in ('bytes','sha256')},'exact executed retained binary '+name)
    return r
def verify(capture,package,profile):
    capture=Path(capture);package=Path(package);source=source_check.check(package,profile);copied=source_check.check(capture/'source',profile);require(source==copied,'complete executed source snapshot');r=json.loads(regular(capture/'RUN.json'));build=ready(capture/'retained');domain=r['domain'];require(r['source_profile']==profile and r['domain'] in read_public.capture.DOMAINS and r['status'] in ('VERIFYING','PASS'),'fixed complete runtime domain')
    producer=Path(r['producer_root']);require(producer.is_absolute() and r['fixture']==str(producer/'workspaces'/domain),'fixed absolute input fixture')
    for role in ('native','original'):
        folder=capture/role;lane=json.loads(regular(capture/(role+'.lane.json')));summary=json.loads(regular(folder/('lane.json' if domain.startswith('body-') else 'result.json')));binary=build['binaries']['native-private' if role=='native' else 'original']
        require(lane['status']=='PASS' and lane['schema']=='hepta.runtime.extract-public-lane-guard.v1' and lane['role']==role and lane['domain']==domain and lane['fixture']==r['fixture'] and lane['output']==str(producer/role) and lane['binary']==binary['path'] and lane['kind']=='private','actual lane identity')
        require(lane['driver']=='qualify_public.py' and lane['driver_pin']==PIN(regular(package/'qualify_public.py')) and lane['outer_lane_deadline_seconds']==180 and lane['per_exchange_deadline_seconds']==60 and lane['alarm_fired'] is False and lane['cleanup_in_recording_driver'] is True and read_public.number(lane['elapsed_seconds'],180) and lane['elapsed_seconds']<180 and summary['elapsed_seconds']<=lane['elapsed_seconds'] and lane['capture']==PIN(regular(folder/('lane.json' if domain.startswith('body-') else 'result.json'))),'unchanged actual lane budget and source')
        for stream in ('stdout','stderr'):
            raw=regular(capture/(role+'.lane.'+stream));require(lane[stream]=={'path':role+'.lane.'+stream,**PIN(raw)} and raw==b'','complete Python recording-driver streams')
    result=read_public.compare_lane(capture/'native',capture/'original',capture/'source',native_binary={k:restore.BINARIES['native-private'][k] for k in ('bytes','sha256')},original_binary={k:restore.BINARIES['original'][k] for k in ('bytes','sha256')},domain=domain)
    require(not (capture/'workspaces'/domain).exists(),'completed mutable fixture remains')
    return {'status':'COMPLETE_PUBLIC_EXTRACT_DOMAIN_PASS','domain':domain,'source':source,'comparison':result,'native_or_rust_executions':0,'runtime_hia_images':118,'installed_handlers':10,'full_async_cancellation_qualified':False,'remote_sftp_qualified':False,'whole_runtime_replaced':False}
def guarded(capture,package,profile):
    for encoding in ('ascii','utf-8','utf-8-sig'):codecs.lookup(encoding)
    assert gzip.decompress(gzip.compress(b'',mtime=0))==b''
    source_check.check(package,profile)
    result=read_only_guard.guarded(lambda:verify(capture,package,profile),roots=[Path(capture),Path(package)],foreign_path=Path('/dev/null'))
    require(result['before']==result['after'] and len(result['probes'])==11 and result['reader_writes']==result['native_or_rust_executions']==0,'strict full public read-only gate');return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--capture',type=Path,required=True);p.add_argument('--package',type=Path,required=True);p.add_argument('--profile',required=True);a=p.parse_args();print(json.dumps(guarded(a.capture,a.package,a.profile),sort_keys=True,allow_nan=False))

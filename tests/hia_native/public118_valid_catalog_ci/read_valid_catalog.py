"""Read complete new valid-config original/native catalog captures and all source custody."""
from pathlib import Path
import codecs,gzip,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import source_check,restore,read_public,read_only_guard,valid_catalog_admission
from receipt_support import regular,PIN,require
def verify(capture,package,profile):
    capture,package=Path(capture),Path(package);source=source_check.check(package,profile)
    require(source_check.check(capture/'source',profile)==source,'complete current source snapshot')
    r=json.loads(regular(capture/'RUN.json'));domain=r['domain']
    require(r['schema']=='hepta.runtime.new-valid-catalog-domain.v1' and r['status'] in ('VERIFYING','PASS') and r['source_profile']==profile and domain in ('catalog-legacy','catalog-modern'),'fixed new valid-config domain')
    require(r['old_835_original_replayed'] is False and r['binary_recompiled'] is False and r['new_original_input_domain'] is True,'new domain never replayed old originals')
    ready=restore.verify_ready(capture/'retained',domain)
    admission=valid_catalog_admission.check(capture,package)
    require(admission==json.loads(regular(capture/'DOMAIN_ADMISSION.json')),'complete new input admission')
    origin=Path(r['producer_root']);require(origin.is_absolute() and r['fixture']==str(origin/'workspaces'/domain),'fixed actual new fixture path')
    for role in ('original','native'):
        binary=ready['binaries']['native-private' if role=='native' else 'original']
        lane=json.loads(regular(capture/(role+'.lane.json')));report=json.loads(regular(capture/role/'result.json'))
        require(lane['status']=='PASS' and lane['schema']=='hepta.runtime.extract-public-lane-guard.v1' and lane['role']==role and lane['domain']==domain and lane['fixture']==r['fixture'] and lane['output']==str(origin/role) and lane['binary']==binary['path'] and lane['kind']=='private','complete actual lane identity')
        require(lane['driver']=='qualify_public.py' and lane['driver_pin']==PIN(regular(package/'qualify_public.py')) and lane['outer_lane_deadline_seconds']==180 and lane['per_exchange_deadline_seconds']==60 and lane['alarm_fired'] is False and lane['cleanup_in_recording_driver'] is True and read_public.number(lane['elapsed_seconds'],180) and lane['elapsed_seconds']<180 and report['elapsed_seconds']<=lane['elapsed_seconds'] and lane['capture']==PIN(regular(capture/role/'result.json')),'fixed lane budget and unchanged original recorder')
        for name in ('stdout','stderr'):
            raw=regular(capture/(role+'.lane.'+name));require(lane[name]=={'path':role+'.lane.'+name,**PIN(raw)} and raw==b'','complete recording driver streams')
    compared=read_public.compare_lane(capture/'native',capture/'original',package,native_binary={k:restore.BINARIES['native-private'][k] for k in ('bytes','sha256')},original_binary={k:restore.BINARIES['original'][k] for k in ('bytes','sha256')},domain=domain,original_source_root=package)
    require(compared['actual_rows_per_provider']==(5 if domain.endswith('modern') else 6),'all original/new native catalog inputs')
    require(not (capture/'workspaces'/domain).exists(),'completed owned fixture retired')
    state=capture/'workspaces'/(domain+'-admin-state')
    require(state.is_dir(),'actual native config startup state retained')
    return {'status':'COMPLETE_VALID_CATALOG_NEW_DOMAIN_PASS','domain':domain,'source':source,'input_admission':admission,'comparison':compared,'runtime_hia_images':118,'physical_images':111,'installed_handlers':10,'old_835_original_replayed':False,'new_original_input_domain':True,'native_or_rust_executions':0,'reference_cli_startup_effects_compared':False,'public_wait_qualified':False,'whole_runtime_replaced':False}
def guarded(capture,package,profile):
    for name in ('ascii','utf-8','utf-8-sig','cp437'):codecs.lookup(name)
    require(gzip.decompress(gzip.compress(b'',mtime=0))==b'','gzip preload')
    source_check.check(package,profile)
    guard=read_only_guard.guarded(lambda:verify(capture,package,profile),roots=[Path(capture),Path(package)],foreign_path='/proc/self/status')
    require(guard['before']==guard['after'] and len(guard['probes'])==11 and guard['reader_writes']==guard['native_or_rust_executions']==0,'complete read-only gate')
    return guard

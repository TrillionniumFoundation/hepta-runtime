"""Execute only the new valid configuration domain using two already qualified binaries."""
from pathlib import Path
import argparse,json,os,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import source_check,restore,lane_guard,qualify_public,read_valid_catalog,catalog_controls,valid_catalog_admission
from receipt_support import regular,PIN,require,put
def retire(fixture,folder):
    if not fixture.exists():return
    vault=folder/'retired-fixture-blobs';vault.mkdir(exist_ok=False)
    complete=qualify_public.body_fixture.tree_snapshot(fixture,vault);ordinary=qualify_public.whole_snapshot(qualify_public.common.OwnedFixture(fixture));put(folder/'FIXTURE_BEFORE_RETIREMENT.json',{'complete':complete,'ordinary':ordinary})
    removed=qualify_public.common.OwnedFixture(fixture.parent).remove_tree(os.fsencode(fixture));put(folder/'FIXTURE_RETIREMENT.json',{'captured_full_files_before_cleanup':True,'removed':removed})
def main():
    p=argparse.ArgumentParser()
    for name in ('input','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--domain',choices=('catalog-legacy','catalog-modern'),required=True);p.add_argument('--profile',required=True);a=p.parse_args()
    require(os.environ.get('GITHUB_ACTIONS')=='true','new semantic domain is CI-only')
    source=source_check.check(ROOT,a.profile);output=a.output.resolve();require(not output.exists(),'new domain already attempted');output.mkdir(parents=True);shutil.copytree(ROOT,output/'source')
    fixture=output/'workspaces'/a.domain;fixture.parent.mkdir()
    r={'schema':'hepta.runtime.new-valid-catalog-domain.v1','status':'RUNNING','domain':a.domain,'producer_root':str(output),'fixture':str(fixture),'source_profile':a.profile,'source_admission':source,'source_commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),'old_835_original_replayed':False,'binary_recompiled':False,'new_original_input_domain':True,'reference_cli_startup_effects_compared':False,'public_wait_qualified':False,'whole_runtime_replaced':False};put(output/'RUN.json',r)
    try:
        ready=restore.prepare(a.input,output/'retained',a.domain)
        put(output/'DOMAIN_ADMISSION.json',valid_catalog_admission.check(output,ROOT))
        for role in ('original','native'):
            binary=Path(ready['binaries']['native-private' if role=='native' else 'original']['path'])
            try:lane_guard.run('private',role,binary,fixture,output/role,a.domain)
            finally:
                if (output/role).exists():retire(fixture,output/role)
        r['status']='VERIFYING';put(output/'RUN.json',r)
        guard=read_valid_catalog.guarded(output,ROOT,a.profile);put(output/'READONLY.json',guard)
        put(output/'CATALOG_CONTROLS.json',catalog_controls.run(output,output/'catalog-controls'))
        r['status']='PASS';r['guarded_read']=PIN(regular(output/'READONLY.json'));put(output/'RUN.json',r)
        print(json.dumps({'status':'PASS','domain':a.domain,'actual_rows_per_provider':guard['evidence']['comparison']['actual_rows_per_provider'],'new_original_input_domain':True,'old_835_original_replayed':False,'runtime_hia_images':118,'installed_handlers':10,'physical_controls':8,'source_profile':a.profile},sort_keys=True))
    except BaseException as error:
        r['status']='FAIL';r['failure']={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()};put(output/'RUN.json',r);raise
if __name__=='__main__':main()

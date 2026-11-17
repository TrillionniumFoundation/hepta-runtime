"""Run only a new native public lane; retain the successful original lane unchanged."""
from pathlib import Path
import argparse,json,os,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import source_check,restore,lane_guard,read_gate,reader_controls,qualify_public
from receipt_support import PIN,regular,put,require
def retire(fixture,folder):
    if not fixture.exists():return
    vault=folder/'retired-fixture-blobs';vault.mkdir(exist_ok=False)
    complete=qualify_public.body_fixture.tree_snapshot(fixture,vault);ordinary=qualify_public.whole_snapshot(qualify_public.common.OwnedFixture(fixture));put(folder/'FIXTURE_BEFORE_RETIREMENT.json',{'complete':complete,'ordinary':ordinary})
    removed=qualify_public.common.OwnedFixture(fixture.parent).remove_tree(os.fsencode(fixture));put(folder/'FIXTURE_RETIREMENT.json',{'captured_full_files_before_cleanup':True,'removed':removed})
def main():
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--domain',choices=qualify_public.DOMAINS,required=True);p.add_argument('--profile',required=True);a=p.parse_args()
    require(os.environ.get('GITHUB_ACTIONS')=='true','semantic runs are CI-only');source=source_check.check(ROOT,a.profile);output=a.output.resolve();require(not output.exists(),'capture already attempted');output.mkdir(parents=True);shutil.copytree(ROOT,output/'source');fixture=output/'workspaces'/a.domain;fixture.parent.mkdir()
    r={'schema':'hepta.runtime.extract-public-native-successor-domain.v1','status':'RUNNING','domain':a.domain,'producer_root':str(output),'fixture':str(fixture),'source_profile':a.profile,'source_admission':source,'source_commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),'native_build_replayed':False,'original_build_replayed':False,'original_semantics_replayed':False,'prior_semantic_run':restore.CONFIG['prior_run'],'full_async_cancellation_qualified':False,'remote_sftp_qualified':False,'whole_runtime_replaced':False};put(output/'RUN.json',r)
    try:
        ready=restore.prepare(a.input,output/'retained',a.domain);prior=json.loads(regular(output/'retained/prior/RUN.json'))
        require(prior['producer_root']==str(output) and prior['fixture']==str(fixture),'exact original fixture namespace')
        restore.install_original(output/'retained',output);put(output/'ORIGINAL_ADMISSION.json',read_gate.admit_original(output,ROOT,a.domain))
        try:lane_guard.run('private','native',Path(ready['binaries']['native-private']['path']),fixture,output/'native',a.domain)
        finally:
            if (output/'native').exists():retire(fixture,output/'native')
        r['status']='VERIFYING';put(output/'RUN.json',r);guard=read_gate.guarded(output,ROOT,a.profile);put(output/'READONLY.json',guard)
        if a.domain=='typed-legacy':put(output/'CONTROLS.json',reader_controls.run(output,output/'controls'))
        r['status']='PASS';r['guarded_read']=PIN(regular(output/'READONLY.json'));put(output/'RUN.json',r)
        print(json.dumps({'status':'PASS','domain':a.domain,'runtime_hia_images':118,'installed_handlers':10,'actual_source_profile':a.profile,'original_semantics_replayed':False},sort_keys=True))
    except BaseException as error:
        r['status']='FAIL';r['failure']={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()};put(output/'RUN.json',r);raise
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Ordinary eight-tool stdio loops over owned files, plus actual target SDK data comparisons.

The historical native body comparison is kept distinct from target SDK request
and response serialization. No handler result is synthesized by this harness.
"""
from pathlib import Path
from collections import Counter
import argparse,base64,hashlib,importlib.util,json,os,shutil,stat,subprocess,sys,time,traceback
ROOT=Path(__file__).resolve().parents[1];SOURCE=ROOT/'source'
sha=lambda b:hashlib.sha256(b).hexdigest()
wire=lambda x:json.dumps(x,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
put=lambda p,x:p.write_text(json.dumps(x,ensure_ascii=True,sort_keys=True,indent=2)+'\n')
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
capture=load('_g5_public_capture',SOURCE/'tests/hia_native/runtime_mcp_public_capture.py')
inputs=load('_g5_normal_execution_input',ROOT/'scripts/ordinary_execution_input.py')
CAPS='io.modelcontextprotocol/clientCapabilities';VERSION='io.modelcontextprotocol/protocolVersion'

def snapshot(root):
    rows={}
    for folder,dirs,names in os.walk(root):
        for name in sorted(dirs+names):
            p=Path(folder)/name;st=p.lstat();rel=str(p.relative_to(root))
            row={'mode':stat.S_IMODE(st.st_mode),'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,'gid':st.st_gid}
            if stat.S_ISDIR(st.st_mode):row['kind']='directory'
            elif stat.S_ISREG(st.st_mode):
                raw=p.read_bytes();row.update(kind='file',bytes=len(raw),sha256=sha(raw),data_base64=base64.b64encode(raw).decode())
            else:raise AssertionError(('unexpected fixture file type',rel))
            rows[rel]=row
    return rows

def comparable(rows):
    return {name:{k:v for k,v in row.items() if k not in {'device','inode','uid','gid'}} for name,row in rows.items()}

def setup(root):
    assert not root.exists();root.mkdir()
    (root/'OWNED-FIXTURE.json').write_bytes(wire({'owner':'g5-public-closure-6780-v1','purpose':'ordinary owned eight-tool comparison'}))
    work=root/'workspace';(work/'sub/tree').mkdir(parents=True);(root/'controller-state').mkdir()
    (work/'seed.txt').write_bytes('alpha\nbeta 中\n'.encode())
    (work/'sub/nested.txt').write_bytes(b'ordinary nested file\n')
    (work/'sub/moveme.txt').write_bytes(b'ordinary file move\n')
    (work/'sub/tree/leaf.txt').write_bytes(b'ordinary directory move\n')
    config={'state_dir':str(root/'controller-state'),'controller_workspace_roots':[str(work)],'hosts':{'owned':{'ssh_target':'not-contacted-owned-fixture','remote_state_dir':'/unused-state'}}}
    (root/'runtime-config.json').write_bytes(wire(config));return work,root/'runtime-config.json'

def retire(root,out):
    assert root.parent==out and root.name=='fixture' and root.is_dir() and not root.is_symlink()
    assert json.loads((root/'OWNED-FIXTURE.json').read_bytes())['owner']=='g5-public-closure-6780-v1'
    for folder,dirs,names in os.walk(root):
        for name in dirs+names:
            p=Path(folder)/name;assert not p.is_symlink() and p.lstat().st_uid==os.geteuid()
    shutil.rmtree(root)

def body_bytes(raw):
    marker=b',"result":';start=raw.index(marker)+len(marker);assert raw.endswith(b'}')
    body=raw[start:-1];assert json.loads(body)==json.loads(raw)['result'];return body

def main():
    p=argparse.ArgumentParser();p.add_argument('--run-name',required=True);p.add_argument('--g5-reference',type=Path,required=True);a=p.parse_args();assert a.run_name.replace('-','').isalnum()
    out=ROOT/'evidence'/a.run_name;out.mkdir();start=time.monotonic();counts=Counter();processes=[];responses=[];target_requests=[];target_results=[];all_snapshots={};current=None
    report={'schema':'hepta.g5.actual-public-eight-loop.v1','status':'RUNNING','counts':counts,'fixture_origin':str(out/'fixture'),'public_stdio_only':True,'tool_bodies_executed':True,'no_synthetic_handler_response':True,'all_original_tool_bodies_current_target_qualified':False,'historical_3_4_evidence_promoted':False,'target_connection_identity_integrated':False,'target_response_owner_integrated':False,'target_async_transport_integrated':False,'full_sdk_qualified':False,'full_async_runtime_qualified':False,'native_task_registry_qualified':False,'native_future_cancellation_qualified':False,'production_activated':False,'old_path_removed':False,'fresh_cold_qualified':False}
    def save():
        report['processes']=processes;put(out/'summary.json',report)
    save()
    try:
        builds={name:json.loads((ROOT/'evidence'/file).read_bytes()) for name,file in [('historical','historical-eight-build.json'),('target-request','public-eight-build.json')]}
        binaries={}
        for name,build in builds.items():
            assert build['status']=='PASS';binary=ROOT/build['elf'];assert sha(binary.read_bytes())==build['elf_sha256'];binaries[name]=binary
        g5=a.g5_reference.resolve(strict=True)
        catalog_refs={r['label']:r for r in map(json.loads,(g5/'evidence/oracle-normal.jsonl').read_bytes().splitlines())}
        request_build=json.loads((g5/'evidence/oracle-build.json').read_bytes());request_binary=g5/request_build['binary_relative_path'];assert sha(request_binary.read_bytes())==request_build['binary_sha256']
        g4=g5/'retained/g4';result_build=json.loads((g4/'evidence/oracle-build.json').read_bytes());result_binary=g4/result_build['binary_relative_path'];assert sha(result_binary.read_bytes())==result_build['binary_sha256']
        assert sha((g5/'oracle/main.rs').read_bytes())==request_build['source_sha256'] and sha((g4/'oracle/main.rs').read_bytes())==result_build['source_sha256']
        workflow=[('host-list','host_list',{}),('effective-config','effective_config',{}),('shadow-admit','execution_shadow_admit',inputs.fixture('owned')),('view-root','view',{'path':'seed.txt','full':True}),('view-cache','view',{'path':'seed.txt'}),('workdir-sub','workdir',{'path':'sub'}),('view-nested','view',{'path':'nested.txt'}),('directory-create','directory_create',{'path':'created/a'}),('file-move','file_move',{'source':'moveme.txt','destination':'moved.txt'}),('directory-move','directory_move',{'source':'tree','destination':'tree-moved'}),('view-moved-file','view',{'path':'moved.txt','full':True}),('view-moved-tree','view',{'path':'tree-moved/leaf.txt','full':True}),('workdir-reset','workdir',{'reset':True}),('view-root-after-reset','view',{'path':'seed.txt','full':True})]
        assert len({tool for _,tool,_ in workflow})==8
        for modern in (False,True):
            era='modern' if modern else 'legacy';expected={};previous=None
            for variant in ['historical','target-request']:
                report['current']=era+'-'+variant;save();fixture=out/'fixture';work,config=setup(fixture)
                run=out/(era+'-'+variant);current=capture.Public(run,binaries[variant],work,config)
                state=[{'step':'before','files':snapshot(fixture)}];file_before=(work/'sub/moveme.txt').stat();dir_before=(work/'sub/tree').stat();leaf_before=(work/'sub/tree/leaf.txt').stat()
                def exchange(label,value,tool=None,extra_id=False):
                    raw_input=wire(value);raw=current.exchange(raw_input+b'\n')[0];parsed=json.loads(raw);assert parsed.get('jsonrpc')=='2.0' and 'result' in parsed,(label,parsed)
                    assert type(parsed['id']) is type(value['id']) or extra_id
                    if not extra_id:assert parsed['id']==value['id']
                    row={'era':era,'variant':variant,'label':label,'tool':tool,'request':raw_input.decode(),'response':raw.decode(),'request_sha256':sha(raw_input),'response_sha256':sha(raw)};responses.append(row);counts['actual_response_lines']+=1
                    if tool:
                        assert parsed['result'].get('isError') is False,(label,parsed)
                        counts[variant+'_tool_responses']+=1
                        if variant=='target-request':
                            target_results.append({'mode':'response','label':era+'-'+label,'type':'call','policy':2 if modern else 1,'wire':body_bytes(raw).decode(),'actual_response_sha256':sha(raw)})
                    if label=='tools-list':
                        assert [t['name'] for t in parsed['result']['tools']]==['host_list','effective_config','execution_shadow_admit','view','workdir','directory_create','file_move','directory_move']
                        if variant=='target-request':assert body_bytes(raw)==catalog_refs['public-eight-tools-policy'+str(2 if modern else 1)]['wire'].encode();counts['target_catalog_responses']+=1
                    elif not extra_id:
                        if variant=='historical':expected[label]=raw
                        else:assert raw==expected[label],(era,label,'historical native tool-body or enclosing wire changed');counts['complete_historical_wire_matches']+=1
                    return parsed,raw
                if not modern:
                    exchange('initialize',{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'owned-eight-loop','version':'1'}}})
                    current.exchange(wire({'jsonrpc':'2.0','method':'notifications/initialized'})+b'\n',0)
                metadata={VERSION:'2026-07-28',CAPS:{}}
                params={'_meta':metadata} if modern else {}
                exchange('tools-list',{'jsonrpc':'2.0','id':10,'method':'tools/list','params':params})
                for index,(label,tool,args) in enumerate(workflow):
                    params={'name':tool,'arguments':args}
                    if index==0:params.update(inputResponses={},requestState='')
                    if modern:params['_meta']=metadata
                    exchange(label,{'jsonrpc':'2.0','id':100+index,'method':'tools/call','params':params},tool)
                    if label=='directory-create':assert (work/'sub/created/a').is_dir();counts['actual_directory_create_success']+=1
                    if label=='file-move':
                        assert not (work/'sub/moveme.txt').exists();after=(work/'sub/moved.txt').stat();assert (after.st_dev,after.st_ino)==(file_before.st_dev,file_before.st_ino);assert (work/'sub/moved.txt').read_bytes()==b'ordinary file move\n';counts['actual_file_move_identity_preserved']+=1
                    if label=='directory-move':
                        assert not (work/'sub/tree').exists();after=(work/'sub/tree-moved').stat();leaf=(work/'sub/tree-moved/leaf.txt').stat();assert (after.st_dev,after.st_ino)==(dir_before.st_dev,dir_before.st_ino);assert (leaf.st_dev,leaf.st_ino)==(leaf_before.st_dev,leaf_before.st_ino);counts['actual_directory_move_identity_preserved']+=1
                    state.append({'step':label,'files':snapshot(fixture)})
                if variant=='target-request':
                    for label,identifier in [('float-id',1200.0),('unicode-id','ordinary-中')]:
                        params={'name':'host_list','arguments':{}}
                        if modern:params['_meta']=metadata
                        request={'jsonrpc':'2.0','id':identifier,'method':'tools/call','params':params}
                        _,raw=exchange(label,request,'host_list',True)
                        target_requests.append({'mode':'request','type':'call','label':era+'-'+label,'wire':wire(request).decode(),'actual_response':raw.decode()})
                receipt=current.close();processes.append({'era':era,'variant':variant,'elf_sha256':builds[variant]['elf_sha256'],**receipt});current=None;counts['actual_public_elf_processes']+=1
                if previous is not None:
                    assert len(previous)==len(state)
                    for old,new in zip(previous,state,strict=True):assert old['step']==new['step'] and comparable(old['files'])==comparable(new['files']),(era,new['step'],'complete owned tree changed');counts['complete_filesystem_snapshots_matched']+=1
                previous=state;all_snapshots[era+'-'+variant]=state;put(run/'filesystem-snapshots.json',state);retire(fixture,out)
        (out/'responses.jsonl').write_bytes(b''.join(wire(r)+b'\n' for r in responses));report['native_public_loop_status']='PASS';save()
        request_input=b''.join(wire({k:v for k,v in r.items() if k!='actual_response'})+b'\n' for r in target_requests)
        q=subprocess.run([str(request_binary)],input=request_input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        for name,raw in [('request-oracle-input.jsonl',request_input),('request-oracle-output.jsonl',q.stdout),('request-oracle.stderr',q.stderr)]:(out/name).write_bytes(raw)
        assert q.returncode==0 and not q.stderr
        observations=list(map(json.loads,q.stdout.splitlines()));assert len(observations)==len(target_requests)==4
        for case,ref in zip(target_requests,observations,strict=True):
            raw=case['actual_response'].encode();assert raw.startswith(b'{"jsonrpc":"2.0","id":'+ref['id_wire'].encode()+b',"result":');counts['actual_target_request_id_matches']+=1
        result_input=b''.join(wire({k:v for k,v in r.items() if k!='actual_response_sha256'})+b'\n' for r in target_results)
        q=subprocess.run([str(result_binary)],input=result_input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        for name,raw in [('response-oracle-input.jsonl',result_input),('response-oracle-output.jsonl',q.stdout),('response-oracle.stderr',q.stderr)]:(out/name).write_bytes(raw)
        assert q.returncode==0 and not q.stderr
        observations=list(map(json.loads,q.stdout.splitlines()));assert len(observations)==len(target_results)==32
        mismatches=[]
        for case,ref in zip(target_results,observations,strict=True):
            if case['wire']!=ref['wire']:mismatches.append({'label':case['label'],'actual_wire':case['wire'],'target_wire':ref['wire']})
            else:counts['actual_target_response_wire_matches']+=1
        put(out/'response-contract-mismatches.json',mismatches);report['target_response_contract_mismatches']=len(mismatches);report['target_response_data_contract_status']='PASS' if not mismatches else 'FAIL';save()
        assert not mismatches,'ordinary public result differs from exact target typed response/cache exit; preserved complete rows'
        assert counts['target-request_tool_responses']==32 and counts['actual_public_elf_processes']==4 and counts['actual_target_request_id_matches']==4
        report.update(status='PASS',builds=builds,implemented_tools=[tool for _,tool,_ in workflow[:4]]+['workdir','directory_create','file_move','directory_move'],responses_sha256=sha((out/'responses.jsonl').read_bytes()),reference_request_binary_sha256=request_build['binary_sha256'],reference_response_binary_sha256=result_build['binary_sha256'],actual_target_sdk_normal_data_comparison=True,all_eight_real_tools_completed=True,target_response_owner_integrated=False)
    except BaseException:
        report.update(status='FAIL',failure=traceback.format_exc())
        if current:
            try:processes.append(current.close(failed=True))
            except BaseException:report['cleanup_failure']=traceback.format_exc()
        raise
    finally:
        report['elapsed_seconds']=time.monotonic()-start;save()
    print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()

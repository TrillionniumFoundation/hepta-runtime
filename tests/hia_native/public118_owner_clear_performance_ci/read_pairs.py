"""Reopen complete real buffers, native returns, source, compiler and observer evidence."""
from pathlib import Path
import gzip,hashlib,json,math,stat,struct
import cases,archive_stream,restore
from retained_pairs import pin
def need(ok,message):
    if not ok:raise ValueError(message)
def rawpin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def regular(path):
    path=Path(path);need(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode),'regular evidence');return path.read_bytes()
def decode(root,item):
    name=item['file'];need(Path(name).name==name,'captured blob path')
    path=root/name;need(pin(path)==item['stored'],'complete compressed observation')
    with gzip.open(path,'rb') as f:raw=f.read()
    need(rawpin(raw)==item['raw'],'complete uncompressed observation');return raw
def read(root,source):
    root,source=Path(root),Path(source);report=json.loads(regular(root/'PAIRS.json'));domain=json.loads(regular(root/'DOMAIN.json'))
    need(report['status']=='COMPLETE_OWNER_CLEAR_PAIRS_CAPTURED' and report['whole_public_domain_qualified'] is False,'complete owner pair status')
    need(domain==cases.domain() and len(domain['cases'])==35 and report['domain']==pin(root/'DOMAIN.json'),'exact input-only domain')
    need(report['lane_seconds']==180 and type(report['elapsed_seconds']) in (float,int) and 0<=report['elapsed_seconds']<180,'whole unchanged lane deadline')
    package=json.loads(regular(source/'PACKAGE.json'));need(pin(root/'source/PACKAGE.json')==pin(source/'PACKAGE.json'),'exact immutable reader/capture source')
    for name,row in package['files'].items():
        need(regular(root/'source'/name)==regular(source/name) and rawpin(regular(source/name))=={k:row[k] for k in ('bytes','sha256')},'full frozen source '+name)
    build=json.loads(regular(root/'BUILD.json'));need(build['compiler']=={'bytes':673413,'sha256':'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'} and build['fresh_leaf_compiles']==3 and build['retained_owner_images']==1,'exact retained B3 and fresh image count')
    archive_stream.verify_selection(root/'retained/native',restore.CONFIG['native'],choose_native)
    need(pin(root/'retained/native-proof.zip')=={k:restore.CONFIG['native-proof'][k] for k in ('bytes','sha256')},'complete retained native proof ZIP')
    restore.proof_verify(root/'retained/native-proof.zip',root/'retained/native-proof')
    for generation in ('B1','B2','B3'):need(pin(root/'build/bootstrap'/(generation+'.image.bin'))==build['compiler'],'copied and reverified actual compiler generation')
    image_rows=build['images'];need(set(image_rows)=={'before-owner','after-owner','before-helper','after-helper'},'complete fixed image set')
    for name,row in image_rows.items():
        need(pin(root/row['path'])==row['pin'],'actual immutable HIA image '+name)
        need(pin(root/row['source'])==row['source_pin'],'actual immutable HIA source '+name)
    need(image_rows['before-owner']['pin']=={'bytes':128422,'sha256':'795da0a7234853e9e1afbf8f993321a2f12aa86f16c06a6374a1913473693417'},'retained production owner image')
    need(image_rows['before-owner']['source_pin']['sha256']=='c8762a6c08a7270e473b6868798de059cbee2443ad47c1cd49962fe5d27b4775','original owner source')
    need(image_rows['after-owner']['source_pin']['sha256']=='bbffb3be87e042e38d1b947be29f1f8f9a59cdb5b919e12d9482d50c214dc373','only proposed owner source')
    for name,row in build['compiles'].items():
        receipt=json.loads(regular(root/row['receipt']));need(name in ('after-owner','before-helper','after-helper') and receipt['status']=='returned' and receipt['abi_status']==0 and receipt['source_unchanged'] is True and receipt['forbidden_compiler_modules_loaded']==[] and receipt['artifact_sha256']==build['compiler']['sha256'],'actual B3 compilation receipt')
        need(receipt['input_sha256']==image_rows[name]['source_pin']['sha256'] and receipt['produced_sha256']==image_rows[name]['pin']['sha256'] and receipt['produced_bytes']==image_rows[name]['pin']['bytes'],'actual compile source/image binding')
    need(pin(root/'observer/observer.elf')==build['observer'] and regular(root/'source/observer.S')==regular(source/'observer.S'),'fixed syscall observer custody')
    need(len(report['pairs'])==35,'complete paired case set')
    logical=0;traps=0;metrics=[];seen_processes=set()
    for index,(case,expected) in enumerate(zip(report['pairs'],domain['cases'],strict=True)):
        folder=root/'pairs'/f'{index:03d}';need(case['index']==index and case['spec']==expected['spec'],'case order and frozen input')
        seen={'before.json','after.json','CASE.json'};initial={}
        for name,item in case['initial'].items():seen.add(item['file']);initial[name]=decode(folder,item);need(rawpin(initial[name])==expected['inputs'][name],'complete frozen preimage')
        results=[]
        for row in case['sides']:
            side=row['side'];need(side in ('before','after') and json.loads(regular(folder/(side+'.json')))==row,'complete actual process receipt')
            need(row['pid'] not in seen_processes,'fresh owned native process');seen_processes.add(row['pid'])
            need(row['framing_error'] is None and row['fd_seals']==[15,15,7,7] and row['parent_owned_size_sealed_shared_observation'] is True and row['deadline_seconds']==60 and row['timed_out'] is False and row['kill_requested'] is False and row['failure'] is None and row['elapsed_seconds']<60,'actual native process admission')
            key=side+'-'+expected['spec']['kind'];need(row['image']==image_rows[key]['pin'] and row['observer']==build['observer'],'executed actual image')
            request=decode(folder,row['request']);stdout=decode(folder,row['stdout']);stderr=decode(folder,row['stderr'])
            seen.update(row[k]['file'] for k in ('request','stdout','stderr'))
            need(len(request)==72 and request[:8]==b'HCALL001','actual complete observer input');f=struct.unpack_from('<8Q',request,8)
            need(len(set(f[::2]))==4 and all(x>=3 for x in f[::2]) and f[1::2]==(row['image']['bytes'],len(initial['input']),len(initial['output']),len(initial['workspace'])),'actual observer FDs and complete capacities')
            if row['exit_code']==0:
                need(len(stdout)==48 and stdout[:8]==b'HHCPR001' and stderr==b'','complete actual returned frame')
                code,s0,n0,s1,n1=struct.unpack_from('<5Q',stdout,8);need(code==row['raw_return'] and row['native_elapsed_ns']==(s1-s0)*1000000000+n1-n0 and 0<=row['native_elapsed_ns']<60*1000000000,'actual native return and timing')
            else:need(row['exit_code'] in (-4,-6,-11) and stdout==b'' and row['raw_return'] is None,'actual trapped process and unclaimed output')
            buffers={}
            for name,item in row['buffers'].items():
                seen.add(item['file']);buffers[name]=decode(folder,item);need(len(buffers[name])==len(initial[name]),'full observed buffer extent');logical+=len(buffers[name])
            need(set(buffers)==set(initial)=={'input','output','workspace'} and buffers['input']==initial['input'],'full immutable input and shared buffers')
            results.append((row['exit_code'],row['raw_return'],buffers))
        need([r['side'] for r in case['sides']]==['before','after'] and results[0]==results[1],'full actual before/after bytes and status differ')
        trapped=results[0][0]<0 or (results[0][1] is not None and results[0][1]>>32!=0);traps+=int(trapped)
        if expected['spec']['kind']=='helper':
            if 'trap' in expected['spec']['name']:need(trapped,'actual abnormal helper trap')
            else:need(results[0][:2]==(0,0),'actual normal helper return')
        if expected['spec']['name'] in ('dispose','dispose-zero-output'):need(results[0][:2]==(0,0),'actual completed production owner disposal')
        need(json.loads(regular(folder/'CASE.json'))==case and {p.name for p in folder.iterdir()}==seen,'complete per-case artifact inventory')
        metrics.append({'name':case['spec']['name'],'before_ns':case['sides'][0]['native_elapsed_ns'],'after_ns':case['sides'][1]['native_elapsed_ns']})
    need(traps>=6 and len(seen_processes)==70,'actual abnormal-range domain and fresh process count')
    return {'status':'COMPLETE_CALLER_CLEAR_BUFFER_DIFFERENTIAL_PASS','pairs':35,'actual_native_calls_retained':70,'actual_trap_pairs':traps,'full_buffer_bytes':logical,'native_or_rust_executions':0,'whole_public_domain_qualified':False,'metrics':metrics,'source_after':image_rows['after-owner']['source_pin'],'image_after':image_rows['after-owner']['pin']}

def choose_native(name):
    return restore.native_selected(name) or name.startswith('instances/bootstrap/') or name.startswith('production/build/modules/public-task-batch-extract-authority/')

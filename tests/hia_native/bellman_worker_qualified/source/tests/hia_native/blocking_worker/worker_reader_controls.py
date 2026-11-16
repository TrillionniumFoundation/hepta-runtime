"""Physical, rehashed evidence mutations against the independent readonly readers."""
from __future__ import annotations
import argparse,gzip,json,os,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from worker_common import BASE,read,put,document,sha,require,tree_files,source_evidence
from worker_buffer_evidence import verify_buffers
from worker_build_evidence import verify_build
from worker_group_evidence import verify_group
from worker_evidence import verify_process
from worker_export_evidence import verify_export_controls
from worker_reference_evidence import complete_buffers,original_evidence

def copy_files(source,target):
    pins=tree_files(source)
    for name,pin in pins.items():
        body=read(source/name);require(len(body)==pin['bytes'] and sha(body)==pin['sha256'],'copy input changed')
        put(target/name,body);(target/name).chmod((source/name).stat().st_mode&0o777)
    require(tree_files(target)==pins,'physical copy changed');return pins

def replace_blob(folder,old,body):
    blobs=complete_buffers(folder);index=document(folder/'buffers.json');calls=document(folder/'calls.json');new=sha(body)
    require(new not in blobs,'control unexpectedly aliases another buffer');blobs[new]=body;del blobs[old]
    index[new]=index.pop(old);index[new]['bytes']=len(body)
    for row in calls:
        for key,value in row.items():
            if value==old:row[key]=new
    with gzip.GzipFile(filename=str(folder/'buffers.bin.gz'),mode='wb',compresslevel=1,mtime=0) as stream:
        for key in sorted(index,key=lambda h:index[h]['index']):stream.write(struct.pack('<Q',len(blobs[key])));stream.write(blobs[key])
    put(folder/'buffers.json',index);put(folder/'calls.json',calls)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['capture','source-root','output']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source-pins-sha256',required=True);a=p.parse_args();cap=a.capture.resolve();root=a.source_root.resolve();out=a.output.resolve()
    out.mkdir(mode=0o700);source_evidence(root,a.source_pins_sha256)
    component=document(cap/'native-build/bridge/component.json');records=[]
    def reject(name,mutation,reader,folder):
        before=tree_files(folder);mutation();changed=tree_files(folder)
        require(before!=changed,'control did not actually mutate physical bytes')
        try:reader()
        except (AssertionError,KeyError,ValueError,FileNotFoundError,EOFError) as exc:
            records.append({'name':name,'status':'REJECTED','exception':type(exc).__name__,'message':str(exc),
                            'before_files':before,'mutated_files':changed})
        else:raise AssertionError('reader accepted '+name)
    for name,field,offset in [('input','input',31),('output','after_output',39),('workspace','before_workspace',0)]:
        folder=out/name;copy_files(cap/'native/elapsed',folder)
        def mutation(folder=folder,field=field,offset=offset):
            row=document(folder/'calls.json')[0];key=row[field];body=bytearray(complete_buffers(folder)[key]);body[offset]^=1;replace_blob(folder,key,bytes(body))
        reject('rehashed-full-'+name,mutation,lambda folder=folder:verify_buffers(folder,root,cap/'native-build/build','elapsed'),folder)
    folder=out/'missing-case';copy_files(cap/'native/elapsed',folder)
    def missing_case():
        calls=document(folder/'calls.json');put(folder/'calls.json',calls[2:]);r=document(folder/'report.json');r['cases']-=1;r['native_calls']-=2;put(folder/'report.json',r)
    reject('omitted-case-and-updated-count',missing_case,lambda:verify_buffers(folder,root,cap/'native-build/build','elapsed'),folder)
    folder=out/'changed-source';copy_files(root,folder)
    reject('changed-hia-source',lambda:put(folder/'native/bellman_timed_core.hepta',read(folder/'native/bellman_timed_core.hepta')+b'\n'),lambda:source_evidence(folder,a.source_pins_sha256),folder)
    folder=out/'compiler';copy_files(cap/'native-build',folder)
    reject('empty-rehashed-compiler-stdout',lambda:put(folder/'build/modules/worker-pool/module.stdout.log',b'{}\n'),lambda:verify_build(folder,root,a.source_pins_sha256),folder)
    folder=out/'worker-pool';copy_files(cap/'native/groups/lifetime',folder)
    def worker_pool():
        raw=bytearray(read(folder/'stdout.bin'));raw[168]^=1;put(folder/'stdout.bin',bytes(raw));r=document(folder/'process.json');r['stdout']={'bytes':len(raw),'sha256':sha(raw)};put(folder/'process.json',r)
        report=verify_process(folder,component);report['group']='lifetime';put(folder/'report.json',report)
    reject('rehashed-caller-pool-observation',worker_pool,lambda:verify_group(folder,root,component,'lifetime'),folder)
    folder=out/'worker-clock';copy_files(cap/'native/groups/lifetime',folder)
    def worker_clock():
        raw=read(folder/'stderr.bin');at=raw.index(b'HBCLOCK1');raw=raw[:at]+raw[at+192:];put(folder/'stderr.bin',raw);r=document(folder/'process.json');r['stderr']={'bytes':len(raw),'sha256':sha(raw)};put(folder/'process.json',r)
    reject('rehashed-omitted-actual-clock',worker_clock,lambda:verify_process(folder,component),folder)
    folder=out/'borrow';copy_files(cap/'native/export',folder)
    def borrowed():
        capture=folder/'capture';rows=document(capture/'calls.json');row=next(r for r in rows if r['function']=='receive' and r['result']==32)
        key=row['after_output'];body=bytearray(complete_buffers(capture)[key]);body[-1]^=1;replace_blob(capture,key,bytes(body))
    reject('rehashed-borrow-output-tail',borrowed,lambda:verify_export_controls(folder,component),folder)
    folder=out/'original';copy_files(cap/'original',folder)
    def original_missing():
        path=folder/'processes/ordinary.stdout';raw=b'\n'.join(read(path).splitlines()[1:])+b'\n';put(path,raw)
        r=document(folder/'processes/ordinary.json');r['stdout']={'path':'processes/ordinary.stdout','bytes':len(raw),'sha256':sha(raw)};put(folder/'processes/ordinary.json',r)
    reject('rehashed-omitted-original-case',original_missing,lambda:original_evidence(folder,root),folder)
    result={'status':'PHYSICAL_READER_CONTROLS_PASS','refusals':len(records),'controls':records,'native_or_rust_executed':False,
            'source_pins_sha256':a.source_pins_sha256,'public_handler_qualified':False}
    require(len(records)==10,'reader control domain changed');put(out/'RESULT.json',result);print(json.dumps({'status':result['status'],'refusals':len(records)},sort_keys=True))

if __name__=='__main__':main()

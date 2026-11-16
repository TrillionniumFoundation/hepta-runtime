"""Physical rehashed mutations and a separate write-free complete refusal reader."""
from __future__ import annotations
import argparse,gzip,io,json,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from worker_common import read,put,document,encoded,sha,require,tree_files,source_evidence
from worker_buffer_evidence import verify_buffers
from worker_build_evidence import verify_build
from worker_group_evidence import verify_group
from worker_evidence import verify_process,packets,words
from worker_transport import decode_journal
from worker_export_evidence import verify_export_controls
from worker_reference_evidence import complete_buffers,original_evidence

# The ten original domains remain; two terminal omissions are additive.
CONTROL_NAMES=(
    ('input','rehashed-full-input'),('output','rehashed-full-output'),
    ('workspace','rehashed-full-workspace'),('missing-case','omitted-case-and-updated-count'),
    ('changed-source','changed-hia-source'),('compiler','empty-rehashed-compiler-stdout'),
    ('worker-pool','rehashed-caller-pool-observation'),('worker-clock','rehashed-omitted-actual-clock'),
    ('borrow','rehashed-borrow-output-tail'),('original','rehashed-omitted-original-case'),
    ('worker-last-core-clock','rehashed-omitted-cancelled-final-core-clock'),
    ('worker-last-writer-clock','rehashed-omitted-cancelled-final-writer-clock'),
)


def copy_files(source,target):
    pins=tree_files(source)
    for name,pin in pins.items():
        body=read(source/name);require(len(body)==pin['bytes'] and sha(body)==pin['sha256'],'copy input changed')
        put(target/name,body);(target/name).chmod((source/name).stat().st_mode&0o777)
    require(tree_files(target)==pins,'physical copy changed');return pins


def blob_changes(folder,old,body):
    """Produce changed bytes only; no evidence write occurs here."""
    blobs=complete_buffers(folder);index=document(folder/'buffers.json');calls=document(folder/'calls.json');new=sha(body)
    require(new not in blobs,'control unexpectedly aliases another buffer');blobs[new]=body;del blobs[old]
    index[new]=index.pop(old);index[new]['bytes']=len(body)
    for row in calls:
        for key,value in row.items():
            if value==old:row[key]=new
    output=io.BytesIO()
    with gzip.GzipFile(filename='',fileobj=output,mode='wb',compresslevel=1,mtime=0) as stream:
        for key in sorted(index,key=lambda h:index[h]['index']):
            stream.write(struct.pack('<Q',len(blobs[key])));stream.write(blobs[key])
    return {'buffers.json':encoded(index),'calls.json':encoded(calls),'buffers.bin.gz':output.getvalue()}


def clock_deletion(folder,which):
    """Select an actual cancelled successful worker with no delivered body."""
    raw=read(folder/'stderr.bin');cancelled={};completed={};clocks=[];offset=0
    for magic,body in decode_journal(raw):
        if magic==b'HBWPL001':
            request=words(body[32:96]);code,sequence=struct.unpack_from('<2Q',body,96)
            if code==128 and request[1]==6:cancelled[request[2]]=sequence
            if code==128 and request[1]==5 and request[4]==0:completed[request[2]]=sequence
        elif magic==b'HBCLOCK1':
            header=words(body[:64]);clocks.append((offset,header[2],header[4],body))
        offset+=len(body)
    delivered={words(body[:64])[4] for body in packets(read(folder/'stdout.bin')) if words(body[:64])[6]}
    jobs=sorted(job for job in cancelled if job in completed and job not in delivered and cancelled[job]<completed[job])
    require(jobs,'control needs a completed cancelled worker without TAKE')
    job=jobs[0];selected=[row for row in clocks if row[1]==job]
    if which=='first':selected=selected[:1]
    elif which=='last-core':selected=[row for row in selected if row[2]==1][-1:]
    elif which=='last-writer':selected=[row for row in selected if row[2]==2][-1:]
    else:raise AssertionError('unknown CLOCK mutation')
    require(len(selected)==1,'missing chosen actual CLOCK')
    offset,_,owner,body=selected[0];require(len(body)==192,'CLOCK complete extent')
    descriptor=words(body[64:])
    if which=='last-core':require(descriptor[4:6]==[5,0],'last core CLOCK is not final completion')
    if which=='last-writer':require(descriptor[4]==14 and descriptor[9:13]==[1,0,0,2],'last writer CLOCK is not final closing byte')
    changed=raw[:offset]+raw[offset+192:]
    receipt=document(folder/'process.json');receipt['stderr']={'bytes':len(changed),'sha256':sha(changed)}
    evidence={'job':job,'owner':owner,'offset':offset,'bytes':192,'deleted_sha256':sha(body),
              'descriptor':descriptor,'cancel_sequence':cancelled[job],'complete_sequence':completed[job],
              'delivered_body':False,'which':which}
    return {'stderr.bin':changed,'process.json':encoded(receipt)},evidence


def mutation(slug,folder):
    if slug in ('input','output','workspace'):
        field,offset={'input':('input',31),'output':('after_output',39),'workspace':('before_workspace',0)}[slug]
        row=document(folder/'calls.json')[0];key=row[field];body=bytearray(complete_buffers(folder)[key]);body[offset]^=1
        return blob_changes(folder,key,bytes(body)),None
    if slug=='missing-case':
        calls=document(folder/'calls.json');report=document(folder/'report.json');report['cases']-=1;report['native_calls']-=2
        return {'calls.json':encoded(calls[2:]),'report.json':encoded(report)},None
    if slug=='changed-source':
        name='native/bellman_timed_core.hepta';return {name:read(folder/name)+b'\n'},None
    if slug=='compiler':return {'build/modules/worker-pool/module.stdout.log':b'{}\n'},None
    if slug=='worker-pool':
        raw=bytearray(read(folder/'stdout.bin'));raw[168]^=1;raw=bytes(raw)
        receipt=document(folder/'process.json');receipt['stdout']={'bytes':len(raw),'sha256':sha(raw)}
        report=document(folder/'report.json');report['streams']['output_sha256']=sha(raw)
        return {'stdout.bin':raw,'process.json':encoded(receipt),'report.json':encoded(report)},None
    if slug.startswith('worker-'):
        which={'worker-clock':'first','worker-last-core-clock':'last-core','worker-last-writer-clock':'last-writer'}[slug]
        return clock_deletion(folder,which)
    if slug=='borrow':
        capture=folder/'capture';rows=document(capture/'calls.json');row=next(r for r in rows if r['function']=='receive' and r['result']==32)
        key=row['after_output'];body=bytearray(complete_buffers(capture)[key]);body[-1]^=1
        return {'capture/'+name:value for name,value in blob_changes(capture,key,bytes(body)).items()},None
    if slug=='original':
        name='processes/ordinary.stdout';raw=b'\n'.join(read(folder/name).splitlines()[1:])+b'\n'
        receipt=document(folder/'processes/ordinary.json');receipt['stdout']={'path':name,'bytes':len(raw),'sha256':sha(raw)}
        return {name:raw,'processes/ordinary.json':encoded(receipt)},None
    raise AssertionError('unknown mutation')


def domain(slug,cap,root,pins,component,folder):
    if slug in ('input','output','workspace','missing-case'):
        return cap/'native/elapsed',lambda:verify_buffers(folder,root,cap/'native-build/build','elapsed')
    if slug=='changed-source':return root,lambda:source_evidence(folder,pins)
    if slug=='compiler':return cap/'native-build',lambda:verify_build(folder,root,pins)
    if slug=='worker-pool':return cap/'native/groups/lifetime',lambda:verify_group(folder,root,component,'lifetime')
    if slug in ('worker-clock','worker-last-core-clock','worker-last-writer-clock'):
        return cap/'native/groups/lifetime',lambda:verify_process(folder,component)
    if slug=='borrow':return cap/'native/export',lambda:verify_export_controls(folder,component)
    if slug=='original':return cap/'original',lambda:original_evidence(folder,root)
    raise AssertionError('unknown reader domain')


def rejected(reader):
    try:reader()
    except (AssertionError,KeyError,ValueError,FileNotFoundError,EOFError) as exc:
        return {'exception':type(exc).__name__,'message':str(exc)}
    raise AssertionError('reader accepted a physical control')


def expected_changed(before,changes):
    require(changes and all(name in before for name in changes),'control change set must replace admitted files')
    result=dict(before)
    for name,body in changes.items():result[name]={'bytes':len(body),'sha256':sha(body)}
    require(result!=before,'control did not actually mutate physical bytes');return result


def create_controls(cap,root,pins,out):
    out.mkdir(mode=0o700);source_evidence(root,pins)
    component=document(cap/'native-build/bridge/component.json');records=[]
    for slug,name in CONTROL_NAMES:
        folder=out/slug;base,reader=domain(slug,cap,root,pins,component,folder)
        before=copy_files(base,folder);changes,selection=mutation(slug,base)
        expected=expected_changed(before,changes)
        for relative,body in changes.items():put(folder/relative,body)
        require(tree_files(folder)==expected,'physical mutation bytes differ')
        records.append({'name':name,'folder':slug,'status':'REJECTED',**rejected(reader),
                        'before_files':before,'mutated_files':expected,'selection':selection})
    result={'status':'PHYSICAL_READER_CONTROLS_PASS','refusals':len(records),'controls':records,'native_or_rust_executed':False,
            'capture_origin':str(cap),'source_origin':str(root),'output_origin':str(out),
            'source_pins_sha256':pins,'public_handler_qualified':False}
    put(out/'RESULT.json',result)
    return verify_controls(cap,root,pins,out)


def verify_controls(cap,root,pins,out):
    """Read all physical copies and rerun refusals without writing or execution."""
    source_evidence(root,pins);component=document(cap/'native-build/bridge/component.json');result=document(out/'RESULT.json')
    require(set(result)=={'status','refusals','controls','native_or_rust_executed','capture_origin','source_origin','output_origin',
                          'source_pins_sha256','public_handler_qualified'},'control report fields differ')
    require(result['status']=='PHYSICAL_READER_CONTROLS_PASS' and type(result['refusals']) is int and result['refusals']==len(CONTROL_NAMES),
            'physical control count or status differs')
    require(result['source_pins_sha256']==pins and result['native_or_rust_executed'] is False and result['public_handler_qualified'] is False,
            'control identity or scope differs')
    require(all(type(result[key]) is str and Path(result[key]).is_absolute() for key in ('capture_origin','source_origin','output_origin')),
            'control origin is not absolute')
    require(len(result['controls'])==len(CONTROL_NAMES),'control record count differs')
    all_files={'RESULT.json'}
    for record,(slug,name) in zip(result['controls'],CONTROL_NAMES):
        folder=out/slug;base,reader=domain(slug,cap,root,pins,component,folder)
        before=tree_files(base);changes,selection=mutation(slug,base);expected=expected_changed(before,changes)
        require(tree_files(folder)==expected,'physical control clone differs: '+slug)
        expected_record={'name':name,'folder':slug,'status':'REJECTED',**rejected(reader),
                         'before_files':before,'mutated_files':expected,'selection':selection}
        require(record==expected_record,'physical refusal record differs: '+slug)
        all_files.update(slug+'/'+relative for relative in expected)
    require(set(tree_files(out))==all_files,'physical control complete inventory differs')
    return {'status':result['status'],'refusals':len(CONTROL_NAMES),'result_sha256':sha(read(out/'RESULT.json')),
            'control_files':len(all_files),'native_or_rust_executed':False,'writes':False,
            'source_pins_sha256':pins,'public_handler_qualified':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['capture','source-root','output']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source-pins-sha256',required=True);p.add_argument('--phase',choices=['create','verify'],default='create')
    a=p.parse_args();cap=a.capture.resolve();root=a.source_root.resolve();out=a.output.resolve()
    result=(create_controls if a.phase=='create' else verify_controls)(cap,root,a.source_pins_sha256,out)
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()

"""Reject physically deleted CLOCK records from cancelled workers without TAKE."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,struct,sys,time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from caller_worker_evidence import verify_process,journal_records,packets,words

def pin(path):
    with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'bytes':path.stat().st_size,'sha256':digest}
def snapshot(root):
    result={}
    for path in sorted(root.iterdir()):
        assert path.is_file() and not path.is_symlink();info=path.stat()
        result[path.name]=[info.st_mode,info.st_dev,info.st_ino,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns,pin(path)]
    return result
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--worker',type=Path,required=True);p.add_argument('--component',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--timeout-seconds',type=int,required=True)
    a=p.parse_args();worker=a.worker.resolve(strict=True);component=json.loads(a.component.read_bytes())
    output=a.output.resolve();output.mkdir(mode=0o700);before=snapshot(worker);started=time.monotonic()
    reading=False;denied=[]
    def guard(event,args):
        if not reading:return
        forbidden={'subprocess.Popen','os.system','os.posix_spawn','os.fork','ctypes.dlopen','ctypes.dlsym','mmap.__new__',
            'os.mkdir','os.remove','os.rmdir','os.rename','os.chmod','os.chown','os.utime','os.truncate','os.link','os.symlink'}
        writing=False
        if event=='open':
            _,mode,flags=args;writing=bool(isinstance(mode,str) and any(c in mode for c in 'wax+')) or bool(isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
        if event in forbidden or writing:denied.append(event);raise PermissionError('reader performed a forbidden operation')
    sys.addaudithook(guard)
    reading=True
    try:positive=verify_process(worker,component,timeout_seconds=a.timeout_seconds)
    finally:reading=False
    taken={words(frame[:64])[4] for frame in packets((worker/'stdout.bin').read_bytes()) if words(frame[:64])[6]}
    cancelled={words(frame[:64])[3] for frame in packets((worker/'stdin.bin').read_bytes()) if words(frame[:64])[1]==3}
    complete={};clocks={};last_writer={};at=0
    for magic,frame in journal_records(worker/'stderr.bin'):
        h=words(frame[:64])
        if magic==b'HBWPL001' and h[3]==5:
            request=words(frame[32:96]);complete[request[2]]=request[4]
        if magic==b'HBCLOCK1' and h[4]==1:
            record=clocks.setdefault(h[2],{'first':(at,len(frame)),'last':(at,len(frame)),'count':0})
            record['last']=(at,len(frame));record['count']+=1
        if magic==b'HBCLOCK1' and h[4]==2:last_writer[h[2]]=(at,len(frame))
        at+=len(frame)
    eligible=[job for job,code in complete.items() if code==0 and job in cancelled and job not in taken and job in clocks]
    assert eligible;job=max(eligible,key=lambda key:clocks[key]['count']);assert clocks[job]['count']>1 and job in last_writer
    plans=[('first-core',clocks[job]['first'],'complete core CLOCK sequence'),
        ('last-core',clocks[job]['last'],'complete core CLOCK sequence'),
        ('last-writer',last_writer[job],'complete commitment CLOCK closure')]
    rows=[]
    for position,(offset,extent),expected_error in plans:
        name='cancelled-untaken-success-delete-'+position+'-clock';folder=output/name;folder.mkdir()
        for member in ('stdin.bin','stdout.bin'):shutil.copyfile(worker/member,folder/member)
        assert extent==192
        with (worker/'stderr.bin').open('rb') as source,(folder/'stderr.bin').open('xb') as target:
            remaining=offset
            while remaining:
                block=source.read(min(1<<20,remaining));assert block;target.write(block);remaining-=len(block)
            removed=source.read(extent);assert len(removed)==extent and removed[:8]==b'HBCLOCK1'
            shutil.copyfileobj(source,target,1<<20)
        receipt=json.loads((worker/'process.json').read_bytes());receipt['stderr']=pin(folder/'stderr.bin')
        (folder/'process.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
        frozen=snapshot(folder);reading=True;rejection=None;begin=time.monotonic()
        try:verify_process(folder,component,timeout_seconds=a.timeout_seconds)
        except AssertionError as error:rejection=str(error)
        finally:reading=False
        assert rejection is not None and expected_error in rejection,(name,rejection)
        assert snapshot(folder)==frozen and not denied
        rows.append({'name':name,'job':job,'actual_cancelled':True,'taken':False,'removed_offset':offset,'removed_bytes':extent,'removed_sha256':hashlib.sha256(removed).hexdigest(),
            'recomputed_process_stream_hash':True,'full_other_bytes_retained':True,'rejection':rejection,'wall_seconds':time.monotonic()-begin,
            'files':{key:value[-1] for key,value in frozen.items()}})
    assert snapshot(worker)==before and not denied
    result={'status':'UNTAKEN_COMPLETE_CLOCK_DELETION_REFUSALS_PASS','positive':positive,'controls':rows,
        'source_worker_unchanged':True,'reader_native_images_loaded':0,'reader_native_or_rust_processes':0,
        'reader_files_written':0,'complete_original_journal':pin(worker/'stderr.bin'),'wall_seconds':time.monotonic()-started,
        'reader_source':pin(ROOT/'caller_worker_evidence.py'),'public_handler_qualified':False,'whole_runtime_replaced':False}
    (output/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('controls','positive')},sort_keys=True))
if __name__=='__main__':main()

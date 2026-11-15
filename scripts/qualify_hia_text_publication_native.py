"""Run the actual static HIA publisher ELF against serialized owned fixtures.

The subprocess owns every native transition and Linux effect. This harness only
frames requests, captures full streams, creates fixtures, and checks observations.
"""
from __future__ import annotations
import argparse, hashlib, json, os, selectors, signal, struct, subprocess, sys, time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from hia_native_text_publication_fixtures import (
    INVALID,b64,unb64,digest,corpus,setup_fixture,request_bytes,version,
    save_blob,snapshot,expected_output,save_json,
)

def require(condition,message):
    if not condition:raise ValueError(message)

def file_pin(path):
    raw=Path(path).read_bytes()
    return {'bytes':len(raw),'sha256':digest(raw)}

class StreamProcess:
    def __init__(self,elf,root,flags=('--trace',)):
        self.root=Path(root);self.root.mkdir()
        self.started=time.monotonic();self.command=[str(elf),*flags]
        self.streams={name:(self.root/(name+'.bin')).open('xb') for name in ('stdin','stdout','stderr')}
        self.counts={name:0 for name in self.streams};self.hashes={name:hashlib.sha256() for name in self.streams}
        self.proc=subprocess.Popen(self.command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                   bufsize=0,cwd=self.root,start_new_session=True)
        self.selector=selectors.DefaultSelector();self.buffer=bytearray();self.stdout_eof=False
        for name in ('stdin','stdout','stderr'):os.set_blocking(getattr(self.proc,name).fileno(),False)
        for name in ('stdout','stderr'):
            self.selector.register(getattr(self.proc,name),selectors.EVENT_READ,name)
        self.exchanges=[];self.terminated=False
    def capture(self,name,raw):
        self.streams[name].write(raw);self.hashes[name].update(raw);self.counts[name]+=len(raw)
    def read_event(self,key):
        raw=os.read(key.fd,65536)
        if raw:
            self.capture(key.data,raw)
            if key.data=='stdout':self.buffer.extend(raw)
        else:
            self.selector.unregister(key.fileobj)
            if key.data=='stdout':self.stdout_eof=True
    def exchange(self,wire,kind):
        started=time.monotonic();deadline=started+60
        before=dict(self.counts);payload=struct.pack('<Q',len(wire))+wire;at=0;size=None
        self.selector.register(self.proc.stdin,selectors.EVENT_WRITE,'stdin')
        while True:
            remaining=deadline-time.monotonic()
            require(remaining>0,'unchanged 60-second native exchange deadline')
            for key,_ in self.selector.select(min(remaining,0.25)):
                if key.data=='stdin':
                    count=os.write(key.fd,payload[at:at+65536])
                    require(count>0,'zero native stdin write')
                    self.capture('stdin',payload[at:at+count]);at+=count
                    if at==len(payload):self.selector.unregister(self.proc.stdin)
                else:self.read_event(key)
            if len(self.buffer)>=8 and size is None:
                size=struct.unpack_from('<Q',self.buffer)[0]
                require(64<=size<=1024,'fixed admitted result-envelope extent')
            if size is not None and len(self.buffer)>=size+8:
                require(at==len(payload),'native response before complete request consumed')
                require(len(self.buffer)==size+8,'unsolicited extra native response')
                record=bytes(self.buffer[8:]);self.buffer.clear();break
            require(not self.stdout_eof,'native stdout EOF before complete result')
        row={'kind':kind,'started_stream_offsets':before,'ended_stream_offsets':dict(self.counts),
             'request_bytes':len(wire),'request_sha256':digest(wire),
             'record_bytes':len(record),'record_sha256':digest(record),
             'elapsed_seconds':time.monotonic()-started,'timeout_seconds':60}
        self.exchanges.append(row)
        require(record[:8]==b'HTXTER01','native result-envelope magic')
        code,generation,sequence,payload_len,live,phase,reserved=struct.unpack_from('<7Q',record,8)
        require(reserved==0 and code<1<<32 and payload_len==len(record)-64,'native envelope scalar contract')
        require(live==0,'native terminal live descriptor leak')
        return {'code':code,'generation':generation,'sequence':sequence,'phase':phase,'live_fds':live,
                'payload':record[64:],'record':record,'exchange':row}
    def finish(self,failure=None):
        if not self.proc.stdin.closed:
            try:self.selector.unregister(self.proc.stdin)
            except KeyError:pass
            self.proc.stdin.close()
        if failure is not None and self.proc.poll() is None:
            os.killpg(self.proc.pid,signal.SIGKILL);self.terminated=True
        deadline=time.monotonic()+60
        while self.selector.get_map():
            require(time.monotonic()<deadline,'native natural EOF cleanup deadline')
            for key,_ in self.selector.select(0.25):self.read_event(key)
        code=self.proc.wait(timeout=max(0.01,deadline-time.monotonic()))
        self.selector.close()
        for stream in self.streams.values():stream.close()
        result={'command':self.command,'cwd':str(self.root),'pid':self.proc.pid,'exit_code':code,
                'elapsed_seconds':time.monotonic()-self.started,'failure':failure,
                'killed_by_harness':self.terminated,'streams':{
                    name:{'bytes':self.counts[name],'sha256':self.hashes[name].hexdigest(),'file':name+'.bin'}
                    for name in self.streams},'exchanges':self.exchanges,'stdout_unframed_bytes':len(self.buffer)}
        save_json(self.root/'process.json',result)
        if failure is None:
            require(code==0 and not self.buffer,'native clean frame-boundary EOF')
        return result

def receipt_records(path):
    raw=Path(path).read_bytes();require(len(raw)%256==0,'complete fixed native effect receipts')
    records=[];last_sequence=0;last_generation=0
    for at in range(0,len(raw),256):
        frame=raw[at:at+256]
        require(frame[:8]==b'HTXTEF01','effect receipt magic')
        generation,sequence,kind,phase,raw_return,workcap,reserved=struct.unpack_from('<7Q',frame,8)
        fields=struct.unpack_from('<16Q',frame,64)
        magic,fxseq,fxgen,fxkind,*rest=fields
        args=list(rest[:6]);value,errno,aux,ready,flags,fxreserved=rest[6:]
        require(frame[64:72]==b'HTXTFX01' and (fxseq,fxgen,fxkind)==(sequence,generation,kind),'bound complete effect')
        require(sequence==last_sequence+1 and generation>=last_generation> -1 and generation>0,'effect monotonic identity')
        require(1<=kind<=19 and workcap>=4096 and reserved==aux==flags==fxreserved==0 and ready==1,'effect completion contract')
        require(errno<=4095 and (not errno or value==0),'normalized kernel completion')
        signed_return=raw_return if raw_return<1<<63 else raw_return-(1<<64)
        if errno:require(signed_return==-errno,'actual negative kernel return provenance')
        if kind in (1,2,6,13) and not errno:require(value==1 and signed_return>=0,'descriptor-return normalization')
        slots=[]
        for slot in range(4):
            fd,serial=struct.unpack_from('<qQ',frame,192+slot*16)
            slots.append({'slot':slot+1,'fd':fd,'opening_sequence':serial})
        records.append({'stream_offset':at,'generation':generation,'sequence':sequence,'kind':kind,
                        'phase':phase,'raw_linux_return':signed_return,'workspace_capacity':workcap,
                        'args':args,'value':value,'errno':errno,'slots':slots,'frame_sha256':digest(frame)})
        last_sequence=sequence;last_generation=generation
    return records

def non_directory(rows):return [r for r in rows if r['kind']!='directory']

def check_case(description,result,before,after,root,diagnostics,blobs):
    expected=description['expect'];body=result['payload'];kind=expected['kind']
    if kind=='private':
        require(result['code']==INVALID and body==b'' and result['phase']==0,'private framing rejection')
        require(before==after,'private rejection changed actual fixture')
        return None
    require(result['phase']==100 and result['code']==len(body) and body[:8]==b'HTXTR001','terminal HIA body')
    tag,error_len,size,was_new,generation,sequence,reserved=struct.unpack_from('<7Q',body,8)
    require((generation,sequence)==(result['generation'],result['sequence']) and reserved==0,'result body lifecycle identity')
    if kind=='error':
        error=expected['error'];message=diagnostics[error] if type(error) is int else error
        require(tag==1 and size==was_new==0 and error_len==len(body)-64 and body[64:]==message.encode(),'complete original diagnostic text')
        require(before==after,'rejected ordinary operation changed filesystem state')
        return None
    require(tag==0 and error_len==0 and len(body)==160 and body[152:]==b'\0'*8,'success body layout')
    target=expected['target_base64'];actual=[r for r in after if r['path_base64']==target]
    require(len(actual)==1 and actual[0]['kind']=='file','actual published ordinary file')
    actual=actual[0];want=expected_output(description);body_pin=actual.get('data')
    require(body_pin is not None,'published file fully readable')
    require((Path(blobs)/body_pin['file']).read_bytes()==want,'complete published bytes')
    require(size==len(want) and body[120:152]==hashlib.sha256(want).digest(),'native publication count and digest')
    require(list(struct.unpack_from('<7Q',body,64))==actual['identity'],'returned seven-field version equals actual file stat')
    require(actual['identity']==version(os.lstat(os.fsencode(root)+b'/'+unb64(target))),'post-capture stat is stable')
    require(was_new==(description['request']['mode']==1),'publication create indicator')
    old=[r for r in before if r['path_base64']==target]
    wanted_mode=0o600 if was_new else old[0]['mode']
    require(actual['mode']==wanted_mode and actual['nlink']==1 and actual.get('xattrs')=={},'preserved plain-file metadata')
    if old:require(old[0]['identity'][:2]!=actual['identity'][:2],'replace/append publishes a distinct inode')
    require([r for r in non_directory(before) if r['path_base64']!=target]==
            [r for r in non_directory(after) if r['path_base64']!=target],'unrelated fixture nodes unchanged')
    require(all(not unb64(r['path_base64']).split(b'/')[-1].startswith(b'.hepta-text-') for r in after),'no staging pathname remains')
    return {'bytes':len(want),'sha256':digest(want),'mode':wanted_mode,'version':actual['identity']}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--elf',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path);parser.add_argument('--diagnostics',required=True,type=Path)
    parser.add_argument('--domain',required=True,choices=('ordinary','wide','metadata','paths','admission'))
    args=parser.parse_args();args.elf=args.elf.resolve();args.output=args.output.resolve()
    require(os.geteuid()!=0,'fixtures require original ordinary account rights')
    args.output.mkdir(parents=True,exist_ok=False);blobs=args.output/'blobs';blobs.mkdir()
    fixtures=args.output/'fixtures';fixtures.mkdir();cases_root=args.output/'cases';cases_root.mkdir()
    descriptions=[row for row in corpus() if row['domain']==args.domain]
    source_pins={str(Path(__file__).name):file_pin(__file__),
                 'hia_native_text_publication_fixtures.py':file_pin(Path(__file__).with_name('hia_native_text_publication_fixtures.py'))}
    diagnostics=json.loads(args.diagnostics.read_bytes());manifest_pin=save_json(args.output/'corpus.json',descriptions)
    elf_pin=file_pin(args.elf);started=time.monotonic();rows=[];failure=None;process=None
    generation=0;sequence=0
    try:
        process=StreamProcess(args.elf,args.output/'process')
        for ordinal,description in enumerate(descriptions):
            name=description['name'];case_root=cases_root/name;case_root.mkdir()
            fixture=fixtures/str(ordinal);setup_fixture(fixture,description['setup'])
            wire,request=request_bytes(fixture,description);(case_root/'input.bin').write_bytes(wire)
            before=snapshot(fixture,blobs);save_json(case_root/'before.json',before)
            result=process.exchange(wire,name);(case_root/'record.bin').write_bytes(result['record'])
            after=snapshot(fixture,blobs);save_json(case_root/'after.json',after)
            observation=check_case(description,result,before,after,fixture,diagnostics,blobs)
            private=description['expect']['kind']=='private'
            require(result['generation']==generation+(0 if private else 1),'retained engine generation progression')
            require(result['sequence']>=sequence,'retained engine sequence progression')
            before_sequence=sequence;generation=result['generation'];sequence=result['sequence']
            if private:require(sequence==before_sequence,'private rejected request performed effects')
            else:
                drop=b'HTXTQ001'+struct.pack('<7Q',2,0,0,0,0,generation,0)
                dropped=process.exchange(drop,name+'/drop');(case_root/'drop-record.bin').write_bytes(dropped['record'])
                require(dropped['code']==64 and dropped['phase']==0 and dropped['generation']==generation and dropped['sequence']==sequence,'explicit terminal DROP lifecycle')
                require(dropped['payload']==b'HTXTR001'+struct.pack('<7Q',2,0,0,0,generation,sequence,0),'complete DROP body')
            row={'name':name,'ordinal':ordinal,'kind':description['expect']['kind'],'original_eligible':description['original_eligible'],
                 'request':request,'fixture':str(fixture),'generation':generation,'first_sequence':before_sequence+1,
                 'last_sequence':sequence,'effects':sequence-before_sequence,'code':result['code'],'observation':observation,
                 'record':file_pin(case_root/'record.bin'),'input':file_pin(case_root/'input.bin'),'status':'PASS'}
            save_json(case_root/'case.json',row);rows.append(row)
            print(json.dumps({'case':name,'status':'PASS','code':result['code'],'effects':row['effects']},sort_keys=True),flush=True)
        process_result=process.finish();process=None
        receipts=receipt_records(args.output/'process'/'stderr.bin')
        require(len(receipts)==sequence,'all effects represented by complete receipts')
        for row in rows:
            selected=[r for r in receipts if row['first_sequence']<=r['sequence']<=row['last_sequence']]
            require(len(selected)==row['effects'] and all(r['generation']==row['generation'] for r in selected),'case-specific effect provenance')
            published=[r for r in selected if r['kind']==17 and r['errno']==0]
            require(len(published)==(1 if row['kind']=='success' else 0),'actual rename agrees with publication outcome')
        receipts_pin=save_json(args.output/'effects.json',receipts)
        require(file_pin(args.elf)==elf_pin,'native ELF unchanged')
        require({name:file_pin(Path(__file__).with_name(name)) for name in source_pins}==source_pins,'qualification sources unchanged')
        result={'schema':'hepta.runtime.text-publication-native-domain.v1','status':'PASS','domain':args.domain,
                'cases':len(rows),'original_eligible_cases':sum(r['original_eligible'] for r in rows),'native_effects':len(receipts),
                'native_elf':{'path':str(args.elf),**elf_pin},'source_pins':source_pins,'corpus':manifest_pin,'effects':receipts_pin,
                'process':process_result,'rows':rows,'elapsed_seconds':time.monotonic()-started,
                'original_comparison_complete':False,'private_descriptor_controls_complete':False,
                'race_and_fault_qualification_complete':False,'public_handler_complete':False,'whole_runtime_replaced':False}
        save_json(args.output/'RESULT.json',result)
        print(json.dumps({k:v for k,v in result.items() if k not in ('rows','process','source_pins')},sort_keys=True),flush=True)
    except BaseException as error:
        failure=repr(error)
        if process is not None:
            try:process.finish(failure)
            except BaseException as cleanup_error:failure+='; cleanup: '+repr(cleanup_error)
        save_json(args.output/'FAILURE.json',{'failure':failure,'completed_cases':rows,'elapsed_seconds':time.monotonic()-started})
        raise

if __name__=='__main__':main()

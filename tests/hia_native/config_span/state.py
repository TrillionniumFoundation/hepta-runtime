"""Actual growing HIA entries; explicitly synthetic child/effect completions.

No OS operation is issued by this test. Every complete input and both mutable
buffers before and after every entry are retained, including failing attempts.
"""
from pathlib import Path
import argparse, ctypes, gzip, hashlib, importlib.util, json, os, struct, sys, time, traceback
PACK=lambda *values:struct.pack('<'+'Q'*len(values),*values)
WORD=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
GROW=0xffffffd0;CALL=0xffffffe0;EFFECT=0xfffffff0;INVALID=0xffffffff;CAPACITY=0xfffffffe
def require(ok,label):
    if not ok:raise AssertionError(label)
def pin(path):
    with path.open('rb')as stream:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(stream,'sha256').hexdigest()}
def write(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def setword(borrow,at,value):borrow.put(at,PACK(value))
def word(borrow,at):return WORD(borrow.bytes(at,8),0)
class Recorder:
    def __init__(self,path,modules):
        self.raw=gzip.open(path/'buffers.bin.gz','wb',compresslevel=1);self.log=(path/'calls.jsonl').open('x');self.offset=0;self.count=0;self.modules=modules;self.controls=[]
    def call(self,name,label,wire,out,work,expected=None,unchanged=False):
        self.count+=1;ob=out.bytes();wb=work.bytes();source=ctypes.create_string_buffer(wire,max(1,len(wire)));ctypes.memset(out.ptr+out.cap,0xa5,16);ctypes.memset(work.ptr+work.cap,0x5a,16)
        code=self.modules[name]._entry(source,len(wire),out.ptr,out.cap,work.ptr,work.cap);oa=out.bytes();wa=work.bytes()
        parts=[label.encode(),wire,ob,wb,oa,wa];record=b'HRCST002'+PACK(self.count,code,*map(len,parts))+b''.join(parts);self.raw.write(record)
        row={'sequence':self.count,'owner':name,'label':label,'offset':self.offset,'bytes':len(record),'sha256':SHA(record),'code':code,'expected_code':expected,'both_buffers_unchanged_required':unchanged,'parts':[{'bytes':len(value),'sha256':SHA(value)}for value in parts]};self.offset+=len(record);self.log.write(json.dumps(row,sort_keys=True)+'\n');self.log.flush()
        require(source.raw==(wire or b'\0')and ctypes.string_at(out.ptr+out.cap,16)==b'\xa5'*16 and ctypes.string_at(work.ptr+work.cap,16)==b'\x5a'*16,'actual source and guard preservation')
        if expected is not None:require(code==expected,(label,hex(code),hex(expected)))
        if unchanged:require(ob==oa and wb==wa,(label,'full refusal buffers changed'))
        self.controls.append(row);return code,oa,wa
    def close(self):self.raw.close();self.log.close()
def grow(raw,kind,required=None):
    require(raw[:8]==b'HGRWS002'and WORD(raw,8)==kind and WORD(raw,24)==0,'complete native growth record')
    if required is not None:require(WORD(raw,16)==required,'exact native required extent')
    return WORD(raw,16)
def exact_resize(Borrow,old,size):
    fresh=Borrow(size);ctypes.memmove(fresh.ptr,old.ptr,old.cap);old.close();return fresh
def main():
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--build-sha256',required=True);p.add_argument('--support',type=Path,required=True);p.add_argument('--loader-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir();write(a.output/'remote-process.json',{'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text()});start=time.monotonic()
    require(pin(a.build/'result.json')['sha256']==a.build_sha256,'actual graph build');built=json.loads((a.build/'result.json').read_bytes());byname={r['name']:r for r in built['members']}
    sys.path.insert(0,str(a.loader_source/'scripts'));from hia_native_loader import NativeModule
    support=load(a.support,'_config_growing_support');Borrow=support.Borrow;modules={};sources={str(Path(__file__)):pin(Path(__file__)),str(a.support):pin(a.support),str(a.build/'result.json'):pin(a.build/'result.json')}
    for name in ('owner','fs','json','validation'):
        row=byname['config-'+name];path=Path(row['manifest']);require(pin(path)['sha256']==row['manifest_sha256'],'actual manifest');modules[name]=NativeModule(path,manifest_sha256=row['manifest_sha256']);sources[str(path)]=pin(path);sources[str(Path(row['source']))]=pin(Path(row['source']))
    write(a.output/'SOURCE.json',sources);r=Recorder(a.output,modules);groups=[];borrows=[]
    def new(size):
        value=Borrow(size);borrows.append(value);return value
    def replace(old,size):
        fresh=exact_resize(Borrow,old,size);borrows.remove(old);borrows.append(fresh);return fresh
    def done(name,before):groups.append({'name':name,'native_calls':r.count-before})
    try:
        first=r.count
        for owner,capacity in [('json',65536),('validation',262144),('fs',32<<20),('owner',16<<20)]:
            w=new(capacity);o=new(8256 if owner=='fs'else 64);ctypes.memset(w.ptr,0x5a,w.cap);ctypes.memset(o.ptr,0xa5,o.cap)
            for wire in (b'',b'x',b'WRONG000'+bytes(144)):
                r.call(owner,'malformed-'+owner+'-'+str(len(wire)),wire,o,w,INVALID,True)
            small=new(31 if owner in ('json','owner')else 0)
            if owner=='validation':
                wire=b'HRCFGV01'+PACK(1,128)+bytes(128);tiny=new(0)
            else:wire=b'';tiny=w
            r.call(owner,'short-output-'+owner,wire,small,tiny,CAPACITY,True)
        done('framing-and-complete-refusal-buffers',first)
        first=r.count
        jsonw=new(65536);jsono=new(32);data=b'{"state_dir":"/s","hosts":{"h":{"ssh_target":"h","remote_state_dir":"/r","privileged_actions":{"a":{"executable":"/x","allow_extra_args":true,"extra_arg_patterns":["a"]}}}}}'
        wire=b'HRCFGJ01'+PACK(2,100,2,len(data))+b'/s'+data
        code,raw,_=r.call('json','json-first-output-growth',wire,jsono,jsonw,GROW);needed=grow(raw,2);require(word(jsonw,192)==1,'cached complete JSON result')
        changed=bytearray(wire);struct.pack_into('<Q',changed,8,1)
        r.call('json','json-cached-operation-mismatch',bytes(changed),jsono,jsonw,INVALID,True)
        before=jsonw.bytes();r.call('json','json-repeat-short-output',wire,jsono,jsonw,GROW);require(jsonw.bytes()==before,'cached JSON output retry did not reparse')
        jsono=replace(jsono,needed);code,raw,_=r.call('json','json-complete-cached-arena',wire,jsono,jsonw,needed);arena=raw[:code];require(arena[:8]==b'HRCFGA01'and word(jsonw,192)==0,'actual completed arena')
        done('completed-json-output-growth',first)
        first=r.count
        vw=new(262144);vo=new(32);validation=b'HRCFGV01'+PACK(1,len(arena))+arena
        r.call('validation','validation-actual-child-request',validation,vo,vw,CALL)
        footer=vw.cap-256;seq=word(vw,footer+8);vw.put(122880,b'HRGREX01'+PACK(0,1,0));vw.put(footer+80,PACK(32,seq,1,0));completed=vw.bytes()
        for index in range(15):
            vw.put(0,completed);setword(vw,footer+8*index,word(vw,footer+8*index)^1)
            r.call('validation','validation-corrupt-ack-'+str(index),validation,vo,vw,INVALID,True)
        vw.put(0,completed);vw.put(122880,b'HRGREX01'+PACK(1,0,0))
        code,raw,_=r.call('validation','validation-error-output-growth',validation,vo,vw,GROW);needed=grow(raw,2);require(word(vw,81928)==2,'completed regex is cached before output growth');saved=vw.bytes()
        r.call('validation','validation-repeat-output-growth',validation,vo,vw,GROW);require(vw.bytes()==saved,'completed regex does not run twice')
        vo=replace(vo,needed);code,raw,_=r.call('validation','validation-cached-error-complete',validation,vo,vw,needed)
        require(raw[32:]==b'host `h` privileged action `a` has invalid argument regex'and word(vw,81936)==seq and word(vw,81928)==0,'complete cached synthetic-error result')
        done('validation-completion-and-corrupt-ack',first)
        first=r.count
        ow=new(16<<20);oo=new(32);footer=ow.cap-256;setword(ow,footer+120,4);r.call('owner','owner-real-absent-init',b'',oo,ow,0)
        setword(ow,footer+120,1);query=b'HRCFGQ01'+PACK(7,0);code,raw,_=r.call('owner','owner-absent-output-growth',query,oo,ow,GROW);needed=grow(raw,2);cached=ow.bytes();r.call('owner','owner-repeat-short-cached-output',query,oo,ow,GROW);require(ow.bytes()==cached,'owner cached reply unchanged')
        oo=replace(oo,needed);code,raw,_=r.call('owner','owner-cached-reply-complete',query,oo,ow,needed);require(raw[32:]==b'runtime tools are disabled; start with --runtime-config <file>','original absent error')
        r.call('owner','owner-repeat-installed-read',query,oo,ow,needed);done('owner-completed-reply-growth',first)
        first=r.count
        ow2=new(8388864);oo2=new(32);path=b'/synthetic-config';startup=b'HRCFGC01'+PACK(0,len(path),0,0,0,0,0)+path
        r.call('owner','owner-real-configure-first-child',startup,oo2,ow2,CALL);footer=ow2.cap-256;require(word(ow2,footer+16)==1 and word(ow2,8)==10,'first actual HIA child is filesystem read')
        payload=b' '*((2<<20)+3);child=b'HRCFSR01'+PACK(0,0,0,0,len(payload),0,0)+payload;seq=word(ow2,footer+8);ow2.put(footer+80,PACK(len(child),seq,1,0,1,0,len(child)))
        code,raw,_=r.call('owner','owner-completed-read-needs-growth',child,oo2,ow2,GROW);required=grow(raw,1);saved=ow2.bytes();r.call('owner','owner-repeat-unmapped-growth',child,oo2,ow2,GROW);require(ow2.bytes()==saved,'short mapping retry keeps completed child')
        ow2=replace(ow2,required);r.call('owner','owner-resume-completed-read-once',child,oo2,ow2,CALL);footer=ow2.cap-256
        require(word(ow2,footer+16)==2 and word(ow2,footer+8)==seq+1 and word(ow2,footer+112)==0,'no repeated filesystem child after growth');at=word(ow2,footer+32);size=word(ow2,footer+40);parsed=ow2.bytes(at,size);default_len=WORD(parsed,24)
        require(parsed[:8]==b'HRCFGJ01'and parsed[40+default_len:]==payload,'complete delivered bytes survived region relocation');done('owner-retained-child-delivery-and-region-relocation',first)
        first=r.count
        fw=new(32<<20);fo=new(8256);request=b'HRCFSQ01'+PACK(3,2)+b'/x'
        r.call('fs','fs-actual-open-request',request,fo,fw,EFFECT);require(word(fw,528)==12,'actual open effect');seq=word(fw,16);fw.put(576,PACK(seq,0,17,0))
        code,raw,_=r.call('fs','fs-completed-open-work-growth',request,fo,fw,GROW);required=grow(raw,1);require(word(fw,152)==0 and word(fw,16)==seq,'open completion not consumed early');saved=fw.bytes();r.call('fs','fs-repeat-unmapped-open-growth',request,fo,fw,GROW);require(fw.bytes()==saved,'no duplicate ownership mutation')
        fw=replace(fw,required);r.call('fs','fs-resume-open-once',request,fo,fw,EFFECT);require(word(fw,16)==seq+1 and word(fw,152)==17 and word(fw,528)==13,'one read after completed open')
        seq=word(fw,16);payload=b'Z'*65536;fw.put(word(fw,552),payload);fw.put(576,PACK(seq,0,len(payload),0))
        code,raw,_=r.call('fs','fs-completed-read-next-window-growth',request,fo,fw,GROW);required=grow(raw,1);require(word(fw,160)==0 and word(fw,16)==seq,'read ACK not consumed before allocation');saved=fw.bytes();r.call('fs','fs-repeat-unmapped-read-growth',request,fo,fw,GROW);require(fw.bytes()==saved,'completed read remains pending')
        fw=replace(fw,required);r.call('fs','fs-resume-read-once',request,fo,fw,EFFECT);require(word(fw,160)==65536 and word(fw,16)==seq+1,'exactly one completed read counted')
        seq=word(fw,16);fw.put(576,PACK(seq,0,0,0));r.call('fs','fs-eof-close-request',request,fo,fw,EFFECT);require(word(fw,528)==11 and word(fw,536)==17,'exactly one close requested');seq=word(fw,16);fw.put(576,PACK(seq,0,0,0))
        code,raw,_=r.call('fs','fs-closed-read-output-growth',request,fo,fw,GROW);required=grow(raw,2);require(word(fw,152)==0,'no remaining fd ownership after completed close');saved=fw.bytes();r.call('fs','fs-repeat-closed-output-growth',request,fo,fw,GROW);require(fw.bytes()==saved,'completed close not issued again')
        fo=replace(fo,required);code,raw,_=r.call('fs','fs-complete-read-after-growth',request,fo,fw,64+len(payload));require(raw[64:]==payload and word(fw,16)==seq and word(fw,8)==0,'complete actual native read result and cleanup');done('fs-completion-growth-close-lifetime',first)
        first=r.count
        maximum=(1<<64)-1;setword(fw,8,60);setword(fw,16,maximum);fw.put(512,PACK(3544404732657488456,maximum,12,0,0,8454144,2,0,maximum,0,17,0));setword(fw,152,0)
        saved=fw.bytes();code,raw,_=r.call('fs','fs-next-effect-sequence-overflow',request,fo,fw,GROW);grow(raw,3,0);require(fw.bytes()==saved,'unrepresentable next effect preserves complete pending ACK and handle custody')
        done('fs-sequence-resource-preflight',first)
        r.close();write(a.output/'groups.json',groups);require({path:pin(Path(path))for path in sources}==sources,'all actual source pins unchanged')
        result={'status':'PASS','groups':len(groups),'actual_native_calls':r.count,'complete_mutable_buffers':True,'synthetic_private_completions':True,'actual_filesystem_effects':0,'original_semantic_cases_added':0,'elapsed_seconds':time.monotonic()-start,'artifacts':{path.name:pin(path)for path in a.output.iterdir()if path.is_file()}};write(a.output/'RESULT.json',result);print(json.dumps({k:v for k,v in result.items()if k!='artifacts'},sort_keys=True),flush=True)
    except BaseException:
        r.close();write(a.output/'FAILURE.json',{'traceback':traceback.format_exc(),'completed_groups':groups,'native_calls':r.count,'elapsed_seconds':time.monotonic()-start});raise
    finally:
        for item in borrows:item.close()
        for item in modules.values():item.close()
if __name__=='__main__':main()

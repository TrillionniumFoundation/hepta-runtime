"""Growing configuration HIA against both complete retained Rust corpora.

This is a test-only borrowed-span call bridge. Every JSON, policy, identity
and regex result is produced by the actual admitted HIA machine code. It
performs no filesystem effects and is not a production service transport.
"""
from pathlib import Path
import argparse, collections, ctypes, gzip, hashlib, importlib.util, json, mmap, os, struct, sys, time, traceback
SHA=lambda value:hashlib.sha256(value).hexdigest()
PACK=lambda *values:struct.pack('<'+'Q'*len(values),*values)
WORD=lambda value,at:struct.unpack_from('<Q',value,at)[0]
CALL=0xffffffe0;GROW=0xffffffd0
def pin(path):
    with path.open('rb')as stream:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(stream,'sha256').hexdigest()}
def write(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def require(ok,message):
    if not ok:raise AssertionError(message)
def import_file(path,name):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
class Borrow:
    def __init__(self,size=0):
        self.cap=size;self.mapping=mmap.mmap(-1,max(1,size)+16);self.anchor=ctypes.c_char.from_buffer(self.mapping);self.ptr=ctypes.addressof(self.anchor)
    def bytes(self,at=0,n=None):return ctypes.string_at(self.ptr+at,self.cap-at if n is None else n)
    def put(self,at,raw):
        require(0<=at<=self.cap and len(raw)<=self.cap-at,'borrowed write extent');ctypes.memmove(self.ptr+at,raw,len(raw))
    def close(self):del self.anchor;self.mapping.close()
    def resize(self,needed):
        old=self.cap;current=max(4096,old)
        while current<needed:current*=2
        require(old<needed<=current<1<<63,'actual monotonic growth')
        fresh=Borrow(current)
        if old:ctypes.memmove(fresh.ptr,self.ptr,old)
        self.close();self.cap=fresh.cap;self.mapping=fresh.mapping;self.anchor=fresh.anchor;self.ptr=fresh.ptr
        return old,current
class Graph:
    NAMES={2:'config-json',3:'config-validation',4:'config-identity',10:'config-regex_syntax',11:'config-regex_unicode_data',12:'config-regex_hir',13:'config-regex_nfa',14:'config-regex_match',15:'config-regex_controller'}
    EDGES={3:{15},15:{10,12,13,14},10:{11},12:{11},14:{11}}
    def __init__(self,built,loader,folder):
        byname={row['name']:row for row in built['members']};self.modules={};self.work={};self.sequences=collections.Counter();self.counts=collections.Counter();self.case=0;self.events=[]
        self.raw=gzip.open(folder/'calls.bin.gz','wb',compresslevel=1);self.log=(folder/'calls.jsonl').open('x');self.offset=0
        for slot,name in self.NAMES.items():
            row=byname[name];path=Path(row['manifest']);require(pin(path)['sha256']==row['manifest_sha256'],'actual module manifest')
            module=loader.NativeModule(path,manifest_sha256=row['manifest_sha256']);require(module.metadata['image_sha256']==row['image_sha256'] and module.metadata['source_sha256']==row['source_sha256'],'actual HIA image')
            self.modules[slot]=module;size=0 if slot in (2,3) else 65536 if slot==11 else 32<<20 if slot in (4,14) else 256<<20;self.work[slot]=Borrow(size)
    def record(self,slot,depth,wire,code,output,footer,workcap,outcap):
        seq=self.counts['actual_native_calls']+1;self.counts['actual_native_calls']=seq;self.counts['slot_'+str(slot)]+=1
        header=b'HRCALL02'+PACK(seq,self.case,slot,depth,code,workcap,outcap,len(wire),len(output),len(footer));record=header+wire+output+footer;self.raw.write(record)
        row={'sequence':seq,'case_id':self.case,'slot':slot,'depth':depth,'code':code,'workspace_capacity':workcap,'output_capacity':outcap,'offset':self.offset,'bytes':len(record),'sha256':SHA(record),'input_bytes':len(wire),'input_sha256':SHA(wire),'output_bytes':len(output),'output_sha256':SHA(output),'footer_bytes':len(footer),'footer_sha256':SHA(footer)}
        self.log.write(json.dumps(row,sort_keys=True)+'\n');self.offset+=len(record)
    def call(self,slot,wire,outptr,outcap,depth=0):
        require(depth<=3,'actual fixed native call graph depth');w=self.work[slot];module=self.modules[slot];incoming=ctypes.create_string_buffer(wire,max(1,len(wire)))
        while True:
            ctypes.memset(w.ptr+w.cap,0x5a,16);code=module._entry(incoming,len(wire),outptr,outcap,w.ptr,w.cap)
            require(incoming.raw==(wire or b'\0') and ctypes.string_at(w.ptr+w.cap,16)==b'\x5a'*16,'native readonly/workspace guards')
            require(code>=0xffff0000 or code<=outcap,'native output extent');extent=code if code<0xffff0000 else 32 if code==GROW and outcap>=32 else 0
            output=ctypes.string_at(outptr,extent);footer=w.bytes(w.cap-256,120) if code==CALL else b'';self.record(slot,depth,wire,code,output,footer,w.cap,outcap)
            if code==GROW:
                require(slot in (2,3) and output[:8]==b'HGRWS002' and WORD(output,24)==0,'actual owner growth ABI')
                kind,needed=struct.unpack_from('<2Q',output,8);require(kind in (1,2),'semantic corpus has no resource exhaustion')
                if kind==2:return code,output
                old,new=w.resize(needed);self.counts['workspace_growth']+=1;self.events.append({'kind':'grow','slot':slot,'old':old,'required':needed,'new':new,'sequence':self.counts['actual_native_calls']});continue
            if code!=CALL:return code,output
            action=struct.unpack('<15Q',footer);require(footer[:8]==b'HIACAL01' and action[2] in self.EDGES.get(slot,set()),'source-owned native edge')
            require(action[1]==self.sequences[slot]+1 and action[3]==action[6]==2 and not any(action[9:]),'fresh child sequence and empty ACK')
            sequence=action[1];self.sequences[slot]=sequence;child=action[2];input_at,input_len,output_at,output_len=action[4],action[5],action[7],action[8];limit=w.cap-256
            require(input_at<=limit and input_len<=limit-input_at and output_at<=limit and output_len<=limit-output_at,'actual child spans')
            require(not input_len or not output_len or input_at+input_len<=output_at or output_at+output_len<=input_at,'no overlapping child input/output')
            child_input=w.bytes(input_at,input_len);child_code,child_output=self.call(child,child_input,w.ptr+output_at,output_len,depth+1)
            require(child_code!=GROW,'unchanged regex child carrier');self.counts['actual_child_executions']+=1
            w.put(w.cap-256+80,PACK(child_code,sequence,1,0));self.events.append({'kind':'completion','parent':slot,'child':child,'sequence':sequence,'code':child_code,'child_output_sha256':SHA(child_output),'after_call':self.counts['actual_native_calls']})
    def invoke(self,slot,wire,output=None):
        own=output is None;o=Borrow(32) if own else output
        try:
            while True:
                ctypes.memset(o.ptr+o.cap,0xa5,16);code,body=self.call(slot,wire,o.ptr,o.cap);require(ctypes.string_at(o.ptr+o.cap,16)==b'\xa5'*16,'native output guard')
                if code!=GROW:return code,body
                require(WORD(body,8)==2,'remaining native output growth');needed=WORD(body,16);old,new=o.resize(needed);self.counts['output_growth']+=1;self.events.append({'kind':'output-grow','slot':slot,'old':old,'required':needed,'new':new,'sequence':self.counts['actual_native_calls']})
        finally:
            if own:o.close()
    def close(self):
        self.raw.close();self.log.close()
        for item in self.work.values():item.close()
        for item in self.modules.values():item.close()
def main():
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--build-sha256',required=True);p.add_argument('--reference-source',type=Path,required=True);p.add_argument('--loader-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir();write(a.output/'remote-process.json',{'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text()});start=time.monotonic();g=None
    require(pin(a.build/'result.json')['sha256']==a.build_sha256,'actual built graph identity');built=json.loads((a.build/'result.json').read_bytes())
    paths=[Path(__file__),a.build/'result.json',a.loader_source/'scripts/hia_native_loader.py',*[a.reference_source/'tests/hia_native'/name for name in ('config_typed_cases.py','config_semantics_cases.py','config_runtime_original_output.txt.gz')],a.reference_source/'scripts/config_schema.py'];before={str(path):pin(path)for path in paths};write(a.output/'SOURCE.json',before)
    sys.path[:0]=[str(a.loader_source/'scripts'),str(a.reference_source/'scripts'),str(a.reference_source/'tests/hia_native')]
    import hia_native_loader as loader
    typed=import_file(a.reference_source/'tests/hia_native/config_typed_cases.py','_growing_typed');semantics=import_file(a.reference_source/'tests/hia_native/config_semantics_cases.py','_growing_semantics')
    try:
        g=Graph(built,loader,a.output);typed_rows=typed.cases();requests=b''.join(wire.hex().encode()+b'\n'for _,wire in typed_rows)
        require(len(typed_rows)==6491 and SHA(requests)=='87a619c1f79f22d4e8f5074856d0e49ed4fd475bf2809deb91e79d492f65b7c1','all original typed input bytes');(a.output/'typed-requests.hex').write_bytes(requests);results=[]
        for index,(_,wire)in enumerate(typed_rows):
            g.case=index;code,body=g.invoke(2,wire);results.append(f'{code:08x}:'.encode()+body.hex().encode()+b'\n')
        observed=b''.join(results);(a.output/'typed-output.txt').write_bytes(observed);require(SHA(observed)=='7d72f4df20f45a0b2317782dec628048360a79b724d008231d5f6a46439fb9f7','complete original typed output bytes')
        rows=semantics.cases();requests=b''.join(wire.hex().encode()+b'\n'for _,wire in rows)
        require(len(rows)==2063 and SHA(requests)=='b817774c48233e843a9b7b5f3f1577a0306846946694ca9f6be1c4e0517ddee2','all original semantic input bytes');(a.output/'semantic-requests.hex').write_bytes(requests)
        reference=gzip.decompress((a.reference_source/'tests/hia_native/config_runtime_original_output.txt.gz').read_bytes());require(SHA(reference)=='f749e18917afe6cc798749dd09418bd0682bec2dde92863c4548b26a4f583cbc','unchanged complete original semantic capture');results=[];typed_refusal_observations=[]
        for index,((category,wire),expected)in enumerate(zip(rows,reference.split(b'\n')[:-1],strict=True)):
            g.case=10000+index;op=WORD(wire,8);parse=bytearray(wire);struct.pack_into('<Q',parse,8,2);code,arena=g.invoke(2,bytes(parse))
            if code==0xffffffff:
                require(expected.startswith(b'ffffffff:'),'same original typed refusal code')
                typed_refusal_observations.append({'case_id':g.case,'category':category,'full_original':expected.decode('ascii'),'native_diagnostic_text_owned':False})
                actual=b'ffffffff:';expected=b'ffffffff:'
            else:
                require(code<0xffff0000,'original valid arena produced');request=(b'HRCFGI01'if op==4 else b'HRCFGV01')+PACK(1 if op==4 else op,len(arena))+arena
                code,body=g.invoke(4 if op==4 else 3,request);require(code<0xffff0000,('actual semantic code',index,category,code))
                if op==4:actual=b'00000000:'+body.hex().encode()
                else:
                    require(body[:8]==b'HRCFGR01'and WORD(body,24)==len(body)-32,'actual validation result framing');actual=f'{WORD(body,8):08x}:'.encode()+body[32:].hex().encode()
            require(actual==expected,('complete original semantic difference',index,category,actual[:256],expected[:256]));results.append(actual+b'\n')
        observed=b''.join(results);(a.output/'semantic-output.txt').write_bytes(observed);require(SHA(observed)=='2432dc5bd65694895ddb055a72d59126bd031087a88fb7ba8d838107b4be8748','all semantic output bytes')
        write(a.output/'typed-refusal-original-observations.json',typed_refusal_observations)
        g.close();counts=dict(g.counts);write(a.output/'events.json',g.events);g=None;require({str(path):pin(path)for path in paths}==before,'same complete sources before/after')
        result={'status':'PASS','typed_cases':6491,'semantic_cases':2063,'actual_hia_counts':counts,'new_rust_processes':0,'retained_original_bytes_compared':True,'actual_filesystem_effects':0,'test_only_native_bridge':True,'public_mcp_complete':False,'elapsed_seconds':time.monotonic()-start,'artifacts':{path.name:pin(path)for path in a.output.iterdir()if path.is_file()}};write(a.output/'RESULT.json',result);print(json.dumps({k:v for k,v in result.items()if k!='artifacts'},sort_keys=True),flush=True)
    except BaseException:
        if g is not None:g.close()
        write(a.output/'FAILURE.json',{'traceback':traceback.format_exc(),'elapsed_seconds':time.monotonic()-start,'actual_counts':dict(g.counts)if g else None});raise
if __name__=='__main__':main()

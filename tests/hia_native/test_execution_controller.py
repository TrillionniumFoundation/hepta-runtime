"""Exercise real native call composition and hostile internal receipts.

Host replies in this suite are explicitly dependency fixtures. Actual installed
configuration and the static MCP executable are qualified separately.
"""
from pathlib import Path
import argparse,contextlib,ctypes,gzip,hashlib,json,struct,sys,time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/hia_native'));sys.path.insert(0,str(ROOT/'scripts'))
from execution_json_cases import cases
from execution_shadow_cases import fixture,record,packet
from hia_native_loader import NativeModule,NativeRejected,NativeCapacityError
CALL=0xffffffe0;INVALID=0xffffffff;CAPACITY=0xfffffffe
FOOTER=(256<<20)-256;REGION=64<<20
DISABLED=b'runtime tools are disabled; start with --runtime-config <file>'
PREFIX=b'failed to deserialize parameters: '
sha=lambda data:hashlib.sha256(data).hexdigest()
identity=lambda path:sha(Path(path).read_bytes())

def invoke(session,wire):
    try:
        data=session.invoke(wire);return len(data),data
    except (NativeRejected,NativeCapacityError) as error:return error.code,b''

def framed(raw):return struct.pack('<8s2Q',b'HXSREQ01',1,len(raw))+raw
def result(status,payload,diagnostic=0):return struct.pack('<8s3Q',b'HRCFGM01',status,diagnostic,len(payload))+payload
def owner_reply(name,mode):
    if mode=='disabled':return result(1,DISABLED,9)
    if mode=='exact' and name!=b'host-1':return result(1,b'unknown host `'+name+b'`; call host_list for configured names',12)
    return result(0,struct.pack('<8s3Q',b'HRCFHOST',1,4096,len(name))+name)
def host_from_packet(data):
    at=64;fields=[]
    for _ in range(14):
        n=struct.unpack_from('<Q',data,at)[0];at+=8;fields.append(data[at:at+n]);at+=n
    assert at==len(data);return fields[9]
def projected_core(data):
    magic,tag,canonical,digest,response,error,zero,zero2=struct.unpack_from('<8s7Q',data)
    assert magic==b'HXSRSL01' and zero==zero2==0
    if tag:return result(1,data[64:])
    return result(0,data[64+canonical+digest:])

class Bridge:
    def __init__(self,session,typed,core):self.session=session;self.typed=typed;self.core=core;self.rows=[]
    def word(self,at,value=None):
        pointer=ctypes.addressof(self.session._workspace)+at
        if value is None:return ctypes.c_uint64.from_address(pointer).value
        ctypes.c_uint64.from_address(pointer).value=value
    def read(self,at,size):return ctypes.string_at(ctypes.addressof(self.session._workspace)+at,size)
    def write(self,at,data):ctypes.memmove(ctypes.addressof(self.session._workspace)+at,data,len(data))
    def reset(self):
        ctypes.memset(self.session._workspace,0,4096)
        ctypes.memset(self.session._output,0xa6,self.session.output_capacity)
    def request(self):
        row=struct.unpack('<8s13Q',self.read(FOOTER,112))
        magic,seq,target,inkind,offset,size,outkind,output,capacity,reserved,rcode,completed,done,error=row
        assert magic==b'HIACAL01' and seq>0 and inkind==outkind==2
        assert target in (0,7,8) and reserved==rcode==completed==done==error==0
        assert capacity==REGION and offset+size<=FOOTER and output+capacity<=FOOTER
        return {'sequence':seq,'target':target,'offset':offset,'size':size,'output':output,'capacity':capacity,'wire':self.read(offset,size)}
    def complete(self,request,code,data=b''):
        assert len(data)<=request['capacity']
        self.write(request['output'],data);self.word(FOOTER+80,code);self.word(FOOTER+88,request['sequence']);self.word(FOOTER+96,1)
    def run(self,wire,mode):
        calls=[]
        for _ in range(4):
            code,data=invoke(self.session,wire)
            if code!=CALL:return code,data,calls
            request=self.request();target=request['target'];calls.append(target)
            if target==7:childcode,childdata=invoke(self.typed,request['wire'])
            elif target==8:childcode,childdata=invoke(self.core,request['wire'])
            else:
                magic,op,n=struct.unpack_from('<8s2Q',request['wire']);name=request['wire'][24:]
                assert magic==b'HRCFGQ01' and op==4 and n==len(name)
                childdata=owner_reply(name,mode);childcode=len(childdata)
            self.rows.append({'target':target,'request_sha256':sha(request['wire']),'response_sha256':sha(childdata),'code':childcode})
            self.complete(request,childcode,childdata)
        raise AssertionError('unbounded native child loop')

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--typed-manifest',type=Path,required=True)
    p.add_argument('--core-manifest',type=Path,required=True);p.add_argument('--serde-manifest',type=Path,required=True)
    p.add_argument('--original',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700);start=time.monotonic()
    metas={};reports=[];mismatches=[];receipt_controls=[];payload_controls=[]
    with contextlib.ExitStack() as stack:
        modules={}
        for name,path in [('controller',a.manifest),('typed',a.typed_manifest),('core',a.core_manifest),('value',a.serde_manifest)]:
            modules[name]=stack.enter_context(NativeModule(path,manifest_sha256=identity(path)));metas[name]=modules[name].metadata
        for name,source in [('controller','execution_controller'),('typed','execution_json'),('core','execution_shadow')]:assert metas[name]['source_sha256']==identity(ROOT/'native'/(source+'.hepta'))
        typed_cases=syntax=0
        # The two independent 256 MiB owners execute in serial phases. Retain
        # every actual canonical Value byte before releasing its private arena.
        with modules['value'].session(output_capacity=8<<20,workspace_capacity=256<<20) as value_session,gzip.open(a.original,'rb') as original,gzip.open(out/'canonical-parameters.jsonl.gz','wb') as prepared:
            for index,((label,kind,raw),line) in enumerate(zip(cases(),original,strict=True)):
                if kind!=11:continue
                actual=json.loads(line);code,canonical=invoke(value_session,struct.pack('<8s2Q',b'HSJVAL01',1,len(raw))+raw)
                if code==INVALID:
                    assert not actual['accepted'] and actual['category'] in ('Syntax','Eof');syntax+=1;continue
                assert code==len(canonical) and canonical
                prepared.write((json.dumps({'index':index,'label':label,'actual':actual,'canonical':canonical.hex()},sort_keys=True,separators=(',',':'))+'\n').encode())
        sessions={name:stack.enter_context(module.session(output_capacity=8<<20,workspace_capacity=(256<<20 if name=='controller' else (32<<20 if name=='typed' else 65536)))) for name,module in modules.items() if name!='value'}
        bridge=Bridge(sessions['controller'],sessions['typed'],sessions['core'])
        with gzip.open(out/'canonical-parameters.jsonl.gz','rb') as prepared,gzip.open(out/'requests.hex.gz','wb') as inputs,gzip.open(out/'outputs.hex.gz','wb') as outputs:
            for line in prepared:
                item=json.loads(line);index=item['index'];label=item['label'];actual=item['actual'];canonical=bytes.fromhex(item['canonical'])
                wire=framed(canonical)
                if actual['accepted']:
                    record_wire=bytes.fromhex(actual['value']['packet']);host=host_from_packet(record_wire)
                    core_code,core_data=invoke(sessions['core'],record_wire);assert core_code==len(core_data)
                modes=['exact','disabled','all'] if actual['accepted'] else ['exact']
                for mode in modes:
                    if not actual['accepted']:
                        wanted=result(1,PREFIX+actual['error'].encode());call_order=[7]
                    else:
                        host_result=owner_reply(host,mode)
                        if struct.unpack_from('<Q',host_result,8)[0]:wanted=host_result;call_order=[7,0]
                        else:wanted=projected_core(core_data);call_order=[7,0,8]
                    code,observed,order=bridge.run(wire,mode)
                    matches=code==len(wanted) and observed==wanted and order==call_order
                    row={'index':index,'label':label,'mode':mode,'matches':matches,'calls':order,'request_sha256':sha(wire),'response_sha256':sha(observed),'code':code}
                    reports.append(row);typed_cases+=1
                    inputs.write(mode.encode()+b' '+wire.hex().encode()+b'\n');outputs.write(f'{code:08x}:'.encode()+observed.hex().encode()+b'\n')
                    if not matches:mismatches.append({**row,'observed':observed[:4096].decode(errors='replace'),'wanted':wanted[:4096].decode(errors='replace')})
        ordinary=json.dumps({'record':record(fixture())},sort_keys=True,separators=(',',':')).encode();wire=framed(ordinary)
        # Every request field and completion field is checked before consuming
        # a child result. Malformed receipts publish no output bytes.
        for offset in range(0,112,8):
            for delta in [1,0xffffffffffffffff]:
                bridge.reset();assert invoke(sessions['controller'],wire)[0]==CALL;r=bridge.request()
                cc,dd=invoke(sessions['typed'],r['wire']);assert cc==len(dd);bridge.complete(r,cc,dd)
                old=bridge.word(FOOTER+offset);bridge.word(FOOTER+offset,(old+delta)&((1<<64)-1))
                code,data=invoke(sessions['controller'],wire)
                # Mutating the reported result length is also rejected by its
                # typed-frame length checks, before configuration is consulted.
                assert code==INVALID and not data,(offset,delta,code)
                assert ctypes.string_at(sessions['controller']._output,sessions['controller'].output_capacity)==b'\xa6'*sessions['controller'].output_capacity
                receipt_controls.append({'offset':offset,'delta':delta,'code':code})
        # Mutate each returned envelope independently at the phase consuming it.
        for phase in (1,2,3):
            for mutation in ('magic','short','long','length','tag'):
                bridge.reset()
                for step in range(1,phase+1):
                    assert invoke(sessions['controller'],wire)[0]==CALL;r=bridge.request()
                    if r['target']==7:cc,dd=invoke(sessions['typed'],r['wire'])
                    elif r['target']==8:cc,dd=invoke(sessions['core'],r['wire'])
                    else:dd=owner_reply(b'host-1','exact');cc=len(dd)
                    assert cc==len(dd)
                    if step==phase:
                        data=bytearray(dd)
                        if mutation=='magic':data[0]^=1
                        elif mutation=='short':data=data[:7]
                        elif mutation=='long':data+=b'x'
                        elif mutation=='length':struct.pack_into('<Q',data,24 if phase!=1 else 64,(1<<64)-1)
                        else:struct.pack_into('<Q',data,8,17)
                        dd=bytes(data);cc=len(dd)
                    bridge.complete(r,cc,dd)
                code,data=invoke(sessions['controller'],wire);assert code==INVALID and not data,(phase,mutation,code)
                payload_controls.append({'phase':phase,'mutation':mutation,'code':code})
        # Reuse persistent state for successive legitimate calls; failed framed
        # requests and a too-small output cannot leak partial JSON or text.
        bridge.reset();code,wanted,order=bridge.run(wire,'exact');assert code==len(wanted) and order==[7,0,8]
        bridge.reset();seq_controls=[]
        for _ in range(3):
            code,data,order=bridge.run(wire,'exact');assert data==wanted and order==[7,0,8];seq_controls.append(bridge.word(8))
        assert seq_controls==[3,6,9]
        framing=0
        for bad in [wire[:n] for n in range(24)]+[wire+b'x',b'X'+wire[1:],wire[:8]+struct.pack('<Q',2)+wire[16:]]:
            bridge.reset();assert invoke(sessions['controller'],bad)[0]==INVALID;framing+=1
        sessions['controller'].close()
        capacity=0
        for size in (0,31,len(wanted)-1,len(wanted)):
            with modules['controller'].session(output_capacity=size,workspace_capacity=256<<20) as small:
                sb=Bridge(small,sessions['typed'],sessions['core']);sb.reset();code,data,order=sb.run(wire,'exact')
                if size==len(wanted):assert data==wanted
                else:assert code==CAPACITY and not data and ctypes.string_at(small._output,size)==b'\xa6'*size;capacity+=1
        with modules['controller'].session(output_capacity=1024,workspace_capacity=(256<<20)-1) as short:
            assert invoke(short,wire)[0]==CAPACITY;capacity+=1
        (out/'call-trace.json').write_text(json.dumps(bridge.rows,sort_keys=True,indent=2)+'\n')
    (out/'mismatches.json').write_text(json.dumps(mismatches,sort_keys=True,indent=2)+'\n')
    with gzip.open(out/'observations.jsonl.gz','wb') as stream:
        for row in reports:stream.write((json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode())
    report={'status':'PASS' if not mismatches else 'FAIL','controller_calls':typed_cases,'raw_syntax_refusals':syntax,'mismatches':len(mismatches),'receipt_refusals':len(receipt_controls),'payload_refusals':len(payload_controls),'framing_refusals':framing,'capacity_refusals':capacity,'exact_capacity':1,'persistent_sequences':seq_controls,'receipt_controls':receipt_controls,'payload_controls':payload_controls,'sources':{n:m['source_sha256'] for n,m in metas.items()},'images':{n:m['image_sha256'] for n,m in metas.items()},'elapsed_seconds':time.monotonic()-start,'host_owner':'explicit dependency fixture only','actual_installed_host_comparison':False,'production_activated':False}
    (out/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True));assert not mismatches

if __name__=='__main__':main()

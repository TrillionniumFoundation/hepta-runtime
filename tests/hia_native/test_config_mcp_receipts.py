"""Native protocol continuation/capacity controls with labeled child receipts.

Synthetic child acknowledgements here test the controller boundary. Actual
Value/config/execution composition is exercised by the static-ELF suite.
"""
from pathlib import Path
import argparse,ctypes,hashlib,json,struct,sys,time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule,NativeRejected,NativeCapacityError
WORK=256<<20;P=WORK-4096;FOOTER=WORK-256;CALL=0xffffffe0;INVALID=0xffffffff;CAPACITY=0xfffffffe
sha=lambda b:hashlib.sha256(b).hexdigest()
def wire(value):return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
def invoke(s,raw):
    try:
        result=s.invoke(raw);return len(result),result
    except NativeRejected as e:return e.code,b''
    except NativeCapacityError:return CAPACITY,b''
def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);start=time.monotonic();count=0;receipt_controls=[]
    mpath=a.manifest.resolve(strict=True)
    with NativeModule(mpath,manifest_sha256=sha(mpath.read_bytes())) as m,m.session(output_capacity=1<<20,workspace_capacity=WORK) as s:
        assert m.metadata['source_sha256']==sha((ROOT/'native/config_mcp.hepta').read_bytes())
        w=ctypes.addressof(s._workspace)
        def word(at,value=None):
            if value is None:return ctypes.c_uint64.from_address(w+at).value
            ctypes.c_uint64.from_address(w+at).value=value
        initialize={'jsonrpc':'2.0','id':'\n'*300000,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'fixture','version':'1'}}}
        assert invoke(s,wire(initialize))[0]==CAPACITY;count+=1;assert word(P+520)==0
        initialize['id']=0;code,data=invoke(s,wire(initialize));count+=1;assert code==len(data) and json.loads(data)['id']==0 and word(P+520)==1
        assert invoke(s,b'{"jsonrpc":"2.0","method":"notifications/initialized"}')==(0,b'');count+=1
        ping=b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
        assert json.loads(invoke(s,ping)[1])['result']=={};count+=1
        raw=b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"host_list","arguments":{}}}'
        def prepared():
            word(P+1024,0)
            assert invoke(s,raw)==(CALL,b'')
            assert word(FOOTER+16)==9 and word(FOOTER+40)==26
            output=word(FOOTER+56);ctypes.memmove(w+output,b'{}',2)
            word(FOOTER+80,2);word(FOOTER+88,word(FOOTER+8));word(FOOTER+96,1)
        for offset in range(0,112,8):
            prepared();old=word(FOOTER+offset);word(FOOTER+offset,(old+1)&((1<<64)-1))
            code,_=invoke(s,raw);count+=2;assert code==INVALID,(offset,code);receipt_controls.append(offset)
        prepared();code,_=invoke(s,raw);count+=2;assert code==CALL and word(FOOTER+16)==0
        assert (word(FOOTER+32),word(FOOTER+40),word(FOOTER+56),word(FOOTER+64))==(33550336,24,100667392,67108864)
        response=struct.pack('<8s3Q',b'HRCFGM01',0,0,2)+b'{}';ctypes.memmove(w+word(FOOTER+56),response,len(response))
        word(FOOTER+80,len(response));word(FOOTER+88,word(FOOTER+8));word(FOOTER+96,1)
        code,data=invoke(s,raw);count+=1
        assert code==0xffffffd1 and data==b''
        assert word(FOOTER+160)==int.from_bytes(b'HRPPUB01','little')
        assert (word(FOOTER+168),word(FOOTER+176),word(FOOTER+192),word(FOOTER+200))==(100667424,2,0,1)
        prefix=ctypes.string_at(s._output,word(FOOTER+184))
        assert prefix==b'{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":'
        assert ctypes.string_at(w+word(FOOTER+168),word(FOOTER+176))==b'{}'
        # A resume with another input span is refused before consuming its
        # pending typed child result; no invocation is reinterpreted as startup.
        prepared();assert invoke(s,raw+b' ')[0]==INVALID;count+=2
        word(P+1024,0);assert json.loads(invoke(s,ping)[1])['result']=={};count+=1
    report={'schema':'hepta.runtime.config-mcp-receipts.v1','status':'PASS','groups':4,'native_calls':count,'corrupt_receipt_offsets':receipt_controls,'capacity_initialization_committed':False,'synthetic_child_receipts':True,'typed_text_publication_handoff_checked':True,'actual_child_semantics_in_separate_static_elf_suite':True,'elapsed':time.monotonic()-start,'manifest_sha256':sha(mpath.read_bytes()),'source_sha256':sha((ROOT/'native/config_mcp.hepta').read_bytes())}
    (out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()

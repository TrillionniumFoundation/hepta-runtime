"""Actual extra-engine result admission, target mapping and fixed slot-57 edge."""
import argparse,ctypes,json,mmap,os,pathlib,struct,sys,time,traceback
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from port_transport import Port,get,pack,put,sha
INVALID=0xffffffff
MAX=(1<<64)-1
def domain():
 rows=[]
 for kind in range(4):
  for close in [0,1]:
   for error in [0,1]:
    for prefix in [0,5]:
     for body in [0,3]:
      for seq in [0,1,MAX]:
       frame=pack(b'HRCMFR02',kind,close,prefix,body,error,seq,0)+b'p'*prefix+b'b'*body
       valid=kind!=3 or body==0;rows.append((f'old-{kind}-{close}-{error}-{prefix}-{body}-{seq}',frame,64 if valid else INVALID))
 seed=pack(b'HRCMFR02',0,0,0,0,0,0,0)
 for offset,value in [(16,2),(40,2),(56,1),(24,MAX),(32,MAX)]:
  b=bytearray(seed);struct.pack_into('<Q',b,offset,value);rows.append(('old-bad-'+str(offset),bytes(b),INVALID))
 rows.append(('old-bad-magic',b'X'+seed[1:],INVALID))
 for seq in [0,1,MAX]:rows.append(('pending-'+str(seq),pack(b'HRCMFR02',4,0,0,0,0,seq,0),64))
 for offset in [16,24,32,40,56]:
  for value in [1,MAX]:
   b=bytearray(pack(b'HRCMFR02',4,0,0,0,0,1,0));struct.pack_into('<Q',b,offset,value);rows.append((f'pending-bad-{offset}-{value}',bytes(b),INVALID))
 for kind in [5,MAX]:rows.append(('kind-'+str(kind),pack(b'HRCMFR02',kind,0,0,0,0,1,0),INVALID))
 return rows

class Engine:
 def __init__(self,folder,meta):
  raw=(folder/'module.bin').read_bytes();assert sha(raw)==meta['image_sha256'] and len(raw)==meta['image_bytes']
  self.mapping=mmap.mmap(-1,len(raw),prot=3);self.mapping.write(raw);self.address=ctypes.addressof(ctypes.c_char.from_buffer(self.mapping))
  libc=ctypes.CDLL(None,use_errno=True);libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];assert libc.mprotect(self.address,len(raw),5)==0
  self.meta=meta
  self.invoke=ctypes.CFUNCTYPE(ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64)(self.address+meta['exports']['fixture_invoke'])
  self.port_invoke=ctypes.CFUNCTYPE(ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64)(self.address+meta['exports']['fixture_port_invoke'])
  self.target=ctypes.CFUNCTYPE(ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64)(self.address+meta['exports']['runtime_grow_target'])
  self.destroy=ctypes.CFUNCTYPE(ctypes.c_uint64,ctypes.c_uint64)(self.address+meta['exports']['fixture_destroy'])
 def close(self):self.invoke=self.port_invoke=self.target=self.destroy=None;self.mapping.close()

def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();a.output.mkdir()
 fixture=a.build/'engine-fixture-v1';meta=json.loads((fixture/'BUILD.json').read_bytes());assert meta['status']=='ACTUAL_GAS_ENGINE_FIXTURE_BUILD_PASS'
 engines={role:Engine(fixture/role,row) for role,row in meta['images'].items()};blobs=a.output/'blobs';blobs.mkdir();records=[];targets=[]
 def blob(b):
  h=sha(b);path=blobs/h
  if not path.exists():path.write_bytes(b)
  return {'bytes':len(b),'sha256':h}
 try:
  for parent in range(59):
   for child in range(17):
    before=engines['old'].target(parent,child);after=engines['new'].target(parent,child)
    expected=47 if (parent,child)==(18,13) else 57 if (parent,child)==(18,14) else before
    assert after==expected
    targets.append({'parent':parent,'child':child,'old':before,'new':after})
  for label,wire,expected in domain():
   row={'label':label,'input':blob(wire),'new_expected':expected,'versions':{}}
   for role,engine in engines.items():
    state=ctypes.create_string_buffer(16384);out=ctypes.create_string_buffer(b'\xa5'*4096,4096);work=ctypes.create_string_buffer(b'\x5a'*4096,4096);source=ctypes.create_string_buffer(wire+b'\xd6'*8,len(wire)+8)
    struct.pack_into('<Q',state,8,ctypes.addressof(state)+8192);state[40:48]=b'HRGENG02'
    desc=8192+18*64;struct.pack_into('<8Q',state,desc,engine.address+engine.meta['exports']['fixture_frame'],ctypes.addressof(work),4096,0,ctypes.addressof(out),4096,0,0)
    before={'engine':blob(state.raw),'output':blob(out.raw),'workspace':blob(work.raw),'input':blob(source.raw)}
    code=engine.invoke(ctypes.addressof(state),18,ctypes.addressof(source),len(wire));want=INVALID if role=='old' and get(wire,8)==4 else expected
    assert code==want and source.raw==wire+b'\xd6'*8 and work.raw==b'\x5a'*4096 and out.raw==wire+b'\xa5'*(4096-len(wire))
    assert get(state.raw,desc+48)==code and get(state.raw,desc+56)==(64+get(wire,24)+get(wire,32) if code==64 else 0)
    row['versions'][role]={'code':code,'before':before,'after':{'engine':blob(state.raw),'output':blob(out.raw),'workspace':blob(work.raw),'input':blob(source.raw)}}
   records.append(row)
  # This separate cohort enters the real frozen eight-HIA port through the
  # new extra-engine selector, with no successful stub capability invoked.
  port=Port(a.build/'build-v3',a.output/'port')
  try:
   port.create()
   # The actual installed table entry is fixed before attaching this engine.
   original_address=ctypes.cast(port.fn['invoke'],ctypes.c_void_p).value-port.component['exports']['invoke']
   e=ctypes.create_string_buffer(16384);struct.pack_into('<Q',e,8,ctypes.addressof(e)+8192);e[40:48]=b'HRGENG02';struct.pack_into('<Q',e,8192+57*64,original_address)
   port.engines.append(e);port.emit({'phase':'engine','index':0,'address':ctypes.addressof(e),'before':port.blob(e.raw)})
   assert port.call('attach',[port.ctx,ctypes.addressof(e)])==0
   port.fn['invoke']=engines['new'].port_invoke
   assert engines['new'].destroy(ctypes.addressof(e))==MAX-21
   tag=port.allocate(e);body=b'{"states":[{"actions":[{"kind":"terminal","value":2.5},null,null,null,null,null]}]}'
   d=port.command(e,1,tag,body);assert get(d,8)==3;job=get(d,24);port.wait_ready(job);d=port.command(e,2,tag);assert get(d,8)==0 and json.loads(d[64:])['states'][0]['value']==2.5
   port.retire(e,tag);assert port.call('detach',[port.ctx,ctypes.addressof(e)])==0
   assert port.call('shutdown',[port.ctx])==0;port.service();assert port.call('destroy',[port.ctx])==0
   joined={'status':'ACTUAL_SLOT57_DISPATCH_PASS','tag':tag,'job':job,'full_result':blob(d),'worker_contexts':1,'public_handler_qualified':False}
  finally:port.close()
  put(a.output/'RECORDS.json',{'cases':records,'targets':targets,'joined':joined})
  result={'status':'ACTUAL_ENGINE_EDGE_PASS','frame_cases':len(records),'paired_frames':2*len(records),'target_pairs':len(targets),'actual_worker_jobs':1,'old_source_sha256':meta['images']['old']['source_sha256'],'new_source_sha256':meta['images']['new']['source_sha256'],'public_handler_qualified':False}
  put(a.output/'RESULT.json',result);print(json.dumps(result,sort_keys=True))
 finally:
  for engine in engines.values():engine.close()
if __name__=='__main__':
 try:main()
 except BaseException:traceback.print_exc();sys.stderr.flush();os._exit(1)

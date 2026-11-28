"""Mechanical execution of owned native HIA continuation frames for G5.

All protocol, metadata, request and catalog decisions are made by native owners.
This driver copies ABI spans and stops before any actual public tool body.
"""
from pathlib import Path
import ctypes,hashlib,json,struct
from hia_native_loader import NativeModule
word=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
pack=lambda *values:struct.pack('<'+'Q'*len(values),*values)
sha=lambda raw:hashlib.sha256(raw).hexdigest()
CALL=0xfffffff0;GROW=0xffffffd0;DELIVERY=0xffffffcd

def extent(code,head):
 if code==192 and head[:8]==b'HRJPRR02':return 192+word(head,48)+word(head,56)+word(head,64)
 if code==64 and head[:8]==b'HRCMFR02':return 64+word(head,24)+word(head,32)
 if code==48 and head[:8]==b'HCMADR02':return 48+word(head,32)
 if code==32:
  if head[:8] in (b'HRCATR02',b'HJSVR002'):return 32+word(head,16)
  if head[:8]==b'HRCMPR02':return 32+word(head,24)
 return code

class PendingTool(Exception):
 def __init__(self,child,wire):self.child=child;self.wire=wire

class State:
 def __init__(self,name,module,events,workspace=1<<20,output=1<<16):
  self.name=name;self.module=module;self.events=events;self.work_size=workspace;self.out_size=output
  self.work=ctypes.create_string_buffer(workspace+16);self.out=ctypes.create_string_buffer(output+16)
 def get(self,at):return ctypes.c_uint64.from_address(ctypes.addressof(self.work)+at).value
 def put(self,at,value):ctypes.c_uint64.from_address(ctypes.addressof(self.work)+at).value=value
 def read(self,at,size):
  assert 0<=at<=self.work_size and 0<=size<=self.work_size-at
  return ctypes.string_at(ctypes.addressof(self.work)+at,size)
 def write(self,at,raw):
  assert 0<=at<=self.work_size and len(raw)<=self.work_size-at
  ctypes.memmove(ctypes.addressof(self.work)+at,raw,len(raw))
 def resize(self,kind,size):
  assert kind in (1,2) and size>0
  old=self.work if kind==1 else self.out;current=self.work_size if kind==1 else self.out_size
  limit=self.module.metadata['workspace_capacity' if kind==1 else 'output_capacity'];assert current<size<=limit
  new=ctypes.create_string_buffer(size+16);ctypes.memmove(new,old,current)
  if kind==1:self.work=new;self.work_size=size
  else:self.out=new;self.out_size=size
 def call(self,wire):
  assert len(wire)<=self.module.metadata['input_capacity']
  source=ctypes.create_string_buffer(wire,max(1,len(wire)))
  ctypes.memset(ctypes.addressof(self.work)+self.work_size,0x5a,16);ctypes.memset(ctypes.addressof(self.out)+self.out_size,0xa5,16)
  code=self.module._entry(source,len(wire),self.out,self.out_size,self.work,self.work_size)
  assert source.raw==(wire or b'\0')
  assert ctypes.string_at(ctypes.addressof(self.work)+self.work_size,16)==b'Z'*16
  assert ctypes.string_at(ctypes.addressof(self.out)+self.out_size,16)==b'\xa5'*16
  head=ctypes.string_at(self.out,min(192,self.out_size))
  record={'owner':self.name,'code':code,'input_hex':wire.hex(),'output_capacity':self.out_size,'workspace_capacity':self.work_size}
  if code==CALL:
   raw=self.read(256,112);record['action_hex']=raw.hex()
  elif code==GROW:
   raw=head[:32];record['growth_hex']=raw.hex()
  else:
   assert code<0xffff0000,(self.name,hex(code),head[:32].hex())
   size=extent(code,head);assert 0<=size<=self.out_size,(self.name,code,size,self.out_size)
   raw=ctypes.string_at(self.out,size);record['output_hex']=raw.hex()
  self.events(record)
  return code,raw

class Engine:
 def __init__(self,root,events):
  self.root=Path(root);self.events=events;self.modules={};self.states={}
  rows=json.loads((self.root/'evidence/hia-modules.json').read_bytes())['members']
  rows.update(json.loads((self.root/'evidence/frontend-modules.json').read_bytes())['members'])
  self.members=rows
  for name in ['message','request','bridge','frontend','protocol','admission','client','wide_value','public_catalog','baseline_catalog']:
   m=rows[name];self.modules[name]=NativeModule(self.root/m['path'],manifest_sha256=m['sha256'])
  self.new_session()
 def new_session(self):
  self.states={name:State(name,module,self.events,workspace=(96<<20 if name in ('message','request','bridge') else 1<<20)) for name,module in self.modules.items()}
 def close(self):
  self.states.clear()
  for module in self.modules.values():module.close()
 def run(self,name,wire,protocol_bridge=False):
  state=self.states[name];completed={}
  for step in range(128):
   code,raw=state.call(wire)
   if code==GROW:
    assert raw[:8]==b'HGRWS002';state.resize(word(raw,8),word(raw,16));continue
   if code!=CALL:return code,raw
   action=raw;sequence=word(action,8);target=word(action,16);start=word(action,32);length=word(action,40)
   child_wire=state.read(start,length)
   if name=='frontend' and target>=4:raise PendingTool(target,child_wire)
   if sequence not in completed:
    assert word(action,24)==0
    if name=='frontend':
     if target==0 and protocol_bridge:
      assert child_wire[:8]==b'HRJPRQ02' and word(child_wire,16)==len(wire) and child_wire[32:]==wire
      message=self.run('message',b'HRCJQ001'+pack(1,len(wire))+wire)[1]
      request=self.run('request',message)[1]
      joined=b'HRQFB001'+pack(word(child_wire,8),len(wire),len(message),len(request))+wire+message+request
      result=self.run('bridge',joined)
     else:
      result=self.run({0:'protocol',1:'admission',2:'public_catalog',3:'wide_value'}[target],child_wire)
    elif name=='admission':result=self.run({0:'wide_value',1:'client'}[target],child_wire)
    elif name=='client':
     assert target==1;result=self.run('wide_value',child_wire)
    else:raise AssertionError((name,'unexpected private child',target))
    completed[sequence]=result
   else:assert word(action,24)==1
   child_code,child_raw=completed[sequence]
   state.put(320,sequence);state.put(352,len(child_raw))
   if len(child_raw)>word(action,56):state.put(328,DELIVERY);continue
   state.write(word(action,48),child_raw);state.put(328,child_code)
  raise AssertionError((name,'ordinary continuation bound'))

#!/usr/bin/env python3
"""Actual new wrapper rejection branches; whole original fixture and ptrace."""
import argparse,json,sys,time,traceback
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from evidence_common import encoded,decode,pin,require,source_evidence
from buffer_store import Writer
from carrier import Carrier
from composition_prepare import Preparer
from parent_capture import setup,discard,projection,concrete
from protocol import U,proc_fds

NAMES=('actual-ready-mismatch','actual-planner-invalid','physical-invalid-header')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in('images','build','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();out=a.output.absolute();require(not out.exists(),'fresh boundary capture');out.mkdir(parents=True)
 source=source_evidence(ROOT);started=time.monotonic_ns();binary=a.build.resolve()/'binary-write-composition.elf'
 require(pin(binary)==decode((a.build/'BUILD.json').read_bytes())['executable'],'actual frozen composed ELF')
 domain=decode((ROOT/'parent/DOMAIN.json').read_bytes());original=domain['cases'][0]
 store=Writer(out/'buffers');prep=Preparer(a.images.resolve()/'adapter',out/'preparation');rows=[]
 try:
  for ordinal,name in enumerate(NAMES):
   began=time.monotonic_ns();fixture=out/'fixture';initial=setup(fixture);before=projection(fixture)
   query=concrete(original,fixture,True);start,preparation=prep.request(query,20000+ordinal,name)
   require(start is not None,'original exact String input')
   wire=bytearray(start)
   if name=='actual-ready-mismatch':wire[-2]^=1
   elif name=='actual-planner-invalid':wire[48+304]=255
   else:wire=wire[:48];wire[0]^=1
   wire=bytes(wire);folder=out/name;folder.mkdir();carrier=Carrier(binary,folder,store)
   row=dict(name=name,query=query,preparation=preparation,application_input=store.put(wire),setup=initial,before=before,events=[],snapshots={})
   def exchange(command,payload=b'',application=False):
    raw,index=carrier.exchange(command,0,payload,application=application)
    row['events'].append(dict(command=command,exchange=index,result=U(raw,8)))
    return raw,index
   def snapshot(command,label):
    raw,index=exchange(command);require(U(raw,8)==0,'whole actual boundary snapshot')
    entry=dict(exchange=index,bytes=store.put(raw[64:]));row['snapshots'][label]=entry
    if command in(4,29):entry['actual_process_bytes']=carrier.observed_context(raw[64:])
    return raw[64:]
   try:
    raw,_=exchange(8);require(U(raw,8)==0,'actual observed composition construction')
    for cmd,label in((4,'parent_before'),(29,'wrapper_before'),(30,'adapter_before'),(11,'pool_before')):snapshot(cmd,label)
    row['fds_before']=proc_fds(carrier.pid)
    raw,index=exchange(1,wire,True);row['application_exchange']=index;row['application_frame']=store.put(raw[64:])
    expected=0xffffffff if name=='physical-invalid-header'else 64
    require(U(raw,8)==expected and U(raw,24)==(0 if expected!=64 else 2),'actual frozen boundary terminal')
    for cmd,label in((4,'parent_held'),(29,'wrapper_held'),(30,'adapter_held'),(31,'planner_held'),(32,'adapter_output'),(33,'planner_output'),(34,'input_held')):
     value=snapshot(cmd,label)
     if label=='wrapper_held':held=value
    if expected==64:
     for label,cmd,payload in(('busy-invoke',1,wire),('busy-destroy',3,b'')):
      raw,index=exchange(cmd,payload);require(U(raw,8)==0xfffffffd,'actual held wrapper refusal')
      require(snapshot(29,label)==held,'busy refusal preserves whole live wrapper')
    raw,index=exchange(2);row['release_exchange']=index
    require(U(raw,8)==(0xffffffff if expected!=64 else 0),'actual held-or-idle release result')
    for cmd,label in((4,'parent_released'),(29,'wrapper_released'),(30,'adapter_released'),(32,'adapter_release_output')):snapshot(cmd,label)
    row['fds_after_release']=proc_fds(carrier.pid)
    raw,index=exchange(3);row['destroy_exchange']=index;require(U(raw,8)==0,'actual boundary owner destruction')
    snapshot(11,'pool_after_destroy');row['fds_after_destroy']=proc_fds(carrier.pid)
    row['process']=carrier.finish();row['after']=projection(fixture)
    require(encoded(before)==encoded(row['after']),'boundary rejection altered any target bytes or metadata')
    row['elapsed_ns']=time.monotonic_ns()-began;require(row['elapsed_ns']<180_000_000_000,'original boundary case budget')
    (folder/'BOUNDARY.json').write_bytes(encoded(row));rows.append(dict(name=name,record=pin(folder/'BOUNDARY.json')))
    discard(fixture)
   except BaseException as error:
    (folder/'FAILURE.json').write_bytes(encoded(dict(status='HOLD',observations=row,error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc())))
    raise
   finally:carrier.cleanup()
  preparation=prep.close();prep=None
  require(source_evidence(ROOT)==source,'full boundary source custody')
  result=dict(schema='hepta.runtime.binary-write-composition-boundary.v1',status='COMPLETE_ACTUAL_BOUNDARY_CAPTURE',source=source,
              executable=pin(binary),images=pin(a.images/'IMAGES.json'),cases=rows,preparation=preparation,
              elapsed_ns=time.monotonic_ns()-started,buffers=dict(images=store.images,logical_bytes=store.logical_bytes,blocks=len(store.known)),
              public_binary_write_registered=False,whole_runtime_replaced=False)
  (out/'BOUNDARY.json').write_bytes(encoded(result));print(json.dumps(dict(status=result['status'],cases=len(rows),elapsed_ns=result['elapsed_ns']),sort_keys=True))
 finally:
  if prep is not None:prep.close()

if __name__=='__main__':main()

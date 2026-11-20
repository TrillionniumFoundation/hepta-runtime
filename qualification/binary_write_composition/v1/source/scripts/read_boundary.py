#!/usr/bin/env python3
"""Independent full DATA admission of the new wrapper's actual refusal paths."""
import argparse,gzip,hashlib,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from evidence_common import encoded,decode,pin,require,source_evidence
from buffer_store import Reader
from protocol import U
from read_kernel import read_trace
from read_parent_capture import journal,all_buffers,fd_view,filesystem
from read_composition import Prepared,composed_calls,complete_chain,PACK,mismatch_frame
from composition_domain import query_from_case

def read_all(folder,images,build,authority):
 folder,images,build=map(lambda p:Path(p).resolve(strict=True),(folder,images,build))
 source=source_evidence(ROOT);raw=(folder/'BOUNDARY.json').read_bytes()
 require(hashlib.sha256(raw).hexdigest()==authority,'external complete boundary authority')
 report=decode(raw);binary=pin(build/'binary-write-composition.elf')
 require(report['schema']=='hepta.runtime.binary-write-composition-boundary.v1' and report['status']=='COMPLETE_ACTUAL_BOUNDARY_CAPTURE'
         and report['source']==source and report['executable']==binary and report['images']==pin(images/'IMAGES.json')
         and report['public_binary_write_registered']is False and report['whole_runtime_replaced']is False,'frozen actual boundary scope')
 names=('actual-ready-mismatch','actual-planner-invalid','physical-invalid-header')
 require([x['name']for x in report['cases']]==list(names),'complete independently fixed boundary order')
 store=Reader(folder/'buffers');prep=Prepared(folder/'preparation',images/'adapter');original=decode((ROOT/'parent/DOMAIN.json').read_bytes())['cases'][0]
 checked=[]
 for number,(name,binding)in enumerate(zip(names,report['cases'])):
  root=folder/name;case_raw=(root/'BOUNDARY.json').read_bytes();require(pin(root/'BOUNDARY.json')==binding['record'],'whole actual boundary record')
  row=decode(case_raw);all_buffers(row,store);query=query_from_case(original,folder/'fixture',True)
  require(row['name']==name and row['query']==query and row['elapsed_ns']<180_000_000_000,'exact bounded declared boundary input')
  require(filesystem(row['setup'])==filesystem(row['before']) and encoded(row['before'])==encoded(row['after']),'all actual target nodes, bytes and metadata unchanged by rejection')
  nominal=bytes.fromhex(prep.rows[number]['request_hex'])
  prepared=prep.request(row['preparation'],query,20000+number,name,nominal)
  wire=bytearray(nominal)
  if number==0:wire[-2]^=1
  elif number==1:wire[352]=255
  else:wire=wire[:48];wire[0]^=1
  wire=bytes(wire);require(store.get(row['application_input'])==wire,'independently reconstructed exact invalid/mismatching input')
  process=row['process'];require(process==decode((root/'carrier-process.json').read_bytes()) and process['binary']==binary
          and process['argv']==[str(build/'binary-write-composition.elf')] and process['returncode']==0
          and process['same_outer_process_group']is True and process['elapsed_ns']<180_000_000_000,'whole actual bounded executable process')
  require(process['observer_wait']==dict(kind='SIGCHLD-pipe',parent_only=True,target_signal_replacement=False),'unaltered actual observer')
  for stream in('stdin','stderr'):require(pin(root/('carrier.'+stream))==process['streams'][stream],'whole actual carrier stream')
  require((root/'carrier.stderr').read_bytes()==b'','actual target stderr')
  output=gzip.decompress((root/'carrier.stdout.gz').read_bytes())
  require(pin(root/'carrier.stdout.gz')==process['stdout']['compressed'] and dict(bytes=len(output),sha256=hashlib.sha256(output).hexdigest())==process['stdout']['raw'],'whole actual output stream')
  exchanges=[decode(line)for line in(root/'exchanges.jsonl').read_bytes().splitlines()];all_buffers(exchanges,store)
  sequence=[(8,None),(4,'parent_before'),(29,'wrapper_before'),(30,'adapter_before'),(11,'pool_before'),(1,'application'),
            (4,'parent_held'),(29,'wrapper_held'),(30,'adapter_held'),(31,'planner_held'),(32,'adapter_output'),(33,'planner_output'),(34,'input_held')]
  if number<2:sequence += [(1,'busy-invoke-call'),(29,'busy-invoke'),(3,'busy-destroy-call'),(29,'busy-destroy')]
  sequence += [(2,'release'),(4,'parent_released'),(29,'wrapper_released'),(30,'adapter_released'),(32,'adapter_release_output'),(3,'destroy'),(11,'pool_after_destroy')]
  require(len(exchanges)==len(sequence) and [e['exchange']for e in exchanges]==list(range(1,len(sequence)+1)),'every exact private fixture exchange')
  require(b''.join(store.get(e['input'])for e in exchanges)==(root/'carrier.stdin').read_bytes()
          and b''.join(store.get(e['output'])for e in exchanges)==output,'complete input/output attribution')
  expected_events=[]
  for index,(exchange,(command,label))in enumerate(zip(exchanges,sequence),1):
   payload=wire if command==1 else b'';expected=b'HBWTFQ01'+PACK(command,0,len(payload),0,0,0,0)+payload
   actual=store.get(exchange['output']);expected_code=0
   if label=='application':expected_code=0xffffffff if number==2 else 64
   elif label in('busy-invoke-call','busy-destroy-call'):expected_code=0xfffffffd
   elif label=='release'and number==2:expected_code=0xffffffff
   require(exchange['command']==command and exchange['session']==0 and exchange['application']is(label=='application')
           and exchange['elapsed_ns']<60_000_000_000 and store.get(exchange['input'])==PACK(len(expected))+expected
           and actual[:8]==b'HBWTFR01' and U(actual,8)==expected_code and U(actual,16)==len(actual)-64,'exact physical request and actual return')
   if label in row['snapshots']:
    s=row['snapshots'][label];require(s['exchange']==index and store.get(s['bytes'])==actual[64:],'whole actual snapshot bound to exact exchange')
   elif label=='application':require(row['application_exchange']==index and store.get(row['application_frame'])==actual[64:],'actual entire refusal publication')
   elif label=='release':require(row['release_exchange']==index and len(actual)==64,'actual empty release response')
   elif label=='destroy':require(row['destroy_exchange']==index and len(actual)==64,'actual empty destroy response')
   else:require(len(actual)==64,'no unexpected fixture payload')
   expected_events.append(dict(command=command,exchange=index,result=expected_code))
  require(row['events']==expected_events,'summary cannot rename actual controls')
  kernel=read_trace(root,process['kernel']);require(kernel['application_calls']==1,'one real boundary invoke')
  scopes={mark['scope']for mark in kernel['marks']if mark['application']}
  active=[call for call in kernel['calls']if call['scope']in scopes]
  require(active and all(call['number']in(0,1,9,10,11,39)for call in active),'refusal performs only observed transport, memory and PID primitives')
  require(all(call['args'][0]in(1,3)for call in active if call['number']==1)
          and all(call['args'][0]==0 for call in active if call['number']==0),'no target file read/write on refusal')
  observed=journal(root,process['journal'],store)
  require(observed['parent_calls']==observed['body_calls']==0 and observed['actors']==[] and observed['first_parent_input']is None
          and observed['all_frames']==len(observed['composition_rows']),'no parent/body/effect/actor entry can hide among complete raw frames')
  calls,last,address=composed_calls(observed['composition_rows']);at,first,_=complete_chain(calls,1,7,wire)
  held=store.get(row['snapshots']['wrapper_held']['bytes']);released=store.get(row['snapshots']['wrapper_released']['bytes'])
  parent=store.get(row['snapshots']['parent_before']['bytes'])
  require(parent==store.get(row['snapshots']['parent_held']['bytes'])==store.get(row['snapshots']['parent_released']['bytes'])
          and parent[:8]==b'HBPWCI01' and U(parent,56)==U(parent,192)==U(parent,248)==0,'whole real parent remains never invoked')
  for label in('parent_before','parent_held','parent_released','wrapper_before','wrapper_held','wrapper_released',*(()if number==2 else('busy-invoke','busy-destroy'))):
   snapshot=row['snapshots'][label];value=store.get(snapshot['bytes']);obs=snapshot['actual_process_bytes']
   matches=[item for item in obs['candidates']if store.get(item['bytes'])==value]
   require(obs['writes']==0 and obs['observation']=='process_vm_readv' and len(matches)==1
           and matches[0]['address']==obs['address'] and store.get(matches[0]['second'])==value,'full actual read-only context observation')
   require(obs['address']==(U(held,384)if label.startswith('parent')else address),'exact observed parent/wrapper capabilities')
  require(held[:8]==released[:8]==b'HBCWCI01' and U(held,480)==U(parent,480)==process['pid']
          and U(held,376)==U(parent,376) and U(held,408)==U(parent,408) and U(held,192)==1 and U(held,568)==0 and U(held,640)==0,'exact owned graph with no parent loan')
  initial=store.get(row['snapshots']['input_held']['bytes']);require(initial==wire+bytes(len(initial)-len(wire)),'entire immutable boundary request')
  if number==2:
   require(first['code']==0xffffffff and at==len(calls)+1 and U(held,56)==U(held,576)==0
           and held==released and store.get(row['application_frame'])==b'','physical rejection stays idle and release cannot mutate it')
   require(store.get(row['snapshots']['adapter_before']['bytes'])==store.get(row['snapshots']['adapter_held']['bytes'])
           ==store.get(row['snapshots']['adapter_released']['bytes'])==bytes(4096),'physical input rejection retains whole initial HIA workspace')
  else:
   plan=wire[48:48+U(wire,40)];require(first['frame']==b'HBWAR001'+PACK(1,1,len(plan),0,0,0,0)+plan,'actual fixed planner request')
   at,child,_=complete_chain(calls,at,8,plan)
   if number==0:require(child['code']==len(prepared['ready']) and child['frame']==prepared['ready'],'mismatch still consumes actual unchanged planner result')
   else:require(child['code']==0xffffffff and child['frame']==b'','actual invalid planner return, without fabricated child bytes')
   resume=b'HBWAQ001'+PACK(2,1,child['code'],len(child['frame']),0)+child['frame']
   at,done,_=complete_chain(calls,at,7,resume)
   expected=mismatch_frame(done['frame'],child['frame'],1,2 if number==0 else 1)
   require(done['frame']==expected==store.get(row['application_frame']) and U(held,56)==2 and U(held,576)==1
           and U(held,584)==len(expected) and U(held,168)==len(expected),'complete actual mismatch owner publication and retained adapter loan')
   for label in('busy-invoke','busy-destroy'):require(store.get(row['snapshots'][label]['bytes'])==held,'actual busy operations preserve every context byte')
   at,end,_=complete_chain(calls,at,7,b'HBWAQ001'+PACK(3,1,0,0,0))
   require(at==len(calls)+1 and end['frame']==b'HBWAR001'+PACK(0,1,0,0,0,0,0),'actual complete release, no hidden invocation')
   expected_context=bytearray(held)
   for offset in(56,168,176,568,576,640):struct.pack_into('<Q',expected_context,offset,0)
   for offset,value in((208,48),(248,U(held,248)+1),(632,1)):struct.pack_into('<Q',expected_context,offset,value)
   require(released==bytes(expected_context),'whole mismatch release changes only declared control words')
   require(store.get(row['snapshots']['adapter_held']['bytes'])==done['after'] and store.get(row['snapshots']['adapter_released']['bytes'])==end['after']
           and store.get(row['snapshots']['adapter_output']['bytes'])==done['output'] and store.get(row['snapshots']['adapter_release_output']['bytes'])==end['output']
           and store.get(row['snapshots']['planner_held']['bytes'])==child['after'] and store.get(row['snapshots']['planner_output']['bytes'])==child['output'],'all actual pure buffers retained through held and released phases')
  require(store.get(row['snapshots']['pool_before']['bytes'])==store.get(row['snapshots']['pool_after_destroy']['bytes']),'whole shared orphan pool unchanged')
  require(fd_view(row['fds_before'])==fd_view(row['fds_after_release'])==fd_view(row['fds_after_destroy']),'actual target descriptor table unchanged')
  require((root/'BOUNDARY.json').read_bytes()==case_raw,'whole boundary raw custody');checked.append(dict(name=name,native_entries=len(calls),parent_entries=0))
 require(prep.finish()==report['preparation'],'every actual boundary predecessor call credited')
 buffers=store.finish();require(source_evidence(ROOT)==source and(folder/'BOUNDARY.json').read_bytes()==raw,'whole boundary source/evidence custody')
 return dict(status='PASS_ACTUAL_COMPOSITION_BOUNDARIES',source=source,executable=binary,cases=checked,buffers=buffers,
             public_binary_write_registered=False,whole_runtime_replaced=False)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in('capture','images','build','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--capture-sha256',required=True);a=p.parse_args();require(not a.output.exists(),'fresh boundary DATA receipt')
 a.output.write_bytes(encoded(read_all(a.capture,a.images,a.build,a.capture_sha256)))

#!/usr/bin/env python3
"""Compare current SDK normal list responses to the repacked native fixture."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,sys,time,traceback
ROOT=Path(__file__).resolve().parents[1];sha=lambda b:hashlib.sha256(b).hexdigest()
frame=lambda magic,op,b:magic+struct.pack('<QQ',op,len(b))+b
U=lambda b,n:struct.unpack_from('<Q',b,n)[0]
def main():
 p=argparse.ArgumentParser();p.add_argument('--run-name',default='cache-sessions-v1');a=p.parse_args();assert a.run_name.replace('-','').isalnum()
 out=ROOT/'evidence'/a.run_name;out.mkdir();report={'schema':'hepta.g4.default-cache-sessions.v1','status':'RUNNING','sessions':0,'native_message_calls':0,'native_connection_calls':0,'native_fixture_calls':0,'matched_response_lines':0,'elf_sessions':0,'elf_response_lines':0,'full_target_qualified':False,'production_activated':False,'old_path_removed':False};start=time.monotonic()
 def save():(out/'summary.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 save()
 try:
  cases=[json.loads(x) for x in (ROOT/'cases/normal.jsonl').read_bytes().splitlines()];refs=[json.loads(x) for x in (ROOT/'evidence/oracle-normal.jsonl').read_bytes().splitlines()]
  pairs=[(c,r) for c,r in zip(cases,refs,strict=True) if c['mode']=='session'];stage=ROOT/'transport-regression'
  mods=json.loads((stage/'evidence/hia-modules.json').read_bytes())['members'];sys.path.insert(0,str(ROOT/'scripts'));from hia_native_loader import NativeModule
  def module(name):m=mods[name];return NativeModule(stage/m['path'],manifest_sha256=m['sha256'])
  eventlog=[]
  with module('message') as mm,module('connection') as cm,module('fixture') as fm:
   with mm.session(output_capacity=1<<20,workspace_capacity=2<<20) as msg,fm.session(output_capacity=1<<20,workspace_capacity=65536) as fixture:
    for case,ref in pairs:
     assert case['label']==ref['label'] and ref['terminal']=={'phase':'running','quit':'Closed'}
     with cm.session(output_capacity=2<<20,workspace_capacity=1<<20) as connection:
      for event,expected in zip(case['events'],ref['events'],strict=True):
       raw=event['wire'].encode();projection=msg(frame(b'HRCJQ001',1,raw));admission=connection(frame(b'HRCNQ001',1,projection));kind=U(admission,8)
       assert kind in [2,3];reply=fixture(admission);want=expected['response_raw'].encode();assert reply+b'\n'==want,(case['label'],event['wire'],reply,want)
       eventlog.append({'session':case['label'],'request':event['wire'],'projection_hex':projection.hex(),'admission_hex':admission.hex(),'response_hex':reply.hex()})
       report['native_message_calls']+=1;report['native_connection_calls']+=1;report['native_fixture_calls']+=1;report['matched_response_lines']+=1
      end=connection(frame(b'HRCNQ001',2,b''));assert U(end,8)==6;report['native_connection_calls']+=1
     report['sessions']+=1
  (out/'native-events.jsonl').write_text(''.join(json.dumps(r,sort_keys=True,separators=(',',':'))+'\n' for r in eventlog))
  pm=stage/'hia-build-g4/g4-transport-elf/manifest.json';packed=json.loads(pm.read_bytes());elf=pm.parent/packed['executable'];assert sha(elf.read_bytes())==packed['elf_sha256']
  for index,(case,ref) in enumerate(pairs):
   raw=b''.join(e['wire'].encode()+b'\n' for e in case['events']);expected=b''.join(e['response_raw'].encode() for e in ref['events']);r=subprocess.run([str(elf)],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
   for suffix,b in [('stdin',raw),('stdout',r.stdout),('stderr',r.stderr)]:(out/(str(index)+'.'+suffix)).write_bytes(b)
   assert r.returncode==0 and not r.stderr and r.stdout==expected,case['label'];report['elf_sessions']+=1;report['elf_response_lines']+=r.stdout.count(b'\n')
  assert report['sessions']==3 and report['matched_response_lines']==15
  report.update(status='PASS',elf_sha256=packed['elf_sha256'],new_default_fixture_source_sha256=mods['fixture']['source_sha256'],actual_current_sdk_compared=True,normal_protocol_versions=['2024-11-05','2025-11-25','2026-07-28'])
 except BaseException:report.update(status='FAIL',failure=traceback.format_exc());raise
 finally:report['elapsed_seconds']=time.monotonic()-start;save()
 print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()

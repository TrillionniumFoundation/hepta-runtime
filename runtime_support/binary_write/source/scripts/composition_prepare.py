"""Qualification-only actual Map/typed/planner preparation; no file policy."""
import contextlib,importlib.util,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'adapter/scripts'));sys.path.insert(0,str(ROOT/'adapter/dependency/scripts'))
from hia_native_loader import NativeModule
from common import PACK,WORD,start_wire
spec=importlib.util.spec_from_file_location('fixed_adapter_capture',ROOT/'adapter/scripts/capture_worker.py')
fixed=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixed)
from evidence_common import encoded,pin,require

class Preparer:
 def __init__(self,images,output):
  self.images=Path(images);self.output=Path(output);self.output.mkdir();self.stack=contextlib.ExitStack();self.rows=[]
  record=json.loads((self.images/'IMAGES.json').read_bytes())
  require(set(record['members'])=={'map','typed','planner','adapter'},'actual four fixed preparation images')
  modules={}
  for name,row in record['members'].items():
   manifest=self.images/row['manifest'];require(pin(manifest)==row['identity'],'actual preparation module manifest')
   modules[name]=self.stack.enter_context(NativeModule(manifest,manifest_sha256=row['identity']['sha256']))
  self.rec=fixed.Recorder(self.output,modules)
 def request(self,query,case,label):
  value={name:query[name]for name in('path','expected_version','data_base64')};value['host']='composition-fixture'
  raw=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
  result=fixed.typed_case(self.rec,raw,case,label)
  result.update(case_id=case,label=label,raw_json_hex=raw.hex(),planner_calls=[],request_hex=None)
  typed=bytes.fromhex(result['typed_frame'])if result['typed_frame']is not None else None
  if typed is not None and WORD(typed,8)==0:
   root=query['root'].encode();feedback=b'HRCFGM01'+PACK(0,0,len(root))+root
   wire=b'HBPLQ001'+PACK(2,0,len(typed),len(feedback),0)+typed+feedback
   code,ready,calls=self.rec.invoke('planner',wire,case,label+'-planner')
   require(code==len(ready) and ready[:8]==b'HBPLR001' and WORD(ready,8)==3,'original typed write produced no actual ready planner result')
   packet=start_wire(wire,ready)
   result.update(planner_calls=calls,planner_return=code,planner_request_hex=wire.hex(),ready_hex=ready.hex(),request_hex=packet.hex())
  else:packet=None
  self.rows.append(result)
  return packet,len(self.rows)
 def close(self):
  summary=self.rec.close();self.stack.close()
  (self.output/'PREPARED.json').write_bytes(encoded(self.rows))
  record=dict(schema='hepta.runtime.binary-write-composition-preparation.v1',images=pin(self.images/'IMAGES.json'),summary=summary,requests=len(self.rows),parent_effect_calls=0)
  (self.output/'PREPARATION.json').write_bytes(encoded(record));return record

"""Meaningful rejection controls over whole real development capture bytes."""
import base64,copy,hashlib,json,lzma,struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import read_composition as reader
from evidence_common import pin
FOLDER=ROOT/'inputs/reader-controls'

def load():
 origin=json.loads((FOLDER/'ORIGIN.json').read_bytes())
 for name,row in origin['files'].items():assert pin(FOLDER/name)==row
 raw=lzma.decompress((FOLDER/'CONTROL.json.xz').read_bytes())
 assert len(raw)==origin['decoded_control_bytes'] and hashlib.sha256(raw).hexdigest()==origin['decoded_control_sha256']
 value=json.loads(raw);assert value['qualification']is False and value['case']['input']['id']==0 and value['case']['lane']=='native-observed'
 value['pure_rows']=[dict(index=r['index'],head=bytes.fromhex(r['head']),payload=base64.b64decode(r['payload'],validate=True))for r in value['pure_rows']]
 value['prepared']={k:bytes.fromhex(v)for k,v in value['prepared'].items()};value['parent_input']=bytes.fromhex(value['parent_input'])
 return value

class Store:
 def __init__(self,data):self.data=data
 def get(self,ref):
  raw=base64.b64decode(self.data['buffer_bytes_base64'][ref['sha256']],validate=True)
  if len(raw)!=ref['bytes']or hashlib.sha256(raw).hexdigest()!=ref['sha256']:raise ValueError('whole immutable fixture buffer')
  return raw

def check(value):
 return reader.check_flow(value['pure_rows'],value['prepared'],Store(value),value['case'],value['parent_input'],value['parent_first'],value['parent_last'])

def word(raw,at,value):
 b=bytearray(raw);struct.pack_into('<Q',b,at,value);return bytes(b)

def rebind(value,label,offset,new):
 """Change bytes and every matching raw observation identity consistently.
 This ensures controls exercise semantic ownership, not a trivial hash error.
 """
 ref=value['case']['snapshots'][label]['bytes'];old=ref['sha256'];raw=Store(value).get(ref);raw=word(raw,offset,new);sha=hashlib.sha256(raw).hexdigest()
 replacement=dict(bytes=len(raw),sha256=sha,blocks=[hashlib.sha256(raw[i:i+4096]).hexdigest()for i in range(0,len(raw),4096)])
 value['buffer_bytes_base64'][sha]=base64.b64encode(raw).decode()
 def replace(v):
  if type(v)is dict:
   if set(v)=={'bytes','sha256','blocks'}and v['sha256']==old:v.clear();v.update(replacement)
   else:
    for child in v.values():replace(child)
  elif type(v)is list:
   for child in v:replace(child)
 replace(value['case'])

class CompositionDataTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.original=load()
 def fresh(self):return copy.deepcopy(self.original)
 def rejects(self,value):
  with self.assertRaises((ValueError,KeyError,IndexError,struct.error)):check(value)
 def test_00_complete_actual_four_entry_flow(self):
  self.assertEqual(check(self.fresh()),dict(calls=4,parent_started=True,adapter_released=True))
 def test_01_each_omitted_entry_rejected(self):
  for at in range(0,20,5):
   with self.subTest(at=at):
    v=self.fresh();del v['pure_rows'][at:at+5];self.rejects(v)
 def test_02_every_adjacent_span_reordering_rejected(self):
  for at in range(19):
   with self.subTest(at=at):
    v=self.fresh();v['pure_rows'][at],v['pure_rows'][at+1]=v['pure_rows'][at+1],v['pure_rows'][at];self.rejects(v)
 def test_03_fixed_owner_and_invocation_cannot_be_renamed(self):
  for at in range(0,20,5):
   for offset,new in((16,9),(24,2),(56,99)):
    with self.subTest(at=at,offset=offset):
     v=self.fresh()
     for r in v['pure_rows'][at:at+5]:r['head']=word(r['head'],offset,new)
     self.rejects(v)
 def test_04_exact_phase_sequence_and_borrow_flags(self):
  for at in range(0,20,5):
   for offset in(40,96,104,112,120):
    with self.subTest(at=at,offset=offset):
     v=self.fresh()
     for r in v['pure_rows'][at:at+5]:r['head']=word(r['head'],offset,reader.U(r['head'],offset)+1)
     self.rejects(v)
 def test_05_whole_input_of_every_owner_is_bound(self):
  for at in(0,5,10,15):
   with self.subTest(at=at):
    v=self.fresh();raw=bytearray(v['pure_rows'][at]['payload']);raw[-1]^=1;v['pure_rows'][at]['payload']=bytes(raw);self.rejects(v)
 def test_06_actual_planner_payload_cannot_match_only_a_header(self):
  v=self.fresh();raw=bytearray(v['pure_rows'][8]['payload']);raw[reader.U(v['pure_rows'][8]['head'],48)-2]^=1;v['pure_rows'][8]['payload']=bytes(raw);self.rejects(v)
 def test_07_parent_receives_whole_exact_adapter_packet(self):
  v=self.fresh();v['parent_input']=v['parent_input'][:-1]+bytes([v['parent_input'][-1]^1]);self.rejects(v)
 def test_08_parent_cannot_start_before_permission_or_outlive_release(self):
  for field,new in(('parent_first',1),('parent_last',1<<32)):
   v=self.fresh();v[field]=new;self.rejects(v)
 def test_09_all_workspace_bytes_are_owned(self):
  for at in(1,6,11,16):
   v=self.fresh();raw=bytearray(v['pure_rows'][at]['payload']);raw[-1]^=1;v['pure_rows'][at]['payload']=bytes(raw);self.rejects(v)
 def test_10_all_output_before_and_after_tails_are_owned(self):
  for at in(2,3,7,8,12,13,17,18):
   v=self.fresh();raw=bytearray(v['pure_rows'][at]['payload']);raw[-1]^=1;v['pure_rows'][at]['payload']=bytes(raw);self.rejects(v)
 def test_11_held_child_capabilities_and_actual_address_are_bound(self):
  for offset in(384,376,408,480,568,576,584):
   v=self.fresh();c=Store(v).get(v['case']['snapshots']['composition']['bytes']);rebind(v,'composition',offset,reader.U(c,offset)+1);self.rejects(v)
 def test_12_extra_release_mutation_cannot_hide_behind_valid_phase(self):
  for label,offset in(('composition_after_release',1000),('composition_after_release',192),('parent_after_release',272),('parent_after_release',1000),('adapter_after_release',1000)):
   v=self.fresh();rebind(v,label,offset,0x71);self.rejects(v)
 def test_13_context_address_cannot_be_reassigned_by_journal(self):
  v=self.fresh()
  for r in v['pure_rows']:r['head']=word(r['head'],80,reader.U(r['head'],80)+4096)
  self.rejects(v)
 def test_14_capacities_cannot_be_claimed_by_mutable_headers(self):
  for offset in(64,72,88):
   v=self.fresh()
   for r in v['pure_rows'][:5]:r['head']=word(r['head'],offset,reader.U(r['head'],offset)+1)
   self.rejects(v)
 def test_15_replayed_child_or_release_sequence_rejected(self):
  for at in(10,15):
   v=self.fresh();v['pure_rows'][at]['payload']=word(v['pure_rows'][at]['payload'],16,2);self.rejects(v)

class PreparationDataTests(unittest.TestCase):
 def make(self):
  p=reader.Prepared.__new__(reader.Prepared);p.folder=FOLDER;p.native,p.summary=reader.old.records(FOLDER);p.used=set();p.cursor=0;p.rows=json.loads((FOLDER/'PREPARED.json').read_bytes());p.receipt=json.loads((FOLDER/'PREPARATION.json').read_bytes());p.null_error=b'not used in the String fixture';return p
 def test_00_actual_preparation_all_calls_credited_once(self):
  p=self.make();v=load();query=v['case']['query']
  self.assertEqual(p.request(1,query,0,'native-observed',v['prepared']['start']),v['prepared'])
  query=dict(query,observer=False);p.request(2,query,0,'native-unobserved',v['prepared']['start']);self.assertEqual(p.finish(),p.receipt)
 def test_01_ordinal_case_label_and_actual_packet_bound(self):
  for changed in('ordinal','case','label','packet'):
   p=self.make();v=load();args=[1,v['case']['query'],0,'native-observed',v['prepared']['start']]
   if changed=='ordinal':args[0]=2
   elif changed=='case':args[2]=1
   elif changed=='label':args[3]='native-unobserved'
   else:args[4]=args[4][:-1]+bytes([args[4][-1]^1])
   with self.subTest(changed=changed),self.assertRaises(ValueError):p.request(*args)
 def test_02_another_valid_map_context_cannot_impersonate_the_input(self):
  p=self.make();v=load();p.rows[0]['value_calls']=p.rows[1]['value_calls']
  with self.assertRaises(ValueError):p.request(1,v['case']['query'],0,'native-observed',v['prepared']['start'])
 def test_03_mutable_planner_return_cannot_replace_actual_code(self):
  p=self.make();v=load();p.rows[0]['planner_return']+=1
  with self.assertRaises(ValueError):p.request(1,v['case']['query'],0,'native-observed',v['prepared']['start'])
 def test_04_missing_preparation_cannot_be_silently_uncredited(self):
  p=self.make();v=load();p.request(1,v['case']['query'],0,'native-observed',v['prepared']['start'])
  with self.assertRaises(ValueError):p.finish()
 def test_05_none_cannot_be_converted_to_absent_or_empty_string(self):
  p=self.make();v=load();query=dict(v['case']['query'],expected_version=None)
  with self.assertRaises(ValueError):p.request(1,query,0,'native-observed',v['prepared']['start'])

class MismatchDataTests(unittest.TestCase):
 def values(self):
  value=json.loads((ROOT/'inputs/actual-mismatch-frames.json').read_bytes());self.assertTrue(value['development_only'])
  return [(bytes.fromhex(row['actual_frame_hex']),bytes.fromhex(row['actual_child_hex']),row['sequence'],row['detail'])for row in value['rows']]
 def test_00_entire_actual_child_and_invalid_child_results(self):
  rows=self.values();self.assertGreater(len(rows[0][1]),64);self.assertEqual(rows[1][1],b'')
  for frame,child,seq,detail in rows:self.assertEqual(reader.mismatch_frame(frame,child,seq,detail),frame)
 def test_01_child_payload_cannot_be_dropped_or_substituted(self):
  frame,child,seq,detail=self.values()[0]
  for bad in(frame[:64],frame[:-1],frame+b'x',frame[:64]+child[:-1]+bytes([child[-1]^1])):
   with self.subTest(length=len(bad)),self.assertRaises(ValueError):reader.mismatch_frame(bad,child,seq,detail)
  with self.assertRaises(ValueError):reader.mismatch_frame(frame,b'',seq,detail)
 def test_02_complete_header_sequence_detail_extent_and_reserved_words(self):
  for frame,child,seq,detail in self.values():
   for offset in(0,8,16,24,32,40,48,56):
    raw=bytearray(frame);raw[offset]^=1
    with self.subTest(offset=offset),self.assertRaises(ValueError):reader.mismatch_frame(bytes(raw),child,seq,detail)

class CompleteDomainPartitionTests(unittest.TestCase):
 def values(self):
  import read_composition_source
  return read_composition_source.partition,json.loads((ROOT/'parent/DOMAIN.json').read_bytes())
 def test_00_complete_985_and_seven_original_lanes(self):
  partition,domain=self.values();result=partition(domain)
  self.assertEqual((len(result['original']),len(result['admitted']),len(result['typed_rejected'])),(992,985,7))
  self.assertEqual(sum(lane=='native-unobserved'for _,lane in result['admitted']),223)
  self.assertIn([244,'native-observed'],result['typed_rejected']);self.assertNotIn([244,'native-unobserved'],result['original'])
 def test_01_no_input_or_lane_can_be_omitted_or_reordered(self):
  for kind in('case-omit','case-reorder','lane-omit','lane-reorder'):
   partition,domain=self.values()
   if kind=='case-omit':domain['cases'].pop(100)
   elif kind=='case-reorder':domain['cases'][100],domain['cases'][101]=domain['cases'][101],domain['cases'][100]
   elif kind=='lane-omit':domain['lanes'].pop()
   else:domain['lanes'][0],domain['lanes'][1]=domain['lanes'][1],domain['lanes'][0]
   with self.subTest(kind=kind),self.assertRaises(ValueError):partition(domain)
 def test_02_original_fault_and_none_semantics_cannot_be_changed_to_match_a_count(self):
  for kind in('fault','none','drop-eligible-unobserved'):
   partition,domain=self.values()
   if kind=='fault':domain['cases'][244]['fault_plans']=[]
   elif kind=='none':domain['cases'][244]['expected_version']=''
   else:domain['cases'][0]['nofile']=1
   with self.subTest(kind=kind),self.assertRaises(ValueError):partition(domain)

if __name__=='__main__':unittest.main()

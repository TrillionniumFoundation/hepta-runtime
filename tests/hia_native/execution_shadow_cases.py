"""Independent data construction and Python comparison for original shadow records."""
import copy,hashlib,json,struct
CLASSES=['read_only_inspection','file_read','non_destructive_build','restricted_file_write','durable_process','privileged_action','cross_host_device']
CURRENT=['current','stale','unknown']
FIELDS=['run_id','turn_id','cell_id','organ_id','operation_id','principal','objective_digest','policy_digest','candidate_digest','host','idempotency_key','predecessor','rollback_reference','payload_digest']
ERRORS=['execution v1 schema or generation invalid','shadow protocol requires a current first intent with no predecessor','invalid execution identity','shadow execution must bind exactly one cell or organ','invalid canonical execution digest','invalid rollback reference','effectful proposal requires explicit rollback reference','execution record exceeds canonical byte budget']

def fixture():
 return {'schema_version':1,'generation':1,'class':0,'currentness':0,'run_id':'run-1','turn_id':'turn-1','cell_id':'cell-1','organ_id':None,'operation_id':'op-1','principal':'agent-1','objective_digest':'1'*64,'policy_digest':'2'*64,'candidate_digest':'3'*64,'host':'host-1','idempotency_key':'idem-1','predecessor':None,'rollback_reference':None,'payload_digest':'6'*64}

def packet(c):
 options=sum(bit for name,bit in [('cell_id',1),('organ_id',2),('predecessor',4),('rollback_reference',8)] if c[name] is not None)
 out=struct.pack('<8s7Q',b'HXSREC01',1,c['schema_version'],c['generation'],c['class'],c['currentness'],options,0)
 for name in FIELDS:
  raw=b'' if c[name] is None else c[name].encode('utf-8')
  out+=struct.pack('<Q',len(raw))+raw
 return out

def record(c):
 b={name:c[name] for name in ['schema_version','run_id','turn_id','cell_id','organ_id','operation_id','principal','objective_digest','policy_digest','candidate_digest','host','generation','idempotency_key','predecessor']}
 b.update(currentness=CURRENT[c['currentness']],final_use={'state':'not_granted'},rollback_reference=c['rollback_reference'])
 return {'kind':'execution_intent','record':{'binding':b,'class':CLASSES[c['class']],'payload_digest':c['payload_digest']}}

def text(s):return bool(s) and len(s.encode())<=256 and all(33<=ord(ch)<=126 for ch in s)
def digest(s):return len(s)==64 and any(ch!='0' for ch in s) and all(ch in '0123456789abcdef' for ch in s)
def diagnostic(c):
 if c['schema_version']!=1 or c['generation']==0:return ERRORS[0]
 if c['predecessor'] is not None or c['currentness']!=0:return ERRORS[1]
 if not all(text(c[n]) for n in ['run_id','turn_id','operation_id','principal','host','idempotency_key']):return ERRORS[2]
 if (c['cell_id'] is None)==(c['organ_id'] is None) or not text(c['cell_id'] if c['cell_id'] is not None else c['organ_id']):return ERRORS[3]
 if not all(digest(c[n]) for n in ['objective_digest','policy_digest','candidate_digest','payload_digest']):return ERRORS[4]
 if c['rollback_reference'] is not None and not text(c['rollback_reference']):return ERRORS[5]
 if c['class']>=2 and c['rollback_reference'] is None:return ERRORS[6]
 return None

def expected(c):
 error=diagnostic(c)
 if error:
  raw=error.encode();return struct.pack('<8s7Q',b'HXSRSL01',1,0,0,0,len(raw),0,0)+raw
 canonical=json.dumps(record(c),ensure_ascii=False,separators=(',',':')).encode()
 if len(canonical)>32768:
  raw=ERRORS[7].encode();return struct.pack('<8s7Q',b'HXSRSL01',1,0,0,0,len(raw),0,0)+raw
 hashed=hashlib.sha256(b'codex.execution-record.v1\0'+canonical).hexdigest().encode()
 response=json.dumps({'executable':False,'operation_id':c['operation_id'],'record_digest':hashed.decode(),'schema_version':1,'status':'shadow_only'},ensure_ascii=False,separators=(',',':')).encode()
 return struct.pack('<8s7Q',b'HXSRSL01',0,len(canonical),64,len(response),0,0,0)+canonical+hashed+response

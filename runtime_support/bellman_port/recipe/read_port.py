"""Read complete private Bellman port observations; never executes or writes."""
import argparse,collections,hashlib,json,pathlib,stat,struct,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from worker_projection import verify_projection,decode_body
INVALID=0xffffffff
DELIVERY=0xffffffcd
EXPECTED_ELF='b4a9ed3ad469e882be47a545346072c4347d35a85b9ace4484d60be1c535d55d'
EXPECTED_ASM='e889fb0d5a4470cad7a5a92e91fb5a3b3dd15c422da261210f653328bca7444e'
EXPECTED_WORKER='033876f0263be071c421723dea17d97dbcc188caa37c85506fd0c344cb547304'
WORKER_MAGICS={b'HBWPL001',b'HBCLOCK1',b'HBPWHLD1',b'HBWPEND1',b'HBWPROC1'}
PORT_MAGICS={b'HBPWIN01',b'HBPMSR01',b'HBPAC001',b'HBPAA001'}
def sha(b):return hashlib.sha256(b).hexdigest()
def get(b,o):return struct.unpack_from('<Q',b,o)[0]
def read(p):assert stat.S_ISREG(p.lstat().st_mode),str(p);return p.read_bytes()
def doc(p):return json.loads(read(p))
def words(b):assert len(b)%8==0;return struct.unpack('<'+'Q'*(len(b)//8),b)

def journal_records(path):
 size=path.stat().st_size;at=0
 with path.open('rb') as stream:
  while at<size:
   prefix=stream.read(16);assert len(prefix)==16,('partial journal header',at)
   magic=prefix[:8];extent=get(prefix,8)
   assert magic in WORKER_MAGICS|PORT_MAGICS and 16<=extent<=min(128<<20,size-at),(magic,extent)
   tail=stream.read(extent-16);assert len(tail)==extent-16
   if magic==b'HBWPL001':assert extent==256
   if magic==b'HBCLOCK1':assert extent==192
   if magic in {b'HBPWHLD1',b'HBWPROC1'}:assert extent==64
   if magic in {b'HBPAC001',b'HBPAA001'}:assert extent==144
   yield at,magic,prefix+tail;at+=extent
  assert at==size and stream.read(1)==b''

def verify(build,capture):
 component=doc(build/'component.json');packed=doc(build/'pack.receipt.json');elf=read(build/'bellman-port-packed.elf')
 assert sha(elf)==EXPECTED_ELF==component['executable_sha256']==packed['executable_sha256']
 assert len(elf)==component['executable_bytes']==packed['code'] and component['source_sha256']==EXPECTED_ASM
 assert packed['status']=='ACTUAL_HIA_PORT_PACK_PASS' and packed['public_handler_qualified'] is False
 assert read(build/'bellman-port.elf')==elf and sha(read(build/'source/runtime_mcp_bellman_port.S'))==EXPECTED_ASM
 assert read(build/'pack.output.bin')==elf+bytes([0xa5])*4096 and read(build/'pack.workspace.bin')==bytes([0x5a])*64
 members=sorted(component['members'].items(),key=lambda kv:kv[1]['offset']);images=[]
 assert [k for k,v in members]==['caller','params','diagnostic','worker']
 for name,row in members:
  image=elf[row['offset']:row['offset']+row['bytes']];assert len(image)==row['bytes'] and sha(image)==row['image_sha256'];images.append(image)
  if name=='worker':assert sha(image)==EXPECTED_WORKER
 assert read(build/'pack.input.bin')==b'HBLPPK01'+struct.pack('<5Q',*[len(i) for i in images],0)+b''.join(images)
 for name,filename in [('input','pack.input.bin'),('output','pack.output.bin'),('workspace','pack.workspace.bin')]:
  b=read(build/filename);assert packed[name]=={'bytes':len(b),'sha256':sha(b)}
 process=doc(capture.parent/'process.json');assert process['started'] is True and process['timed_out'] is False and process['returncode']==0
 assert process['timeout_seconds']==60 and 0<=process['elapsed_ns']<=60_000_000_000
 assert process['pid']==process['pgid'] and process['pid']>0 and process['parent_pid']>0
 command=process['command'];assert len(command)==9 and command[1:4]==['-I','-S','-B'] and pathlib.Path(command[4]).name=='lifecycle_port.py' and command[5]=='--build' and command[7]=='--output' and pathlib.Path(command[8]).name=='capture'
 for name in ['stdout','stderr']:
  b=read(capture.parent/name);assert process[name]=={'bytes':len(b),'sha256':sha(b)}
 assert read(capture.parent/'stderr')==b''
 result=doc(capture/'RESULT.json');assert result['status']=='ACTUAL_NATIVE_PORT_LIFECYCLE_PASS'
 assert result['timeout_seconds']==60 and 0<=result['elapsed_seconds']<=60
 assert result['executable_sha256']==EXPECTED_ELF and result['source_sha256']==EXPECTED_ASM and result['public_handler_qualified'] is False
 assert json.loads(read(capture.parent/'stdout'))=={k:v for k,v in result.items() if k not in ('groups','controls')}
 seen={};blob_values={}
 def blob(pin):
  assert type(pin) is dict and set(pin)=={'bytes','sha256'} and type(pin['bytes']) is int and pin['bytes']>=0
  h=pin['sha256'];assert type(h) is str and len(h)==64 and all(c in '0123456789abcdef' for c in h)
  if h not in blob_values:
   raw=read(capture/'blobs'/h);assert sha(raw)==h;blob_values[h]=raw
  raw=blob_values[h];assert len(raw)==pin['bytes'];seen[h]=pin;return raw
 rows=[json.loads(line) for line in read(capture/'calls.jsonl').splitlines()]
 assert rows and rows[0]['phase']=='identity';identity=rows[0]
 assert identity['pid']==process['pid'] and identity['pgid']==process['pgid'] and identity['parent_pid']==process['parent_pid']
 assert identity['executable_sha256']==EXPECTED_ELF
 assert blob(identity['component'])==read(build/'component.json') and blob(identity['pack_receipt'])==read(build/'pack.receipt.json')
 engine_addresses=[];last=None;begins={};ends={};wires={};ready_views=[];stops=[];resumes=[];active=None
 def snapshot(s):
  assert set(s)=={'context','engines','rows','ready'} and len(s['engines'])==len(engine_addresses)
  engines=[blob(x) for x in s['engines']]
  for i,b in enumerate(engines):
   assert len(b)==16384 and b[40:48]==b'HRGENG02' and get(b,8)==engine_addresses[i]+8192
  if s['context'] is None:assert not s['rows'] and not s['ready'];return
  c=blob(s['context']);assert len(c)==4096 and c[:8]==b'HRBPCT01' and get(c,16)==process['pid'] and get(c,40)==0
  assert get(c,32) in (1,2) and get(c,56)==len(s['rows']) and c[120:128]==bytes(8) and c[160:192]==bytes(32) and c[256:]==bytes(3840)
  pointers=[r['address'] for r in s['rows']];assert len(set(pointers))==len(pointers)
  assert get(c,48)==(pointers[0] if pointers else 0)
  for i,row in enumerate(s['rows']):
   r=blob(row['state']);assert len(r)==4096 and r[:8]==b'HBLROW01' and r[192:]==bytes(3904)
   assert get(r,8)==(pointers[i+1] if i+1<len(pointers) else 0)
   assert get(r,16) in engine_addresses and 0<get(r,24)<=get(c,24) and get(r,32) in (0,1,2) and get(r,40)<=4
   assert set(row['buffers'])=={'48','72','88','120','136','152','168'}
   for off in [48,72,88,120,136,152,168]:
    pointer,size=get(r,off),get(r,off+8);assert size<=256<<20 and bool(pointer)==bool(size)
    if pointer:assert len(blob(row['buffers'][str(off)]))==size
    else:assert row['buffers'][str(off)] is None
   assert get(r,64)<=get(r,56)
   if get(r,72):
    work=blob(row['buffers']['72']);assert work[:8]==b'HBLCST01' and get(work,24)==get(r,24)
   if get(r,88):
    out=blob(row['buffers']['88']);assert out[:8]==b'HBLCLR01' and get(out,8)==get(r,40) and get(out,16)==get(r,24) and 64+get(out,32)<=len(out) and out[40:64]==bytes(24)
  pointers=[r['address'] for r in s['ready']];assert len(set(pointers))==len(pointers)
  assert get(c,64)==(pointers[0] if pointers else 0) and get(c,72)==(pointers[-1] if pointers else 0)
  assert get(c,112) in ([0,pointers[0]] if pointers else [0])
  for i,row in enumerate(s['ready']):
   b=blob(row['state']);assert len(b)==4096 and get(b,0)==(pointers[i+1] if i+1<len(pointers) else 0)
   assert get(b,8)==192 and b[24:32]==bytes(8) and b[32:40]==b'HBPMSR01' and get(b,48)==2 and b[224:]==bytes(3872)
   assert get(b,16)<=get(c,104)
 for row in rows[1:]:
  phase=row['phase']
  if phase=='engine':
   assert active is None and row['index']==len(engine_addresses);engine_addresses.append(row['address'])
   initial=blob(row['before']);assert len(initial)==16384 and get(initial,8)==row['address']+8192 and initial[40:48]==b'HRGENG02'
   adjusted=dict(last);adjusted['engines']=list(last['engines'])+[row['before']];last=adjusted
  elif phase=='begin':
   assert active is None and row['call']==len(begins);active=row['call'];snapshot(row['before'])
   if last is not None:assert row['before']==last,('unobserved owned-state mutation',active)
   assert 0<=row['journal_bytes']<=(capture/'journal.bin').stat().st_size;begins[active]=row
  elif phase=='end':
   assert row['call']==active and row['name']==begins[active]['name'];snapshot(row['after']);ends[active]=row
   assert begins[active]['journal_bytes']<=row['journal_bytes']<=(capture/'journal.bin').stat().st_size
   last=row['after'];active=None
  elif phase=='wire':
   index=row['call'];assert active is None and index in ends and index not in wires and begins[index]['name']=='invoke'
   wire=blob(row['input']);before=blob(row['input_full_before']);after=blob(row['input_full_after']);out=blob(row['output']);descriptor=blob(row['descriptor'])
   assert before==after==wire+bytes([0xd6])*8 and row['code']==ends[index]['return'] and len(descriptor)==64
   engine=blob(ends[index]['after']['engines'][row['engine']]);assert engine[8192+57*64:8192+58*64]==descriptor
   if row['code'] in (32,64):assert get(descriptor,48)==row['code'] and get(descriptor,56)==len(out)<=get(descriptor,40)
   else:assert out==b''
   wires[index]=(row,wire,out)
  elif phase=='ready':
   index=row['call'];assert active is None and index in ends and begins[index]['name']=='ready_receive' and row['code']==ends[index]['return']
   before=blob(row['before']);after=blob(row['after']);event=blob(row['event']);assert before==bytes([0xa5])*40
   if row['code']==32:
    assert after[:8]==b'HBRPBR01' and get(after,16)==len(event)==192 and get(after,24)==row['token'] and after[32:]==bytes([0xa5])*8
    assert event[:8]==b'HBPMSR01' and get(event,16)==2;ready_views.append(event)
   else:assert after==before and event==b'' and row['token']==0
  elif phase=='stop':
   assert active is None and row['signal']==19 and row['pgid']==process['pgid'] and row['first_clock_observed'] is True
   status=blob(row['actual_status']);assert any(line.startswith(b'State:') and b'T' in line for line in status.splitlines())
   assert b'Pid:\t'+str(row['pid']).encode()+b'\n' in status;stops.append(row)
  elif phase=='resume':assert active is None and row['signal']==18;resumes.append(row)
  else:raise AssertionError(('unknown observation',phase))
 assert active is None and len(begins)==len(ends)==result['export_calls'] and last['context'] is None
 assert set(wires)=={i for i,b in begins.items() if b['name']=='invoke'}
 assert len(engine_addresses)==result['engines']==2 and len(stops)==len(resumes)==3
 assert [s['pid'] for s in stops]==[r['pid'] for r in resumes] and len({s['pid'] for s in stops})==3
 # Each returned and acknowledged continuation is complete. Mode 1 has no
 # worker control and must deliver the previous immutable result exactly once.
 requests=[];outputs=[];action=None;actions=[];sequences={};pending={};events=[];pool_controls=[]
 for at,magic,b in journal_records(capture/'journal.bin'):
  if magic==b'HBPAC001':
   assert action is None;tag,job=get(b,16),get(b,24);d=words(b[32:]);assert b[32:40]==b'HBLCAC01' and d[1]>0 and d[2]<=2 and d[3]<=1 and d[8:]==(0,)*6
   if d[3]==0:assert d[1]>sequences.get(tag,0);sequences[tag]=d[1]
   else:assert tag in pending and (d[1],d[2],d[5])==pending[tag][:3]
   action={'before':b,'offset':at,'requests':[],'outputs':[]};actions.append(action)
  elif magic==b'HBPWIN01':
   req=b[16:];assert len(req)>=64 and req[:8]==b'HBWKRQ01' and len(req)==64+get(req,40)
   assert get(req,8) in (1,2,3,4) and get(req,32)==get(req,48)==get(req,56)==0
   assert action is not None and get(action['before'],48)==2 and get(action['before'],56)==0
   assert get(req,16)==get(action['before'],16);requests.append(req);action['requests'].append(req)
  elif magic==b'HBPMSR01':
   outputs.append(b);events.append(b)
   if get(b,16)==1:assert action is not None;action['outputs'].append(b)
  elif magic==b'HBPAA001':
   assert action is not None;before=action['before'];d=words(before[32:]);ack=words(b[32:])
   assert get(b,16)==get(before,16) and b[32:96]==before[32:96] and ack[8]==d[1] and ack[10:12]==(0,0) and ack[13]==0 and ack[12]>0
   assert ack[9]==(ack[12] if ack[12]<=ack[7] else DELIVERY)
   tag=get(b,16)
   if d[3]==1:
    assert not action['requests'] and not action['outputs'] and ack[12]==pending[tag][3]
   elif d[2]==2:
    assert len(action['requests'])==len(action['outputs'])==1
    response=action['outputs'][0];req=action['requests'][0]
    assert get(response,24)==tag and (get(req,8)==1 or get(response,32)==get(req,24))
    assert ack[12]==len(response)
   else:assert not action['requests'] and not action['outputs']
   if ack[9]==DELIVERY:pending[tag]=(d[1],d[2],d[5],ack[12])
   else:pending.pop(tag,None)
   action['after']=b;action['end']=at+len(b);action=None
  elif magic==b'HBWPL001':pool_controls.append(b)
 assert action is None and not pending
 assert ready_views==[b for b in outputs if get(b,16)==2]
 worker=verify_projection(requests,outputs,((m,b) for _,m,b in journal_records(capture/'journal.bin') if m in WORKER_MAGICS),process['pid'])
 assert worker['jobs']==worker['physical_clones']==worker['physical_reaps']==result['worker_jobs']==4
 assert worker['successful_complete_without_take']==2 and worker['held_jobs']==0
 assert len(ready_views)==result['ready']==4
 assert len(requests)==13 and sum(get(x['before'],56)==1 and get(x['before'],48)==2 for x in actions)==1
 assert collections.Counter((get(a['before'],48),get(a['before'],56)) for a in actions)=={(0,0):7,(0,1):6,(1,0):1,(2,0):13,(2,1):1}
 # Bind every port continuation to its one observed host turn, not a summary.
 for action in actions:
  owners=[i for i,b in begins.items() if b['name']=='invoke' and b['journal_bytes']<=action['offset'] and action['end']<=ends[i]['journal_bytes']]
  assert len(owners)==1;row,wire,out=wires[owners[0]];assert wire[:8]==b'HBLCLQ01' and get(wire,16)==get(action['before'],16)
 taken={get(b,32):decode_body(b[192:]) for b in outputs if get(b,16)==1 and get(b,48)}
 tags={};retired=set();groups=result['groups'];control_labels=[]
 for index,(row,wire,out) in wires.items():
  label=begins[index]['label']
  if row['code']==32 and wire[:8]==b'HBLTAG01':
   tag=get(out,8);assert out[:8]==b'HBLTGR01' and out[16:]==bytes(16) and tag==len(tags)+1;tags[tag]=row['engine']
  elif row['code']==32 and wire[:8]==b'HBLRET01':
   tag=get(wire,16);assert tag in tags and tag not in retired and tags[tag]==row['engine'] and out==b'HBLRTR01'+struct.pack('<3Q',tag,0,0);retired.add(tag)
  elif row['code']==64:
   tag=get(wire,16);assert wire[:8]==b'HBLCLQ01' and tag in tags and tag not in retired and tags[tag]==row['engine']
   assert out[:8]==b'HBLCLR01' and get(out,16)==tag and len(out)==64+get(out,32) and out[40:64]==bytes(24)
   status=get(out,8)
   if status==0:assert get(out,24) in taken and out[64:]==taken[get(out,24)][1][2][64:]
   elif status==1:assert tag==4 and out[64:]==b'failed to deserialize parameters: missing field `states`'
   elif status==2:assert tag in (3,5) and out[64:]==b'native Bellman planning capacity exhausted; no work admitted'
   elif status==3:assert tag in (1,2,6,7) and len(out)==64 and get(out,24)>0
   elif status==4:assert tag in (1,7) and len(out)==64
   else:raise AssertionError(('caller status',status))
  if label and label.startswith('reject-'):control_labels.append(label[7:])
 assert set(tags)==retired==set(range(1,8)) and result['private_tags']==7
 assert [get(e,32) for e in ready_views]==[1,3,2,4]
 assert [g['name'] for g in groups]==['shared-two-permits-and-cancel-retention','complete-ready-fifo-borrow','one-pool-result-capacity-delivery','shutdown-drain-after-detach']
 assert groups[0]['jobs']==[1,2] and groups[0]['stops']==[{k:v for k,v in s.items() if k!='phase'} for s in stops[:2]]
 cancel=blob(groups[0]['cancelled']);assert cancel in outputs and get(cancel,112)==get(cancel,120)==1 and get(cancel,160)==2
 assert blob(groups[1]['event'])==ready_views[0] and groups[1]['token']==1
 assert groups[2]['small_job']==3 and groups[2]['wide_job']==2 and blob(groups[2]['wide_result'])[64:]==taken[2][1][2][64:]
 assert groups[3]['job']==4 and groups[3]['stop']=={k:v for k,v in stops[2].items() if k!='phase'}
 assert result['control_count']==len(result['controls'])==29 and len(set(result['controls']))==29
 expected_controls=['empty','short-magic','short-header','trailing','magic']+['word-'+str(i) for i in range(8,64,8)]+['foreign-engine-tag','unstarted-poll','unstarted-cancel','duplicate-start','duplicate-cancel','retired-poll','borrow-service','borrow-attach','borrow-detach','borrow-shutdown','borrow-destroy','borrow-receive','borrow-invoke','wrong-ready-token','released-ready-token','detached-engine','closed-allocation']
 assert result['controls']==expected_controls
 seed=b'HBLTAG01'+struct.pack('<7Q',1,0,0,0,0,0,0)
 bad={'reject-empty':b'','reject-short-magic':seed[:7],'reject-short-header':seed[:63],'reject-trailing':seed+b'x','reject-magic':b'X'+seed[1:]}
 for offset in range(8,64,8):
  altered=bytearray(seed);struct.pack_into('<Q',altered,offset,2 if offset==8 else 1);bad['reject-word-'+str(offset)]=bytes(altered)
 bad.update({'foreign-engine-tag':b'HBLCLQ01'+struct.pack('<7Q',2,1,0,0,0,0,0),'unstarted-poll':b'HBLCLQ01'+struct.pack('<7Q',2,1,0,0,0,0,0),'unstarted-cancel':b'HBLCLQ01'+struct.pack('<7Q',3,1,0,0,0,0,0),'duplicate-cancel':b'HBLCLQ01'+struct.pack('<7Q',3,1,0,0,0,0,0),'retired-poll':b'HBLCLQ01'+struct.pack('<7Q',2,1,0,0,0,0,0),'detached-engine':b'HBLCLQ01'+struct.pack('<7Q',2,2,0,0,0,0,0),'closed-allocation':seed,'borrow-invoke':seed})
 witnessed=set()
 for index,(row,wire,out) in wires.items():
  label=begins[index]['label']
  if label in bad:assert label not in witnessed and wire==bad[label] and row['code']==INVALID;witnessed.add(label)
 assert witnessed==set(bad)
 for index,b in begins.items():
  r=ends[index]['return'];before=b['before'];after=ends[index]['after'];label=b['label']
  if b['name'] in {'service','attach','detach','shutdown','destroy','ready_receive','ready_release'} and r in (INVALID,0xfffffffe,0xfffffff8):assert before==after,('refusal changed owned buffers',index)
  if label=='borrow-invoke':assert before==after
  if b['name']=='wake_fd':assert before==after
 # Every physical blob must be accounted for; foreign files and truncated
 # streams do not become invisible behind an otherwise plausible PASS JSON.
 assert {p.name for p in (capture/'blobs').iterdir()}==set(seen)
 assert {p.name for p in capture.iterdir()}=={'blobs','calls.jsonl','journal.bin','RESULT.json'}
 return {'status':'READ_ONLY_PORT_PASS','worker':worker,'export_calls':len(begins),'runtime_hia_images':8,'actions':len(actions),'mode1_actions':sum(get(a['before'],56)==1 for a in actions),'actual_worker_controls':len(requests),'ready':len(ready_views),'private_tags':len(tags),'engines':len(engine_addresses),'full_blobs':len(seen),'full_blob_bytes':sum(p['bytes'] for p in seen.values()),'journal_bytes':(capture/'journal.bin').stat().st_size,'process_seconds':process['elapsed_ns']/1e9,'public_handler_qualified':False,'native_or_rust_executed':False}

def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=pathlib.Path,required=True);p.add_argument('--capture',type=pathlib.Path,required=True);a=p.parse_args()
 print(json.dumps(verify(a.build,a.capture),sort_keys=True))
if __name__=='__main__':main()

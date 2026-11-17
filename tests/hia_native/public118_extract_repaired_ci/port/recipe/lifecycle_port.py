"""Actual shared-port lifecycle with held owned workers and immutable control wire."""
import argparse,ctypes,json,os,pathlib,sys,time,traceback
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from port_transport import Port,pack,get,put,INVALID,BUSY,CAPACITY

BUSY_TEXT=b'native Bellman planning capacity exhausted; no work admitted'
def payload(count):
 return json.dumps({'states':[{'actions':[{'kind':'terminal','value':2.5},None,None,None,None,None]} for _ in range(count)]},separators=(',',':'),sort_keys=True).encode()

def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
 port=Port(a.build,a.output);groups=[];controls=[];start=time.monotonic()
 try:
  port.create();e1=port.engine();e2=port.engine();assert port.call('wake_fd',[port.ctx])>=3
  # Rejections retain complete engine/context/row buffers and each entire input.
  seed=pack(b'HBLTAG01',1,0,0,0,0,0,0)
  bad=[('empty',b''),('short-magic',seed[:7]),('short-header',seed[:63]),('trailing',seed+b'x'),('magic',b'X'+seed[1:])]
  for offset in range(8,64,8):
   changed=bytearray(seed);changed[offset:offset+8]=(2 if offset==8 else 1).to_bytes(8,'little');bad.append(('word-'+str(offset),bytes(changed)))
  for name,wire in bad:
   r,d=port.invoke(e1,wire,label='reject-'+name);assert r==INVALID and not d;controls.append(name)
  t1=port.allocate(e1);t2=port.allocate(e2);assert (t1,t2)==(1,2)
  port.command(e2,2,t1,expected=INVALID,label='foreign-engine-tag');controls.append('foreign-engine-tag')
  port.command(e1,2,t1,expected=INVALID,label='unstarted-poll');controls.append('unstarted-poll')
  port.command(e1,3,t1,expected=INVALID,label='unstarted-cancel');controls.append('unstarted-cancel')
  wide=payload(4096);small=payload(1)
  d1=port.command(e1,1,t1,wide,label='first-running');assert get(d1,8)==3;j1=get(d1,24);pid1,stop1=port.stop_after_clock(j1)
  d2=port.command(e2,1,t2,wide,label='second-running');assert get(d2,8)==3;j2=get(d2,24);pid2,stop2=port.stop_after_clock(j2)
  assert j1!=j2 and pid1!=pid2
  t3=port.allocate(e1);d=port.command(e1,1,t3,small,label='third-rejected');assert get(d,8)==2 and d[64:]==BUSY_TEXT;port.retire(e1,t3)
  t4=port.allocate(e2);before=port.last_control();d=port.command(e2,1,t4,b'{}',label='typed-before-busy');assert get(d,8)==1 and d[64:]==b'failed to deserialize parameters: missing field `states`';assert port.last_control()==before;port.retire(e2,t4)
  d=port.command(e1,2,t1,label='running-poll');assert get(d,8)==3
  port.retire(e1,t1,expected=BUSY);assert port.call('detach',[port.ctx,ctypes.addressof(e1)])==BUSY
  assert port.call('destroy',[port.ctx])==BUSY
  port.command(e1,1,t1,small,expected=INVALID,label='duplicate-start');controls.append('duplicate-start')
  d=port.command(e1,3,t1,label='cancel-running');assert get(d,8)==4 and len(d)==64
  cancelled=port.last_control();assert get(cancelled,112)==1 and get(cancelled,120)==1 and get(cancelled,160)==2
  port.command(e1,3,t1,expected=INVALID,label='duplicate-cancel');controls.append('duplicate-cancel');port.retire(e1,t1)
  port.command(e1,2,t1,expected=INVALID,label='retired-poll');controls.append('retired-poll')
  t5=port.allocate(e1);d=port.command(e1,1,t5,small,label='cancelled-still-full');assert get(d,8)==2 and d[64:]==BUSY_TEXT;port.retire(e1,t5)
  groups.append({'name':'shared-two-permits-and-cancel-retention','stops':[stop1,stop2],'jobs':[j1,j2],'cancelled':port.blob(cancelled)})
  port.resume(pid1)
  # Leave the first READY borrowed while testing every mutating host entry.
  deadline=time.monotonic()+30
  while not port.service():assert time.monotonic()<deadline;time.sleep(.001)
  port.receive(31,expected=CAPACITY);r,event,token=port.receive(32,expected=32);assert get(event,32)==j1
  before=port.snapshot()
  for name,args in [('service',[port.ctx]),('attach',[port.ctx,ctypes.addressof(e1)]),('detach',[port.ctx,ctypes.addressof(e2)]),('shutdown',[port.ctx]),('destroy',[port.ctx])]:
   assert port.call(name,args,label='borrow-refusal')==INVALID;assert port.snapshot()==before;controls.append('borrow-'+name)
  port.receive(32,expected=INVALID);assert port.snapshot()==before;controls.append('borrow-receive')
  r,_=port.invoke(e1,seed,label='borrow-invoke');assert r==INVALID and port.snapshot()==before;controls.append('borrow-invoke')
  port.release(token+1,expected=INVALID);assert port.snapshot()==before;controls.append('wrong-ready-token')
  assert port.call('wake_fd',[port.ctx])>=3 and port.snapshot()==before
  port.release(token);port.release(token,expected=INVALID);controls.append('released-ready-token')
  groups.append({'name':'complete-ready-fifo-borrow','event':port.blob(event),'token':token})
  t6=port.allocate(e1);d=port.command(e1,1,t6,small,label='permit-reused-after-complete');assert get(d,8)==3;j3=get(d,24)
  port.wait_ready(j3);d=port.command(e1,2,t6,label='take-small');assert get(d,8)==0 and len(json.loads(d[64:]))==36;port.retire(e1,t6)
  port.resume(pid2);port.wait_ready(j2);d=port.command(e2,2,t2,label='take-wide');assert get(d,8)==0 and len(json.loads(d[64:])['states'])==4096;port.retire(e2,t2)
  groups.append({'name':'one-pool-result-capacity-delivery','small_job':j3,'wide_job':j2,'wide_result':port.blob(d)})
  assert port.call('detach',[port.ctx,ctypes.addressof(e2)])==0
  port.command(e2,2,t2,expected=INVALID,label='detached-engine');controls.append('detached-engine')
  t7=port.allocate(e1);d=port.command(e1,1,t7,wide,label='shutdown-running');assert get(d,8)==3;j4=get(d,24);pid4,stop4=port.stop_after_clock(j4)
  assert port.call('shutdown',[port.ctx])==0
  d=port.command(e1,3,t7,label='shutdown-caller-retirement');assert get(d,8)==4;port.retire(e1,t7)
  r,_=port.invoke(e1,seed,label='closed-allocation');assert r==INVALID;controls.append('closed-allocation')
  assert port.call('detach',[port.ctx,ctypes.addressof(e1)])==0
  assert port.call('destroy',[port.ctx])==BUSY
  port.resume(pid4);port.wait_ready(j4)
  assert port.call('destroy',[port.ctx])==0
  groups.append({'name':'shutdown-drain-after-detach','stop':stop4,'job':j4})
  assert [get(e,32) for e in port.events]==[j1,j3,j2,j4]
  elapsed=time.monotonic()-start;assert elapsed<60
  result={'status':'ACTUAL_NATIVE_PORT_LIFECYCLE_PASS','groups':groups,'controls':controls,'control_count':len(controls),'engines':2,'private_tags':7,'worker_jobs':4,'ready':4,'export_calls':port.calls,'elapsed_seconds':elapsed,'timeout_seconds':60,'executable_sha256':port.component['executable_sha256'],'source_sha256':port.component['source_sha256'],'public_handler_qualified':False}
  put(a.output/'RESULT.json',result);print(json.dumps({k:v for k,v in result.items() if k not in ('groups','controls')},sort_keys=True))
 finally:port.close()
if __name__=='__main__':
 try:main()
 except BaseException:
  traceback.print_exc();sys.stderr.flush();os._exit(1)

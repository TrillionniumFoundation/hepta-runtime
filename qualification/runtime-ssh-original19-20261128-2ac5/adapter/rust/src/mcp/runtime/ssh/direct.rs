#![allow(dead_code)]
use anyhow::{anyhow, bail, Result};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;
use tokio::sync::{oneshot, Mutex as AsyncMutex, Notify};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const QUEUED:u8=0;
const CANCELLED:u8=1;
const COMMITTED:u8=2;
const REAP:Duration=Duration::from_secs(3);
type Entry=Box<dyn FnOnce()->Result<Box<dyn Send>>+Send>;

#[link(name="ssh_original19",kind="static")]
unsafe extern "C" {
 fn ssh_direct_owner_create(observer:usize,opaque:usize)->isize;
 fn ssh_direct_owner_freeze(ctx:usize)->isize;
 fn ssh_direct_owner_shutdown(ctx:usize)->isize;
 fn ssh_direct_join_result(ctx:usize)->isize;
 fn ssh_direct_submit(ctx:usize,frame:*const u8,flen:usize,input:*const u8,ilen:usize,options:*const u64)->isize;
 fn ssh_direct_cancel(request:usize)->isize;
 fn ssh_direct_result(request:usize,result:*mut u64)->isize;
 fn ssh_direct_capture_result(request:usize,result:*mut u64)->isize;
 fn ssh_direct_request_release(request:usize);
 fn ssh_direct_request_phase(request:usize)->usize;
 fn ssh_direct_owner_gate_lock(ctx:usize)->isize;
 fn ssh_direct_owner_gate_unlock(ctx:usize);
 fn ssh_direct_owner_state_lock(ctx:usize)->usize;
 fn ssh_direct_owner_state_unlock(ctx:usize);
 fn ssh_qa_request_retain(request:usize);
 fn ssh_qa_request_drop(request:usize);
 fn ssh_qa_hidden_cleanup(request:usize)->isize;
 fn ssh_qa_hidden_release(request:usize)->isize;
 fn ssh_qa_observer();
 fn ssh_qa_entry();
 fn ssh_qa_entry_drop();
 fn ssh_qa_guard_drop();
}
unsafe fn word(base:usize,off:usize)->u64 {
 unsafe { ((base+off) as *const AtomicU64).as_ref().unwrap().load(Ordering::Acquire) }
}
unsafe fn atomic32(base:usize,off:usize)->u32 {
 unsafe { ((base+off) as *const AtomicU32).as_ref().unwrap().load(Ordering::Acquire) }
}
fn futex_wake(p:&AtomicU32) {
 unsafe {libc::syscall(libc::SYS_futex,p as *const AtomicU32,libc::FUTEX_WAKE|libc::FUTEX_PRIVATE_FLAG,i32::MAX,0,0,0);}
}
fn futex_wait(p:&AtomicU32,value:u32) {
 unsafe {libc::syscall(libc::SYS_futex,p as *const AtomicU32,libc::FUTEX_WAIT|libc::FUTEX_PRIVATE_FLAG,value,0,0,0);}
}

#[derive(Clone,Copy)]
enum Stdio { Inherit, Pipe, Null }
impl Stdio {fn piped()->Self {Self::Pipe} fn null()->Self{Self::Null} }
struct Command {program:OsString,args:Vec<OsString>,stdio:[Stdio;3]}
impl Command {
 fn new<S:AsRef<OsStr>>(s:S)->Self { Self{program:s.as_ref().to_owned(),args:vec![],stdio:[Stdio::Inherit;3]} }
 fn arg<S:AsRef<OsStr>>(&mut self,s:S)->&mut Self {self.args.push(s.as_ref().to_owned());self}
 fn args<I,S>(&mut self,x:I)->&mut Self where I:IntoIterator<Item=S>,S:AsRef<OsStr> {for s in x{self.arg(s);}self}
 fn stdin(&mut self,s:Stdio)->&mut Self {self.stdio[0]=s;self}
 fn stdout(&mut self,s:Stdio)->&mut Self {self.stdio[1]=s;self}
 fn stderr(&mut self,s:Stdio)->&mut Self {self.stdio[2]=s;self}
 fn kill_on_drop(&mut self,_enabled:bool)->&mut Self {self}
 fn frame(&self)->Result<Vec<u8>> {
  let executable=if self.program.as_bytes().contains(&b'/') {self.program.clone()}else{
   let path=std::env::var_os("PATH").unwrap_or_default();
   let mut selected=None;
   for root in std::env::split_paths(&path) {
    let candidate=root.join(&self.program);
    let c=std::ffi::CString::new(candidate.as_os_str().as_bytes())?;
    if unsafe{libc::access(c.as_ptr(),libc::X_OK)}==0 {selected=Some(candidate.into_os_string());break}
   }
   selected.ok_or_else(||anyhow!("fixture executable is absent from actual PATH"))?
  };
  let mut argv=vec![self.program.as_bytes().to_vec()];
  argv.extend(self.args.iter().map(|v|v.as_bytes().to_vec()));
  let env:Vec<Vec<u8>>=std::env::vars_os().map(|(k,v)|{let mut b=k.as_bytes().to_vec();b.push(b'=');b.extend_from_slice(v.as_bytes());b}).collect();
  let mut flags=0u64;
  for (i,s) in self.stdio.iter().enumerate(){match s {Stdio::Pipe=>flags|=1<<i,Stdio::Null=>flags|=1<<(i+3),Stdio::Inherit=>{}}}
  let mut b=vec![0u8;64];b[..8].copy_from_slice(b"HSDCMD01");
  b[8..16].copy_from_slice(&(executable.as_bytes().len() as u64).to_le_bytes());
  b[16..24].copy_from_slice(&(argv.len() as u64).to_le_bytes());
  b[24..32].copy_from_slice(&(env.len() as u64).to_le_bytes());
  b[32..40].copy_from_slice(&flags.to_le_bytes());
  for raw in std::iter::once(executable.as_bytes()).chain(argv.iter().map(Vec::as_slice)).chain(env.iter().map(Vec::as_slice)) {if raw.contains(&0){bail!("NUL in mechanical exec frame")}}
  b.extend_from_slice(executable.as_bytes());b.push(0);
  for raw in argv.iter().chain(env.iter()) {b.extend_from_slice(&(raw.len()as u64).to_le_bytes());b.extend_from_slice(raw);b.push(0);}
  let n=b.len()as u64;b[40..48].copy_from_slice(&n.to_le_bytes());Ok(b)
 }
}

struct CancelState {request:usize,cancelled:bool}
impl Drop for CancelState {fn drop(&mut self){if self.request!=0 {unsafe{ssh_qa_request_drop(self.request)}}}}
struct Phase {state:Arc<Mutex<CancelState>>}
impl Phase {fn load(&self,_order:Ordering)->u8{let s=self.state.lock().unwrap();if s.request==0{if s.cancelled{CANCELLED}else{QUEUED}}else{unsafe{ssh_direct_request_phase(s.request)as u8}}}}
struct Cancellation {
 token:CancellationToken,
 phase:Phase,
 state:Arc<Mutex<CancelState>>,
 outer:AtomicBool,
}
impl Cancellation {
 fn new()->Arc<Self> {
  let state=Arc::new(Mutex::new(CancelState{request:0,cancelled:false}));
  Arc::new(Self{token:CancellationToken::new(),phase:Phase{state:state.clone()},state,outer:AtomicBool::new(false)})
 }
 fn cancel(&self) {
  let mut s=self.state.lock().unwrap();s.cancelled=true;
  if s.request!=0 {unsafe{ssh_direct_cancel(s.request);}}
  self.token.cancel();
 }
 fn bind(&self,r:usize) {
  let mut s=self.state.lock().unwrap();assert_eq!(s.request,0);
  unsafe{ssh_qa_request_retain(r);}
  s.request=r;
  if s.cancelled || self.token.is_cancelled(){unsafe{ssh_direct_cancel(r);}}
 }
}
struct CancelOnDrop(Arc<Cancellation>);
impl Drop for CancelOnDrop{fn drop(&mut self){self.0.cancel();}}
struct Request {target:String,command:Command,input:Vec<u8>,deadline:Instant,cancel:Arc<Cancellation>,reply:oneshot::Sender<Result<Output>>,entry:Option<Entry>}

#[repr(C)]
struct Event {next:usize,kind:u64,a:usize,b:usize,c:usize,result:i64,done:AtomicU32,reserved:u32,extra:u64}
#[repr(C)]
struct Service {
 head:AtomicUsize,wake:AtomicU32,stop:AtomicU32,journal_fd:i64,events:AtomicU64,
 observations:AtomicU64,error:AtomicU64,journal_lock:AtomicU64,ack_lock:AtomicU64,
 core:AtomicUsize,thread:Mutex<Option<std::thread::JoinHandle<()>>>,journal:File,
}
static OWNER_INDEX:AtomicU64=AtomicU64::new(0);
impl Service {
 fn new()->Result<Arc<Self>> {
  let base=std::env::var_os("HIA_SSH19_JOURNAL_DIR").ok_or_else(||anyhow!("explicit journal directory required"))?;
  let id=OWNER_INDEX.fetch_add(1,Ordering::AcqRel);
  let p=PathBuf::from(base).join(format!("owner-{}-{id}.journal",std::process::id()));
  let journal=OpenOptions::new().create_new(true).write(true).open(p)?;
  let s=Arc::new(Self{head:AtomicUsize::new(0),wake:AtomicU32::new(0),stop:AtomicU32::new(0),journal_fd:journal.as_raw_fd()as i64,events:AtomicU64::new(0),observations:AtomicU64::new(0),error:AtomicU64::new(0),journal_lock:AtomicU64::new(0),ack_lock:AtomicU64::new(0),core:AtomicUsize::new(0),thread:Mutex::new(None),journal});
  let raw=Arc::as_ptr(&s) as usize;
  let t=std::thread::Builder::new().name("ssh19-qa-effects".into()).spawn(move||unsafe{(&*(raw as *const Service)).run()})?;
  *s.thread.lock().unwrap()=Some(t);Ok(s)
 }
 fn run(&self) {
  loop {
   let seen=self.wake.load(Ordering::Acquire);
   let mut at=self.head.swap(0,Ordering::AcqRel);
   if at==0 {
    if self.stop.load(Ordering::Acquire)!=0{break}
    futex_wait(&self.wake,seen);continue
   }
   // Producers retain each complete event until ACK. Reverse the intrusive
   // batch to preserve enqueue order while allowing independent producers.
   let mut rev=0usize;
   while at!=0 {unsafe{let e=&mut*(at as*mut Event);let next=e.next;e.next=rev;rev=at;at=next;}}
   while rev!=0 {
    let e=unsafe{&mut*(rev as*mut Event)};let next=e.next;
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||self.handle(e)));
    while self.ack_lock.compare_exchange(0,1,Ordering::AcqRel,Ordering::Acquire).is_err(){std::hint::spin_loop();}
    e.result=match result {Ok(v)=>v,Err(_)=>{self.error.store(71,Ordering::Release);-71}};
    e.done.store(1,Ordering::Release);futex_wake(&e.done);self.ack_lock.store(0,Ordering::Release);rev=next;
   }
  }
 }
 fn stop_and_join(&self) {
  self.stop.store(1,Ordering::Release);self.wake.fetch_add(1,Ordering::AcqRel);futex_wake(&self.wake);
  if let Some(t)=self.thread.lock().unwrap().take(){t.join().unwrap();}
 }
 fn handle(&self,e:&Event)->i64 {
  match e.kind {
   1=>{let q=unsafe{&*(e.a as*const ReqState)};
    let entry=q.entry.lock().unwrap().take();
    match entry {
     Some(f)=>match f() {
      Ok(g)=>{*q.guard.lock().unwrap()=Some(g);unsafe{(e.b as*mut usize).write(e.a);}0}
      Err(err)=>{*q.entry_error.lock().unwrap()=Some(format!("{err:#}"));1}
     },
     None=>71
    }
   }
   2=>{let q=unsafe{&*(e.a as*const ReqState)};q.entry.lock().unwrap().take();0}
   3=>{let q=unsafe{&*(e.a as*const ReqState)};q.guard.lock().unwrap().take();0}
   5=>{let q=unsafe{&*(e.b as*const ReqState)};q.cancel.bind(e.a);q.request.store(e.a,Ordering::Release);0}
   7=>{let core=unsafe{&*(self.core.load(Ordering::Acquire)as*const Core)};let q=unsafe{&*(e.b as*const ReqState)};
    let hooks=core.hooks.child.lock().unwrap().take().unwrap_or_default();
    q.hide_wait.store(u64::from(hooks.unconfirmed_wait),Ordering::Release);
    *q.hooks.lock().unwrap()=Some(hooks);0
   }
   6=>{
    let core=unsafe{&*(self.core.load(Ordering::Acquire)as*const Core)};
    core.hooks.spawned.store(unsafe{word(core.ctx,216)},Ordering::Release);
    core.hooks.last_spawned_pid.store(unsafe{word(e.a,80)},Ordering::Release);
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
     assert!(!core.hooks.panic_after_registration.swap(false,Ordering::AcqRel),"injected owner unwind after registration");
    }));
    if result.is_err(){core.injected_panics.fetch_add(1,Ordering::AcqRel);1}else{0}
   }
   10=>{
    let core=unsafe{&*(self.core.load(Ordering::Acquire)as*const Core)};
    if let Some(gate)=core.hooks.after_commit.lock().unwrap().take(){gate.block();}
    0
   }
   11=>{
    let q=unsafe{&*(word(e.a,496)as*const ReqState)};
    if let Some(h)=q.hooks.lock().unwrap().as_ref(){
     if let Some(gate)=h.before_reap.lock().unwrap().take(){gate.block();}
    }
    0
   }
   _=>{self.error.store(71,Ordering::Release);-71}
  }
 }
}
impl Drop for Service {fn drop(&mut self){
 self.stop_and_join();
 self.journal.sync_all().unwrap();
 assert_eq!(self.error.load(Ordering::Acquire),0,"unexpected mechanical callback failure");
}}

#[repr(C)]
struct ReqState {
 service:usize,request:AtomicUsize,hide_wait:AtomicU64,real_wait_pid:AtomicU64,
 real_wait_status:AtomicU64,cached_receipt:AtomicU64,cleanup_used:AtomicU64,released:AtomicU64,
 cancel:Arc<Cancellation>,entry:Mutex<Option<Entry>>,guard:Mutex<Option<Box<dyn Send>>>,
 entry_error:Mutex<Option<String>>,hooks:Mutex<Option<tests::ChildHooks>>,
}
impl ReqState {
 fn new(core:&Core,cancel:Arc<Cancellation>,entry:Option<Entry>)->Arc<Self>{
  Arc::new(Self{service:Arc::as_ptr(&core.service)as usize,request:AtomicUsize::new(0),hide_wait:AtomicU64::new(0),real_wait_pid:AtomicU64::new(0),real_wait_status:AtomicU64::new(0),cached_receipt:AtomicU64::new(0),cleanup_used:AtomicU64::new(0),released:AtomicU64::new(0),cancel,entry:Mutex::new(entry),guard:Mutex::new(None),entry_error:Mutex::new(None),hooks:Mutex::new(None)})
 }
}
struct GateMutex{ctx:usize}
struct GateGuard{ctx:usize,value:bool}
impl GateMutex {fn lock(&self)->io::Result<GateGuard>{let r=unsafe{ssh_direct_owner_gate_lock(self.ctx)};if r<0{Err(io::Error::from_raw_os_error(-r as i32))}else{Ok(GateGuard{ctx:self.ctx,value:r==0})}}}
impl Deref for GateGuard{type Target=bool;fn deref(&self)->&bool{&self.value}}
impl Drop for GateGuard{fn drop(&mut self){unsafe{ssh_direct_owner_gate_unlock(self.ctx)}}}
struct Sequence {ctx:usize}
impl Sequence {fn load(&self,_order:Ordering)->u64{unsafe{let w=ssh_direct_owner_state_lock(self.ctx);let x=word(w,56);ssh_direct_owner_state_unlock(self.ctx);x}}}
struct Children{ctx:usize}
struct ChildrenGuard{ctx:usize,values:BTreeMap<u64,Arc<OwnedChild>>}
impl Children {
 fn lock(&self)->io::Result<ChildrenGuard> {
  unsafe {
   let w=ssh_direct_owner_state_lock(self.ctx);
   if (w as isize)<0 {return Err(io::Error::from_raw_os_error(-(w as isize)as i32))}
   let used=word(w,96)as usize;
   assert!(used>=320 && (used-320)%64==0);
   let mut values=BTreeMap::new();
   for at in (320..used).step_by(64){
    if word(w,at+24)==1 {
     let id=word(w,at);let r=word(w,at+8)as usize-4352;
     ssh_qa_request_retain(r);
     values.insert(id,Arc::new(OwnedChild{id,request:r,state:AsyncMutex::new(ChildState{wait_failed:word(r,4352+56)!=0,reaped:word(r,4352+48)!=0})}));
    }
   }
   Ok(ChildrenGuard{ctx:self.ctx,values})
  }
 }
}
impl Deref for ChildrenGuard{type Target=BTreeMap<u64,Arc<OwnedChild>>;fn deref(&self)->&Self::Target{&self.values}}
impl Drop for ChildrenGuard{fn drop(&mut self){unsafe{ssh_direct_owner_state_unlock(self.ctx)}}}
struct ChildState{wait_failed:bool,reaped:bool}
struct OwnedChild{id:u64,request:usize,state:AsyncMutex<ChildState>}
impl Drop for OwnedChild{fn drop(&mut self){unsafe{ssh_qa_request_drop(self.request)}}}
impl OwnedChild {
 async fn stop_and_reap(&self)->Result<()>{
  let mut state=self.state.lock().await;
  if state.reaped{return Ok(())}
  if state.wait_failed{bail!("direct SSH original wait failed; refusing an uncertain signal")}
  let r=unsafe{ssh_qa_hidden_cleanup(self.request)};
  if r!=0{bail!("qualification cached original wait not available: {r}")}
  state.reaped=true;Ok(())
 }
}
struct Core {
 ctx:usize,accepting:GateMutex,children:Children,sequence:Sequence,
 hooks:tests::Hooks,service:Arc<Service>,requests:Mutex<BTreeMap<usize,Arc<ReqState>>>,injected_panics:AtomicU64,
}
impl Core {
 fn freeze(&self){let r=unsafe{ssh_direct_owner_freeze(self.ctx)};assert_eq!(r,0);}
 async fn release(&self,c:&Arc<OwnedChild>)->Result<()>{
  if !c.state.lock().await.reaped{bail!("direct SSH child was not reaped; original custody retained")}
  let r=unsafe{ssh_qa_hidden_release(c.request)};
  if r!=0{bail!("qualification original registry release failed: {r}")}
  Ok(())
 }
}
impl Drop for Core {fn drop(&mut self){
 // This is embedder teardown after the same persistent owner join. It does not
 // synthesize successful shutdown or destroy quarantined original children.
 unsafe {
  let _=ssh_direct_owner_shutdown(self.ctx);
  while ssh_direct_join_result(self.ctx)==1 {std::thread::sleep(Duration::from_millis(1));}
  while atomic32(self.ctx,120)!=0{std::thread::sleep(Duration::from_millis(1));}
 }
 self.service.stop_and_join();
}}
struct NativeThread{ctx:usize}
impl NativeThread {
 fn join(self)->std::thread::Result<Result<()>>{
  let first=unsafe{ssh_direct_owner_shutdown(self.ctx)};
  let mut r=first;
  while r==1 {std::thread::sleep(Duration::from_millis(1));r=unsafe{ssh_direct_join_result(self.ctx)};}
  if r==0{Ok(Ok(()))}else{Ok(Err(anyhow!("direct SSH persistent owner join failed: {r}")))}
 }
}
struct JoinState {thread:Option<NativeThread>,started:bool,finished:Option<std::result::Result<(),String>>}
struct JoinStateMutex{ctx:usize,state:Mutex<JoinState>}
impl JoinStateMutex {
 fn lock(&self)->std::sync::LockResult<MutexGuard<'_,JoinState>>{
  let mut g=self.state.lock()?;
  let started=unsafe{word(self.ctx,144)}!=0;
  if started {g.started=true;g.thread.take();
   let r=unsafe{ssh_direct_join_result(self.ctx)};
   if r!=1{g.finished=Some(if r==0{Ok(())}else{Err(format!("direct SSH persistent owner join failed: {r}"))});}
  }
  Ok(g)
 }
}
struct JoinReceipt{state:JoinStateMutex,done:Notify}
struct Sender{core:Arc<Core>}
impl Sender {
 fn send(&self,request:Request)->std::result::Result<(),String>{
  let core=self.core.clone();
  std::thread::Builder::new().name("ssh19-qa-caller".into()).spawn(move||{
   let Request{target,command,input,deadline,cancel,reply,entry}=request;
   let frame=match command.frame(){Ok(v)=>v,Err(e)=>{let _=reply.send(Err(e));return}};
   let state=ReqState::new(&core,cancel.clone(),entry);
   let raw=Arc::as_ptr(&state)as usize;
   core.requests.lock().unwrap().insert(raw,state.clone());
   let mut clock:libc::timespec=unsafe{std::mem::zeroed()};
   let remaining=deadline.checked_duration_since(Instant::now());
   assert_eq!(unsafe{libc::clock_gettime(libc::CLOCK_MONOTONIC,&mut clock)},0);
   let now=(clock.tv_sec as u128)*1_000_000_000+(clock.tv_nsec as u128);
   let d=match remaining{Some(v)=>now+v.as_nanos(),None=>now-1};
   let has_entry=state.entry.lock().unwrap().is_some();
   let options=[d as u64,(d>>64)as u64,if has_entry{ssh_qa_entry as usize as u64}else{0},raw as u64,if has_entry{ssh_qa_guard_drop as usize as u64}else{0},if has_entry{ssh_qa_entry_drop as usize as u64}else{0},raw as u64,0x3130415144535348];
   let r=unsafe{ssh_direct_submit(core.ctx,frame.as_ptr(),frame.len(),input.as_ptr(),input.len(),options.as_ptr())};
   if r<=0{let _=reply.send(Err(anyhow!("native submit failed for {target}: {r}")));return}
   assert_eq!(state.request.load(Ordering::Acquire),r as usize);
   let mut result=[0u64;12];
   loop {
    let n=unsafe{if cancel.outer.load(Ordering::Acquire){ssh_direct_capture_result(r as usize,result.as_mut_ptr())}else{ssh_direct_result(r as usize,result.as_mut_ptr())}};
    if n==1{std::thread::sleep(Duration::from_millis(1));continue}
    let value=if n==0{decode_result(&state,&result)}else{Err(anyhow!("native result failed: {n}"))};
    let _=reply.send(value);break
   }
   unsafe{ssh_direct_request_release(r as usize);}
  }).map(|_|()).map_err(|e|e.to_string())
 }
}
fn decode_result(state:&ReqState,raw:&[u64;12])->Result<Output>{
 if raw[0]!=u64::from_le_bytes(*b"HSSRES01") || raw[1]!=96 ||raw[11]!=0{bail!("invalid native result")}
 if raw[2]!=0 {
  if let Some(e)=state.entry_error.lock().unwrap().clone(){bail!("{e}")}
  let reason=raw[3];
  let text=match reason{
   703|102|403=>"direct SSH original deadline expired; no automatic retry",
   405=>"missing SSH stdout",
   404=>"missing SSH stdin",
   406=>"missing SSH stderr",
   411|412=>"SSH response exceeded 8 MiB",
   _=>"direct SSH original attempt failed; no automatic retry",
  };
  bail!("{text}; native reason={reason} errno={}",raw[4])
 }
 if raw[7]>8388608 || raw[9]>8388608{bail!("invalid native stream extent")}
 let copy=|ptr:u64,len:u64|->Vec<u8>{if len==0{Vec::new()}else{assert_ne!(ptr,0);unsafe{std::slice::from_raw_parts(ptr as*const u8,len as usize)}.to_vec()}};
 Ok(Output{status:ExitStatus::from_raw(raw[5]as i32),stdout:copy(raw[6],raw[7]),stderr:copy(raw[8],raw[9])})
}
struct Proxy{sender:Sender,core:Arc<Core>,join:Arc<JoinReceipt>}
impl Proxy {
 fn start()->Result<Arc<Self>>{
  let service=Service::new()?;
  let ctx=unsafe{ssh_direct_owner_create(ssh_qa_observer as usize,Arc::as_ptr(&service)as usize)};
  if ctx<=0{bail!("native private owner creation failed {ctx}")}
  let ctx=ctx as usize;
  let core=Arc::new(Core{ctx,accepting:GateMutex{ctx},children:Children{ctx},sequence:Sequence{ctx},hooks:tests::Hooks::default(),service:service.clone(),requests:Mutex::new(BTreeMap::new()),injected_panics:AtomicU64::new(0)});
  service.core.store(Arc::as_ptr(&core)as usize,Ordering::Release);
  Ok(Arc::new(Self{sender:Sender{core:core.clone()},core,join:Arc::new(JoinReceipt{state:JoinStateMutex{ctx,state:Mutex::new(JoinState{thread:Some(NativeThread{ctx}),started:false,finished:None})},done:Notify::new()})}))
 }
 async fn capture(&self,target:&str,command:Command,input:&[u8],deadline:Instant)->Result<Output>{
  self.capture_owned(target,command,input,deadline,None).await
 }
 async fn capture_with_entry<F,G>(&self,target:&str,command:Command,input:&[u8],deadline:Instant,enter:F)->Result<Output>
 where F:FnOnce()->Result<G>+Send+'static,G:Send+'static {
  let entry:Entry=Box::new(move||enter().map(|g|Box::new(g)as Box<dyn Send>));
  self.capture_owned(target,command,input,deadline,Some(entry)).await
 }
 async fn capture_owned(&self,target:&str,command:Command,input:&[u8],deadline:Instant,entry:Option<Entry>)->Result<Output>{
  let cancel=Cancellation::new();cancel.outer.store(true,Ordering::Release);
  let _drop=CancelOnDrop(cancel.clone());
  let (reply,receive)=oneshot::channel();
  self.sender.send(Request{target:target.into(),command,input:input.to_vec(),deadline,cancel,reply,entry}).map_err(|e|anyhow!(e))?;
  receive.await.map_err(|_|anyhow!("direct SSH owner failed; outcome unconfirmed"))?
 }
 async fn shutdown(&self)->Result<()>{
  let mut r=unsafe{ssh_direct_owner_shutdown(self.core.ctx)};
  loop {
   {drop(self.join.state.lock().unwrap());}
   if r!=1 {if r==0{return Ok(())}else{bail!("direct SSH persistent owner join failed: {r}")}}
   tokio::time::sleep(Duration::from_millis(1)).await;
   r=unsafe{ssh_direct_join_result(self.core.ctx)};
  }
 }
}
#[path="ssh_direct_tests.rs"]
mod tests;

// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// New frozen inputs against unchanged direct owner and original test support.
use super::*;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};

#[derive(Clone)]
struct Probe {
    entered: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    live: Arc<AtomicU64>,
    entry_tid: Arc<AtomicU64>,
    caller_tid: Arc<AtomicU64>,
}
impl Probe {
    fn new() -> Self {
        Self {entered: Arc::new(AtomicU64::new(0)),dropped: Arc::new(AtomicU64::new(0)),
            live: Arc::new(AtomicU64::new(0)),entry_tid: Arc::new(AtomicU64::new(0)),caller_tid: Arc::new(AtomicU64::new(0))}
    }
    fn enter(self, denied: bool) -> Result<ProbeGuard> {
        self.entered.fetch_add(1, Ordering::AcqRel);
        self.entry_tid.store(unsafe {libc::syscall(libc::SYS_gettid)} as u64, Ordering::Release);
        if denied {bail!("frozen lifecycle final Entry denied: 17");}
        self.live.fetch_add(1, Ordering::AcqRel);
        Ok(ProbeGuard {probe:self,not_sync:std::cell::Cell::new(())})
    }
}
struct ProbeGuard {probe:Probe,not_sync:std::cell::Cell<()>}
impl Drop for ProbeGuard {
    fn drop(&mut self) {
        self.not_sync.set(());
        self.probe.dropped.fetch_add(1,Ordering::AcqRel);
        self.probe.live.fetch_sub(1,Ordering::AcqRel);
    }
}
fn save_result(root:&Path,slot:usize,value:&Result<Output>) {
    let mut frame=[0u64;12];frame[0]=u64::from_le_bytes(*b"HSSRES01");frame[1]=96;
    match value {
        Ok(output)=>{
            frame[5]=output.status.into_raw() as u32 as u64;frame[7]=output.stdout.len() as u64;frame[9]=output.stderr.len() as u64;
            std::fs::write(root.join(format!("stdout-{slot}")),&output.stdout).unwrap();
            std::fs::write(root.join(format!("stderr-{slot}")),&output.stderr).unwrap();
        }
        Err(error)=>{
            frame[2]=1;
            std::fs::write(root.join(format!("stdout-{slot}")),b"").unwrap();
            std::fs::write(root.join(format!("stderr-{slot}")),b"").unwrap();
            std::fs::write(root.join(format!("error-{slot}")),format!("{error:#}\n")).unwrap();
        }
    }
    std::fs::write(root.join(format!("RESULT-{slot}")),frame.iter().flat_map(|x|x.to_le_bytes()).collect::<Vec<_>>()).unwrap();
}
fn make_command(spec:&[u64;16],root:&Path,child:&str,slot:usize)->Command {
    let executable=if spec[2]==5 {"/hepta-ssh-frozen-domain-no-such-executable"} else {child};
    let mut c=Command::new(executable);c.env_clear();
    c.arg(root).arg(slot.to_string()).arg(spec[12].to_string()).arg(spec[8].to_string())
        .arg(spec[9].to_string()).arg(spec[10].to_string()).arg(spec[11].to_string())
        .arg(u64::from(spec[2]==1).to_string()).arg(spec[13].to_string());
    let mode=|role:u32|if spec[5]&(1<<role)!=0 {Stdio::piped()}
        else if spec[5]&(1<<(role+3))!=0 {Stdio::null()} else {Stdio::inherit()};
    c.stdin(mode(0)).stdout(mode(1)).stderr(mode(2)).kill_on_drop(true);c
}
async fn capture(proxy:Arc<Proxy>,probe:Probe,command:Command,input:Vec<u8>,spec:[u64;16])->Result<Output>{
    let deadline=Instant::now()+Duration::from_millis(spec[4]);
    if spec[6]!=0 {
        proxy.capture_with_entry("frozen-lifecycle-target",command,&input,deadline,move||probe.enter(spec[6]==2)).await
    }else{proxy.capture("frozen-lifecycle-target",command,&input,deadline).await}
}
#[tokio::test]
async fn frozen_lifecycle_probe(){
    let case=std::fs::read(std::env::var("HSS_CASE").unwrap()).unwrap();assert!(case.len()>=128);
    let mut spec=[0u64;16];for (i,s) in spec.iter_mut().enumerate(){*s=u64::from_le_bytes(case[i*8..i*8+8].try_into().unwrap());}
    assert_eq!(spec[0],u64::from_le_bytes(*b"HSSCASE1"));assert_eq!(case.len(),128+spec[7] as usize);
    let root=PathBuf::from(std::env::var("HSS_OUTPUT").unwrap());let child=std::env::var("HSS_CHILD").unwrap();
    let input=case[128..].to_vec();let owner=Owner::new();let probe=Probe::new();let count=spec[3] as usize;
    probe.caller_tid.store(unsafe{libc::syscall(libc::SYS_gettid)} as u64,Ordering::Release);
    let mut live_when_caller_gone=0;let mut pending_join=0;let mut ready_peak=0;
    if spec[2]==2 {
        let gate=Arc::new(Gate::default());let _release=ReleaseGate(gate.clone());
        *owner.0.core.hooks.after_commit.lock().unwrap()=Some(gate.clone());
        let cancellation=Cancellation::new();let(reply,receive)=oneshot::channel();
        let p=probe.clone();let entry:Option<Entry>=if spec[6]!=0 {Some(Box::new(move||p.enter(spec[6]==2).map(|g|Box::new(g) as Box<dyn Send>)))}else{None};
        let request=Request{target:"frozen-lifecycle-target".into(),command:make_command(&spec,&root,&child,0),
            input,deadline:Instant::now()+Duration::from_millis(spec[4]),cancel:cancellation.clone(),reply,entry};
        assert!(owner.0.sender.send(request).is_ok());until(||gate.reached.load(Ordering::Acquire)).await;
        assert_eq!(cancellation.phase.load(Ordering::Acquire),COMMITTED);cancellation.cancel();
        assert_eq!(cancellation.phase.load(Ordering::Acquire),COMMITTED);gate.release();
        let result=receive.await.unwrap();assert!(result.is_err());save_result(&root,0,&result);owner.finish().await;
    } else if spec[2]==3 {
        let gate=Arc::new(Gate::default());let _release=ReleaseGate(gate.clone());
        *owner.0.core.hooks.child.lock().unwrap()=Some(ChildHooks{before_reap:Mutex::new(Some(gate.clone())),unconfirmed_wait:false});
        let proxy=owner.0.clone();let p=probe.clone();let command=make_command(&spec,&root,&child,0);
        let caller=std::thread::spawn(move||{
            p.caller_tid.store(unsafe{libc::syscall(libc::SYS_gettid)} as u64,Ordering::Release);
            let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(capture(proxy,p,command,input,spec))
        });
        let result=caller.join().unwrap();assert!(result.is_err());save_result(&root,0,&result);
        until(||gate.reached.load(Ordering::Acquire)).await;live_when_caller_gone=probe.live.load(Ordering::Acquire);
        assert_eq!(live_when_caller_gone,1);assert_eq!(owner.0.core.children.lock().unwrap().len(),1);
        let joining=owner.0.clone();let first=tokio::spawn(async move{joining.shutdown().await});
        until(||owner.0.join.state.lock().unwrap().started).await;
        assert!(owner.0.join.state.lock().unwrap().finished.is_none());pending_join=1;
        first.abort();assert!(first.await.unwrap_err().is_cancelled());gate.release();owner.finish().await;
    }else{
        let mut tasks=Vec::new();for slot in 0..count {
            let proxy=owner.0.clone();let p=probe.clone();let command=make_command(&spec,&root,&child,slot);let bytes=input.clone();
            tasks.push(tokio::spawn(async move{capture(proxy,p,command,bytes,spec).await}));
        }
        if spec[2]==1 {
            until(||(0..count).all(|i|root.join(format!("ready-{i}")).exists())).await;
            ready_peak=count as u64;assert_eq!(owner.0.core.children.lock().unwrap().len(),count);
            for i in 0..count{std::fs::write(root.join(format!("release-{i}")),b"release").unwrap();}
        }
        for(slot,task)in tasks.into_iter().enumerate(){let result=task.await.unwrap();save_result(&root,slot,&result);}
        owner.finish().await;
    }
    let join=owner.0.join.state.lock().unwrap();
    assert!(join.started&&join.finished.as_ref().unwrap().is_ok());
    let report=serde_json::json!({"schema":"ssh-original-lifecycle.v1","case":spec[1],"mode":spec[2],"requests":count,
        "entered":probe.entered.load(Ordering::Acquire),"dropped":probe.dropped.load(Ordering::Acquire),
        "live":probe.live.load(Ordering::Acquire),"spawned":owner.0.core.hooks.spawned.load(Ordering::Acquire),
        "registry":owner.0.core.children.lock().unwrap().len(),"entry_tid":probe.entry_tid.load(Ordering::Acquire),
        "caller_tid":probe.caller_tid.load(Ordering::Acquire),"live_when_caller_gone":live_when_caller_gone,
        "join_pending_before_release":pending_join,"ready_peak":ready_peak,"join_started":join.started,"join_success":true});
    std::fs::write(root.join("RUN.json"),serde_json::to_vec(&report).unwrap()).unwrap();
    assert_eq!(probe.live.load(Ordering::Acquire),0);
}

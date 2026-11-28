// Copyright 2026 Muvon Un Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Private observer for original publisher futures and actual SDK transport.
//! Original publisher, gateway, configuration and SDK sources are unchanged.
//! The observer counters are never SDK identities or authorization.
use super::*;
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::sync::{Condvar, Mutex, OnceLock};
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tokio::io::AsyncReadExt;

static ENABLED: AtomicBool = AtomicBool::new(false);
static NEXT: AtomicU64 = AtomicU64::new(1);
static START: OnceLock<Instant> = OnceLock::new();
static EVENTS: OnceLock<Mutex<Vec<Value>>> = OnceLock::new();

fn record(mut value: Value) {
    if !ENABLED.load(Ordering::SeqCst) { return; }
    let mut rows = EVENTS.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap();
    value["ordinal"] = json!(rows.len());
    value["elapsed_ns"] = json!(START.get_or_init(Instant::now).elapsed().as_nanos().to_string());
    value["thread"] = json!(format!("{:?}", std::thread::current().id()));
    rows.push(value);
}

pub(crate) struct FutureObservation { number: u64, path: String, complete: bool, enabled: bool }
impl FutureObservation {
    pub(crate) fn new(path: &str) -> Self {
        let enabled = ENABLED.load(Ordering::SeqCst);
        let number = if enabled { NEXT.fetch_add(1, Ordering::SeqCst) } else { 0 };
        if enabled { record(json!({"event":"entered","number":number,"path":path})); }
        Self { number, path:path.to_owned(), complete:false, enabled }
    }
    pub(crate) fn completed(&mut self, ok: bool) {
        self.complete = true;
        if self.enabled { record(json!({"event":"returned","number":self.number,"path":self.path,"ok":ok})); }
    }
}
impl Drop for FutureObservation {
    fn drop(&mut self) {
        if self.enabled { record(json!({"event":"dropped","number":self.number,
            "path":self.path,"after_return":self.complete})); }
    }
}

fn events() -> Vec<Value> {
    EVENTS.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap().clone()
}
fn unsigned(row:&Value, key:&str) -> Result<u64> {
    row[key].as_u64().ok_or_else(|| anyhow::anyhow!("missing fixture unsigned field {key}"))
}
fn text<'a>(row:&'a Value, key:&str) -> Result<&'a str> {
    row[key].as_str().ok_or_else(|| anyhow::anyhow!("missing fixture string field {key}"))
}
fn parse_proc_number(value:&str) -> Option<u64> {
    value.strip_prefix("0x").map(|v|u64::from_str_radix(v,16).ok()).unwrap_or_else(||value.parse().ok())
}

// Read this process's own blocked syscall, matching the exact held directory.
// No process is stopped and no original implementation instruction is changed.
fn blocked_snapshot(path:&std::path::Path) -> Result<Value> {
    let wanted = std::fs::metadata(path)?;
    let mut tasks = Vec::new();
    let mut matching = Vec::new();
    let mut entries = std::fs::read_dir("/proc/self/task")?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|e|e.file_name());
    for entry in entries {
        let tid = entry.file_name().to_string_lossy().to_string();
        let raw = match std::fs::read_to_string(entry.path().join("syscall")) {
            Ok(raw)=>raw,
            Err(error)=>{tasks.push(json!({"tid":tid,"read_error":error.to_string()}));continue;}
        };
        let parts = raw.split_whitespace().collect::<Vec<_>>();
        let mut row = json!({"tid":tid,"syscall":raw.clone()});
        if parts.len() >= 3 && parse_proc_number(parts[0]) == Some(libc::SYS_flock as u64)
            && parse_proc_number(parts[2]) == Some(libc::LOCK_EX as u64) {
            if let Some(fd) = parse_proc_number(parts[1]) {
                let fd_path = PathBuf::from(format!("/proc/self/fd/{fd}"));
                if let Ok(metadata) = std::fs::metadata(&fd_path) {
                    let same = metadata.dev()==wanted.dev() && metadata.ino()==wanted.ino();
                    row["fd"] = json!(fd);
                    row["dev"] = json!(metadata.dev());
                    row["ino"] = json!(metadata.ino());
                    row["link"] = json!(std::fs::read_link(&fd_path)?.to_string_lossy());
                    row["matching_directory"] = json!(same);
                    if same { matching.push(tid.clone()); }
                }
            }
        }
        tasks.push(row);
    }
    Ok(json!({"pid":std::process::id(),"path":path.to_string_lossy(),
        "dev":wanted.dev(),"ino":wanted.ino(),"matching_tids":matching,"tasks":tasks}))
}

struct Session {
    reader: Option<BufReader<ReadHalf<DuplexStream>>>,
    writer: Option<WriteHalf<DuplexStream>>,
    task: Option<tokio::task::JoinHandle<Result<(),String>>>,
}
impl Session {
    fn start(server:OctofsServer) -> Self {
        let (client,transport) = tokio::io::duplex(65536);
        let task=tokio::spawn(async move {
            record(json!({"event":"serve_begin"}));
            let running=match server.serve(transport).await {
                Ok(running)=>running,
                Err(error)=>{
                    let error=error.to_string();
                    record(json!({"event":"serve_failed","error":error}));
                    return Err(error);
                }
            };
            record(json!({"event":"serve_ready"}));
            let result=running.waiting().await.map(|_|()).map_err(|e|format!("{e:?}"));
            record(json!({"event":"serve_finished","result":result.as_ref().err()}));
            result
        });
        let (reader,writer)=tokio::io::split(client);
        Self { reader:Some(BufReader::new(reader)),writer:Some(writer),task:Some(task) }
    }
    async fn send(&mut self,raw:&[u8]) -> Result<()> {
        self.writer.as_mut().ok_or_else(||anyhow::anyhow!("send after EOF"))?.write_all(raw).await?;
        tokio::task::yield_now().await;
        Ok(())
    }
    async fn line(&mut self) -> Result<Vec<u8>> {
        let mut raw=Vec::new();
        let count=tokio::time::timeout(Duration::from_secs(60),
            self.reader.as_mut().ok_or_else(||anyhow::anyhow!("read after close"))?.read_until(b'\n',&mut raw)).await??;
        if count==0 || raw.last()!=Some(&b'\n') { bail!("response ended before full line"); }
        Ok(raw)
    }
    async fn eof(&mut self) -> Result<()> {
        let mut writer=self.writer.take().ok_or_else(||anyhow::anyhow!("duplicate EOF"))?;
        writer.shutdown().await?;
        drop(writer);
        tokio::task::yield_now().await;
        Ok(())
    }
    fn close(&mut self) {
        self.reader.take();
        self.writer.take();
    }
    async fn drain(&mut self) -> Result<Value> {
        let mut raw=Vec::new();
        if let Some(mut reader)=self.reader.take() {
            tokio::time::timeout(Duration::from_secs(60),reader.read_to_end(&mut raw)).await??;
        }
        let task=self.task.take().ok_or_else(||anyhow::anyhow!("duplicate service drain"))?;
        let outcome=tokio::time::timeout(Duration::from_secs(60),task).await?;
        let terminal=match outcome {
            Ok(Ok(()))=>json!({"joined":true,"service_ok":true}),
            Ok(Err(error))=>json!({"joined":true,"service_ok":false,"error":error}),
            Err(error)=>json!({"joined":false,"join_error":error.to_string(),
                "cancelled":error.is_cancelled(),"panic":error.is_panic()}),
        };
        Ok(json!({"wire_hex":hex(&raw),"terminal":terminal}))
    }
}

type Direct = tokio::task::JoinHandle<Result<String,String>>;
struct PeerCarrier;
impl ServerHandler for PeerCarrier {}
struct Blocker { release:Arc<(Mutex<bool>,Condvar)>, task:tokio::task::JoinHandle<()> }
impl Blocker {
    fn start(runtime:&tokio::runtime::Runtime) -> Result<Self> {
        let release=Arc::new((Mutex::new(false),Condvar::new()));
        let worker=release.clone();
        let (tx,rx)=std::sync::mpsc::sync_channel(1);
        let task=runtime.spawn_blocking(move || {
            record(json!({"event":"blocking_slot_occupied"}));
            tx.send(()).unwrap();
            let (lock,condition)=&*worker;
            let mut ready=lock.lock().unwrap();
            while !*ready { ready=condition.wait(ready).unwrap(); }
            record(json!({"event":"blocking_slot_released"}));
        });
        rx.recv_timeout(Duration::from_secs(60))?;
        Ok(Self{release,task})
    }
    fn release(&self) {
        let (lock,condition)=&*self.release;
        *lock.lock().unwrap()=true;
        condition.notify_all();
    }
}

fn state(servers:&[OctofsServer;2],sequence:u64) -> Value {
    let caches=servers.iter().map(|s|hex(&fs::delta::fixture_snapshot(&s.view_cache,1))).collect::<Vec<_>>();
    let sessions=servers.iter().map(|s|json!({"root":s.workdir.root.to_string_lossy(),
        "current":s.workdir.current.read().ok().and_then(|v|v.clone()).map(|p|p.to_string_lossy().to_string()),
        "effective":s.workdir.get_current().to_string_lossy(),
        "session_applied":s.session_applied.load(Ordering::SeqCst),
        "poisoned":s.workdir.current.is_poisoned()})).collect::<Vec<_>>();
    json!({"cache_snapshots_hex":caches,"sessions":sessions,
        "history_snapshot_hex":hex(&fs::core::fixture_history_snapshot(1,sequence+1)),
        "lock_snapshot_hex":hex(&fs::text_editing::fixture_lock_snapshot(1,sequence+1)),
        "scope_unbound_after_exchange":request_ctx::with_view_cache(|_|false).is_none(),
        "events":events()})
}

pub(crate) fn main() -> Result<()> {
    let config=std::env::args().nth(2).ok_or_else(||anyhow::anyhow!("async fixture config required"))?;
    let mode=std::env::args().nth(3).ok_or_else(||anyhow::anyhow!("async fixture mode required"))?;
    if !["public","direct","queued"].contains(&mode.as_str()) { bail!("unknown observer mode"); }
    let config:runtime::config::RuntimeConfig=serde_json::from_slice(&std::fs::read(config)?)?;
    runtime::config::install_for_reference(config);
    ENABLED.store(true,Ordering::SeqCst);
    START.get_or_init(Instant::now);
    let root=std::env::current_dir()?.canonicalize()?;
    let servers=std::array::from_fn::<_,2,_>(|_|OctofsServer {
        view_cache:Arc::new(fs::delta::ViewCache::default()),
        workdir:Arc::new(SessionWorkdir::new(root.clone())),
        session_applied:Arc::new(AtomicBool::new(false)),
    });
    let mut builder=tokio::runtime::Builder::new_current_thread();
    builder.enable_all();
    if mode=="queued" { builder.max_blocking_threads(1); }
    let runtime=builder.build()?;
    let mut blocker=if mode=="queued" {Some(Blocker::start(&runtime)?)} else {None};
    let mut sessions=runtime.block_on(async {
        if mode=="public" {servers.iter().cloned().map(Session::start).collect::<Vec<_>>()} else {Vec::new()}
    });
    let (mut peers,peer_inputs)=runtime.block_on(async {
        let mut peers=Vec::new();let mut inputs=Vec::new();
        if mode!="public" {
            for _ in 0..2 {
                let (service_io,input)=tokio::io::duplex(4096);
                peers.push(rmcp::service::serve_directly::<RoleServer,_,_,_,_>(PeerCarrier,service_io,None));
                inputs.push(input);
            }
        }
        (peers,inputs)
    });
    let mut direct=BTreeMap::<u64,Direct>::new();
    let mut output=io::BufWriter::new(io::stdout().lock());
    for (sequence,line) in io::stdin().lock().lines().enumerate() {
        let row:Value=serde_json::from_str(&line?)?;
        let sid=unsigned(&row,"session")? as usize;
        if sid>=2 {bail!("fixture session out of range");}
        let kind=text(&row,"kind")?;
        record(json!({"event":"command_begin","command":kind,"sequence":sequence,"session":sid}));
        if kind=="finalize" {
            if sessions.iter().any(|s|s.task.is_some()) || !direct.is_empty() || blocker.is_some() {
                bail!("finalize requires observed service/direct/blocker retirement");
            }
            for peer in peers.drain(..) {runtime.block_on(peer.cancel())?;}
            drop(peer_inputs);
            record(json!({"event":"runtime_drop_begin"}));
            drop(runtime); // actual Tokio Runtime Drop waits for detached blocking work
            record(json!({"event":"runtime_drop_complete"}));
            let result=json!({"kind":kind,"sequence":sequence,"id":row["id"],"session":sid,
                "result":{"runtime_dropped":true},"state":state(&servers,sequence as u64)});
            serde_json::to_writer(&mut output,&result)?;
            output.write_all(b"\n")?;output.flush()?;
            return Ok(());
        }
        let result=match kind {
            "send" => {
                if mode!="public" {bail!("send outside public observer");}
                let raw=unhex(text(&row,"wire_hex")?)?;
                runtime.block_on(sessions[sid].send(&raw))?;
                json!({"bytes":raw.len()})
            }
            "read" => {
                if mode!="public" {bail!("read outside public observer");}
                json!({"wire_hex":hex(&runtime.block_on(sessions[sid].line())?)})
            }
            "eof" => {
                if mode!="public" {bail!("EOF outside public observer");}
                runtime.block_on(sessions[sid].eof())?;
                json!({"writer_shutdown":true})
            }
            "close_transport" => {
                if mode!="public" {bail!("close outside public observer");}
                sessions[sid].close();
                runtime.block_on(tokio::task::yield_now());
                json!({"reader_writer_dropped":true})
            }
            "drain" => {
                if mode!="public" || sessions[sid].writer.is_some() {bail!("drain requires EOF/close");}
                runtime.block_on(sessions[sid].drain())?
            }
            "cache" => {
                let raw=unhex(text(&row,"wire_hex")?)?;
                json!({"output_hex":hex(&fs::delta::fixture_apply(&servers[sid].view_cache,&raw)?)})
            }
            "observe" => json!({"service_finished":sessions.iter()
                .map(|s|s.task.as_ref().map(|task|task.is_finished())).collect::<Vec<_>>()}),
            "drive" => {
                let millis=unsigned(&row,"milliseconds")?;
                if millis>1000 {bail!("observation drive outside fixed bound");}
                runtime.block_on(async {tokio::time::sleep(Duration::from_millis(millis)).await;});
                json!({"driven_milliseconds":millis})
            }
            "wait_events" => {
                let event=text(&row,"event")?.to_owned();
                let count=unsigned(&row,"count")? as usize;
                let after=row.get("after_return").and_then(Value::as_bool);
                runtime.block_on(async {tokio::time::timeout(Duration::from_secs(60),async {
                    loop {
                        let rows=events();
                        let matching=rows.iter().filter(|v|v["event"].as_str()==Some(event.as_str())
                            && after.is_none_or(|value|v["after_return"].as_bool()==Some(value))).count();
                        if matching>=count {return json!({"event":event,"count":matching});}
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }).await})?
            }
            "wait_blocked" => {
                let path=PathBuf::from(text(&row,"path")?).canonicalize()?;
                if !path.starts_with(&root) {bail!("proc observer only admits owned fixture directories");}
                let count=unsigned(&row,"count")? as usize;
                runtime.block_on(async {tokio::time::timeout(Duration::from_secs(60),async {
                    loop {
                        let observation=blocked_snapshot(&path)?;
                        if observation["matching_tids"].as_array().unwrap().len()>=count {
                            return Ok::<_,anyhow::Error>(observation);
                        }
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }).await})??
            }
            "blocked_snapshot" => {
                let path=PathBuf::from(text(&row,"path")?).canonicalize()?;
                if !path.starts_with(&root) {bail!("proc observation outside owned root");}
                blocked_snapshot(&path)?
            }
            "direct_start" | "direct_unpolled_drop" => {
                if mode=="public" {bail!("private future command outside direct observer");}
                let tag=unsigned(&row,"tag")?;
                if direct.contains_key(&tag) {bail!("duplicate private task tag");}
                let typed:TextFileWriteParams=serde_json::from_value(row["parameters"].clone())?;
                let id=serde_json::from_value(json!(tag))?;
                let mut context=RequestContext::<RoleServer>::new(id,peers[sid].peer().clone());
                if !row["metadata"].is_null() {context.meta=serde_json::from_value(row["metadata"].clone())?;}
                let server=servers[sid].clone();
                let future=async move {server.sdk_publish(context,Parameters(typed)).await};
                if kind=="direct_unpolled_drop" {
                    drop(future);
                    json!({"tag":tag,"unpolled_future_dropped":true})
                } else {
                    direct.insert(tag,runtime.spawn(future));
                    runtime.block_on(tokio::task::yield_now());
                    json!({"tag":tag,"spawned":true})
                }
            }
            "direct_drop" | "direct_join" => {
                if mode=="public" {bail!("private future command outside direct observer");}
                let tag=unsigned(&row,"tag")?;
                let task=direct.remove(&tag).ok_or_else(||anyhow::anyhow!("missing private task"))?;
                if kind=="direct_drop" {task.abort();}
                let result=runtime.block_on(async {
                    tokio::time::timeout(Duration::from_secs(60),task).await
                })?;
                match result {
                    Ok(Ok(value))=>json!({"tag":tag,"joined":true,"ok":true,"output_hex":hex(value.as_bytes())}),
                    Ok(Err(error))=>json!({"tag":tag,"joined":true,"ok":false,"output_hex":hex(error.as_bytes())}),
                    Err(error)=>json!({"tag":tag,"joined":false,"cancelled":error.is_cancelled(),
                        "panic":error.is_panic(),"join_error":error.to_string()}),
                }
            }
            "release_blocker" => {
                let old=blocker.take().ok_or_else(||anyhow::anyhow!("no owned blocking-slot fixture"))?;
                old.release();
                runtime.block_on(async {tokio::time::timeout(Duration::from_secs(60),old.task).await})??;
                json!({"released":true})
            }
            _=>bail!("observer command outside frozen domain"),
        };
        record(json!({"event":"command_complete","command":kind,"sequence":sequence,"session":sid}));
        let result=json!({"kind":kind,"sequence":sequence,"id":row["id"],"session":sid,
            "result":result,"state":state(&servers,sequence as u64)});
        serde_json::to_writer(&mut output,&result)?;
        output.write_all(b"\n")?;output.flush()?;
    }
    bail!("observer requires explicit finalized Runtime Drop")
}

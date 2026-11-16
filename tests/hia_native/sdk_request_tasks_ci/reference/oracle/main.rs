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

//! Observe the unchanged RMCP incoming task map through actual serve_inner.
//! The gates belong to this in-process fixture; no network or runtime tool runs.
use anyhow::{Context, ensure};
use rmcp::{
    model::{CallToolResult, ClientJsonRpcMessage, ClientNotification, ClientRequest,
        ContentBlock, EmptyResult, ServerConfig, ServerJsonRpcMessage, ServerResult},
    service::{NotificationContext, RequestContext, serve_directly_with_ct},
    transport::Transport, ErrorData, RoleServer, Service,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::{BufRead, Write}, sync::{Arc, Mutex},
    time::{Duration, Instant}};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

struct Task {
    label: String,
    id: Value,
    ct: CancellationToken,
    done: bool,
    gate: Option<oneshot::Sender<String>>,
    metadata: Value,
    peer_info: Value,
}
struct SendRecord {
    id: Value,
    wire: String,
    status: &'static str,
    gate: Option<oneshot::Sender<()>>,
}
#[derive(Default)]
struct State {
    tasks: Vec<Task>,
    sends: Vec<SendRecord>,
    plans: BTreeMap<String, (bool, bool)>,
    notifications: u64,
    receive_eof: bool,
    closed: bool,
    trace: Vec<Value>,
}
struct Shared {
    state: Mutex<State>,
    changed: Notify,
    outer: CancellationToken,
    began: Instant,
}
impl Shared {
    fn update<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        let result = f(&mut self.state.lock().expect("fixture state"));
        self.changed.notify_waiters();
        result
    }
    fn log(&self, state: &mut State, event: Value) {
        state.trace.push(json!({"index":state.trace.len(),
            "time_ns":self.began.elapsed().as_nanos() as u64, "event":event}));
    }
    fn snapshot(&self) -> Value {
        let state = self.state.lock().expect("fixture state");
        let tasks: Vec<Value> = state.tasks.iter().map(|t| json!({"label":t.label,
            "id":t.id,"cancelled":t.ct.is_cancelled(),"done":t.done,
            "metadata":t.metadata,"peer_info":t.peer_info})).collect();
        let sends: Vec<Value> = state.sends.iter().enumerate().map(|(i,s)|
            json!({"index":i,"id":s.id,"wire":s.wire,"status":s.status})).collect();
        json!({"time_ns":self.began.elapsed().as_nanos() as u64,"tasks":tasks,
            "sends":sends,"notifications":state.notifications,"receive_eof":state.receive_eof,
            "closed":state.closed,"outer_cancelled":self.outer.is_cancelled()})
    }
    async fn wait(&self, seconds: u64, f: impl Fn(&State) -> bool) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(seconds), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if f(&self.state.lock().expect("fixture state")) { return; }
                changed.await;
            }
        }).await.context("ordinary fixture event deadline")?;
        Ok(())
    }
}

#[derive(Clone)]
struct GateService(Arc<Shared>);
impl Service<RoleServer> for GateService {
    async fn handle_request(&self, request: ClientRequest, context: RequestContext<RoleServer>)
        -> Result<ServerResult, ErrorData> {
        let (label, immediate) = match &request {
            ClientRequest::CallToolRequest(call) => (call.params.name.to_string(), false),
            ClientRequest::PingRequest(_) => (context.id.to_string(), true),
            _ => return Err(ErrorData::invalid_params("fixture accepts tools/call and ping", None)),
        };
        let (tx, rx) = oneshot::channel();
        let index = self.0.update(|state| {
            assert!(!state.tasks.iter().any(|t| t.label == label));
            let index = state.tasks.len();
            state.tasks.push(Task { label:label.clone(), id:serde_json::to_value(&context.id).unwrap(),
                ct:context.ct.clone(), done:immediate, gate:if immediate { None } else { Some(tx) },
                metadata:serde_json::to_value(&context.meta).unwrap(),
                peer_info:serde_json::to_value(context.peer.peer_info()).unwrap() });
            self.0.log(state, json!({"kind":"handler_start","label":label,
                "id":context.id,"cancelled":context.ct.is_cancelled(),"immediate":immediate}));
            index
        });
        if immediate {
            return Ok(ServerResult::EmptyResult(EmptyResult {}));
        }
        let outcome = rx.await.map_err(|_| ErrorData::internal_error("fixture gate dropped", None))?;
        self.0.update(|state| {
            state.tasks[index].done = true;
            self.0.log(state, json!({"kind":"handler_return","label":label,
                "id":context.id,"cancelled":context.ct.is_cancelled(),"outcome":outcome}));
        });
        match outcome.as_str() {
            "success" => Ok(ServerResult::CallToolResult(CallToolResult::success(
                vec![ContentBlock::text(format!("finished {label}"))]))),
            "tool_error" => Ok(ServerResult::CallToolResult(CallToolResult::error(
                vec![ContentBlock::text(format!("ordinary tool error {label}"))]))),
            "protocol_error" => Err(ErrorData::invalid_params(format!("ordinary fixture error {label}"), None)),
            _ => Err(ErrorData::internal_error("fixture outcome", None)),
        }
    }
    async fn handle_notification(&self, notification: ClientNotification,
        context: NotificationContext<RoleServer>) -> Result<(), ErrorData> {
        self.0.update(|state| {
            state.notifications += 1;
            self.0.log(state, json!({"kind":"notification_handler","notification":notification,
                "meta":context.meta,"peer_info":context.peer.peer_info()}));
        });
        Ok(())
    }
    fn get_info(&self) -> ServerConfig { ServerConfig::default() }
}

struct SendGuard { shared: Arc<Shared>, index: usize, completed: bool }
impl SendGuard {
    fn complete(&mut self) { self.completed = true; }
}
impl Drop for SendGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.shared.update(|state| {
                state.sends[self.index].status = "aborted";
                self.shared.log(state, json!({"kind":"send_aborted","index":self.index}));
            });
        }
    }
}
struct ObservedTransport { shared: Arc<Shared>, input: mpsc::Receiver<ClientJsonRpcMessage> }
impl Transport<RoleServer> for ObservedTransport {
    type Error = std::io::Error;
    fn send(&mut self, item: ServerJsonRpcMessage)
        -> impl Future<Output=Result<(), Self::Error>> + Send + 'static {
        let value = serde_json::to_value(&item).expect("actual SDK response");
        let id = value["id"].clone();
        let wire = serde_json::to_string(&item).expect("actual SDK response wire");
        let shared = self.shared.clone();
        let (index, gate, fail) = shared.update(|state| {
            let (hold, fail) = state.plans.remove(&id.to_string()).unwrap_or((false,false));
            let (tx, rx) = oneshot::channel();
            let index = state.sends.len();
            state.sends.push(SendRecord { id:id.clone(),wire:wire.clone(),status:"started",
                gate:if hold { Some(tx) } else { None } });
            shared.log(state, json!({"kind":"send_start","index":index,"id":id,"wire":wire,
                "held":hold,"fail":fail}));
            (index,if hold { Some(rx) } else { None },fail)
        });
        let mut guard = SendGuard { shared:shared.clone(),index,completed:false };
        async move {
            if let Some(gate) = gate {
                gate.await.map_err(|_| std::io::Error::other("fixture send gate dropped"))?;
            }
            shared.update(|state| {
                state.sends[index].status = if fail { "failed" } else { "done" };
                shared.log(state,json!({"kind":"send_done","index":index,"success":!fail}));
            });
            guard.complete();
            if fail { Err(std::io::Error::other("ordinary fixture write failure")) } else { Ok(()) }
        }
    }
    async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
        let item = self.input.recv().await;
        if item.is_none() {
            self.shared.update(|state| {
                state.receive_eof = true;
                self.shared.log(state,json!({"kind":"receive_eof"}));
            });
        }
        item
    }
    async fn close(&mut self) -> Result<(), Self::Error> {
        self.shared.update(|state| {
            state.closed = true;
            self.shared.log(state,json!({"kind":"transport_close",
                "outer_cancelled":self.shared.outer.is_cancelled()}));
        });
        Ok(())
    }
}

async fn inject(input: &Option<mpsc::Sender<ClientJsonRpcMessage>>, wire: &str)
    -> anyhow::Result<()> {
    let typed: ClientJsonRpcMessage = serde_json::from_str(wire)?;
    input.as_ref().context("input still open")?.send(typed).await?;
    Ok(())
}
async fn barrier(shared: &Arc<Shared>, input: &Option<mpsc::Sender<ClientJsonRpcMessage>>,
    number: &mut u64) -> anyhow::Result<String> {
    *number += 1;
    let id = format!("registry-barrier-{number}");
    let wire = serde_json::to_string(&json!({"jsonrpc":"2.0","id":id,"method":"ping"}))?;
    inject(input,&wire).await?;
    shared.wait(3, |s| s.sends.iter().any(|v| v.id == id && v.status == "done")).await?;
    Ok(wire)
}
fn release(shared: &Arc<Shared>, label: &str, outcome: &str,
    hold: bool, fail: bool) -> anyhow::Result<()> {
    let tx = shared.update(|state| -> anyhow::Result<_> {
        let task = state.tasks.iter_mut().find(|t| t.label == label).context("existing task")?;
        let tx = task.gate.take().context("unfinished task")?;
        state.plans.insert(task.id.to_string(),(hold,fail));
        Ok(tx)
    })?;
    tx.send(outcome.to_owned()).map_err(|_| anyhow::anyhow!("handler gate receiver"))?;
    Ok(())
}

async fn observe(case: Value) -> anyhow::Result<Value> {
    let shared = Arc::new(Shared { state:Mutex::new(State::default()),changed:Notify::new(),
        outer:CancellationToken::new(),began:Instant::now() });
    let (tx,rx) = mpsc::channel(64);
    let mut input = Some(tx);
    let service = serve_directly_with_ct::<RoleServer,_,_,_,_>(GateService(shared.clone()),
        ObservedTransport { shared:shared.clone(),input:rx },None,shared.outer.clone());
    let mut observations = Vec::new();
    let mut barrier_number = 0;
    let mut draining = false;
    for action in case["events"].as_array().context("ordinary events")? {
        let before = shared.snapshot();
        let mut extra = json!({});
        match action["op"].as_str().context("event operation")? {
            "request" => {
                let label = action["label"].as_str().context("task label")?;
                inject(&input, action["wire"].as_str().context("request wire")?).await?;
                shared.wait(3, |s| s.tasks.iter().any(|t| t.label == label)).await?;
            }
            "notify" => {
                let count = before["notifications"].as_u64().unwrap();
                inject(&input,action["wire"].as_str().context("notification wire")?).await?;
                shared.wait(3, |s| s.notifications == count + 1).await?;
            }
            "finish" => {
                ensure!(!draining,"normal completion before drain");
                let label = action["label"].as_str().context("task label")?;
                release(&shared,label,action["outcome"].as_str().unwrap_or("success"),
                    action["hold_send"].as_bool().unwrap_or(false),
                    action["fail_send"].as_bool().unwrap_or(false))?;
                shared.wait(3, |s| s.tasks.iter().any(|t| t.label == label && t.done)).await?;
                extra["barrier_wire"] = barrier(&shared,&input,&mut barrier_number).await?.into();
            }
            "release_send" => {
                let label = action["label"].as_str().context("task label")?;
                let (index,tx) = shared.update(|state| -> anyhow::Result<_> {
                    let id = state.tasks.iter().find(|t| t.label == label).context("task")?.id.clone();
                    let (index,send) = state.sends.iter_mut().enumerate().find(|(_,s)| s.id == id
                        && s.status == "started").context("held actual send")?;
                    Ok((index,send.gate.take().context("actual send gate")?))
                })?;
                tx.send(()).map_err(|_| anyhow::anyhow!("send receiver"))?;
                shared.wait(3, |s| matches!(s.sends[index].status,"done"|"failed")).await?;
            }
            "begin_drain" => {
                ensure!(!draining,"one drain");
                draining = true;
                extra["begin_ns"] = (shared.began.elapsed().as_nanos() as u64).into();
                match action["reason"].as_str().context("drain reason")? {
                    "eof" => { drop(input.take()); shared.wait(3, |s| s.receive_eof).await?; }
                    "service_cancel" => { shared.outer.cancel(); tokio::task::yield_now().await; }
                    _ => anyhow::bail!("ordinary drain reason"),
                }
            }
            "finish_drain" => {
                ensure!(draining,"draining completion");
                let label = action["label"].as_str().context("task label")?;
                release(&shared,label,action["outcome"].as_str().unwrap_or("success"),false,false)?;
                shared.wait(7, |s| s.closed).await?;
            }
            "await_close" => {
                ensure!(draining,"await an actual drain");
                shared.wait(7, |s| s.closed).await?;
                shared.wait(3, |s| s.sends.iter().all(|v| v.status != "started")).await?;
            }
            "finish_closed" => {
                ensure!(before["closed"] == true,"closed transport");
                let label = action["label"].as_str().context("task label")?;
                release(&shared,label,action["outcome"].as_str().unwrap_or("success"),false,false)?;
                shared.wait(3, |s| s.tasks.iter().any(|t| t.label == label && t.done)).await?;
                tokio::task::yield_now().await;
            }
            _ => anyhow::bail!("unknown ordinary fixture event"),
        }
        observations.push(json!({"action":action,"before":before,"extra":extra,
            "after":shared.snapshot()}));
    }
    let final_snapshot = shared.snapshot();
    ensure!(final_snapshot["closed"] == true,"fixture closes actual service");
    ensure!(final_snapshot["tasks"].as_array().unwrap().iter().all(|t| t["done"] == true),
        "fixture releases every actual handler");
    let quit = tokio::time::timeout(Duration::from_secs(3),service.waiting()).await??;
    // RunningService owns a DropGuard. Keep its later cancellation separate from
    // the transport-close observation of serve_inner's EOF token semantics.
    let after_running_service_drop = shared.outer.is_cancelled();
    let trace = shared.state.lock().expect("fixture state").trace.clone();
    Ok(json!({"schema":"hepta.sdk-request-tasks.actual-original.v1","label":case["label"],
        "events":observations,"final":final_snapshot,"trace":trace,"quit":format!("{quit:?}"),
        "outer_after_running_service_drop":after_running_service_drop,
        "actual_serve_directly_with_ct":true,"actual_request_context_ct":true,
        "custom_in_process_transport":true,"async_rw_transport_qualified":false}))
}

fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let input = std::io::stdin();
    let mut output = std::io::stdout().lock();
    for line in input.lock().lines() {
        let case: Value = serde_json::from_str(&line?)?;
        let result = runtime.block_on(observe(case))?;
        serde_json::to_writer(&mut output,&result)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}

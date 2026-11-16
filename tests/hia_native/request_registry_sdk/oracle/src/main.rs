// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
//! Controlled handler gates observe the unchanged rmcp request registry.
use std::{
    collections::BTreeMap,
    fmt,
    io::{self, BufRead, Write},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use anyhow::{anyhow, bail, ensure, Result};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use rmcp::model::{CallToolRequestParams, CallToolResponse, CallToolResult, CancelledNotificationParam, ContentBlock};
use rmcp::service::{NotificationContext, RequestContext};
use serde_json::{json, Value};
use tokio::{io::{AsyncBufReadExt, AsyncWriteExt}, sync::{oneshot, Notify}};
use tracing::{field::{Field, Visit}, span::{Attributes, Id, Record}, Event, Metadata, Subscriber};

struct RecordState {
    context: RequestContext<RoleServer>,
    gate: Option<oneshot::Sender<()>>,
    completed: bool,
}
#[derive(Default)]
struct State {
    records: BTreeMap<u64, RecordState>,
    started: Vec<Value>,
    notifications: Vec<Value>,
    traces: Vec<String>,
    incoming: Vec<String>,
    responses: Vec<String>,
}
#[derive(Default)]
struct Shared { state: Mutex<State>, changed: Notify }
impl Shared {
    fn emit(&self, value: Value) {
        println!("{}", serde_json::to_string(&value).unwrap());
        io::stdout().flush().unwrap();
    }
    fn snapshot(&self, case_id: u64, ordinal: usize, operation: &str) {
        let state = self.state.lock().unwrap();
        let records: Vec<Value> = state.records.iter().map(|(generation, r)| json!({
            "generation": generation, "cancelled": r.context.ct.is_cancelled(), "completed": r.completed
        })).collect();
        drop(state);
        self.emit(json!({"event":"step","case":case_id,"ordinal":ordinal,"op":operation,"records":records}));
    }
}
async fn until(shared: &Arc<Shared>, predicate: impl Fn(&State) -> bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let notice = shared.changed.notified();
            tokio::pin!(notice);
            notice.as_mut().enable();
            if predicate(&shared.state.lock().unwrap()) { return; }
            notice.await;
        }
    }).await.map_err(|_| anyhow!("actual SDK observer did not reach the requested boundary in 10 seconds"))
}
#[derive(Clone)]
struct Probe(Arc<Shared>);
impl ServerHandler for Probe {
    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>)
        -> Result<CallToolResponse, ErrorData>
    {
        let generation = request.arguments.as_ref().and_then(|a| a.get("generation"))
            .and_then(Value::as_u64).expect("fixture generation");
        let id = serde_json::to_value(&context.id).unwrap();
        let (send, receive) = oneshot::channel();
        {
            let mut state = self.0.state.lock().unwrap();
            assert!(!state.records.contains_key(&generation));
            state.started.push(json!({"generation":generation,"id":id}));
            state.records.insert(generation, RecordState { context, gate:Some(send), completed:false });
        }
        self.0.changed.notify_waiters();
        receive.await.expect("fixture releases every handler");
        {
            let mut state = self.0.state.lock().unwrap();
            state.records.get_mut(&generation).expect("retained handler").completed = true;
        }
        self.0.changed.notify_waiters();
        let marker = format!("registry-completion-{generation}-end");
        if generation % 3 == 0 {
            Err(ErrorData::invalid_params(marker, None))
        } else {
            Ok(CallToolResult::success(vec![ContentBlock::text(marker)]).into())
        }
    }
    async fn on_cancelled(&self, notification: CancelledNotificationParam, _context: NotificationContext<RoleServer>) {
        self.0.state.lock().unwrap().notifications.push(serde_json::to_value(notification).unwrap());
        self.0.changed.notify_waiters();
    }
}
struct Fields(String);
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" { self.0 = format!("{value:?}"); }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" { self.0 = value.to_string(); }
    }
}
struct Observer(Arc<Shared>);
impl Subscriber for Observer {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool { true }
    fn new_span(&self, _attributes: &Attributes<'_>) -> Id { Id::from_u64(1) }
    fn record(&self, _span: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields(String::new()); event.record(&mut fields);
        if ["dropping response for cancelled request", "input stream terminated", "task cancelled"]
            .iter().any(|text| fields.0.contains(text)) {
            self.0.state.lock().unwrap().traces.push(fields.0);
            self.0.changed.notify_waiters();
        }
    }
}
type Writer = tokio::io::WriteHalf<tokio::io::DuplexStream>;
async fn send(shared: &Arc<Shared>, writer: &mut Writer, value: &Value) -> Result<()> {
    let mut raw = serde_json::to_string(value)?; raw.push('\n');
    shared.state.lock().unwrap().incoming.push(raw.clone());
    writer.write_all(raw.as_bytes()).await?;
    writer.flush().await?; Ok(())
}
fn request(step: &Value, modern: bool) -> Value {
    let mut params = json!({"name":"registry_probe","arguments":{"generation":step["generation"]}});
    if modern {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}
        });
    }
    json!({"jsonrpc":"2.0","id":step["id"],"method":"tools/call","params":params})
}
fn trace_count(state: &State, text: &str) -> usize {
    state.traces.iter().filter(|value| value.contains(text)).count()
}

async fn run_case(case: Value) -> Result<()> {
    let started_at = Instant::now();
    let case_id = case["case"].as_u64().ok_or_else(||anyhow!("case id"))?;
    let modern = case["initial_parent"].as_bool().unwrap_or(false);
    let steps = case["steps"].as_array().ok_or_else(||anyhow!("steps"))?;
    let shared = Arc::new(Shared::default());
    let _trace_guard = tracing::subscriber::set_default(Observer(shared.clone()));
    let (client, server) = tokio::io::duplex(16 * 1024 * 1024);
    let (read, mut writer) = tokio::io::split(client);
    let observed = shared.clone();
    let reader = tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(read);
        loop {
            let mut raw = String::new();
            let count = reader.read_line(&mut raw).await?;
            if count == 0 { break; }
            observed.state.lock().unwrap().responses.push(raw);
            observed.changed.notify_waiters();
        }
        Ok::<(),std::io::Error>(())
    });
    if modern {
        let first = steps.iter().find(|step|step["op"]=="register")
            .ok_or_else(||anyhow!("initial modern request"))?;
        send(&shared, &mut writer, &request(first,true)).await?;
    } else {
        send(&shared, &mut writer, &json!({
            "jsonrpc":"2.0","id":"fixture-initialize","method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},
            "clientInfo":{"name":"request-registry-original","version":"1"}}
        })).await?;
        send(&shared, &mut writer, &json!({"jsonrpc":"2.0","method":"notifications/initialized"})).await?;
    }
    let service = Probe(shared.clone()).serve(server).await?;
    if !modern {
        until(&shared, |state| state.responses.iter().any(|raw|
            serde_json::from_str::<Value>(raw).is_ok_and(|v|v["id"]=="fixture-initialize")
        )).await?;
    }
    shared.emit(json!({"event":"case","case":case_id,"name":case["name"],"pid":std::process::id(),"initial_parent":modern}));
    let mut first_register = true;
    let mut parent_cancelled = false;
    let mut input_closed = false;
    for (ordinal, step) in steps.iter().enumerate() {
        let op = step["op"].as_str().ok_or_else(||anyhow!("operation"))?;
        match op {
            "init" => ensure!(ordinal==0, "init must be the first step"),
            "register" => {
                let generation = step["generation"].as_u64().ok_or_else(||anyhow!("generation"))?;
                if !(modern && first_register) {
                    ensure!(!parent_cancelled && !input_closed, "fixture cannot enqueue a request after the service loop exits");
                    send(&shared, &mut writer, &request(step,false)).await?;
                }
                first_register = false;
                until(&shared, |state| state.records.contains_key(&generation)).await?;
            }
            "cancel" => {
                ensure!(!parent_cancelled && !input_closed, "notification must precede service drain");
                let before = shared.state.lock().unwrap().notifications.len();
                let mut params = json!({"reason":format!("notification-{ordinal}")});
                if !step["id"].is_null() { params["requestId"] = step["id"].clone(); }
                send(&shared, &mut writer, &json!({
                    "jsonrpc":"2.0","method":"notifications/cancelled","params":params
                })).await?;
                until(&shared, |state|state.notifications.len()>before).await?;
            }
            "complete" => {
                let generation = step["generation"].as_u64().ok_or_else(||anyhow!("generation"))?;
                let marker = format!("registry-completion-{generation}-end");
                let (gate,dropped) = {
                    let mut state = shared.state.lock().unwrap();
                    let dropped = trace_count(&state,"dropping response for cancelled request");
                    let record = state.records.get_mut(&generation).ok_or_else(||anyhow!("completion must identify a retained handler"))?;
                    (record.gate.take().ok_or_else(||anyhow!("handler already released"))?,dropped)
                };
                gate.send(()).map_err(|_|anyhow!("handler gate receiver was dropped"))?;
                until(&shared, |state|
                    state.responses.iter().any(|raw|raw.contains(&marker))
                    || trace_count(state,"dropping response for cancelled request")>dropped
                ).await?;
            }
            "retire" => {
                let generation = step["generation"].as_u64().ok_or_else(||anyhow!("generation"))?;
                let mut state = shared.state.lock().unwrap();
                ensure!(state.records.get(&generation).is_some_and(|r|r.completed),"only a completed handler may retire");
                state.records.remove(&generation);
            }
            "inspect" => {
                let generation = step["generation"].as_u64().ok_or_else(||anyhow!("generation"))?;
                ensure!(shared.state.lock().unwrap().records.contains_key(&generation),"inspect retained handler");
            }
            "parent" => {
                service.cancellation_token().cancel();
                parent_cancelled=true;
            }
            "drain" => match step["reason"].as_u64() {
                Some(1) => {
                    ensure!(!parent_cancelled && !input_closed,"EOF wins this fixture's shutdown race");
                    writer.shutdown().await?;
                    input_closed = true;
                    until(&shared, |state|trace_count(state,"input stream terminated")>0).await?;
                }
                Some(2) => {
                    ensure!(parent_cancelled,"parent cancellation must precede its drain");
                    until(&shared, |state|trace_count(state,"task cancelled")>0).await?;
                }
                _ => bail!("unknown fixture drain reason"),
            },
            _ => bail!("unknown fixture operation {op}"),
        }
        shared.snapshot(case_id,ordinal,op);
    }
    ensure!(shared.state.lock().unwrap().records.is_empty(),"every fixture handler must complete and retire");
    if !input_closed && !parent_cancelled { writer.shutdown().await?; }
    let terminal = tokio::time::timeout(Duration::from_secs(10),service.waiting()).await??;
    tokio::time::timeout(Duration::from_secs(10),reader).await???;
    let state = shared.state.lock().unwrap();
    shared.emit(json!({
        "event":"end","case":case_id,"started":state.started,"notifications":state.notifications,
        "traces":state.traces,"incoming":state.incoming,"responses":state.responses,
        "terminal":format!("{terminal:?}"),"elapsed_ns":started_at.elapsed().as_nanos(),
        "retained_contexts":state.records.len()
    }));
    Ok(())
}
#[tokio::main(flavor="current_thread")]
async fn main() -> Result<()> {
    for line in io::stdin().lock().lines() {
        let raw = line?;
        if raw.is_empty() { bail!("empty fixture line"); }
        run_case(serde_json::from_str(&raw)?).await?;
    }
    Ok(())
}

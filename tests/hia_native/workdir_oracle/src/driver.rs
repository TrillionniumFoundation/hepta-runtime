// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Test carrier. Slots below are filled with exact original source bytes.
use std::io::{self, BufRead, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use serde_json::{json, Value};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use rmcp::model::{CallToolRequestParams, CallToolResponse};
use rmcp::service::RequestContext;
use rmcp::handler::server::tool::{ToolCallContext, AsyncMethodAdapter};
use rmcp::handler::server::wrapper::Parameters;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

mod mcp {
    use serde::{Serialize, Deserialize};
    use serde_json::Value;
    use std::path::PathBuf;
@@MCP_TOOL_CALL@@

    // Uninhabited test declarations for excluded configuration branches. No
    // profile is constructed or accepted by the input corpus. The original
    // RuntimeConfig declaration, accessors and path-policy bodies stay exact.
    pub mod weight_config {
        #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
        pub enum WeightWorkerProfile {}
    }
    pub mod rea_provider {
        #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
        pub enum ReaStaticProfile {}
    }
    pub mod hia_provider {
        #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
        pub enum HiaWorkerProfile {}
    }

    pub mod runtime {
        pub mod original_config {
            use anyhow::{anyhow, bail, Context, Result};
            use serde::{Deserialize, Serialize};
            use std::collections::BTreeMap;
            use std::ffi::OsString;
            use std::path::{Component, Path, PathBuf};
            use std::sync::OnceLock;
            static RUNTIME_CONFIG: OnceLock<InstalledRuntimeConfig> = OnceLock::new();
@@CONFIG_DEFINITIONS@@
@@INSTALLED_RUNTIME_CONFIG@@
            impl InstalledRuntimeConfig {
@@INSTALLED_RUNTIME_NEW@@
            }
@@DEFAULT_STATE_DIR@@
@@RUNTIME_CONFIG@@
@@MAYBE_RUNTIME_CONFIG@@
            impl RuntimeConfig {
@@HOST_BY_ALIAS@@
            }
@@NORMALIZE_ABSOLUTE@@
@@CANONICAL_POLICY_PATH@@
@@PATH_UNDER@@
@@CHECK_LOCAL_PATH@@
@@REMOTE_PATH_ALLOWED@@
@@CHECK_REMOTE_PATH@@
            pub fn install_for_reference(config: RuntimeConfig) {
                assert!(config.weight_workers.is_empty());
                assert!(config.rea_static_profiles.is_empty());
                assert!(config.hia_worker.is_none());
                assert!(RUNTIME_CONFIG.set(InstalledRuntimeConfig::new(config)).is_ok());
            }
        }
        pub mod config {
            use std::path::Path;
            pub use super::original_config::RuntimeConfig;
            pub fn maybe_runtime_config() -> Option<&'static RuntimeConfig> {
                let result = super::original_config::maybe_runtime_config();
                crate::event("policy_lookup", serde_json::json!({"installed": result.is_some()}));
                result
            }
            pub fn check_local_path(path: &Path) -> anyhow::Result<()> {
                crate::event("local_policy_enter", serde_json::json!({"path_hex": crate::path_hex(path)}));
                let result = super::original_config::check_local_path(path);
                crate::event("local_policy_exit", crate::unit_result(&result));
                result
            }
            pub fn check_remote_path(alias: &str, path: &str, user: bool, port: bool, write: bool) -> anyhow::Result<()> {
                crate::event("remote_policy_enter", serde_json::json!({
                    "alias": alias, "path": path, "user_explicit": user,
                    "port_explicit": port, "write": write}));
                let result = super::original_config::check_remote_path(alias, path, user, port, write);
                crate::event("remote_policy_exit", crate::unit_result(&result));
                result
            }
        }
    }

    pub mod fs {
        pub mod remote {
            use anyhow::{anyhow, Result};
            use std::path::{Path, PathBuf};
@@PATH_SOURCE@@
            mod sftp {
                use super::PathSource;
                pub struct RemoteMetadata { pub is_dir: bool }
                pub async fn remote_canonicalize(_: &PathSource) -> anyhow::Result<String> {
                    panic!("SSH/SFTP I/O is outside the workdir original reference domain");
                }
                pub async fn remote_metadata(_: &PathSource) -> anyhow::Result<RemoteMetadata> {
                    panic!("SSH/SFTP I/O is outside the workdir original reference domain");
                }
            }
@@IO_CANONICALIZE@@
@@IO_IS_DIR@@
        }
        pub use remote::PathSource;
        pub mod workdir {
@@WORKDIR_FILE@@
        }
        pub use workdir::WorkdirResult;
        pub async fn execute_workdir_command(call: &super::McpToolCall) -> anyhow::Result<WorkdirResult> {
            let parameters = crate::blob(&serde_json::to_vec(&call.parameters).unwrap());
            crate::event("helper_enter", serde_json::json!({"parameters_blob": parameters,
                "workdir_hex": crate::path_hex(&call.workdir), "tool_name": call.tool_name,
                "tool_id": call.tool_id}));
            let result = workdir::execute_workdir_command(call).await;
            crate::event("helper_exit", crate::helper_result(&result));
            result
        }
    }

    pub mod server {
        use super::{fs, runtime, McpToolCall};
        use serde::{Deserialize, Serialize};
        use std::path::PathBuf;
        use std::sync::{Arc, RwLock};
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use rmcp::RoleServer;
        use rmcp::service::RequestContext;
        use rmcp::handler::server::wrapper::Parameters;
        use tracing::debug;
@@SESSION_WORKDIR@@
@@WORKDIR_PARAMS@@
@@ENFORCE_RUNTIME_PATH_SPEC@@
        #[derive(Clone)]
        pub struct OctofsServer {
            pub workdir: Arc<SessionWorkdir>,
            pub session_applied: Arc<AtomicBool>,
            pub outer_calls: Arc<AtomicUsize>,
            pub handler_calls: Arc<AtomicUsize>,
        }
        impl OctofsServer {
@@ENSURE_SESSION_WORKDIR@@
@@WORKDIR_HANDLER@@
            pub fn invoke_workdir(&self, context: RequestContext<RoleServer>, params: Parameters<WorkdirParams>)
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>> {
                Box::pin(async move {
                    self.handler_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let typed = crate::blob(&serde_json::to_vec(&params.0).unwrap());
                    crate::event("handler_enter", serde_json::json!({"typed_parameters_blob": typed,
                        "capabilities": context.client_capabilities(), "protocol_version": context.protocol_version(),
                        "request_id": context.id}));
                    let result = self.workdir(context, params).await;
                    let (ok, text) = match &result { Ok(text) => (true, text), Err(text) => (false, text) };
                    let result_blob = crate::blob(text.as_bytes());
                    crate::event("handler_exit", serde_json::json!({"ok": ok, "body_blob": result_blob,
                        "body_bytes": text.len()}));
                    result
                })
            }
        }
    }
}

type OriginalServer = mcp::server::OctofsServer;
type OriginalSession = mcp::server::SessionWorkdir;

#[derive(Default)]
struct Observation {
    next_marker: u64,
    events: Vec<Value>,
    blobs: Vec<Vec<u8>>,
    watch: Option<(Arc<OriginalSession>, Arc<AtomicBool>)>,
}
static OBS: LazyLock<Mutex<Observation>> = LazyLock::new(Default::default);

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes { value.push(DIGITS[(byte >> 4) as usize] as char); value.push(DIGITS[(byte & 15) as usize] as char); }
    value
}
fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value.as_bytes().chunks_exact(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
}
fn path_hex(path: &Path) -> String { hex(path.as_os_str().as_bytes()) }
fn from_hex(value: &Value) -> PathBuf {
    PathBuf::from(std::ffi::OsString::from_vec(unhex(value.as_str().unwrap())))
}
fn snapshot(state: &OriginalSession, latch: &AtomicBool) -> Value {
    let (poisoned, current) = match state.current.read() {
        Ok(guard) => (false, guard.clone()),
        Err(error) => (true, error.into_inner().clone()),
    };
    json!({"root_hex": path_hex(&state.root), "current_hex": current.as_ref().map(|p| path_hex(p)),
           "effective_hex": path_hex(&state.get_current()), "poisoned": poisoned,
           "session_applied": latch.load(Ordering::SeqCst)})
}
fn event(kind: &str, data: Value) {
    let mut obs = OBS.lock().unwrap();
    obs.next_marker += 1;
    let marker = 1_000_000_000 + obs.next_marker;
    // A read-only syscall with an impossible Linux PID gives strace an exact
    // boundary without editing the original functions or logging fake I/O.
    let result = unsafe { libc::getpgid(i32::try_from(marker).unwrap()) };
    assert_eq!(result, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    let state = obs.watch.as_ref().map(|(state, latch)| snapshot(state, latch));
    obs.events.push(json!({"kind": kind, "marker": marker, "data": data, "state": state}));
}
fn blob(bytes: &[u8]) -> usize {
    let mut obs = OBS.lock().unwrap(); let index = obs.blobs.len(); obs.blobs.push(bytes.to_vec()); index
}
fn unit_result(result: &anyhow::Result<()>) -> Value {
    match result { Ok(()) => json!({"ok": true}), Err(error) => json!({"ok": false, "error": error.to_string()}) }
}
fn helper_result(result: &anyhow::Result<mcp::fs::WorkdirResult>) -> Value {
    use mcp::fs::WorkdirResult;
    match result {
        Ok(value) => {
            let body = value.to_json_string(); let body_blob = blob(body.as_bytes());
            let detail = match value {
                WorkdirResult::Get { working_directory } => json!({"kind": "get", "current_hex": path_hex(working_directory)}),
                WorkdirResult::Set { previous, current } => json!({"kind": "set", "previous_hex": path_hex(previous), "current_hex": path_hex(current)}),
                WorkdirResult::Reset => json!({"kind": "reset"}),
            };
            json!({"ok": true, "body_blob": body_blob, "body_bytes": body.len(), "detail": detail})
        }
        Err(error) => {
            let body = error.to_string(); let body_blob = blob(body.as_bytes());
            json!({"ok": false, "body_blob": body_blob, "body_bytes": body.len()})
        }
    }
}
fn write_record(output: &mut impl Write, mut metadata: Value) {
    let mut obs = OBS.lock().unwrap();
    metadata["events"] = json!(std::mem::take(&mut obs.events));
    let blobs = std::mem::take(&mut obs.blobs);
    let bytes = serde_json::to_vec(&metadata).unwrap();
    output.write_all(&(bytes.len() as u64).to_le_bytes()).unwrap();
    output.write_all(&(blobs.len() as u64).to_le_bytes()).unwrap();
    output.write_all(&bytes).unwrap();
    for value in blobs {
        output.write_all(&(value.len() as u64).to_le_bytes()).unwrap();
        output.write_all(&value).unwrap();
    }
    output.flush().unwrap();
}

fn checked_owned(path: PathBuf, root: &Path) -> PathBuf {
    assert!(path.is_absolute() && path.starts_with(root) && path != root);
    assert!(!path.components().any(|part| matches!(part, std::path::Component::ParentDir)));
    path
}
fn actions(values: &Value, root: &Path) {
    for action in values.as_array().unwrap() {
        let path = checked_owned(from_hex(&action["path_hex"]), root);
        match action["kind"].as_str().unwrap() {
            "mkdir" => std::fs::create_dir_all(path).unwrap(),
            "write" => std::fs::write(path, unhex(action["data_hex"].as_str().unwrap())).unwrap(),
            "symlink" => std::os::unix::fs::symlink(from_hex(&action["target_hex"]), path).unwrap(),
            "hardlink" => std::fs::hard_link(checked_owned(from_hex(&action["target_hex"]), root), path).unwrap(),
            "chmod" => std::fs::set_permissions(path, std::fs::Permissions::from_mode(action["mode"].as_u64().unwrap() as u32)).unwrap(),
            "remove_file" => std::fs::remove_file(path).unwrap(),
            "remove_dir" => std::fs::remove_dir(path).unwrap(),
            "rename" => std::fs::rename(path, checked_owned(from_hex(&action["target_hex"]), root)).unwrap(),
            "fifo" => {
                let value = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(value.as_ptr(), 0o600) }, 0);
            }
            other => panic!("unknown actual fixture action: {other}"),
        }
    }
}

impl ServerHandler for OriginalServer {
    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>)
        -> Result<CallToolResponse, ErrorData> {
        self.outer_calls.fetch_add(1, Ordering::SeqCst);
        let canonical_arguments = serde_json::to_vec(&Value::Object(request.arguments.clone().unwrap_or_default())).unwrap();
        let canonical_arguments_blob = blob(&canonical_arguments);
        event("outer_call_tool_enter", json!({"name": request.name,
            "canonical_arguments_blob": canonical_arguments_blob, "canonical_arguments_bytes": canonical_arguments.len()}));
        ToolCallContext::new(self, request, context)
            .invoke::<_, AsyncMethodAdapter<(RequestContext<RoleServer>, Parameters<mcp::server::WorkdirParams>), Result<String, String>>>(Self::invoke_workdir)
            .await
    }
}

struct LiveSession {
    owner: OriginalServer,
    reader: tokio::io::BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    task: tokio::task::JoinHandle<Value>,
}
impl LiveSession {
    fn start(root: PathBuf) -> Self {
        let owner = OriginalServer { workdir: Arc::new(OriginalSession::new(root)),
            session_applied: Arc::new(AtomicBool::new(false)), outer_calls: Arc::new(AtomicUsize::new(0)),
            handler_calls: Arc::new(AtomicUsize::new(0)) };
        let handler = owner.clone();
        let (client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            match handler.serve(server).await {
                Ok(service) => {
                    let result = service.waiting().await;
                    json!({"initialized": true, "terminated": format!("{result:?}")})
                }
                Err(error) => json!({"initialized": false, "error": error.to_string()}),
            }
        });
        let (reader, writer) = tokio::io::split(client);
        Self { owner, reader: tokio::io::BufReader::new(reader), writer, task }
    }
    fn watch(&self) {
        OBS.lock().unwrap().watch = Some((self.owner.workdir.clone(), self.owner.session_applied.clone()));
    }
    fn state(&self) -> Value { snapshot(&self.owner.workdir, &self.owner.session_applied) }
    async fn exchange(&mut self, message: &Value) -> Value {
        let mut bytes = serde_json::to_vec(message).unwrap(); bytes.push(b'\n');
        let request_blob = blob(&bytes);
        self.writer.write_all(&bytes).await.unwrap();
        if message.get("id").is_none() {
            return json!({"request_blob": request_blob, "response_blob": null});
        }
        let mut wire = Vec::new();
        let size = tokio::time::timeout(Duration::from_secs(20), self.reader.read_until(b'\n', &mut wire)).await.unwrap().unwrap();
        assert!(size > 0 && wire.ends_with(b"\n"), "actual SDK response missing");
        let response: Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(response["id"], message["id"]);
        json!({"request_blob": request_blob, "response_blob": blob(&wire), "response_bytes": wire.len()})
    }
    async fn finish(self) -> Value {
        let state = self.state();
        let outer = self.owner.outer_calls.load(Ordering::SeqCst);
        let handler = self.owner.handler_calls.load(Ordering::SeqCst);
        drop(self.reader); drop(self.writer);
        let terminal = tokio::time::timeout(Duration::from_secs(20), self.task).await.unwrap().unwrap();
        json!({"state": state, "outer_calls": outer, "handler_calls": handler, "service": terminal})
    }
}

async fn scenario(row: Value, root: &Path, output: &mut impl Write) {
    assert_eq!(row["schema"], "hepta.runtime.workdir-original-input.v1");
    OBS.lock().unwrap().watch = None;
    event("scenario_setup_begin", json!({"scenario_id": row["scenario_id"]}));
    actions(&row["setup"], root);
    event("scenario_setup_complete", json!({"scenario_id": row["scenario_id"]}));
    let mut sessions = std::collections::BTreeMap::new();
    let mut starts = Vec::new();
    for input in row["sessions"].as_array().unwrap() {
        let id = input["id"].as_str().unwrap().to_owned();
        let mut session = LiveSession::start(from_hex(&input["root_hex"])); session.watch();
        let mut exchanges = Vec::new();
        for request in input["initial_messages"].as_array().unwrap() { exchanges.push(session.exchange(request).await); }
        starts.push(json!({"session": id, "exchanges": exchanges, "state": session.state()}));
        assert!(sessions.insert(id, session).is_none());
    }
    write_record(output, json!({"kind": "scenario_start", "scenario_id": row["scenario_id"],
        "name": row["name"], "policy_id": row["policy_id"], "sessions": starts}));
    for step in row["steps"].as_array().unwrap() {
        let id = step["session"].as_str().unwrap();
        let session = sessions.get_mut(id).unwrap(); session.watch();
        let before = session.state();
        let outer_before = session.owner.outer_calls.load(Ordering::SeqCst);
        let handler_before = session.owner.handler_calls.load(Ordering::SeqCst);
        event("step_begin", json!({"case_id": step["case_id"], "name": step["name"], "domain": step["domain"]}));
        let action = &step["action"];
        let result = match action["kind"].as_str().unwrap() {
            "public" => session.exchange(&action["message"]).await,
            "helper" => {
                let workdir = if action.get("workdir_hex").is_some() { from_hex(&action["workdir_hex"]) }
                    else { session.owner.workdir.get_current() };
                let call = mcp::McpToolCall { tool_name: "workdir".into(), parameters: action["parameters"].clone(),
                    tool_id: String::new(), workdir };
                helper_result(&mcp::fs::execute_workdir_command(&call).await)
            }
            "poison" => {
                let state = session.owner.workdir.clone();
                let panicked = std::panic::catch_unwind(move || {
                    let _guard = state.current.write().unwrap();
                    panic!("workdir reference deliberately poisons the actual RwLock");
                }).is_err();
                assert!(panicked && session.owner.workdir.current.is_poisoned());
                json!({"actual_poisoned_lock": true})
            }
            "state_set" => { session.owner.workdir.set_current(from_hex(&action["path_hex"])); json!({"private_state_action": "set"}) }
            "state_reset" => { session.owner.workdir.reset(); json!({"private_state_action": "reset"}) }
            "state_get" => json!({"effective_hex": path_hex(&session.owner.workdir.get_current())}),
            "render" => {
                let value = match action["variant"].as_str().unwrap() {
                    "get" => mcp::fs::WorkdirResult::Get { working_directory: from_hex(&action["current_hex"]) },
                    "set" => mcp::fs::WorkdirResult::Set { previous: from_hex(&action["previous_hex"]), current: from_hex(&action["current_hex"]) },
                    "reset" => mcp::fs::WorkdirResult::Reset,
                    other => panic!("unknown original result variant: {other}"),
                };
                helper_result(&Ok(value))
            }
            "filesystem" => { actions(&action["actions"], root); json!({"actual_fixture_actions": action["actions"].as_array().unwrap().len()}) }
            other => panic!("unknown step kind: {other}"),
        };
        event("step_end", json!({"case_id": step["case_id"]}));
        write_record(output, json!({"kind": "case", "scenario_id": row["scenario_id"],
            "case_id": step["case_id"], "name": step["name"], "domain": step["domain"], "session": id,
            "state_before": before, "state_after": session.state(), "result": result,
            "outer_call_tool_entries": session.owner.outer_calls.load(Ordering::SeqCst) - outer_before,
            "handler_entries": session.owner.handler_calls.load(Ordering::SeqCst) - handler_before}));
    }
    OBS.lock().unwrap().watch = None;
    let mut terminal = serde_json::Map::new();
    for (id, session) in sessions { terminal.insert(id, session.finish().await); }
    event("scenario_end", json!({"scenario_id": row["scenario_id"]}));
    write_record(output, json!({"kind": "scenario_end", "scenario_id": row["scenario_id"], "sessions": terminal}));
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    assert_eq!(arguments.len(), 3);
    let root = PathBuf::from(&arguments[1]);
    assert!(root.is_absolute() && root.is_dir());
    let policy: Value = serde_json::from_slice(&std::fs::read(&arguments[2]).unwrap()).unwrap();
    if !policy.is_null() {
        let config: mcp::runtime::original_config::RuntimeConfig = serde_json::from_value(policy).unwrap();
        mcp::runtime::original_config::install_for_reference(config);
    }
    let input = io::stdin().lock(); let mut output = io::BufWriter::new(io::stdout().lock());
    output.write_all(b"HWDRO001").unwrap();
    for line in input.lines() {
        let row: Value = serde_json::from_str(&line.unwrap()).unwrap();
        scenario(row, &root, &mut output).await;
    }
    output.flush().unwrap();
}

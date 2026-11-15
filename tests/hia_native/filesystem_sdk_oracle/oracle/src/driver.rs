// Original methods/modules are inserted without byte edits. Observer wrappers
// delegate exactly once. The three-name dispatcher is an explicit test carrier.
use std::io::{self, BufRead, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
    // These excluded profile variants are uninhabited in the input domain.
    // No loader or nonempty profile acceptance is claimed by this carrier.
    pub mod weight_config { #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] pub enum WeightWorkerProfile {} }
    pub mod rea_provider { #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] pub enum ReaStaticProfile {} }
    pub mod hia_provider { #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] pub enum HiaWorkerProfile {} }
    pub mod request_ctx;
    pub mod runtime {
        pub mod original_config {
            use anyhow::{anyhow, bail, Context, Result};
            use serde::{Deserialize, Serialize};
            use std::collections::BTreeMap;
            use std::ffi::OsString;
            use std::path::{Component, Path, PathBuf};
            use std::sync::OnceLock;
@@RUNTIME_STATIC@@
@@CONFIG_DEFINITIONS@@
@@INSTALLED_CONFIG@@
            impl InstalledRuntimeConfig {
@@INSTALLED_CONFIG_NEW@@
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
@@CHECK_DIRECTORY_MOVE_AGAINST_ROOTS@@
@@CHECK_DIRECTORY_MOVE_SOURCE@@
            pub fn install_for_reference(config: RuntimeConfig) {
                assert!(config.weight_workers.is_empty() && config.rea_static_profiles.is_empty() && config.hia_worker.is_none());
                assert!(RUNTIME_CONFIG.set(InstalledRuntimeConfig::new(config)).is_ok());
            }
        }
        pub mod config {
            use std::path::Path;
            pub use super::original_config::{RuntimeConfig, runtime_config};
            pub fn maybe_runtime_config() -> Option<&'static RuntimeConfig> {
                let result = super::original_config::maybe_runtime_config();
                crate::event("policy_lookup", serde_json::json!({"installed": result.is_some()})); result
            }
            pub fn check_local_path(path: &Path) -> anyhow::Result<()> {
                crate::event("local_policy_enter", serde_json::json!({"path_blob": crate::blob(path.as_os_str().as_encoded_bytes())}));
                let result = super::original_config::check_local_path(path);
                crate::event("local_policy_exit", crate::unit_result(&result)); result
            }
            pub fn check_remote_path(alias: &str, path: &str, user: bool, port: bool, write: bool) -> anyhow::Result<()> {
                crate::event("remote_policy_enter", serde_json::json!({"alias": alias, "path": path,
                    "user_explicit": user, "port_explicit": port, "write": write}));
                let result = super::original_config::check_remote_path(alias, path, user, port, write);
                crate::event("remote_policy_exit", crate::unit_result(&result)); result
            }
            pub fn check_directory_move_source(path: &Path) -> anyhow::Result<()> {
                crate::event("directory_guard_enter", serde_json::json!({"path_blob": crate::blob(path.as_os_str().as_encoded_bytes())}));
                let result = super::original_config::check_directory_move_source(path);
                crate::event("directory_guard_exit", crate::unit_result(&result)); result
            }
        }
        pub mod original_effect_owner_fence;
        pub mod effect_owner_fence {
            pub async fn admit_new_effect() -> anyhow::Result<super::original_effect_owner_fence::AdmissionPermit> {
                crate::event("effect_fence_enter", serde_json::json!({}));
                let result = super::original_effect_owner_fence::admit_new_effect().await;
                crate::event("effect_fence_exit", match &result {
                    Ok(_) => serde_json::json!({"ok": true}),
                    Err(error) => crate::error_result(error),
                }); result
            }
        }
    }
    pub mod fs {
        pub mod remote {
            use std::path::{Path, PathBuf};
@@PATH_SOURCE@@
        }
        pub use remote::PathSource;
        pub mod text_editing {
            use super::PathSource;
            use std::path::Path;
@@LOCK_KEY_FOR@@
@@LOCK_KEY_FOR_SOURCE@@
        }
        pub mod original_delta {
            use std::collections::HashMap;
            use std::sync::Mutex;
            use super::text_editing::lock_key_for_source;
            use super::PathSource;
            use crate::mcp::request_ctx::with_view_cache;
@@MAX_CACHED_BYTES@@
@@VIEW_CACHE@@
@@VIEW_CACHE_IMPL@@
@@DELTA_NORMALIZE@@
@@DELTA_NOTE_CREATE@@
@@DELTA_FORGET@@
@@DELTA_FORGET_SUBTREE@@
            pub fn observe(cache: &ViewCache) -> serde_json::Value {
                match cache.entries.lock() {
                    Ok(entries) => serde_json::json!({"poisoned": false,
                        "entries": entries.iter().map(|(k,v)| (k.clone(),v.clone())).collect::<std::collections::BTreeMap<_,_>>()}),
                    Err(error) => serde_json::json!({"poisoned": true,
                        "entries": error.into_inner().iter().map(|(k,v)| (k.clone(),v.clone())).collect::<std::collections::BTreeMap<_,_>>()}),
                }
            }
        }
        pub mod delta {
            pub use super::original_delta::{ViewCache, note_create, observe};
            pub fn forget(source: &super::PathSource) {
                crate::event("cache_forget_enter", serde_json::json!({"path_blob": crate::blob(source.as_local_path().unwrap().as_os_str().as_encoded_bytes())}));
                super::original_delta::forget(source);
                crate::event("cache_forget_exit", serde_json::json!({}));
            }
            pub fn forget_subtree(source: &super::PathSource) {
                crate::event("cache_forget_subtree_enter", serde_json::json!({"path_blob": crate::blob(source.as_local_path().unwrap().as_os_str().as_encoded_bytes())}));
                super::original_delta::forget_subtree(source);
                crate::event("cache_forget_subtree_exit", serde_json::json!({}));
            }
        }
        pub mod original_parity_ops;
        pub mod parity_ops {
            use crate::mcp::McpToolCall;
            fn entered(call: &McpToolCall) {
                crate::event("filesystem_helper_enter", serde_json::json!({"tool": call.tool_name,
                    "parameters_blob": crate::blob(&serde_json::to_vec(&call.parameters).unwrap()),
                    "workdir_blob": crate::blob(call.workdir.as_os_str().as_encoded_bytes()),
                    "request_context_present": crate::mcp::request_ctx::with_view_cache(|_| true).is_some()}));
            }
            fn exited(result: &anyhow::Result<String>) {
                crate::event("filesystem_helper_exit", match result {
                    Ok(body) => serde_json::json!({"ok": true, "body_blob": crate::blob(body.as_bytes()), "body_bytes": body.len()}),
                    Err(error) => crate::error_result(error),
                });
            }
            pub async fn execute_directory_create(call: &McpToolCall) -> anyhow::Result<String> {
                entered(call); let result = super::original_parity_ops::execute_directory_create(call).await; exited(&result); result
            }
            pub async fn execute_file_move(call: &McpToolCall) -> anyhow::Result<String> {
                entered(call); let result = super::original_parity_ops::execute_file_move(call).await; exited(&result); result
            }
            pub async fn execute_directory_move(call: &McpToolCall) -> anyhow::Result<String> {
                entered(call); let result = super::original_parity_ops::execute_directory_move(call).await; exited(&result); result
            }
        }
    }
    pub mod server {
        use super::{fs, runtime, request_ctx, McpToolCall};
        use serde::{Deserialize, Serialize};
        use std::path::PathBuf;
        use std::sync::{Arc, RwLock};
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use rmcp::RoleServer;
        use rmcp::service::RequestContext;
        use rmcp::handler::server::wrapper::Parameters;
        use tracing::debug;
@@SESSION_WORKDIR@@
@@DIRECTORYCREATEPARAMS@@
@@FILEMOVEPARAMS@@
@@DIRECTORYMOVEPARAMS@@
@@ENFORCE_RUNTIME_PATH_SPEC@@
@@APPEND_HINTS@@
        #[derive(Clone)]
        pub struct OriginalServer {
            pub workdir: Arc<SessionWorkdir>, pub session_applied: Arc<AtomicBool>,
            pub view_cache: Arc<fs::delta::ViewCache>, pub outer_calls: Arc<AtomicUsize>, pub handler_calls: Arc<AtomicUsize>,
        }
        impl OriginalServer {
@@ENSURE_SESSION_WORKDIR@@
@@DIRECTORY_CREATE@@
@@FILE_MOVE@@
@@DIRECTORY_MOVE@@
            fn entered(&self, tool: &str, params: &impl Serialize, context: &RequestContext<RoleServer>) {
                self.handler_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                crate::event("handler_enter", serde_json::json!({"tool": tool,
                    "typed_parameters_blob": crate::blob(&serde_json::to_vec(params).unwrap()),
                    "capabilities": context.client_capabilities(), "protocol_version": context.protocol_version(), "request_id": context.id}));
            }
            fn exited(&self, result: &Result<String, String>) {
                let (ok, body) = match result { Ok(text) => (true, text), Err(text) => (false, text) };
                crate::event("handler_exit", serde_json::json!({"ok": ok, "body_blob": crate::blob(body.as_bytes()), "body_bytes": body.len(),
                    "request_context_present": request_ctx::with_view_cache(|_| true).is_some()}));
            }
            pub fn invoke_directory_create(&self, context: RequestContext<RoleServer>, params: Parameters<DirectoryCreateParams>) -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<String,String>>+Send+'_>> {
                Box::pin(async move { self.entered("directory_create", &params.0, &context); let result = self.directory_create(context, params).await; self.exited(&result); result })
            }
            pub fn invoke_file_move(&self, context: RequestContext<RoleServer>, params: Parameters<FileMoveParams>) -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<String,String>>+Send+'_>> {
                Box::pin(async move { self.entered("file_move", &params.0, &context); let result = self.file_move(context, params).await; self.exited(&result); result })
            }
            pub fn invoke_directory_move(&self, context: RequestContext<RoleServer>, params: Parameters<DirectoryMoveParams>) -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<String,String>>+Send+'_>> {
                Box::pin(async move { self.entered("directory_move", &params.0, &context); let result = self.directory_move(context, params).await; self.exited(&result); result })
            }
        }
    }
}

type OriginalServer = mcp::server::OriginalServer;
type OriginalSession = mcp::server::SessionWorkdir;
type OriginalCache = mcp::fs::delta::ViewCache;

#[derive(Default)]
struct Observation {
    next_marker: u64, events: Vec<Value>, blobs: Vec<Vec<u8>>,
    watch: Option<(Arc<OriginalSession>, Arc<AtomicBool>, Arc<OriginalCache>)>,
}
static OBS: LazyLock<Mutex<Observation>> = LazyLock::new(Default::default);

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8;16] = b"0123456789abcdef"; let mut result = String::with_capacity(bytes.len()*2);
    for byte in bytes { result.push(DIGITS[(byte>>4) as usize] as char); result.push(DIGITS[(byte&15) as usize] as char); } result
}
fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len()%2,0); text.as_bytes().chunks_exact(2).map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(),16).unwrap()).collect()
}
fn from_hex(value: &Value) -> PathBuf { PathBuf::from(std::ffi::OsString::from_vec(unhex(value.as_str().unwrap()))) }
fn path_hex(value: &Path) -> String { hex(value.as_os_str().as_bytes()) }
fn state_snapshot(state: &OriginalSession, latch: &AtomicBool, cache: &OriginalCache) -> Value {
    let (poisoned, current) = match state.current.read() { Ok(v) => (false, v.clone()), Err(e) => (true, e.into_inner().clone()) };
    json!({"root_hex": path_hex(&state.root), "current_hex": current.as_ref().map(|p| path_hex(p)),
        "effective_hex": path_hex(&state.get_current()), "poisoned": poisoned, "session_applied": latch.load(Ordering::SeqCst),
        "cache": mcp::fs::delta::observe(cache)})
}
fn event(kind: &str, data: Value) {
    let mut obs = OBS.lock().unwrap(); obs.next_marker += 1; let marker = 1_000_000_000+obs.next_marker;
    let ret = unsafe { libc::getpgid(i32::try_from(marker).unwrap()) };
    assert_eq!(ret,-1); assert_eq!(io::Error::last_os_error().raw_os_error(),Some(libc::ESRCH));
    let state = obs.watch.as_ref().map(|(state,latch,cache)| state_snapshot(state,latch,cache));
    obs.events.push(json!({"kind": kind, "marker": marker, "data": data, "state": state}));
}
fn blob(bytes: &[u8]) -> usize { let mut obs = OBS.lock().unwrap(); let index = obs.blobs.len(); obs.blobs.push(bytes.to_vec()); index }
fn error_result(error: &anyhow::Error) -> Value {
    let short = error.to_string(); let chain = format!("{error:#}");
    json!({"ok": false, "short_blob": blob(short.as_bytes()), "chain_blob": blob(chain.as_bytes()),
        "errno": error.downcast_ref::<io::Error>().and_then(|e| e.raw_os_error())})
}
fn unit_result(result: &anyhow::Result<()>) -> Value { match result { Ok(()) => json!({"ok":true}), Err(e) => error_result(e) } }
fn write_record(output: &mut impl Write, mut metadata: Value) {
    let mut obs = OBS.lock().unwrap(); metadata["events"] = json!(std::mem::take(&mut obs.events));
    let blobs = std::mem::take(&mut obs.blobs); let bytes = serde_json::to_vec(&metadata).unwrap();
    for word in [bytes.len() as u64, blobs.len() as u64] { output.write_all(&word.to_le_bytes()).unwrap(); }
    output.write_all(&bytes).unwrap();
    for body in blobs { output.write_all(&(body.len() as u64).to_le_bytes()).unwrap(); output.write_all(&body).unwrap(); }
    output.flush().unwrap();
}

fn checked_owned(path: PathBuf, root: &Path) -> PathBuf {
    assert!(path.is_absolute() && path.starts_with(root) && path != root);
    assert!(!path.components().any(|p| matches!(p,std::path::Component::ParentDir))); path
}
fn actions(values: &Value, root: &Path) {
    for action in values.as_array().unwrap() {
        let path = checked_owned(from_hex(&action["path_hex"]),root);
        match action["kind"].as_str().unwrap() {
            "mkdir" => std::fs::create_dir_all(path).unwrap(),
            "write" => std::fs::write(path,unhex(action["data_hex"].as_str().unwrap())).unwrap(),
            "symlink" => std::os::unix::fs::symlink(from_hex(&action["target_hex"]),path).unwrap(),
            "hardlink" => std::fs::hard_link(checked_owned(from_hex(&action["target_hex"]),root),path).unwrap(),
            "chmod" => std::fs::set_permissions(path,std::fs::Permissions::from_mode(action["mode"].as_u64().unwrap() as u32)).unwrap(),
            "remove_file" => std::fs::remove_file(path).unwrap(),
            "remove_dir" => std::fs::remove_dir(path).unwrap(),
            "rename" => std::fs::rename(path,checked_owned(from_hex(&action["target_hex"]),root)).unwrap(),
            "fifo" => { let p = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap(); assert_eq!(unsafe{libc::mkfifo(p.as_ptr(),0o600)},0); }
            other => panic!("unknown fixture action {other}"),
        }
    }
}
fn tree_snapshot(roots: &[PathBuf]) -> Value {
    fn walk(path: &Path, base: &Path, rows: &mut Vec<Value>) {
        let mut row = json!({"relative_hex": path_hex(path.strip_prefix(base).unwrap())});
        match std::fs::symlink_metadata(path) {
            Err(error) => { row["errno"] = json!(error.raw_os_error()); rows.push(row); }
            Ok(meta) => {
                row["device"] = json!(meta.dev()); row["inode"] = json!(meta.ino()); row["mode"] = json!(meta.mode());
                row["uid"] = json!(meta.uid()); row["gid"] = json!(meta.gid()); row["links"] = json!(meta.nlink()); row["size"] = json!(meta.len());
                row["mtime"] = json!([meta.mtime(),meta.mtime_nsec()]); row["ctime"] = json!([meta.ctime(),meta.ctime_nsec()]);
                if meta.file_type().is_symlink() {
                    match std::fs::read_link(path) { Ok(target) => row["target_hex"] = json!(path_hex(&target)), Err(e) => row["readlink_errno"] = json!(e.raw_os_error()) }
                } else if meta.is_file() {
                    match std::fs::read(path) { Ok(bytes) => row["content_hex"] = json!(hex(&bytes)), Err(e) => row["read_errno"] = json!(e.raw_os_error()) }
                }
                if meta.is_dir() {
                    match std::fs::read_dir(path) {
                        Ok(entries) => {
                            let mut paths: Vec<_> = entries.map(|e| e.unwrap().path()).collect(); paths.sort_by(|a,b| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
                            rows.push(row); for child in paths { walk(&child,base,rows); } return;
                        }
                        Err(error) => row["readdir_errno"] = json!(error.raw_os_error()),
                    }
                }
                rows.push(row);
            }
        }
    }
    Value::Array(roots.iter().map(|root| { let mut rows=Vec::new(); walk(root,root,&mut rows); json!({"root_hex":path_hex(root),"nodes":rows}) }).collect())
}
fn descriptor_snapshot() -> Value {
    let mut entries = Vec::new();
    for item in std::fs::read_dir("/proc/self/fd").unwrap() {
        let item = item.unwrap(); let fd: i32 = item.file_name().to_str().unwrap().parse().unwrap();
        let target = std::fs::read_link(item.path()).unwrap(); entries.push((fd,path_hex(&target)));
    }
    entries.sort(); json!(entries)
}

impl ServerHandler for OriginalServer {
    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>) -> Result<CallToolResponse,ErrorData> {
        self.outer_calls.fetch_add(1,Ordering::SeqCst);
        let canonical = serde_json::to_vec(&Value::Object(request.arguments.clone().unwrap_or_default())).unwrap();
        event("outer_call_tool_enter",json!({"tool":request.name,"canonical_arguments_blob":blob(&canonical),"canonical_arguments_bytes":canonical.len()}));
        match request.name.as_ref() {
            "directory_create" => ToolCallContext::new(self,request,context).invoke::<_,AsyncMethodAdapter<(RequestContext<RoleServer>,Parameters<mcp::server::DirectoryCreateParams>),Result<String,String>>>(Self::invoke_directory_create).await,
            "file_move" => ToolCallContext::new(self,request,context).invoke::<_,AsyncMethodAdapter<(RequestContext<RoleServer>,Parameters<mcp::server::FileMoveParams>),Result<String,String>>>(Self::invoke_file_move).await,
            "directory_move" => ToolCallContext::new(self,request,context).invoke::<_,AsyncMethodAdapter<(RequestContext<RoleServer>,Parameters<mcp::server::DirectoryMoveParams>),Result<String,String>>>(Self::invoke_directory_move).await,
            _ => panic!("dispatcher is limited to the three declared original methods"),
        }
    }
}
struct LiveSession {
    owner: OriginalServer,
    reader: tokio::io::BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>, task: tokio::task::JoinHandle<Value>,
}
impl LiveSession {
    fn start(root: PathBuf) -> Self {
        let owner = OriginalServer { workdir:Arc::new(OriginalSession::new(root)), session_applied:Arc::new(AtomicBool::new(false)),
            view_cache:Arc::new(OriginalCache::default()), outer_calls:Arc::new(AtomicUsize::new(0)), handler_calls:Arc::new(AtomicUsize::new(0)) };
        let handler = owner.clone(); let (client,server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            match handler.serve(server).await {
                Ok(service) => { let result=service.waiting().await; json!({"initialized":true,"terminated":format!("{result:?}")}) }
                Err(error) => json!({"initialized":false,"error":error.to_string()}),
            }
        });
        let (reader,writer) = tokio::io::split(client); Self { owner,reader:tokio::io::BufReader::new(reader),writer,task }
    }
    fn watch(&self) { OBS.lock().unwrap().watch=Some((self.owner.workdir.clone(),self.owner.session_applied.clone(),self.owner.view_cache.clone())); }
    fn state(&self) -> Value { state_snapshot(&self.owner.workdir,&self.owner.session_applied,&self.owner.view_cache) }
    async fn exchange(&mut self, bytes: Vec<u8>, id: Option<Value>) -> Value {
        assert!(bytes.ends_with(b"\n")); let request_blob=blob(&bytes); let mut written=0;
        while written<bytes.len() {
            match self.writer.write(&bytes[written..]).await {
                Ok(count) if count>0 => written+=count,
                other => {
                    let error=match other { Err(error)=>error, Ok(_)=>io::Error::from(io::ErrorKind::WriteZero) };
                    return json!({"request_blob":request_blob,"response_blob":null,"response_bytes":0,
                        "request_bytes_written":written,"transport":"write-error","error":error.to_string(),
                        "error_kind":format!("{:?}",error.kind()),"errno":error.raw_os_error()});
                }
            }
        }
        if id.is_none() { return json!({"request_blob":request_blob,"response_blob":null,"response_bytes":0,
            "request_bytes_written":written,"transport":"notification"}); }
        let mut wire=Vec::new(); let count=tokio::time::timeout(Duration::from_secs(20),self.reader.read_until(b'\n',&mut wire)).await.unwrap().unwrap();
        if count==0 { return json!({"request_blob":request_blob,"response_blob":blob(&wire),"response_bytes":0,
            "request_bytes_written":written,"transport":"eof"}); }
        assert!(wire.ends_with(b"\n")); let response:Value=serde_json::from_slice(&wire).unwrap(); assert_eq!(response["id"],id.unwrap());
        json!({"request_blob":request_blob,"response_blob":blob(&wire),"response_bytes":wire.len(),
            "request_bytes_written":written,"transport":"response"})
    }
    async fn message(&mut self, message:&Value) -> Value {
        let mut wire=serde_json::to_vec(message).unwrap(); wire.push(b'\n'); self.exchange(wire,message.get("id").cloned()).await
    }
    async fn finish(self) -> Value {
        let state=self.state(); let outer=self.owner.outer_calls.load(Ordering::SeqCst); let entered=self.owner.handler_calls.load(Ordering::SeqCst);
        drop(self.reader);drop(self.writer);let terminal=tokio::time::timeout(Duration::from_secs(20),self.task).await.unwrap().unwrap();
        json!({"state":state,"outer_calls":outer,"handler_calls":entered,"service":terminal})
    }
}

async fn scenario(row:Value,root:&Path,output:&mut impl Write) {
    assert_eq!(row["schema"],"hepta.runtime.filesystem-sdk-original-input.v1"); OBS.lock().unwrap().watch=None;
    event("scenario_setup_begin",json!({"scenario_id":row["scenario_id"]}));actions(&row["setup"],root);
    event("scenario_setup_complete",json!({"scenario_id":row["scenario_id"]}));
    let observed_roots:Vec<_>=row["observed_roots"].as_array().unwrap().iter().map(from_hex).collect();
    let mut sessions=std::collections::BTreeMap::new();let mut starts=Vec::new();
    for input in row["sessions"].as_array().unwrap() {
        let id=input["id"].as_str().unwrap().to_owned();let mut session=LiveSession::start(from_hex(&input["root_hex"]));session.watch();
        let mut exchanges=Vec::new();for message in input["initial_messages"].as_array().unwrap(){exchanges.push(session.message(message).await);}
        starts.push(json!({"session":id,"exchanges":exchanges,"state":session.state()}));assert!(sessions.insert(id,session).is_none());
    }
    write_record(output,json!({"kind":"scenario_start","scenario_id":row["scenario_id"],"name":row["name"],"policy_id":row["policy_id"],
        "fence_id":row["fence_id"],"sessions":starts,"filesystem":tree_snapshot(&observed_roots)}));
    for step in row["steps"].as_array().unwrap() {
        let id=step["session"].as_str().unwrap();let session=sessions.get_mut(id).unwrap();session.watch();
        let before=session.state();let filesystem_before=tree_snapshot(&observed_roots);let fd_before=descriptor_snapshot();
        let outer=session.owner.outer_calls.load(Ordering::SeqCst);let entered=session.owner.handler_calls.load(Ordering::SeqCst);
        event("step_begin",json!({"case_id":step["case_id"],"name":step["name"],"domain":step["domain"]}));
        let action=&step["action"];
        let result=match action["kind"].as_str().unwrap() {
            "public" => {
                if let Some(raw)=action.get("wire_hex") { session.exchange(unhex(raw.as_str().unwrap()),Some(step["case_id"].clone())).await }
                else { session.message(&action["message"]).await }
            }
            "cache_seed" => {
                mcp::request_ctx::with_request_context(session.owner.view_cache.clone(),async {
                    for entry in action["entries"].as_array().unwrap(){mcp::fs::delta::note_create(&mcp::fs::PathSource::Local(from_hex(&entry["path_hex"])),entry["content"].as_str().unwrap());}
                }).await;json!({"private_actual_cache_seed":true})
            }
            "filesystem" => {actions(&action["actions"],root);json!({"private_fixture_actions":action["actions"].as_array().unwrap().len()})}
            other => panic!("unknown input action {other}"),
        };
        event("step_end",json!({"case_id":step["case_id"]}));let fd_after=descriptor_snapshot();let filesystem_after=tree_snapshot(&observed_roots);
        write_record(output,json!({"kind":"case","scenario_id":row["scenario_id"],"case_id":step["case_id"],"name":step["name"],"domain":step["domain"],"session":id,
            "state_before":before,"state_after":session.state(),"filesystem_before":filesystem_before,"filesystem_after":filesystem_after,
            "fds_before":fd_before,"fds_after":fd_after,"result":result,
            "outer_call_tool_entries":session.owner.outer_calls.load(Ordering::SeqCst)-outer,
            "handler_entries":session.owner.handler_calls.load(Ordering::SeqCst)-entered,
            "request_context_present_after":mcp::request_ctx::with_view_cache(|_|true).is_some()}));
    }
    OBS.lock().unwrap().watch=None;let mut terminal=serde_json::Map::new();
    for(id,session)in sessions{terminal.insert(id,session.finish().await);}event("scenario_end",json!({"scenario_id":row["scenario_id"]}));
    write_record(output,json!({"kind":"scenario_end","scenario_id":row["scenario_id"],"sessions":terminal,"filesystem":tree_snapshot(&observed_roots)}));
}

#[tokio::main(flavor="current_thread")]
async fn main(){
    let argv:Vec<_>=std::env::args_os().collect();assert_eq!(argv.len(),3);let root=PathBuf::from(&argv[1]);assert!(root.is_absolute()&&root.is_dir());
    let policy:Value=serde_json::from_slice(&std::fs::read(&argv[2]).unwrap()).unwrap();
    if !policy.is_null(){let config:mcp::runtime::original_config::RuntimeConfig=serde_json::from_value(policy).unwrap();mcp::runtime::original_config::install_for_reference(config);}
    let input=io::stdin().lock();let mut output=io::BufWriter::new(io::stdout().lock());output.write_all(b"HFSSO001").unwrap();
    for line in input.lines(){let row:Value=serde_json::from_str(&line.unwrap()).unwrap();scenario(row,&root,&mut output).await;}
    output.flush().unwrap();
}

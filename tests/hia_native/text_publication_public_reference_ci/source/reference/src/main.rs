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

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::time::Duration;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use rmcp::model::{CallToolRequestParams, CallToolResponse, ExperimentalCapabilities,
    Implementation, JsonObject, ProtocolVersion, ServerCapabilities, ServerConfig,
    CacheScope, ListToolsResult, PaginatedRequestParams, Tool};
use rmcp::handler::server::tool::{AsyncMethodAdapter, ToolCallContext};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};
use rmcp::service::RequestContext;
use rmcp::handler::server::wrapper::Parameters;
use tracing::debug;

include!("types.rs");
include!("publication_types.rs");
pub(crate) struct McpToolCall { tool_name: String, parameters: Value, tool_id: String, workdir: PathBuf }
include!("original_session.rs");
#[derive(Clone)]
struct OctofsServer {
    view_cache: Arc<mcp::fs::delta::ViewCache>,
    workdir: Arc<SessionWorkdir>,
    session_applied: Arc<AtomicBool>,
}
#[rustfmt::skip]
mod mcp {
    pub(crate) use crate::McpToolCall;
    // Nonempty provider profiles remain outside this reference domain.
    pub mod weight_config { #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] pub enum WeightWorkerProfile {} }
    pub mod rea_provider { #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] pub enum ReaStaticProfile {} }
    pub mod hia_provider { #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] pub enum HiaWorkerProfile {} }
    pub mod runtime {
        pub mod config { include!("original_config.rs"); }
        pub mod effect_owner_fence;
    }
    pub mod fs {
        pub mod text_file_write;
        pub mod remote { include!("original_remote.rs"); }
        pub use remote::PathSource;
        pub mod text_editing {
            include!("original_text_editing.rs");
            include!("lock_observer.rs");
        }
        pub mod delta { include!("original_delta.rs"); include!("cache_observer.rs"); }
        pub mod file_ops { include!("original_file_ops.rs"); }
        pub mod core {
            use serde_json::Value;
            use crate::McpToolCall;
            use super::file_ops;
            use super::remote::resolve_path_source;
            include!("original_core.rs");
            include!("original_dispatch.rs");
            include!("history_observer.rs");
        }
        pub use core::execute_text_editor;
    }
    pub mod request_ctx { include!("original_request_ctx.rs"); }
}
#[rustfmt::skip]
mod utils { pub mod line_hash { include!("original_line_hash.rs"); } }
use mcp::{fs, request_ctx, runtime};
include!("original_gateway.rs");
include!("original_publication_gateway.rs");
include!("original_get_info.rs");
include!("original_list_tools.rs");
include!("fixture_catalog_registry.rs");

impl OctofsServer {
    fn sdk_publish(&self, context: RequestContext<RoleServer>, params: Parameters<TextFileWriteParams>)
        -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<String, String>> + Send + '_>> {
        Box::pin(self.text_file_write(context, params))
    }
    fn sdk_text(&self, context: RequestContext<RoleServer>, params: Parameters<TextEditorParams>)
        -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<String, String>> + Send + '_>> {
        Box::pin(self.text_editor(context, params))
    }
}
impl ServerHandler for OctofsServer {
    fn get_info(&self) -> ServerConfig { OriginalInfo::get_info(self) }
    async fn list_tools(&self, request: Option<PaginatedRequestParams>, context: RequestContext<RoleServer>)
        -> Result<ListToolsResult, ErrorData> {
        let mut result = OriginalList::list_tools(self, request, context).await?;
        result.tools.retain(|tool| INSTALLED_TOOLS.contains(&tool.name.as_ref()));
        Ok(result)
    }
    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>)
        -> Result<CallToolResponse, ErrorData> {
        match request.name.as_ref() {
            "text_file_write" => ToolCallContext::new(self, request, context)
                .invoke::<_, AsyncMethodAdapter<(RequestContext<RoleServer>, Parameters<TextFileWriteParams>), Result<String, String>>>(Self::sdk_publish).await,
            "text_editor" => ToolCallContext::new(self, request, context)
                .invoke::<_, AsyncMethodAdapter<(RequestContext<RoleServer>, Parameters<TextEditorParams>), Result<String, String>>>(Self::sdk_text).await,
            _ => Err(ErrorData::invalid_params("tool outside the declared reference domain", None)),
        }
    }
}

fn word(raw: &[u8], at: usize) -> u64 { u64::from_le_bytes(raw[at..at+8].try_into().unwrap()) }
fn unhex(text: &str) -> Result<Vec<u8>> {
    if text.len()%2 != 0 { bail!("fixture hex length"); }
    (0..text.len()).step_by(2).map(|at| Ok(u8::from_str_radix(&text[at..at+2],16)?)).collect()
}
fn hex(raw: &[u8]) -> String {
    const DIGITS: &[u8;16] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len()*2);
    for &b in raw { out.push(DIGITS[(b>>4) as usize] as char); out.push(DIGITS[(b&15) as usize] as char); }
    out
}

struct WireSession {
    reader: BufReader<ReadHalf<DuplexStream>>,
    writer: WriteHalf<DuplexStream>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}
impl WireSession {
    fn start(server: OctofsServer) -> Self {
        let (client, transport) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            let running = server.serve(transport).await.map_err(|e| e.to_string())?;
            running.waiting().await.map(|_| ()).map_err(|e| format!("{e:?}"))
        });
        let (input, writer) = tokio::io::split(client);
        Self { reader: BufReader::new(input), writer, task }
    }
    async fn exchange(&mut self, wire: &[u8], response: bool) -> Result<Vec<u8>> {
        self.writer.write_all(wire).await?;
        if !response { tokio::task::yield_now().await; return Ok(Vec::new()); }
        let mut raw = Vec::new();
        let count = tokio::time::timeout(Duration::from_secs(60), self.reader.read_until(b'\n', &mut raw)).await??;
        if count == 0 || raw.last() != Some(&b'\n') { bail!("SDK response ended before its complete line"); }
        Ok(raw)
    }
    async fn close(self) -> Result<()> {
        drop(self.reader); drop(self.writer);
        let outcome = tokio::time::timeout(Duration::from_secs(60), self.task).await??;
        outcome.map_err(anyhow::Error::msg)
    }
}

fn main() -> Result<()> {
    let executor = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let first_argument = std::env::args().nth(1);
    let stdio_mode = first_argument.as_deref() == Some("--stdio");
    let fixture_sessions = if first_argument.as_deref() == Some("--fixture-single-session") || stdio_mode { 1 } else { 2 };
    let fixture_config = if fixture_sessions == 1 { std::env::args().nth(2) } else { first_argument };
    if let Some(path) = fixture_config {
        let config: runtime::config::RuntimeConfig = serde_json::from_slice(&std::fs::read(path)?)?;
        runtime::config::install_for_reference(config);
    }
    let root = std::env::current_dir()?;
    let servers = std::array::from_fn::<_,2,_>(|_| OctofsServer {
        view_cache: Arc::new(fs::delta::ViewCache::default()),
        workdir: Arc::new(SessionWorkdir::new(root.clone())),
        session_applied: Arc::new(AtomicBool::new(false)),
    });
    if stdio_mode {
        return executor.block_on(async {
            let running = servers[0].clone().serve(tokio::io::stdio()).await?;
            running.waiting().await?;
            Ok(())
        });
    }
    let mut sessions = executor.block_on(async {
        servers.iter().cloned().enumerate().map(|(index, server)| {
            if index < fixture_sessions { Some(WireSession::start(server)) } else { None }
        }).collect::<Vec<_>>()
    });
    let mut output = io::BufWriter::new(io::stdout().lock());
    for (sequence, line) in io::stdin().lock().lines().enumerate() {
        let row: Value = serde_json::from_str(&line?)?;
        let sid = row["session"].as_u64().ok_or_else(|| anyhow::anyhow!("session missing"))? as usize;
        if sid >= fixture_sessions { bail!("session outside fixture domain"); }
        let kind = row["kind"].as_str().ok_or_else(|| anyhow::anyhow!("fixture kind missing"))?;
        let raw = match kind {
            "wire" => {
                let wire = unhex(row["wire_hex"].as_str().unwrap())?;
                let expect = row["response"].as_bool().unwrap();
                let session = sessions[sid].as_mut().ok_or_else(|| anyhow::anyhow!("wire after close"))?;
                executor.block_on(session.exchange(&wire, expect))?
            }
            "cache" => {
                let raw = unhex(row["wire_hex"].as_str().unwrap())?;
                fs::delta::fixture_apply(&servers[sid].view_cache, &raw)?
            }
            "history" => {
                let raw = unhex(row["wire_hex"].as_str().unwrap())?;
                fs::core::fixture_history_apply(&raw)?
            }
            "observe" => Vec::new(),
            "close" => {
                let session = sessions[sid].take().ok_or_else(|| anyhow::anyhow!("duplicate close"))?;
                executor.block_on(session.close())?;
                Vec::new()
            }
            _ => bail!("fixture command outside domain"),
        };
        let caches = servers.iter().map(|s| hex(&fs::delta::fixture_snapshot(&s.view_cache, 1))).collect::<Vec<_>>();
        let states = servers.iter().map(|s| json!({"root":s.workdir.root.to_string_lossy(),
            "current":s.workdir.current.read().ok().and_then(|v|v.clone()).map(|p|p.to_string_lossy().to_string()),
            "effective":s.workdir.get_current().to_string_lossy(),
            "session_applied":s.session_applied.load(Ordering::SeqCst),
            "poisoned":s.workdir.current.is_poisoned()})).collect::<Vec<_>>();
        serde_json::to_writer(&mut output, &json!({"id":row["id"],"session":sid,"kind":kind,
            "output_hex":hex(&raw),"cache_snapshots_hex":caches,"sessions":states,
            "scope_unbound_after_exchange":request_ctx::with_view_cache(|_|false).is_none(),
            "closed_sessions":sessions.iter().map(Option::is_none).collect::<Vec<_>>(),
            "history_snapshot_hex":hex(&fs::core::fixture_history_snapshot(1,sequence as u64+1)),
            "lock_snapshot_hex":hex(&fs::text_editing::fixture_lock_snapshot(1,sequence as u64+1))}))?;
        output.write_all(b"\n")?; output.flush()?;
    }
    for session in sessions.into_iter().flatten() { executor.block_on(session.close())?; }
    Ok(())
}

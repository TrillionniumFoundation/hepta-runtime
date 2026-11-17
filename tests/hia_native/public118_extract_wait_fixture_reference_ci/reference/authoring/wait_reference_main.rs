// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test-owned transport around exact target methods and real SDK dispatch.
//! Extract/Batch/Text, original list policy, and the declared View refusal are routed. It does not
//! substitute the target's complete audit, retained-result or caller router.
#![allow(deprecated)]

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use rmcp::model::{CallToolRequestParams, CallToolResponse, ExperimentalCapabilities,
    Implementation, JsonObject, ProtocolVersion, ServerCapabilities, ServerConfig,
    CacheScope, ListToolsResult, PaginatedRequestParams, Tool};
use rmcp::service::RequestContext;
use rmcp::handler::server::tool::{AsyncMethodAdapter, ToolCallContext};
use rmcp::handler::server::wrapper::Parameters;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};
use tracing::debug;

include!("types.rs");
include!("batch_types.rs");
include!("original_session.rs");

#[derive(Clone)]
struct OctofsServer {
    view_cache: Arc<mcp::fs::delta::ViewCache>,
    workdir: Arc<SessionWorkdir>,
    session_applied: Arc<AtomicBool>,
}

#[rustfmt::skip]
mod mcp {
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::path::PathBuf;
    include!("../original/mcp_call.rs");
    // Nonempty provider profiles are outside this explicitly Local fixture.
    pub mod weight_config { #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] pub enum WeightWorkerProfile {} }
    pub mod rea_provider { #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] pub enum ReaStaticProfile {} }
    pub mod hia_provider { #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] pub enum HiaWorkerProfile {} }
    pub mod runtime {
        pub mod config { include!("original_config.rs"); }
        pub mod effect_owner_fence;
    }
    pub mod fs {
        pub mod remote {
            use anyhow::{anyhow, Result};
            use std::path::{Path, PathBuf};
            use std::time::SystemTime;
            include!("../original/path_source.rs");
            include!("../original/remote_metadata.rs");
            include!("../original/io_metadata_type.rs");
            include!("../original/io_read.rs");
            include!("../original/io_write.rs");
            include!("../original/io_exists.rs");
            include!("../original/io_metadata.rs");
            include!("../original/io_remove.rs");
            include!("original_mkdir.rs");
            mod sftp { include!("original_sftp_unavailable.rs"); }
        }
        pub use remote::PathSource;
        pub mod text_editing {
            include!("../original/text_editing.rs");
            include!("lock_observer.rs");
        }
        pub mod delta {
            use std::collections::HashMap;
            use std::sync::Mutex;
            use super::text_editing::lock_key_for_source;
            use super::PathSource;
            use crate::mcp::request_ctx::with_view_cache;
            use crate::utils::line_hash::line_id_at;
            include!("../original/view_cache.rs");
            include!("../original/removed_marker.rs");
            include!("cache_observer.rs");
        }
        pub mod file_ops { include!("original_file_ops.rs"); }
        pub mod core {
            use serde_json::Value;
            use crate::mcp::McpToolCall;
            use super::{delta, file_ops, text_editing};
            use super::remote::{io_exists, io_read_to_string, io_create_dir_all, resolve_path_source, PathSource};
            use crate::utils::line_hash::{self, Endpoint, resolve_line_index};
            use crate::utils::truncation::format_extracted_content_smart;
            use anyhow::{anyhow, bail, Result};
            use std::collections::HashMap;
            use std::sync::{Mutex, OnceLock};
            include!("../original/history.rs");
            include!("original_dispatch.rs");
            include!("original_batch_dispatch.rs");
            include!("original_extract_dispatch.rs");
            include!("history_observer.rs");
        }
        pub use core::{execute_batch_edit, execute_text_editor, execute_extract_lines};
    }
    pub mod request_ctx { include!("../original/request_ctx.rs"); }
}
#[rustfmt::skip]
mod utils { pub mod line_hash { include!("../original/line_hash.rs"); } pub mod truncation { include!("original_extract_truncation.rs"); } }
use mcp::{fs, request_ctx, runtime, McpToolCall};
include!("original_gateway.rs");
include!("original_batch_gateway.rs");
include!("original_extract_gateway.rs");
include!("original_list_tools.rs");
include!("fixture_catalog_registry.rs");
include!("original_get_info.rs");

impl OctofsServer {
    fn sdk_extract(&self, context: RequestContext<RoleServer>, params: Parameters<ExtractLinesParams>)
        -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<String, String>> + Send + '_>> {
        Box::pin(self.extract_lines(context, params))
    }
    fn sdk_batch(&self, context: RequestContext<RoleServer>, params: Parameters<BatchEditParams>)
        -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<String, String>> + Send + '_>> {
        Box::pin(self.batch_edit(context, params))
    }
    fn sdk_text(&self, context: RequestContext<RoleServer>, params: Parameters<TextEditorParams>)
        -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<String, String>> + Send + '_>> {
        Box::pin(self.text_editor(context, params))
    }
    fn sdk_view_params(&self, _context: RequestContext<RoleServer>, _params: Parameters<ViewParams>)
        -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<String, String>> + Send + '_>> {
        // The frozen stdio row lacks the required path. The actual SDK must
        // reject it before this guard; a successful View body is not supplied.
        Box::pin(async { Err("fixture guard: valid View parameters are outside the refusal-only domain".to_owned()) })
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
            "extract_lines" => ToolCallContext::new(self, request, context)
                .invoke::<_, AsyncMethodAdapter<(RequestContext<RoleServer>, Parameters<ExtractLinesParams>), Result<String, String>>>(Self::sdk_extract).await,
            "batch_edit" => ToolCallContext::new(self, request, context)
                .invoke::<_, AsyncMethodAdapter<(RequestContext<RoleServer>, Parameters<BatchEditParams>), Result<String, String>>>(Self::sdk_batch).await,
            "text_editor" => ToolCallContext::new(self, request, context)
                .invoke::<_, AsyncMethodAdapter<(RequestContext<RoleServer>, Parameters<TextEditorParams>), Result<String, String>>>(Self::sdk_text).await,
            "view" => ToolCallContext::new(self, request, context)
                .invoke::<_, AsyncMethodAdapter<(RequestContext<RoleServer>, Parameters<ViewParams>), Result<String, String>>>(Self::sdk_view_params).await,
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

include!("stdio_bridge.rs");
include!("wait_fixture.rs");
include!("stdio_wait_bridge.rs");

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
    let wait_mode = first_argument.as_deref() == Some("--stdio-wait-fixture");
    let fixture_sessions = if stdio_mode || wait_mode || first_argument.as_deref() == Some("--fixture-single-session") { 1 } else { 2 };
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
    if stdio_mode { return run_actual_stdio(servers[0].clone(), executor); }
    if wait_mode { return run_actual_wait_stdio(servers[0].clone(), executor); }
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

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
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use rmcp::{RoleServer, ServerHandler};
use rmcp::service::{RequestContext, serve_directly};
use rmcp::handler::server::wrapper::Parameters;
use tracing::debug;

include!("types.rs");
include!("publication_types.rs");
pub(crate) struct McpToolCall { tool_name: String, parameters: Value, tool_id: String, workdir: PathBuf }
include!("original_session.rs");
struct OctofsServer {
    view_cache: Arc<mcp::fs::delta::ViewCache>,
    workdir: Arc<SessionWorkdir>,
    session_applied: AtomicBool,
}
struct PeerCarrier;
impl ServerHandler for PeerCarrier {}
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

fn word(raw: &[u8], at: usize) -> u64 { u64::from_le_bytes(raw[at..at+8].try_into().unwrap()) }
fn unhex(text: &str) -> Result<Vec<u8>> {
    if text.len()%2!=0 { bail!("fixture hex length"); }
    (0..text.len()).step_by(2).map(|at| Ok(u8::from_str_radix(&text[at..at+2],16)?)).collect()
}
fn hex(raw: &[u8]) -> String {
    const DIGITS: &[u8;16]=b"0123456789abcdef";
    let mut out=String::with_capacity(raw.len()*2);
    for &b in raw { out.push(DIGITS[(b>>4) as usize] as char);out.push(DIGITS[(b&15) as usize] as char); }
    out
}
fn frame(magic: &[u8;8], words: &[u64], body: &[u8]) -> Vec<u8> {
    let mut out=magic.to_vec();
    for word in words { out.extend_from_slice(&word.to_le_bytes()); }
    out.extend_from_slice(body);out
}
fn main() -> Result<()> {
    let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    if let Some(path)=std::env::args().nth(1) {
        let config:runtime::config::RuntimeConfig=serde_json::from_slice(&std::fs::read(path)?)?;
        runtime::config::install_for_reference(config);
    }
    let root=std::env::current_dir()?;
    let servers=std::array::from_fn::<_,2,_>(|_|OctofsServer {
        view_cache:Arc::new(fs::delta::ViewCache::default()),
        workdir:Arc::new(SessionWorkdir::new(root.clone())),
        session_applied:AtomicBool::new(false),
    });
    let (mut peers, peer_inputs)=runtime.block_on(async {
        let mut services=Vec::new();let mut inputs=Vec::new();
        for _ in 0..2 {
            let (service_io,input)=tokio::io::duplex(4096);
            services.push(serve_directly::<RoleServer,_,_,_,_>(PeerCarrier,service_io,None));
            inputs.push(input);
        }
        (services,inputs)
    });
    for (sequence, line) in io::stdin().lock().lines().enumerate() {
        let row:Value=serde_json::from_str(&line?)?;
        let sid=row["session"].as_u64().unwrap() as usize;
        let server=&servers[sid];
        let (code,output)=match row["kind"].as_str().unwrap() {
            "call" => {
                let (status,text)=if row["tool"].as_str()==Some("text_file_write") {
                    match serde_json::from_value::<TextFileWriteParams>(row["parameters"].clone()) {
                        Err(error)=>(2,error.to_string()),
                        Ok(typed)=>{
                            let id=serde_json::from_value(serde_json::json!(1))?;
                            let mut context=RequestContext::<RoleServer>::new(id,peers[sid].peer().clone());
                            if !row["metadata"].is_null() { context.meta=serde_json::from_value(row["metadata"].clone())?; }
                            match runtime.block_on(server.text_file_write(context,Parameters(typed))) { Ok(v)=>(0,v),Err(v)=>(1,v) }
                        }
                    }
                } else { match serde_json::from_value::<TextEditorParams>(row["parameters"].clone()) {
                    Err(error)=>(2,error.to_string()),
                    Ok(typed)=>{
                        let id=serde_json::from_value(serde_json::json!(1))?;
                        let mut context=RequestContext::<RoleServer>::new(id,peers[sid].peer().clone());
                        if !row["metadata"].is_null() { context.meta=serde_json::from_value(row["metadata"].clone())?; }
                        match runtime.block_on(server.text_editor(context,Parameters(typed))) { Ok(v)=>(0,v),Err(v)=>(1,v) }
                    }
                }};
                (32,frame(b"HRCFGM01",&[status,0,text.len() as u64],text.as_bytes()))
            }
            "cache" => {
                let raw=unhex(row["wire_hex"].as_str().unwrap())?;
                let output=fs::delta::fixture_apply(&server.view_cache,&raw)?;
                (output.len() as u64,output)
            }
            "history" => {
                let raw=unhex(row["wire_hex"].as_str().unwrap())?;
                let output=fs::core::fixture_history_apply(&raw)?;
                (output.len() as u64,output)
            }
            _ => bail!("fixture command outside domain"),
        };
        let caches=servers.iter().map(|s|hex(&fs::delta::fixture_snapshot(&s.view_cache,1))).collect::<Vec<_>>();
        let live=servers.iter().map(|s|Arc::strong_count(&s.view_cache)).collect::<Vec<_>>();
        let sessions=servers.iter().map(|s|json!({"root":s.workdir.root.to_string_lossy(),
            "current":s.workdir.current.read().ok().and_then(|v|v.clone()).map(|p|p.to_string_lossy().to_string()),
            "effective":s.workdir.get_current().to_string_lossy(),
            "session_applied":s.session_applied.load(Ordering::SeqCst),
            "poisoned":s.workdir.current.is_poisoned()})).collect::<Vec<_>>();
        let unbound=request_ctx::with_view_cache(|_|false).is_none();
        println!("{}",serde_json::to_string(&json!({"id":row["id"],"session":sid,"code":code,
            "output_hex":hex(&output),"cache_snapshots_hex":caches,"live_session_arcs":live,
            "scope_unbound_after_call":unbound,"sessions":sessions,
            "history_snapshot_hex":hex(&fs::core::fixture_history_snapshot(1,sequence as u64+1)),
            "lock_snapshot_hex":hex(&fs::text_editing::fixture_lock_snapshot(1,sequence as u64+1))}))?);
    }
    for peer in peers.drain(..) { runtime.block_on(peer.cancel())?; }
    drop(peer_inputs);
    Ok(())
}

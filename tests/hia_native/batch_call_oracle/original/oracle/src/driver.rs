// Pinned original bodies are substituted without edits by verify_sources.py.
// The carrier observes real operations; it never supplies an operation result.
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use serde_json::{json, Value};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use rmcp::model::{CallToolRequestParams, CallToolResponse};
use rmcp::service::RequestContext;
use rmcp::handler::server::tool::{ToolCallContext, AsyncMethodAdapter};
use rmcp::handler::server::wrapper::Parameters;

mod observe;
mod observed_tokio;
mod public_driver;
mod utils { pub mod line_hash; pub mod truncation; }

mod mcp {
    use serde::{Serialize, Deserialize};
    use serde_json::Value;
    use std::path::PathBuf;
@@MCP_TOOL_CALL@@
    // No nonlocal profile is accepted by this carrier's configuration domain.
    pub mod weight_config { #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] pub enum WeightWorkerProfile {} }
    pub mod rea_provider { #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] pub enum ReaStaticProfile {} }
    pub mod hia_provider { #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)] pub enum HiaWorkerProfile {} }
    pub mod original_request_ctx;
    pub mod request_ctx {
        pub use super::original_request_ctx::{with_view_cache, push_hint, drain_hints, observe_context};
        struct ScopeDrop { completed: bool }
        impl Drop for ScopeDrop {
            fn drop(&mut self) {
                crate::observe::event(if self.completed {"scope_future_drop_complete"} else {"scope_future_drop_cancelled"}, serde_json::json!({}));
            }
        }
        pub async fn with_request_context<F>(cache: std::sync::Arc<super::fs::delta::ViewCache>, future: F) -> F::Output
        where F: std::future::Future {
            crate::observe::event("scope_enter", serde_json::json!({}));
            let result = super::original_request_ctx::with_request_context(cache, async move {
                let mut guard = ScopeDrop { completed: false };
                crate::observe::event("scope_first_poll", serde_json::json!({}));
                let result = future.await;
                guard.completed = true;
                crate::observe::event("scope_future_complete", serde_json::json!({}));
                result
            }).await;
            crate::observe::event("scope_exit", serde_json::json!({}));
            result
        }
    }
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
                crate::observe::event("policy_lookup", serde_json::json!({"installed":result.is_some()})); result
            }
            pub fn check_local_path(path: &Path) -> anyhow::Result<()> {
                crate::observe::event("local_policy_enter", serde_json::json!({"path_blob":crate::observe::path_blob(path)}));
                let result = super::original_config::check_local_path(path);
                crate::observe::event("local_policy_exit", crate::observe::unit_result(&result)); result
            }
            pub fn check_remote_path(alias: &str,path: &str,user: bool,port: bool,write: bool) -> anyhow::Result<()> {
                crate::observe::event("remote_policy_enter",serde_json::json!({"alias":alias,"path":path,"user":user,"port":port,"write":write}));
                let result=super::original_config::check_remote_path(alias,path,user,port,write);
                crate::observe::event("remote_policy_exit",crate::observe::unit_result(&result)); result
            }
        }
        pub mod original_effect_owner_fence;
        pub mod effect_owner_fence {
            pub async fn admit_new_effect() -> anyhow::Result<super::original_effect_owner_fence::AdmissionPermit> {
                crate::observe::event("effect_fence_enter",serde_json::json!({}));
                let result=super::original_effect_owner_fence::admit_new_effect().await;
                crate::observe::event("effect_fence_exit",match &result {Ok(_)=>serde_json::json!({"ok":true}),Err(e)=>crate::observe::error_result(e)});
                result
            }
        }
    }
    pub mod fs {
        pub mod original_remote;
        pub mod remote {
            pub use super::original_remote::*;
            pub async fn io_exists(source: &PathSource) -> anyhow::Result<bool> {
                crate::observe::event("exists_enter",serde_json::json!({"path_blob":crate::observe::source_blob(source)}));
                let result=super::original_remote::io_exists(source).await;
                crate::observe::event("exists_exit",match &result {Ok(value)=>serde_json::json!({"ok":true,"value":value}),Err(e)=>crate::observe::error_result(e)});
                crate::observe::after("exists"); result
            }
            pub async fn io_read_to_string(source: &PathSource) -> anyhow::Result<String> {
                crate::observe::event("read_enter",serde_json::json!({"path_blob":crate::observe::source_blob(source)}));
                let result=super::original_remote::io_read_to_string(source).await;
                crate::observe::event("read_exit",match &result {Ok(value)=>serde_json::json!({"ok":true,"body_blob":crate::observe::blob(value.as_bytes())}),Err(e)=>crate::observe::error_result(e)});
                crate::observe::after("read"); result
            }
        }
        pub use remote::PathSource;
        pub mod text_editing;
        pub mod original_delta;
        pub mod delta {
            pub use super::original_delta::*;
            pub fn note_write(source: &super::PathSource, before: &str, after: &str) {
                crate::observe::event("note_write_enter",serde_json::json!({"path_blob":crate::observe::source_blob(source),
                    "before_blob":crate::observe::blob(before.as_bytes()),"after_blob":crate::observe::blob(after.as_bytes())}));
                super::original_delta::note_write(source,before,after);
                crate::observe::event("note_write_exit",serde_json::json!({}));
                crate::observe::after("cache");
            }
        }
        pub mod original_core {
            use super::super::McpToolCall;
            use super::remote::{io_exists,io_read_to_string,PathSource};
            use super::text_editing;
            use anyhow::{anyhow,bail,Result};
            use serde_json::Value;
            use std::collections::HashMap;
            use std::sync::{Mutex,OnceLock};
@@HISTORY_STORE@@
@@EXECUTE_BATCH_EDIT@@
            pub fn observe_history() -> (bool,usize,Vec<String>,std::collections::BTreeMap<String,Vec<String>>) {
                let (poisoned,store)=match file_history().lock(){Ok(store)=>(false,store),Err(error)=>(true,error.into_inner())};
                (poisoned,store.total_bytes,store.order.iter().cloned().collect(),store.files.iter().map(|(k,v)|(k.clone(),v.clone())).collect())
            }
            pub fn reset_history() { *file_history().lock().unwrap()=HistoryStore::default(); }
            pub fn pop_history(key: &str) -> Option<String> { file_history().lock().unwrap().pop(key) }
        }
        pub mod core {
            pub use super::original_core::execute_batch_edit;
            pub async fn save_file_history(source: &super::PathSource) -> anyhow::Result<()> {
                crate::observe::event("history_enter",serde_json::json!({"path_blob":crate::observe::source_blob(source)}));
                let result=super::original_core::save_file_history(source).await;
                crate::observe::event("history_exit",crate::observe::unit_result(&result));
                crate::observe::after("history"); result
            }
        }
        pub use core::execute_batch_edit;
    }
    pub mod server {
        use super::{fs,runtime,request_ctx,McpToolCall};
        use serde::{Deserialize,Serialize};
        use std::path::PathBuf;
        use std::sync::{Arc,RwLock,atomic::{AtomicBool,AtomicUsize,Ordering}};
        use rmcp::RoleServer;
        use rmcp::service::RequestContext;
        use rmcp::handler::server::wrapper::Parameters;
        use tracing::debug;
@@SESSION_WORKDIR@@
@@BATCH_OPERATION_TYPE@@
@@BATCH_PARAMS@@
@@LINE_ENDPOINT_SCHEMA@@
@@ENFORCE_RUNTIME_PATH_SPEC@@
@@APPEND_HINTS@@
        #[derive(Clone)]
        pub struct OriginalServer {
            pub workdir: Arc<SessionWorkdir>, pub session_applied: Arc<AtomicBool>,
            pub view_cache: Arc<fs::delta::ViewCache>,pub outer_calls: Arc<AtomicUsize>,pub handler_calls: Arc<AtomicUsize>,
        }
        impl OriginalServer {
@@ENSURE_SESSION_WORKDIR@@
@@BATCH_EDIT@@
            pub fn invoke_batch(&self,context:RequestContext<RoleServer>,params:Parameters<BatchEditParams>)->std::pin::Pin<Box<dyn std::future::Future<Output=Result<String,String>>+Send+'_>> {
                Box::pin(async move {
                self.handler_calls.fetch_add(1,Ordering::SeqCst);
                crate::observe::event("handler_enter",serde_json::json!({"typed_parameters_blob":crate::observe::blob(&serde_json::to_vec(&params.0).unwrap()),
                    "capabilities":context.client_capabilities(),"protocol_version":context.protocol_version(),"request_id":context.id}));
                let result=self.batch_edit(context,params).await;
                crate::observe::event("handler_exit",match &result{Ok(body)=>serde_json::json!({"ok":true,"body_blob":crate::observe::blob(body.as_bytes())}),
                    Err(body)=>serde_json::json!({"ok":false,"body_blob":crate::observe::blob(body.as_bytes())})});
                result
                })
            }
        }
        pub fn session_state(state:&SessionWorkdir,latch:&AtomicBool)->serde_json::Value {
            let (poisoned,current)=match state.current.read(){Ok(x)=>(false,x.clone()),Err(e)=>(true,e.into_inner().clone())};
            serde_json::json!({"root_blob":crate::observe::path_blob(&state.root),"current_blob":current.as_ref().map(|p|crate::observe::path_blob(p)),
                "effective_blob":crate::observe::path_blob(&state.get_current()),"poisoned":poisoned,"latched":latch.load(Ordering::SeqCst)})
        }
        pub fn append_inner_result(result:anyhow::Result<String>)->Result<String,String>{
            result.map(append_hints).map_err(|e|e.to_string())
        }
    }
}

impl ServerHandler for mcp::server::OriginalServer {
    async fn call_tool(&self,request:CallToolRequestParams,context:RequestContext<RoleServer>)->Result<CallToolResponse,ErrorData>{
        self.outer_calls.fetch_add(1,Ordering::SeqCst);
        observe::event("outer_call_tool_enter",json!({"tool":request.name,"canonical_arguments_blob":observe::blob(&serde_json::to_vec(&Value::Object(request.arguments.clone().unwrap_or_default())).unwrap())}));
        assert_eq!(request.name.as_ref(),"batch_edit");
        ToolCallContext::new(self,request,context).invoke::<_,AsyncMethodAdapter<(RequestContext<RoleServer>,Parameters<mcp::server::BatchEditParams>),Result<String,String>>>(Self::invoke_batch).await
    }
}

fn word(input:&mut impl Read)->u64 { let mut bytes=[0;8];input.read_exact(&mut bytes).unwrap();u64::from_le_bytes(bytes) }
fn bytes(input:&mut impl Read,length:u64)->Vec<u8>{let mut result=vec![0;usize::try_from(length).unwrap()];input.read_exact(&mut result).unwrap();result}
fn input_record(input:&mut impl Read)->(Value,Vec<Vec<u8>>){
    let n=word(input);let k=word(input);let metadata=serde_json::from_slice(&bytes(input,n)).unwrap();
    let blobs=(0..k).map(|_|{let n=word(input);bytes(input,n)}).collect();(metadata,blobs)
}

async fn execute_inner(call:mcp::McpToolCall,cache:Arc<mcp::fs::delta::ViewCache>)->Result<String,String>{
    mcp::request_ctx::with_request_context(cache,async{
        let result=mcp::fs::execute_batch_edit(&call).await;
        observe::event("execute_batch_edit_exit",match &result{Ok(body)=>json!({"ok":true,"body_blob":observe::blob(body.as_bytes())}),Err(e)=>observe::error_result(e)});
        mcp::server::append_inner_result(result)
    }).await
}
fn string_result(result:Result<String,String>)->Value{
    match result{Ok(body)=>json!({"ok":true,"body_blob":observe::blob(body.as_bytes())}),Err(body)=>json!({"ok":false,"body_blob":observe::blob(body.as_bytes())})}
}
async fn fifo_barrier(stage:&str)->Value{
    let event=if stage=="first_read"{"tokio_read_enter"}else{"tokio_write_enter"};
    tokio::time::timeout(std::time::Duration::from_secs(20),async{
        loop{
            if observe::saw_event(event){
                let mut found=Vec::new();
                for entry in std::fs::read_dir("/proc/self/task").unwrap(){
                    let path=entry.unwrap().path();
                    let Ok(wchan)=std::fs::read_to_string(path.join("wchan"))else{continue};
                    if wchan.trim()=="wait_for_partner"{
                        let tid=path.file_name().unwrap().to_str().unwrap().parse::<u32>().unwrap();
                        let syscall=std::fs::read(path.join("syscall")).unwrap();
                        found.push(json!({"tid":tid,"wchan_blob":observe::blob(wchan.as_bytes()),"syscall_blob":observe::blob(&syscall)}));
                    }
                }
                if !found.is_empty(){assert_eq!(found.len(),1,"ambiguous actual blocking FIFO worker");return found.remove(0);}
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }).await.expect("original FIFO open did not reach its actual blocking barrier")
}
async fn wait_fifo_closed(path:&Path){
    tokio::time::timeout(std::time::Duration::from_secs(20),async{
        loop{
            let live=std::fs::read_dir("/proc/self/fd").unwrap().any(|item|item.ok().and_then(|e|std::fs::read_link(e.path()).ok()).as_deref()==Some(path));
            if !live{return;}
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }).await.expect("original late filesystem closure retained its FIFO descriptor")
}
async fn cancel_case(row:&Value,call:mcp::McpToolCall,cache:Arc<mcp::fs::delta::ViewCache>,caches:&std::collections::BTreeMap<u64,Arc<mcp::fs::delta::ViewCache>>)->Value{
    let stage=row["cancel"]["stage"].as_str().unwrap();assert!(matches!(stage,"first_read"|"atomic_write"));
    let task=tokio::spawn(execute_inner(call,cache.clone()));
    let barrier=fifo_barrier(stage).await;
    observe::event("cancel_before_abort",json!({"stage":stage,"barrier":barrier}));
    task.abort();let error=task.await.expect_err("cancelled original handler completed normally");assert!(error.is_cancelled());
    observe::event("cancel_after_abort",json!({"join_error_blob":observe::blob(error.to_string().as_bytes())}));
    let after_cancel=observe::snapshot(caches);
    let cwd=observe::working_directory();let fifo=cwd.join(if stage=="first_read"{"file"}else{".octofs_tmp_file.tmp"});
    let late=if stage=="first_read"{
        let body=observe::input_blob(row["cancel"]["transfer_blob"].as_u64().unwrap() as usize);let sent=body.clone();let path=fifo.clone();
        observe::event("fixture_late_writer_begin",json!({"path_blob":observe::path_blob(&fifo),"body_blob":observe::blob(&body)}));
        let transferred=std::thread::spawn(move||{let mut file=std::fs::OpenOptions::new().write(true).open(path).unwrap();file.write_all(&sent).unwrap();drop(file);sent.len()}).join().unwrap();
        observe::event("fixture_late_writer_end",json!({"bytes":transferred}));
        json!({"kind":"writer","body_blob":observe::blob(&body),"bytes":transferred})
    }else{
        let expected=observe::event_body("tokio_write_enter");let path=fifo.clone();
        observe::event("fixture_late_reader_begin",json!({"path_blob":observe::path_blob(&fifo)}));
        let body=std::thread::spawn(move||{let mut file=std::fs::File::open(path).unwrap();let mut body=Vec::new();file.read_to_end(&mut body).unwrap();drop(file);body}).join().unwrap();
        assert_eq!(body,expected,"actual late blocking write differs from its retained original input");
        observe::event("fixture_late_reader_end",json!({"body_blob":observe::blob(&body),"bytes":body.len()}));
        json!({"kind":"reader","body_blob":observe::blob(&body),"bytes":body.len()})
    };
    wait_fifo_closed(&fifo).await;
    observe::event("late_closure_descriptors_closed",json!({"path_blob":observe::path_blob(&fifo)}));
    let after_late=observe::snapshot(caches);
    let followup=row.get("followup").expect("complete explicit companion followup input required");
    assert_eq!(followup["kind"],"post_cancel_followup");assert_eq!(followup["parent_case_id"],row["case_id"]);
    assert_eq!(followup["session"],row["session"]);assert_eq!(followup["reset_history"],false);assert_eq!(followup["reset_cache"],false);
    let mut actions=followup["initial"].clone();let base=row["followup_blob_base"].as_u64().unwrap();
    for action in actions.as_array_mut().unwrap(){if let Some(index)=action["blob"].as_u64(){action["blob"]=json!(base+index);}}
    observe::actions(&actions);
    let typed:mcp::server::BatchEditParams=serde_json::from_value(followup["params"].clone()).unwrap();
    let parameters=serde_json::to_value(typed).unwrap();let canonical_blob=observe::blob(&serde_json::to_vec(&parameters).unwrap());
    let call=mcp::McpToolCall{tool_name:"batch_edit".into(),parameters,tool_id:String::new(),workdir:cwd};
    observe::event("followup_begin",json!({"canonical_parameters_blob":canonical_blob}));
    let result=string_result(execute_inner(call,cache).await);
    observe::event("followup_end",json!({"result":result}));
    json!({"cancelled":true,"barrier":barrier,"after_cancel":after_cancel,"late":late,"after_late":after_late,
        "followup":{"canonical_parameters_blob":canonical_blob,"result":result},"normal_original_result_received":false})
}

async fn inner_case(row:Value,blobs:Vec<Vec<u8>>,root:&Path,caches:&mut std::collections::BTreeMap<u64,Arc<mcp::fs::delta::ViewCache>>)->Value {
    assert_eq!(row["domain"],"local-batch-inner");
    let session=row["session"].as_u64().unwrap();
    let cache=caches.entry(session).or_default().clone();
    let cwd=observe::begin(&row,blobs,root,cache.clone());
    if row["reset_history"].as_bool().unwrap(){mcp::fs::original_core::reset_history();}
    if row["reset_cache"].as_bool().unwrap(){cache.forget_all();}
    observe::actions(&row["initial"]);
    if let Some(index)=row["cache"].as_u64(){
        let body=String::from_utf8(observe::input_blob(index as usize)).unwrap();
        let path=row["params"]["path"].as_str().unwrap();
        let source=mcp::fs::remote::resolve_path_source(path,&cwd);
        mcp::request_ctx::with_request_context(cache.clone(),async{mcp::fs::delta::note_create(&source,&body)}).await;
    }
    let before=observe::snapshot(caches);
    observe::event("case_begin",json!({"case_id":row["case_id"],"entry":"typed-local-inner"}));
    let typed: mcp::server::BatchEditParams=serde_json::from_value(row["params"].clone()).unwrap();
    let parameters=serde_json::to_value(&typed).unwrap();
    let canonical_blob=observe::blob(&serde_json::to_vec(&parameters).unwrap());
    let call=mcp::McpToolCall{tool_name:"batch_edit".into(),parameters,tool_id:String::new(),workdir:cwd};
    let result=match row["execution"].as_str().unwrap(){
        "sync"=>string_result(execute_inner(call,cache).await),
        "async"=>cancel_case(&row,call,cache,caches).await,
        _=>panic!("unknown original entry mode"),
    };
    observe::event("case_end",json!({"case_id":row["case_id"]}));
    let after=observe::snapshot(caches);
    observe::check_hooks();
    json!({"kind":"case","case_id":row["case_id"],"name":row["name"],"domain":row["domain"],"sequence":row["sequence"],
        "session":session,"canonical_parameters_blob":canonical_blob,"result":result,"before":before,"after":after,
        "request_context_present_after":mcp::request_ctx::with_view_cache(|_|true).is_some(),
        "original_sdk_executed":false,"original_outer_batch_method_executed":false,"original_inner_execute_batch_edit_executed":true})
}

#[tokio::main(flavor="multi_thread",worker_threads=2)]
async fn main(){
    let args:Vec<_>=std::env::args_os().collect();
    if args.get(1).is_some_and(|a|a=="--sdk"){
        assert_eq!(args.len(),4,"expected --sdk /owned/root /policy.json");
        public_driver::run(&PathBuf::from(&args[2]),&PathBuf::from(&args[3])).await;return;
    }
    assert_eq!(args.len(),3,"expected --inner /owned/absolute/fixture-root");assert_eq!(args[1],"--inner");
    let root=PathBuf::from(&args[2]);assert!(root.is_absolute()&&root.is_dir());
    let mut input=std::io::stdin().lock();let mut magic=[0;8];input.read_exact(&mut magic).unwrap();assert_eq!(&magic,b"HBCCI002");
    let count=word(&mut input);let mut output=std::io::stdout().lock();output.write_all(b"HBCCO002").unwrap();output.write_all(&count.to_le_bytes()).unwrap();
    let mut caches=std::collections::BTreeMap::new();
    for _ in 0..count{let (row,blobs)=input_record(&mut input);let result=inner_case(row,blobs,&root,&mut caches).await;observe::write_record(&mut output,result);}
    let mut extra=[0];assert_eq!(input.read(&mut extra).unwrap(),0);
    observe::finish();
}

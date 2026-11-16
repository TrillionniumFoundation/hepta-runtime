//! Real SDK transport/extractor/method carrier. Original global router/get_info
//! and the configuration loader are explicitly outside this carrier's scope.
use std::collections::BTreeMap;
use std::io::{BufRead,Write};
use std::os::unix::ffi::{OsStrExt,OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component,Path,PathBuf};
use std::sync::{Arc,atomic::{AtomicBool,AtomicUsize,Ordering}};
use std::time::Duration;
use serde_json::{json,Value};
use rmcp::ServiceExt;
use tokio::io::{AsyncBufReadExt,AsyncWriteExt};
use crate::{mcp,observe};
type Owner=mcp::server::OriginalServer;

fn raw_path(value:&Value)->PathBuf{PathBuf::from(std::ffi::OsString::from_vec(observe::unhex(value.as_str().unwrap())))}
fn owned(path:PathBuf,root:&Path)->PathBuf{assert!(path.is_absolute()&&path.starts_with(root)&&path!=root&&!path.components().any(|p|matches!(p,Component::ParentDir)));path}
fn actions(values:&Value,root:&Path){
    for action in values.as_array().unwrap(){
        let path=owned(raw_path(&action["path_hex"]),root);
        observe::event("public_fixture_action_enter",json!({"action":action}));
        match action["kind"].as_str().unwrap(){
            "mkdir"=>std::fs::create_dir_all(&path).unwrap(),
            "write"=>{std::fs::write(&path,observe::unhex(action["data_hex"].as_str().unwrap())).unwrap();
                if let Some(mode)=action["mode"].as_u64(){std::fs::set_permissions(&path,std::fs::Permissions::from_mode(mode as u32)).unwrap();}},
            "symlink"=>std::os::unix::fs::symlink(raw_path(&action["target_hex"]),path).unwrap(),
            "hardlink"=>std::fs::hard_link(owned(raw_path(&action["target_hex"]),root),path).unwrap(),
            "remove_file"=>std::fs::remove_file(path).unwrap(),
            "remove_dir"=>std::fs::remove_dir(path).unwrap(),
            "chmod"=>std::fs::set_permissions(path,std::fs::Permissions::from_mode(action["mode"].as_u64().unwrap() as u32)).unwrap(),
            other=>panic!("unknown explicit public fixture action {other}"),
        }
        observe::event("public_fixture_action_exit",json!({"action":action}));
    }
}
struct LiveSession{
    owner:Owner,reader:tokio::io::BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    writer:tokio::io::WriteHalf<tokio::io::DuplexStream>,task:tokio::task::JoinHandle<Value>,
}
impl LiveSession{
    fn start(root:PathBuf)->Self{
        let owner=Owner{workdir:Arc::new(mcp::server::SessionWorkdir::new(root)),session_applied:Arc::new(AtomicBool::new(false)),
            view_cache:Arc::new(mcp::fs::delta::ViewCache::default()),outer_calls:Arc::new(AtomicUsize::new(0)),handler_calls:Arc::new(AtomicUsize::new(0))};
        let handler=owner.clone();let(client,server)=tokio::io::duplex(65536);
        let task=tokio::spawn(async move{match handler.serve(server).await{
            Ok(service)=>{let result=service.waiting().await;json!({"initialized":true,"terminal":format!("{result:?}")})},
            Err(error)=>json!({"initialized":false,"error_blob":observe::blob(error.to_string().as_bytes())}),
        }});
        let(reader,writer)=tokio::io::split(client);Self{owner,reader:tokio::io::BufReader::new(reader),writer,task}
    }
    fn watch(&self){observe::watch(self.owner.workdir.clone(),self.owner.session_applied.clone());}
    fn state(&self)->Value{mcp::server::session_state(&self.owner.workdir,&self.owner.session_applied)}
    async fn exchange(&mut self,wire:Vec<u8>,id:Option<Value>)->Value{
        assert!(wire.ends_with(b"\n"));let request_blob=observe::blob(&wire);let mut written=0;
        while written<wire.len(){match self.writer.write(&wire[written..]).await{
            Ok(n)if n>0=>written+=n,
            other=>{let error=match other{Err(error)=>error,Ok(_)=>std::io::Error::from(std::io::ErrorKind::WriteZero)};
                return json!({"request_blob":request_blob,"request_bytes_written":written,"response_blob":null,"transport":"write-error","error":observe::io_error(&error)});}
        }}
        if id.is_none(){return json!({"request_blob":request_blob,"request_bytes_written":written,"response_blob":null,"transport":"notification"});}
        let mut bytes=Vec::new();let count=tokio::time::timeout(Duration::from_secs(60),self.reader.read_until(b'\n',&mut bytes)).await.unwrap().unwrap();
        if count==0{return json!({"request_blob":request_blob,"request_bytes_written":written,"response_blob":observe::blob(&bytes),"transport":"eof"});}
        assert!(bytes.ends_with(b"\n"));let response:Value=serde_json::from_slice(&bytes).unwrap();assert_eq!(response["id"],id.unwrap());
        json!({"request_blob":request_blob,"request_bytes_written":written,"response_blob":observe::blob(&bytes),"transport":"response"})
    }
    async fn message(&mut self,message:&Value)->Value{let mut bytes=serde_json::to_vec(message).unwrap();bytes.push(b'\n');self.exchange(bytes,message.get("id").cloned()).await}
    async fn finish(self)->Value{
        let state=self.state();let outer=self.owner.outer_calls.load(Ordering::SeqCst);let handler=self.owner.handler_calls.load(Ordering::SeqCst);
        drop(self.reader);drop(self.writer);let terminal=tokio::time::timeout(Duration::from_secs(60),self.task).await.unwrap().unwrap();
        json!({"state":state,"outer_calls":outer,"handler_calls":handler,"service":terminal})
    }
}
async fn scenario(row:Value,root:&Path,output:&mut impl Write){
    assert_eq!(row["schema"],"hepta.runtime.batch-call-sdk-input.v1");
    let observed:Vec<_>=row["observed_roots"].as_array().unwrap().iter().map(|p|owned(raw_path(p),root)).collect();
    assert!(!observed.is_empty());observe::public_begin(root,&observed[0]);
    observe::event("scenario_setup_begin",json!({"scenario_id":row["scenario_id"]}));actions(&row["setup"],root);
    let mut sessions=BTreeMap::new();let mut starts=Vec::new();let mut caches=BTreeMap::new();
    for (ordinal,input) in row["sessions"].as_array().unwrap().iter().enumerate(){
        let name=input["id"].as_str().unwrap().to_owned();let mut session=LiveSession::start(owned(raw_path(&input["root_hex"]),root));session.watch();
        let mut exchanges=Vec::new();for message in input["initial_messages"].as_array().unwrap(){exchanges.push(session.message(message).await);}
        caches.insert(ordinal as u64,session.owner.view_cache.clone());
        starts.push(json!({"session":name,"initialization_fixture":true,"exchanges":exchanges,"state":session.state()}));
        assert!(sessions.insert(name,session).is_none());
    }
    observe::write_record(output,json!({"kind":"scenario_start","scenario_id":row["scenario_id"],"name":row["name"],"sessions":starts,
        "actual_original_full_router":false,"actual_original_get_info":false}));
    for step in row["steps"].as_array().unwrap(){
        let session=sessions.get_mut(step["session"].as_str().unwrap()).unwrap();session.watch();
        let state_before=session.state();let before=observe::snapshot(&caches);
        let files_before:Vec<_>=observed.iter().map(|path|observe::tree_at(path)).collect();
        let outer=session.owner.outer_calls.load(Ordering::SeqCst);let handler=session.owner.handler_calls.load(Ordering::SeqCst);
        observe::event("public_case_begin",json!({"case_id":step["case_id"]}));
        let action=&step["action"];let result=match action["kind"].as_str().unwrap(){
            "public"=>{
                if let Some(raw)=action.get("wire_hex"){session.exchange(observe::unhex(raw.as_str().unwrap()),Some(step["case_id"].clone())).await}
                else{session.message(&action["message"]).await}
            },
            "cache_seed"=>{
                mcp::request_ctx::with_request_context(session.owner.view_cache.clone(),async{
                    for entry in action["entries"].as_array().unwrap(){
                        let source=mcp::fs::PathSource::Local(owned(raw_path(&entry["path_hex"]),root));
                        mcp::fs::delta::note_create(&source,entry["content"].as_str().unwrap());
                    }
                }).await;json!({"actual_private_cache_seed":true})
            },
            "filesystem"=>{actions(&action["actions"],root);json!({"actual_private_fixture_actions":true})},
            other=>panic!("unknown public carrier operation {other}"),
        };
        observe::event("public_case_end",json!({"case_id":step["case_id"]}));
        let state_after=session.state();let after=observe::snapshot(&caches);
        let files_after:Vec<_>=observed.iter().map(|path|observe::tree_at(path)).collect();
        observe::write_record(output,json!({"kind":"case","scenario_id":row["scenario_id"],"case_id":step["case_id"],"name":step["name"],"domain":step["domain"],
            "session":step["session"],"state_before":state_before,"state_after":state_after,"before":before,"after":after,
            "files_before":files_before,"files_after":files_after,"result":result,
            "outer_call_tool_entries":session.owner.outer_calls.load(Ordering::SeqCst)-outer,"handler_entries":session.owner.handler_calls.load(Ordering::SeqCst)-handler,
            "request_context_present_after":mcp::request_ctx::with_view_cache(|_|true).is_some(),"original_full_router_executed":false}));
    }
    observe::unwatch();let mut terminal=serde_json::Map::new();
    for(name,session)in sessions{terminal.insert(name,session.finish().await);}
    observe::event("scenario_end",json!({"scenario_id":row["scenario_id"]}));
    observe::write_record(output,json!({"kind":"scenario_end","scenario_id":row["scenario_id"],"sessions":terminal,"after":observe::snapshot(&caches)}));
}
pub async fn run(root:&Path,policy_file:&Path){
    assert!(root.is_absolute()&&root.is_dir()&&policy_file.is_absolute());
    let config:Value=serde_json::from_slice(&std::fs::read(policy_file).unwrap()).unwrap();
    if !config.is_null(){let config=serde_json::from_value(config).unwrap();mcp::runtime::original_config::install_for_reference(config);}
    let mut input=std::io::stdin().lock();let mut line=String::new();assert!(std::io::BufRead::read_line(&mut input,&mut line).unwrap()>0);
    let row:Value=serde_json::from_str(&line).unwrap();line.clear();assert_eq!(std::io::BufRead::read_line(&mut input,&mut line).unwrap(),0,"one fresh original process per public scenario");
    let mut output=std::io::stdout().lock();output.write_all(b"HBCSO002").unwrap();scenario(row,root,&mut output).await;output.flush().unwrap();observe::finish();
}

use std::collections::{BTreeMap,HashMap};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt,OsStringExt};
use std::os::unix::fs::{MetadataExt,PermissionsExt};
use std::os::unix::fs::FileExt;
use std::os::fd::AsRawFd;
use std::path::{Component,Path,PathBuf};
use std::sync::{Arc,LazyLock,Mutex};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use crate::mcp::fs::{delta::ViewCache,PathSource};

#[derive(Default)]
struct Observation {
    marker:u64,events:Vec<Value>,blobs:Vec<Vec<u8>>,dedup:HashMap<([u8;32],usize),Vec<usize>>,
    input:Vec<Vec<u8>>,cwd:PathBuf,tree_root:PathBuf,hooks:Vec<Value>,used:Vec<bool>,counts:HashMap<String,u64>,
    retained_fds:HashMap<(u64,u64),std::fs::File>,
    watch:Option<(Arc<crate::mcp::server::SessionWorkdir>,Arc<std::sync::atomic::AtomicBool>)>,
}
static OBS:LazyLock<Mutex<Observation>>=LazyLock::new(Default::default);

pub fn unhex(text:&str)->Vec<u8>{
    assert_eq!(text.len()%2,0);text.as_bytes().chunks_exact(2).map(|p|u8::from_str_radix(std::str::from_utf8(p).unwrap(),16).unwrap()).collect()
}
pub fn hex(bytes:&[u8])->String{let mut out=String::with_capacity(bytes.len()*2);for byte in bytes{use std::fmt::Write;write!(&mut out,"{byte:02x}").unwrap();}out}
pub fn blob(bytes:&[u8])->usize{
    let key=(Sha256::digest(bytes).into(),bytes.len());let mut obs=OBS.lock().unwrap();
    if let Some(indices)=obs.dedup.get(&key){for index in indices{if obs.blobs[*index]==bytes{return *index;}}}
    let index=obs.blobs.len();obs.blobs.push(bytes.to_vec());obs.dedup.entry(key).or_default().push(index);index
}
pub fn path_blob(path:&Path)->usize{blob(path.as_os_str().as_bytes())}
pub fn source_blob(source:&PathSource)->usize{path_blob(source.as_local_path().expect("local original domain only"))}
pub fn input_blob(index:usize)->Vec<u8>{OBS.lock().unwrap().input[index].clone()}
pub fn saw_event(kind:&str)->bool{OBS.lock().unwrap().events.iter().any(|event|event["kind"]==kind)}
pub fn event_body(kind:&str)->Vec<u8>{let obs=OBS.lock().unwrap();let event=obs.events.iter().rev().find(|e|e["kind"]==kind).unwrap();obs.blobs[event["data"]["body_blob"].as_u64().unwrap() as usize].clone()}
pub fn working_directory()->PathBuf{OBS.lock().unwrap().cwd.clone()}
pub fn io_error(error:&std::io::Error)->Value{json!({"ok":false,"short_blob":blob(error.to_string().as_bytes()),"kind":format!("{:?}",error.kind()),"errno":error.raw_os_error()})}
pub fn error_result(error:&anyhow::Error)->Value{json!({"ok":false,"short_blob":blob(error.to_string().as_bytes()),"chain_blob":blob(format!("{error:#}").as_bytes()),"errno":error.downcast_ref::<std::io::Error>().and_then(|e|e.raw_os_error())})}
pub fn unit_result(result:&anyhow::Result<()>)->Value{match result{Ok(())=>json!({"ok":true}),Err(error)=>error_result(error)}}
pub fn io_unit(result:&std::io::Result<()>)->Value{match result{Ok(())=>json!({"ok":true}),Err(error)=>io_error(error)}}
pub fn metadata(meta:&std::fs::Metadata)->Value{
    json!({"dev":meta.dev(),"ino":meta.ino(),"mode":meta.mode(),"uid":meta.uid(),"gid":meta.gid(),"nlink":meta.nlink(),"size":meta.len(),
        "mtime":[meta.mtime(),meta.mtime_nsec()],"ctime":[meta.ctime(),meta.ctime_nsec()],"is_file":meta.is_file(),"is_dir":meta.is_dir(),"is_symlink":meta.is_symlink()})
}
pub fn event(kind:&str,data:Value){
    let context=crate::mcp::request_ctx::observe_context();
    let locks=crate::mcp::fs::text_editing::observe_file_locks();
    let watch=OBS.lock().unwrap().watch.clone();
    let session=watch.map(|(state,latch)|crate::mcp::server::session_state(&state,&latch));
    let mut obs=OBS.lock().unwrap();obs.marker+=1;let marker=1_000_000_000+obs.marker;
    assert_eq!(unsafe{libc::getpgid(i32::try_from(marker).unwrap())},-1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(),Some(libc::ESRCH));
    obs.events.push(json!({"marker":marker,"kind":kind,"data":data,"request_context":context,"file_locks":locks,"session":session}));
}
pub fn begin(row:&Value,input:Vec<Vec<u8>>,root:&Path,_cache:Arc<ViewCache>)->PathBuf{
    let relative=if let Some(sequence)=row["sequence"].as_str(){assert!(sequence.chars().all(|c|c.is_ascii_alphanumeric()||c=='-'));format!("sequence-{sequence}")}
        else{format!("case-{:04}",row["case_id"].as_u64().unwrap())};
    let tree_root=root.join(relative);
    let relative=unhex(row["workdir_rel_hex"].as_str().unwrap());
    let cwd=if relative.is_empty(){tree_root.clone()}else{tree_root.join(std::ffi::OsString::from_vec(relative))};
    assert!(!cwd.components().any(|c|matches!(c,Component::ParentDir))&&cwd.starts_with(root));
    if let Some(actual)=row.get("fixture_cwd_hex"){assert_eq!(cwd.as_os_str().as_bytes(),unhex(actual.as_str().unwrap()));}
    std::fs::create_dir_all(&cwd).unwrap();
    let mut obs=OBS.lock().unwrap();assert!(obs.events.is_empty()&&obs.blobs.is_empty());
    obs.input=input;obs.cwd=cwd.clone();obs.tree_root=tree_root;
    obs.watch=None;
    obs.hooks=row["hooks"].as_array().unwrap().clone();obs.used=vec![false;obs.hooks.len()];obs.counts.clear();cwd
}
pub fn public_begin(root:&Path,tree_root:&Path){
    assert!(root.is_absolute()&&tree_root.is_absolute()&&tree_root.starts_with(root));
    let mut obs=OBS.lock().unwrap();assert!(obs.events.is_empty()&&obs.blobs.is_empty());
    obs.cwd=root.to_owned();obs.tree_root=tree_root.to_owned();obs.hooks.clear();obs.used.clear();obs.counts.clear();obs.input.clear();obs.watch=None;
}
pub fn watch(state:Arc<crate::mcp::server::SessionWorkdir>,latch:Arc<std::sync::atomic::AtomicBool>){OBS.lock().unwrap().watch=Some((state,latch));}
pub fn unwatch(){OBS.lock().unwrap().watch=None;}
fn owned(name:&str)->PathBuf{
    let path=Path::new(name);assert!(!path.is_absolute()&&!path.components().any(|c|matches!(c,Component::ParentDir)));
    OBS.lock().unwrap().cwd.join(path)
}
pub fn actions(items:&Value){
    for action in items.as_array().unwrap(){
        let path=owned(action["path"].as_str().unwrap());
        event("fixture_action_enter",json!({"action":action,"path_blob":path_blob(&path)}));
        match action["kind"].as_str().unwrap(){
            "mkdir"=>std::fs::create_dir_all(&path).unwrap(),
            "write"=>{let body=input_blob(action["blob"].as_u64().unwrap() as usize);std::fs::write(&path,body).unwrap();
                let file=std::fs::File::open(&path).unwrap();let meta=file.metadata().unwrap();
                OBS.lock().unwrap().retained_fds.insert((meta.dev(),meta.ino()),file);
                if let Some(mode)=action["mode"].as_u64(){std::fs::set_permissions(&path,std::fs::Permissions::from_mode(mode as u32)).unwrap();}},
            "chmod"=>std::fs::set_permissions(&path,std::fs::Permissions::from_mode(action["mode"].as_u64().unwrap() as u32)).unwrap(),
            "symlink"=>std::os::unix::fs::symlink(action["target"].as_str().unwrap(),&path).unwrap(),
            "hardlink"=>std::fs::hard_link(owned(action["target"].as_str().unwrap()),&path).unwrap(),
            "rename"=>std::fs::rename(&path,owned(action["target"].as_str().unwrap())).unwrap(),
            "remove"=>{let meta=std::fs::symlink_metadata(&path).unwrap();if meta.is_dir(){std::fs::remove_dir(&path).unwrap();}else{std::fs::remove_file(&path).unwrap();}},
            "fifo"=>{let name=std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();assert_eq!(unsafe{libc::mkfifo(name.as_ptr(),action["mode"].as_u64().unwrap_or(0o600) as libc::mode_t)},0);},
            kind=>panic!("unknown input fixture action {kind}"),
        }
        event("fixture_action_exit",json!({"action":action,"path_blob":path_blob(&path)}));
    }
}
pub fn after(name:&str){
    let selected={let mut obs=OBS.lock().unwrap();let count=obs.counts.entry(name.into()).or_default();*count+=1;let occurrence=*count;
        let indices:Vec<_>=obs.hooks.iter().enumerate().filter(|(_,h)|h["event"]==name&&h["occurrence"]==occurrence).map(|(i,_)|i).collect();
        indices.into_iter().map(|i|{assert!(!obs.used[i]);obs.used[i]=true;(i,obs.hooks[i].clone())}).collect::<Vec<_>>()};
    for (index,hook) in selected{event("mutation_begin",json!({"hook":index,"event":name}));actions(&hook["actions"]);event("mutation_end",json!({"hook":index,"event":name}));}
}
pub fn check_hooks(){let obs=OBS.lock().unwrap();assert!(obs.used.iter().all(|v|*v),"declared original mutation did not execute");}
fn tree(path:&Path,base:&Path,rows:&mut Vec<Value>){
    let mut row=json!({"relative_hex":hex(path.strip_prefix(base).unwrap().as_os_str().as_bytes())});
    match std::fs::symlink_metadata(path){
        Err(error)=>row["error"]=io_error(&error),
        Ok(meta)=>{
            row["metadata"]=metadata(&meta);
            if meta.is_symlink(){row["target_hex"]=json!(hex(std::fs::read_link(path).unwrap().as_os_str().as_bytes()));}
            else if meta.is_file(){row["content"]=match std::fs::read(path){
                Ok(body)=>json!({"ok":true,"blob":blob(&body)}),
                Err(error)=>{
                    let retained=OBS.lock().unwrap().retained_fds.get(&(meta.dev(),meta.ino())).map(|file|file.try_clone().unwrap());
                    if let Some(file)=retained{
                        let mut body=Vec::new();let mut piece=[0u8;65536];let mut offset=0;
                        loop{let n=file.read_at(&mut piece,offset).unwrap();if n==0{break;}body.extend_from_slice(&piece[..n]);offset+=n as u64;}
                        json!({"ok":true,"blob":blob(&body),"fixture_retained_fd":true,"pathname_errno":error.raw_os_error()})
                    }else{io_error(&error)}
                }
            };}
            else if meta.is_dir(){match std::fs::read_dir(path){
                Ok(entries)=>{let mut children:Vec<_>=entries.map(|x|x.unwrap().path()).collect();children.sort_by(|a,b|a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
                    rows.push(row);for child in children{tree(&child,base,rows);}return;},
                Err(error)=>row["readdir_error"]=io_error(&error),
            }}
        }
    }
    rows.push(row);
}
pub fn snapshot(caches:&BTreeMap<u64,Arc<ViewCache>>)->Value{
    let (poisoned,total_bytes,order,history)=crate::mcp::fs::original_core::observe_history();
    let history:Vec<_>=history.into_iter().map(|(key,values)|json!({"key_blob":blob(key.as_bytes()),"values":values.iter().map(|value|blob(value.as_bytes())).collect::<Vec<_>>()})).collect();
    let caches:Vec<_>=caches.iter().map(|(id,cache)|{let(poisoned,entries)=crate::mcp::fs::delta::observe_cache(cache);
        json!({"session":id,"poisoned":poisoned,"entries":entries.into_iter().map(|(key,value)|json!({"key_blob":blob(key.as_bytes()),"value_blob":blob(value.as_bytes())})).collect::<Vec<_>>()})}).collect();
    let root=OBS.lock().unwrap().tree_root.clone();let mut nodes=Vec::new();tree(&root,&root,&mut nodes);
    let retained:Vec<_>=OBS.lock().unwrap().retained_fds.values().map(|file|file.as_raw_fd() as u32).collect();
    let mut descriptors:Vec<_>=std::fs::read_dir("/proc/self/fd").unwrap().map(|entry|{let entry=entry.unwrap();let fd=entry.file_name().to_str().unwrap().parse::<u32>().unwrap();json!({"fd":fd,
        "fixture_owned":retained.contains(&fd),"target_hex":hex(std::fs::read_link(entry.path()).unwrap().as_os_str().as_bytes())})}).collect();
    descriptors.sort_by_key(|r|r["fd"].as_u64().unwrap());
    json!({"history":{"poisoned":poisoned,"total_bytes":total_bytes,"order":order,"entries":history},"caches":caches,
        "file_locks":crate::mcp::fs::text_editing::observe_file_locks(),"tree":{"root_blob":path_blob(&root),"nodes":nodes},"descriptors":descriptors})
}
pub fn tree_at(path:&Path)->Value{let mut nodes=Vec::new();tree(path,path,&mut nodes);json!({"root_blob":path_blob(path),"nodes":nodes})}
pub fn finish(){OBS.lock().unwrap().retained_fds.clear();}
pub fn write_record(output:&mut impl Write,mut metadata:Value){
    let mut obs=OBS.lock().unwrap();metadata["events"]=json!(std::mem::take(&mut obs.events));metadata["hook_used"]=json!(obs.used);
    let raw=serde_json::to_vec(&metadata).unwrap();let blobs=std::mem::take(&mut obs.blobs);obs.dedup.clear();obs.input.clear();
    output.write_all(&(raw.len() as u64).to_le_bytes()).unwrap();output.write_all(&(blobs.len() as u64).to_le_bytes()).unwrap();output.write_all(&raw).unwrap();
    for body in blobs{output.write_all(&(body.len() as u64).to_le_bytes()).unwrap();output.write_all(&body).unwrap();}output.flush().unwrap();
}

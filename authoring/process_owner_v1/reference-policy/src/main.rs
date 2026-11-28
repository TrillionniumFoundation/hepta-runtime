// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit test-owned policy observation using original Rust functions.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, Component};
type Result<T,E=String> = std::result::Result<T,E>;
macro_rules! bail { ($($arg:tt)*) => { return Err(format!($($arg)*)) }; }
include!("original.rs");
include!("policy.rs");
fn word(out: &mut [u8], at: usize, value: u64) {
    out[at..at+8].copy_from_slice(&value.to_le_bytes());
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b|format!("{b:02x}")).collect()
}
fn project<T: DeserializeOwned + Serialize>(value: Value) -> Result<Value,String> {
    serde_json::from_value::<T>(value).map(|p|serde_json::to_value(p).unwrap()).map_err(|e|e.to_string())
}
fn frame(kind:u64, params:&Value, original:&Value) -> Vec<u8> {
    let schemas:Value=serde_json::from_str(include_str!("../../SCHEMAS.json")).unwrap();
    let fields=schemas["types"].as_array().unwrap().iter().find(|s|s["id"]==kind).unwrap()["fields"].as_array().unwrap();
    let mut out=vec![0u8;640];
    out[..8].copy_from_slice(b"HPRPAR01");
    word(&mut out,16,kind);
    let mut mask=0u64;
    let mut ordered=fields.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|f|f[1].as_u64().unwrap());
    for field in ordered {
        let name=field[0].as_str().unwrap();
        let id=field[1].as_u64().unwrap();
        let typ=match field[2].as_str().unwrap() {
            "string"=>1,"option_string"=>2,"option_u64"=>3,"option_u8"=>4,
            "option_u16"=>5,"string_vec"=>6,"string_map"=>7,_=>panic!("kind")
        };
        let value=&params[name];
        let present=original.get(name).is_some_and(|v|!v.is_null());
        if present {mask|=1<<id;}
        if value.is_null() {continue}
        let slot=64+(id as usize-1)*24;
        word(&mut out,slot,typ);
        let (payload,numeric)=match typ {
            1|2=>(value.as_str().unwrap().as_bytes().to_vec(),0),
            3|4|5=>(Vec::new(),value.as_u64().unwrap()),
            6=>(serde_json::to_vec(value).unwrap(),value.as_array().unwrap().len() as u64),
            7=>(serde_json::to_vec(value).unwrap(),value.as_object().unwrap().len() as u64),
            _=>unreachable!()
        };
        word(&mut out,slot+8,payload.len() as u64);
        word(&mut out,slot+16,numeric);
        out.extend_from_slice(&payload);
    }
    word(&mut out,24,mask);
    let payload_len=out.len()-640;
    word(&mut out,32,payload_len as u64);
    out
}
fn error_frame(kind:u64,message:&str)->Vec<u8>{
    let mut out=vec![0u8;640];
    out[..8].copy_from_slice(b"HPRPAR01");
    word(&mut out,8,1);word(&mut out,16,kind);word(&mut out,40,message.len() as u64);
    out.extend_from_slice(message.as_bytes());out
}

fn host_frame(name:&str, host:&HostConfig)->Vec<u8> {
 let mut out=vec![0u8;128];out[..8].copy_from_slice(b"HRCFTR01");
 word(&mut out,8,1);word(&mut out,16,1);
 word(&mut out,24,name.len() as u64);
 word(&mut out,32,host.ssh_target.len() as u64);
 word(&mut out,40,host.remote_state_dir.len() as u64);
 word(&mut out,48,if host.platform==Platform::Macos {1}else{0});
 word(&mut out,56,if host.execution_mode==ExecutionMode::Operator {1}else{0});
 let flags=(host.allow_execute as u64)|((host.allow_pty as u64)<<1)|((host.allow_write as u64)<<2)|((host.allow_job_network as u64)<<3)|((host.allow_detached_fallback as u64)<<4);
 word(&mut out,64,flags);
 let lists=[&host.allowed_cwd_prefixes,&host.allowed_read_path_prefixes,&host.allowed_write_path_prefixes,&host.protected_path_prefixes,&host.protected_argument_substrings,&host.denied_executables,&host.allowed_dangerous_executables];
 for (i,list) in lists.iter().enumerate(){word(&mut out,72+i*8,list.len() as u64);}
 out.extend_from_slice(name.as_bytes());out.extend_from_slice(host.ssh_target.as_bytes());out.extend_from_slice(host.remote_state_dir.as_bytes());
 for list in lists{for value in list {out.extend_from_slice(&(value.len() as u64).to_le_bytes());out.extend_from_slice(value.as_bytes());}}
 out
}
fn policy(phase:u64,kind:u64,params:&Value,host:&HostConfig)->Result<[u64;3]>{
 match (phase,kind){
  (0,3)=>{key_only(&serde_json::from_value::<ProcessStartParams>(params.clone()).unwrap())?;},
  (1,3)=>{validate_start(&serde_json::from_value::<ProcessStartParams>(params.clone()).unwrap(),host)?;},
  (2,3)=>{validate_new_host_resource_limits(host.platform,&serde_json::from_value::<ProcessStartParams>(params.clone()).unwrap())?;},
  (3,2)=>{shell_start_prefix(serde_json::from_value::<ShellStartParams>(params.clone()).unwrap(),host)?;},
  (4,5)=>{let p=serde_json::from_value::<ProcessReadParams>(params.clone()).unwrap();return Ok([p.limit.unwrap_or(65_536).min(MAX_LOG_READ_BYTES as u64),p.stdout_offset.unwrap_or(0),p.stderr_offset.unwrap_or(0)]);},
  (4,6)=>{let p=serde_json::from_value::<ProcessWaitParams>(params.clone()).unwrap();return Ok([p.timeout_seconds.unwrap_or(10).min(30),0,0]);},
  (4,7)=>{let p=serde_json::from_value::<ProcessCancelParams>(params.clone()).unwrap();return Ok([p.grace_seconds.unwrap_or(10).min(30),0,0]);},
  (5,9)=>{let p=serde_json::from_value::<ProcessListPageParams>(params.clone()).unwrap();let limit=page_prefix(&p)?;return Ok([limit as u64,0,0]);},
  (6,1)=>{let command=params["command"].as_str().unwrap();if command.trim().is_empty(){bail!("Command parameter cannot be empty");}},
  _=>panic!("noncanonical observer phase"),
 }
 Ok([0;3])
}
fn policy_frame(phase:u64,kind:u64,result:&Result<[u64;3]>)->Vec<u8>{
 let mut out=vec![0u8;80];out[..8].copy_from_slice(b"HPRVLR01");word(&mut out,16,phase);word(&mut out,24,kind);
 match result {
  Ok(values)=>{for (i,v) in values.iter().enumerate(){word(&mut out,48+i*8,*v);}},
  Err(error)=>{word(&mut out,8,1);word(&mut out,32,error.len() as u64);out.extend_from_slice(error.as_bytes());}
 }
 out
}
fn main(){
 let mut output=io::BufWriter::new(io::stdout().lock());
 for line in io::stdin().lock().lines(){
  let row:Value=serde_json::from_str(&line.unwrap()).unwrap();
  let raw=row["raw_json"].as_str().unwrap();let kind=row["kind"].as_u64().unwrap();let phase=row["phase"].as_u64().unwrap();
  let value=Value::Object(serde_json::from_str::<Map<String,Value>>(raw).unwrap());
  let canonical=serde_json::to_string(&value).unwrap();
  let params=match kind {
   1=>Ok(json!({"command":value["command"].as_str().unwrap()})),
   2=>project::<ShellStartParams>(value.clone()),3=>project::<ProcessStartParams>(value.clone()),
   4=>project::<ProcessRefParams>(value.clone()),5=>project::<ProcessReadParams>(value.clone()),
   6=>project::<ProcessWaitParams>(value.clone()),7=>project::<ProcessCancelParams>(value.clone()),
   8=>project::<ProcessListParams>(value.clone()),9=>project::<ProcessListPageParams>(value.clone()),_=>unreachable!()
  }.unwrap();
  let host:HostConfig=serde_json::from_value(row["host"].clone()).unwrap();
  let h=if matches!(phase,1|2|3){host_frame(params["host"].as_str().unwrap(),&host)}else{Vec::new()};
  let typed=frame(kind,&params,&value);
  let mut request=b"HPRVLQ01".to_vec();
  for word in [phase,kind,typed.len() as u64,h.len() as u64,0]{request.extend_from_slice(&word.to_le_bytes());}
  request.extend_from_slice(&typed);request.extend_from_slice(&h);
  let result=policy(phase,kind,&params,&host);
  serde_json::to_writer(&mut output,&json!({"case_id":row["case_id"],"name":row["name"],"kind":kind,"phase":phase,
   "canonical":canonical,"typed_hex":hex(&typed),"host_hex":hex(&h),"request_sha256_input_hex":hex(&request),
   "ok":result.is_ok(),"error":result.as_ref().err(),"values":result.as_ref().ok(),"frame_hex":hex(&policy_frame(phase,kind,&result))})).unwrap();
  output.write_all(b"\n").unwrap();
 }
 output.flush().unwrap();
}

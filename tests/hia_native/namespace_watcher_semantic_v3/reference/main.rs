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
//! Persistent actual original Watcher; observer accessors never perform its effects.
#![allow(dead_code)]
use anyhow::{anyhow,bail,ensure,Result};
use serde_json::{json,Value};
use std::collections::BTreeMap;
use std::io::{BufRead,Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
mod target;
mod owned_environment;
fn hex(raw:&[u8])->String{raw.iter().map(|x|format!("{x:02x}")).collect()}
fn unhex(raw:&str)->Result<Vec<u8>>{
    ensure!(raw.len()%2==0&&raw.is_ascii(),"whole hex input");
    let value=(0..raw.len()).step_by(2).map(|at|u8::from_str_radix(&raw[at..at+2],16))
        .collect::<std::result::Result<Vec<_>,_>>()?;
    ensure!(hex(&value)==raw,"canonical hex");Ok(value)
}
fn n(v:&Value,k:&str)->Result<u64>{v.get(k).and_then(Value::as_u64).ok_or_else(||anyhow!("integer {k}"))}
fn b(v:&Value,k:&str)->Result<bool>{v.get(k).and_then(Value::as_bool).ok_or_else(||anyhow!("boolean {k}"))}
fn t<'a>(v:&'a Value,k:&str)->Result<&'a str>{v.get(k).and_then(Value::as_str).ok_or_else(||anyhow!("string {k}"))}
fn emit(out:&mut impl Write,value:&Value)->Result<()>{
    serde_json::to_writer(&mut *out,value)?;out.write_all(b"\n")?;out.flush()?;Ok(())
}
fn mark(tag:&[u8;8],case:u64,step:u64)->Result<()>{
    let mut raw=Vec::from(*tag);raw.extend(case.to_le_bytes());raw.extend(step.to_le_bytes());
    std::io::stderr().lock().write_all(&raw)?;Ok(())
}
fn success(version:Option<target::Version>)->Result<Value>{
    let token=match version{
        None=>Value::Null,Some(target::Version::Watch(a,b))=>json!([a,b]),
        Some(_)=>bail!("private Watcher unexpectedly returned fingerprint"),
    };
    Ok(json!({"kind":0,"family":0,"code":0,"version":token}))
}
fn outcome(value:Result<Option<target::Version>>)->Result<(Value,Value)>{
    match value {
        Ok(version)=>Ok((success(version)?,Value::Null)),
        Err(error)=>{
            let text=error.to_string();
            let raw=error.downcast_ref::<std::io::Error>().and_then(std::io::Error::raw_os_error);
            let (family,code)=if let Some(errno)=raw{ensure!((1..=4095).contains(&errno),"original OS error");(1,errno)}
            else{
                let strings=["namespace epoch exhausted","namespace event stream closed",
                    "invalid namespace event read length","namespace event drain budget exhausted",
                    "truncated namespace event","namespace event size overflow",
                    "truncated namespace event name","namespace descriptor is not a directory"];
                let at=strings.iter().position(|s|*s==text).ok_or_else(||anyhow!("unclassified original error: {text}"))?;
                (2,i32::try_from(at+1)?)
            };
            Ok((json!({"kind":1,"family":family,"code":code,"version":null}),
                json!({"display":text,"debug":format!("{error:?}"),
                    "chain":error.chain().map(ToString::to_string).collect::<Vec<_>>(),"raw_os_error":raw})))
        }
    }
}
fn state(watchers:&BTreeMap<u64,target::FixtureWatcher>,roots:&BTreeMap<usize,Arc<std::fs::File>>)->Result<Value>{
    let watches=watchers.iter().map(|(id,w)|json!({"wid":id,"state":target::fixture_snapshot(w)})).collect::<Vec<_>>();
    let mut owned=Vec::new();
    for (index,root)in roots{
        let info=root.metadata()?;
        owned.push(json!({"root":index,"fd":root.as_raw_fd(),"strong_count":Arc::strong_count(root),
            "device":info.dev(),"inode":info.ino(),"mode":info.mode()}));
    }
    Ok(json!({"watchers":watches,"roots":owned}))
}
fn normalized_callback(value:&Value)->Result<Value>{
    let mut result=Vec::new();
    for row in value.as_array().ok_or_else(||anyhow!("callback observations"))?{
        let out=&row["result"];
        let answer=if let Some(count)=out.get("count"){json!({"count":count})}
        else{
            let errno=if let Some(errno)=out["raw_os_error"].as_i64(){errno}
                else{match out["kind"].as_str(){Some("Interrupted")=>4,Some("WouldBlock")=>11,_=>bail!("callback kind")}};
            json!({"errno":errno})
        };
        result.push(json!({"index":row["index"],"script_row":row["script_row"],
            "before_hex":row["before_hex"],"after_hex":row["after_hex"],"result":answer}));
    }
    Ok(Value::Array(result))
}
fn main()->Result<()>{
    let args=std::env::args().collect::<Vec<_>>();ensure!(args.len()==2,"fixed process group");
    let group=&args[1];let mut input=std::io::stdin().lock();let mut output=std::io::stdout().lock();
    let layout=owned_environment::reserve()?;let saved=owned_environment::limit()?;
    emit(&mut output,&json!({"command":"ready","role":"original","pid":std::process::id(),
        "parent_pid":unsafe{libc::getppid()},"pgid":unsafe{libc::getpgrp()},
        "uid":unsafe{libc::geteuid()},"gid":unsafe{libc::getegid()},"group":group,"layout":layout}))?;
    let mut selected=None;let mut paths=Vec::<Vec<u8>>::new();
    let mut watchers=BTreeMap::<u64,target::FixtureWatcher>::new();
    let mut roots=BTreeMap::<usize,Arc<std::fs::File>>::new();let mut next_step=0_u64;
    loop{
        let mut line=String::new();if input.read_line(&mut line)?==0{break;}
        ensure!(line.ends_with('\n')&&line.len()<=1<<20,"bounded complete control line");
        let command:Value=serde_json::from_str(&line)?;let case=n(&command,"case")?;
        match t(&command,"cmd")?{
            "prepare"=>{
                ensure!(selected.is_none()&&watchers.is_empty()&&roots.is_empty(),"exact old case released");
                owned_environment::clear()?;paths.clear();
                for (index,row)in command["roots"].as_array().ok_or_else(||anyhow!("owned roots"))?.iter().enumerate(){
                    let path=unhex(t(row,"path_hex")?)?;
                    if !b(row,"late")?{roots.insert(index,Arc::new(owned_environment::open_root(&path,index)?));}
                    paths.push(path);
                }
                selected=Some(case);next_step=0;
                emit(&mut output,&json!({"command":"prepare","case":case,"state":state(&watchers,&roots)?}))?;
            }
            "run"=>{
                let step=n(&command,"step")?;ensure!(selected==Some(case)&&step==next_step,"complete ordered owned operation");
                next_step+=1;let op=&command["operation"];let kind=t(op,"op")?;let mut full_callback=Value::Array(Vec::new());
                mark(b"HNWORGB1",case,step)?;
                let result:Result<Option<target::Version>>=match kind{
                    "new"=>{
                        let id=n(op,"wid")?;ensure!(!watchers.contains_key(&id),"no replaced Watcher");
                        match target::fixture_new(usize::try_from(n(op,"limit")?)?,b(op,"content")?){
                            Ok(w)=>{watchers.insert(id,w);Ok(None)},Err(e)=>Err(e)
                        }
                    }
                    "version"=>{
                        let id=n(op,"wid")?;let root=roots.get(&usize::try_from(n(op,"root")?)?).ok_or_else(||anyhow!("owned root"))?;
                        target::fixture_version(watchers.get_mut(&id).ok_or_else(||anyhow!("live Watcher"))?,
                            root.as_ref(),if b(op,"shared")?{Some(root)}else{None}).map(Some)
                    }
                    "drain"=>target::fixture_drain(watchers.get_mut(&n(op,"wid")?).ok_or_else(||anyhow!("live Watcher"))?).map(|()|None),
                    "changed"=>{
                        let wd=i32::try_from(op["wd"].as_i64().ok_or_else(||anyhow!("signed wd"))?)?;
                        target::fixture_changed(watchers.get_mut(&n(op,"wid")?).ok_or_else(||anyhow!("live Watcher"))?,
                            wd,u32::try_from(n(op,"mask")?)?).map(|()|None)
                    }
                    "seed"=>{
                        let next=t(op,"next_decimal")?.parse::<u64>()?;ensure!(next<1_u64<<63,"private admitted serial seed");
                        target::fixture_seed_serial(watchers.get_mut(&n(op,"wid")?).ok_or_else(||anyhow!("live Watcher"))?,next);Ok(None)
                    }
                    "callback"=>{
                        let directory=if op["root"].is_null(){None}else{
                            let root=roots.get(&usize::try_from(n(op,"root")?)?).ok_or_else(||anyhow!("callback root"))?;
                            Some((root.as_ref(),if b(op,"shared")?{Some(root)}else{None}))
                        };
                        let (out,observed)=target::fixture_callback(watchers.get_mut(&n(op,"wid")?).ok_or_else(||anyhow!("live Watcher"))?,directory,&op["script"]);
                        full_callback=observed;out
                    }
                    "drop"=>{
                        let mut w=watchers.remove(&n(op,"wid")?).ok_or_else(||anyhow!("live Watcher"))?;
                        target::fixture_drop(&mut w);Ok(None)
                    }
                    "release-root"=>{drop(roots.remove(&usize::try_from(n(op,"root")?)?).ok_or_else(||anyhow!("owned root"))?);Ok(None)}
                    "open-root"=>{
                        let id=usize::try_from(n(op,"root")?)?;ensure!(!roots.contains_key(&id)&&id<paths.len(),"fresh late root");
                        roots.insert(id,Arc::new(owned_environment::open_root(&paths[id],id)?));Ok(None)
                    }
                    "limit"=>{owned_environment::set_limit(n(op,"soft")?,saved.rlim_max)?;Ok(None)}
                    "restore-limit"=>{owned_environment::set_limit(saved.rlim_cur,saved.rlim_max)?;Ok(None)}
                    _=>bail!("unlisted fixed operation"),
                };
                mark(b"HNWORGE1",case,step)?;
                let (semantic,error)=outcome(result)?;let callback=normalized_callback(&full_callback)?;
                emit(&mut output,&json!({"command":"run","case":case,"step":step,"operation":kind,
                    "semantic":semantic,"state":state(&watchers,&roots)?,"callback":callback,"original_callback":full_callback,
                    "original_error":error}))?;
            }
            "finish"=>{
                ensure!(selected==Some(case)&&watchers.is_empty(),"all Watchers explicitly dropped before finish");
                roots.clear();paths.clear();owned_environment::set_limit(saved.rlim_cur,saved.rlim_max)?;
                owned_environment::clear()?;selected=None;
                emit(&mut output,&json!({"command":"finish","case":case,"all_owned_descriptors_closed":true}))?;
            }
            _=>bail!("unlisted owned command"),
        }
    }
    ensure!(selected.is_none()&&watchers.is_empty()&&roots.is_empty(),"exact EOF cleanup");
    owned_environment::clear()?;Ok(())
}

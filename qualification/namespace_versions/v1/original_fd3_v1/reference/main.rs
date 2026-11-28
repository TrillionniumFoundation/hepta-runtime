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
//! Actual complete original namespace globals and immutable content scopes.
#![allow(dead_code)]
use anyhow::{anyhow,bail,ensure,Result};
use serde_json::{json,Value};
use std::collections::BTreeMap;
use std::io::{BufRead,Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc,Barrier};
mod target;
mod fixture_elf;
mod owned_environment;
fn hex(raw:&[u8])->String{raw.iter().map(|v|format!("{v:02x}")).collect()}
fn unhex(s:&str)->Result<Vec<u8>>{
    ensure!(s.len()%2==0&&s.is_ascii(),"whole canonical hexadecimal");
    let raw=(0..s.len()).step_by(2).map(|at|u8::from_str_radix(&s[at..at+2],16)).collect::<std::result::Result<Vec<_>,_>>()?;
    ensure!(hex(&raw)==s,"canonical hex");Ok(raw)
}
fn n(v:&Value,k:&str)->Result<u64>{v[k].as_u64().ok_or_else(||anyhow!("integer {k}"))}
fn t<'a>(v:&'a Value,k:&str)->Result<&'a str>{v[k].as_str().ok_or_else(||anyhow!("string {k}"))}
fn b(v:&Value,k:&str)->Result<bool>{v[k].as_bool().ok_or_else(||anyhow!("boolean {k}"))}
fn emit(out:&mut impl Write,v:&Value)->Result<()>{serde_json::to_writer(&mut*out,v)?;out.write_all(b"\n")?;out.flush()?;Ok(())}
fn mark(tag:&[u8;8],case:u64,step:u64)->Result<()>{let mut raw=Vec::from(*tag);raw.extend(case.to_le_bytes());raw.extend(step.to_le_bytes());std::io::stderr().lock().write_all(&raw)?;Ok(())}
fn outcome(value:Result<Option<target::Version>>)->Result<(Value,Value)>{
    match value{
        Ok(token)=>{
            let (kind,version,digest)=match token{
                None=>(0,Value::Null,Value::Null),
                Some(target::Version::Watch(a,b))=>(1,json!([a,b]),Value::Null),
                Some(target::Version::Fingerprint(bytes))=>(2,Value::Null,json!(hex(&bytes))),
            };
            Ok((json!({"kind":kind,"family":0,"code":0,"version":version,"digest":digest}),Value::Null))
        }
        Err(error)=>{
            let text=error.to_string();let os=error.downcast_ref::<std::io::Error>().and_then(std::io::Error::raw_os_error);
            let (family,code)=if let Some(errno)=os{ensure!((0..=4095).contains(&errno),"actual original OS errno");(1,errno)}else{
                let messages=["namespace epoch exhausted","namespace event stream closed","invalid namespace event read length",
                    "namespace event drain budget exhausted","truncated namespace event","namespace event size overflow",
                    "truncated namespace event name","namespace descriptor is not a directory","namespace watcher unavailable",
                    "archive content watcher unavailable","archive content watch set unavailable"];
                (2,i32::try_from(messages.iter().position(|s|*s==text).ok_or_else(||anyhow!("unclassified complete original error {text}"))?+1)?)
            };
            Ok((json!({"kind":3,"family":family,"code":code,"version":null,"digest":null}),
                json!({"display":text,"debug":format!("{error:?}"),"chain":error.chain().map(ToString::to_string).collect::<Vec<_>>(),"raw_os_error":os})))
        }
    }
}
fn state(sets:&BTreeMap<u64,Arc<target::ContentWatchSet>>,roots:&BTreeMap<usize,Arc<std::fs::File>>)->Result<Value>{
    let mut s=target::fixture_snapshot(sets);
    let mut rows=Vec::new();for (id,file)in roots{let m=file.metadata()?;rows.push(json!({"root":id,"fd":file.as_raw_fd(),
        "strong_count":Arc::strong_count(file),"device":m.dev(),"inode":m.ino(),"mode":m.mode()}));}
    s["roots"]=Value::Array(rows);Ok(s)
}
fn main()->Result<()>{
    let args=std::env::args().collect::<Vec<_>>();ensure!(args.len()==2,"fixed single fresh process group");let group=&args[1];
    let symbols=fixture_elf::initialize()?;let bindings=target::fixture_real_bindings();
    let layout=owned_environment::reserve()?;let saved=owned_environment::limit()?;
    let mut input=std::io::stdin().lock();let mut output=std::io::stdout().lock();
    emit(&mut output,&json!({"command":"ready","role":"original","pid":std::process::id(),"parent_pid":unsafe{libc::getppid()},
        "pgid":unsafe{libc::getpgrp()},"uid":unsafe{libc::geteuid()},"gid":unsafe{libc::getegid()},"group":group,"layout":layout,
        "static_bindings":symbols,"rust_types":bindings}))?;
    let mut selected=None;let mut finished=false;let mut next_step=0_u64;
    let mut roots=BTreeMap::<usize,Arc<std::fs::File>>::new();let mut paths=Vec::<Vec<u8>>::new();
    let mut sets=BTreeMap::<u64,Arc<target::ContentWatchSet>>::new();
    loop{
        let mut line=String::new();if input.read_line(&mut line)?==0{break;}
        ensure!(line.ends_with('\n')&&line.len()<=1<<20,"whole bounded private control");
        let c:Value=serde_json::from_str(&line)?;let case=n(&c,"case")?;
        match t(&c,"cmd")?{
            "prepare"=>{
                ensure!(selected.is_none()&&!finished&&roots.is_empty()&&sets.is_empty(),"one physical case per fresh process; globals never reset");
                for (i,row)in c["roots"].as_array().ok_or_else(||anyhow!("root list"))?.iter().enumerate(){
                    let path=unhex(t(row,"path_hex")?)?;
                    if !b(row,"late")?{roots.insert(i,Arc::new(owned_environment::open_root(&path,i)?));}paths.push(path);
                }
                selected=Some(case);emit(&mut output,&json!({"command":"prepare","case":case,"state":state(&sets,&roots)?}))?;
            }
            "run"=>{
                let step=n(&c,"step")?;ensure!(selected==Some(case)&&step==next_step,"whole ordered private operation");next_step+=1;
                let op=&c["operation"];let kind=t(op,"op")?;let mut control=Value::Null;let mut parallel=Vec::new();
                mark(b"HNVORGB1",case,step)?;
                let value:Result<Option<target::Version>>=match kind{
                    "version"=>target::version(roots.get(&usize::try_from(n(op,"root")?)?).ok_or_else(||anyhow!("root"))?).map(Some),
                    "watched"=>target::fixture_watched(roots.get(&usize::try_from(n(op,"root")?)?).ok_or_else(||anyhow!("root"))?).map(Some),
                    "content"=>target::content_version(roots.get(&usize::try_from(n(op,"root")?)?).ok_or_else(||anyhow!("root"))?),
                    "set-new"=>{
                        let sid=n(op,"sid")?;ensure!(!sets.contains_key(&sid),"new independent scope");
                        let members=op["roots"].as_array().ok_or_else(||anyhow!("complete member slice"))?.iter()
                            .map(|v|Ok(roots.get(&usize::try_from(v.as_u64().ok_or_else(||anyhow!("member index"))?)?)
                                .ok_or_else(||anyhow!("live member Arc"))?.clone())).collect::<Result<Vec<_>>>()?;
                        match target::ContentWatchSet::new(&members)?{
                            Some(set)=>{sets.insert(sid,Arc::new(set));control=json!({"constructed":true,"sid":sid});}
                            None=>{control=json!({"constructed":false,"sid":sid});}
                        }Ok(None)
                    }
                    "set-version"=>sets.get(&n(op,"sid")?).ok_or_else(||anyhow!("live scope"))?.version(),
                    "set-drop"=>{drop(sets.remove(&n(op,"sid")?).ok_or_else(||anyhow!("owned final scope"))?);Ok(None)}
                    "closed-standard-watcher"=>{
                        let first=roots.get(&usize::try_from(n(op,"first")?)?).ok_or_else(||anyhow!("first actual watcher root"))?;
                        let second=roots.get(&usize::try_from(n(op,"second")?)?).ok_or_else(||anyhow!("second actual watcher root"))?;
                        control=target::fixture_closed_standard_watcher(first,second,u32::try_from(n(op,"mask")?)?,b(op,"content")?)?;
                        Ok(None)
                    }
                    "seed-next"=>{target::fixture_seed_next(t(op,"value_decimal")?.parse()?);Ok(None)}
                    "seed-watcher"=>{
                        let set=if op["sid"].is_null(){None}else{Some(sets.get(&n(op,"sid")?).ok_or_else(||anyhow!("seed scope"))?.as_ref())};
                        target::fixture_seed_watcher(t(op,"kind")?,set,t(op,"value_decimal")?.parse()?);Ok(None)
                    }
                    "changed-set"=>{
                        target::fixture_changed_set(sets.get(&n(op,"sid")?).ok_or_else(||anyhow!("scope"))?,
                            i32::try_from(op["wd"].as_i64().ok_or_else(||anyhow!("actual signed wd"))?)?,u32::try_from(n(op,"mask")?)?).map(|()|None)
                    }
                    "poison"=>{
                        let set=if op["sid"].is_null(){None}else{Some(sets.get(&n(op,"sid")?).ok_or_else(||anyhow!("poison scope"))?.as_ref())};
                        let actual=target::fixture_poison(t(op,"kind")?,set);control=json!({"actual_unwind":actual});Ok(None)
                    }
                    "parallel-read"=>{
                        let workers=usize::try_from(n(op,"workers")?)?;let count=usize::try_from(n(op,"count")?)?;
                        ensure!((2..=32).contains(&workers)&&count>0&&count<=64,"fixed concurrent domain");
                        let barrier=Arc::new(Barrier::new(workers));let mode=t(op,"kind")?.to_owned();
                        let root=if op["root"].is_null(){None}else{Some(roots.get(&usize::try_from(n(op,"root")?)?).ok_or_else(||anyhow!("parallel root"))?.clone())};
                        let set=if op["sid"].is_null(){None}else{Some(sets.get(&n(op,"sid")?).ok_or_else(||anyhow!("parallel scope"))?.clone())};
                        let mut threads=Vec::new();
                        for worker in 0..workers{
                            let gate=barrier.clone();let mode=mode.clone();let root=root.clone();let set=set.clone();
                            threads.push(std::thread::spawn(move||->Result<Vec<Value>>{
                                gate.wait();let mut rows=Vec::new();
                                for index in 0..count{
                                    let value=match mode.as_str(){
                                        "ordinary"=>target::version(root.as_ref().unwrap()).map(Some),
                                        "content"=>target::content_version(root.as_ref().unwrap()),
                                        "set"=>set.as_ref().unwrap().version(),_=>bail!("fixed parallel mode")};
                                    let (semantic,error)=outcome(value)?;rows.push(json!({"worker":worker,"index":index,
                                        "tid":unsafe{libc::syscall(libc::SYS_gettid)},"semantic":semantic,"original_error":error}));
                                }Ok(rows)
                            }));
                        }
                        for thread in threads{parallel.extend(thread.join().map_err(|_|anyhow!("real thread panic"))??);}Ok(None)
                    }
                    "parallel-new"=>{
                        let workers=usize::try_from(n(op,"workers")?)?;let base=n(op,"sid")?;let root=roots.get(&usize::try_from(n(op,"root")?)?).ok_or_else(||anyhow!("parallel member"))?;
                        ensure!((2..=32).contains(&workers),"fixed concurrent constructor domain");
                        let gate=Arc::new(Barrier::new(workers));let mut threads=Vec::new();
                        for worker in 0..workers{
                            let gate=gate.clone();let member=root.clone();
                            threads.push(std::thread::spawn(move||->Result<(u64,Option<target::ContentWatchSet>,i64)>{
                                gate.wait();Ok((worker as u64,target::ContentWatchSet::new(&[member])?,unsafe{libc::syscall(libc::SYS_gettid)}))
                            }));
                        }
                        for thread in threads{
                            let(worker,set,tid)=thread.join().map_err(|_|anyhow!("real constructor thread panic"))??;
                            let sid=base+worker;ensure!(!sets.contains_key(&sid),"unique concurrent scope");
                            let constructed=set.is_some();if let Some(set)=set{sets.insert(sid,Arc::new(set));}
                            parallel.push(json!({"worker":worker,"sid":sid,"tid":tid,"constructed":constructed}));
                        }Ok(None)
                    }
                    "release-root"=>{drop(roots.remove(&usize::try_from(n(op,"root")?)?).ok_or_else(||anyhow!("owned caller Arc"))?);Ok(None)}
                    "open-root"=>{let i=usize::try_from(n(op,"root")?)?;ensure!(!roots.contains_key(&i),"fresh root slot");roots.insert(i,Arc::new(owned_environment::open_root(&paths[i],i)?));Ok(None)}
                    "limit"=>{owned_environment::set_limit(n(op,"soft")?,saved.rlim_max)?;Ok(None)}
                    "restore-limit"=>{owned_environment::set_limit(saved.rlim_cur,saved.rlim_max)?;Ok(None)}
                    _=>bail!("unlisted frozen original operation"),
                };
                mark(b"HNVORGE1",case,step)?;let(semantic,error)=outcome(value)?;
                emit(&mut output,&json!({"command":"run","case":case,"step":step,"operation":kind,"semantic":semantic,
                    "original_error":error,"state":state(&sets,&roots)?,"control":control,"parallel":parallel}))?;
            }
            "finish"=>{
                ensure!(selected==Some(case)&&sets.is_empty(),"every scoped owner explicitly dropped");roots.clear();paths.clear();
                owned_environment::set_limit(saved.rlim_cur,saved.rlim_max)?;selected=None;finished=true;
                emit(&mut output,&json!({"command":"finish","case":case,"all_sets_and_caller_roots_dropped":true,
                    "globals_live_until_process_exit":true,"state":state(&sets,&roots)?}))?;
            }
            _=>bail!("unlisted frozen control"),
        }
    }
    ensure!(selected.is_none()&&finished&&sets.is_empty()&&roots.is_empty(),"complete real process lifetime; no global reset");
    Ok(())
}

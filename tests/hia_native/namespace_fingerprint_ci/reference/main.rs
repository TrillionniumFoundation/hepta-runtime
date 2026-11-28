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
//! Persistent private original observer; never supplies a filesystem effect.
use anyhow::{anyhow,bail,ensure,Result};
use serde_json::{json,Value};
use std::io::{BufRead,Write};
use std::os::unix::fs::MetadataExt;
mod target;
mod owned_environment;
fn hex(raw:&[u8])->String{raw.iter().map(|x|format!("{x:02x}")).collect()}
fn unhex(raw:&str)->Result<Vec<u8>>{
    ensure!(raw.len()%2==0 && raw.is_ascii(),"hex extent");
    let value=(0..raw.len()).step_by(2).map(|at|u8::from_str_radix(&raw[at..at+2],16)).collect::<std::result::Result<Vec<_>,_>>()?;
    ensure!(hex(&value)==raw,"canonical complete hex");Ok(value)
}
fn number(v:&Value,k:&str)->Result<u64>{v.get(k).and_then(Value::as_u64).ok_or_else(||anyhow!("integer {k}"))}
fn emit(out:&mut impl Write,value:&Value)->Result<()>{
    serde_json::to_writer(&mut *out,value)?;out.write_all(b"\n")?;out.flush()?;Ok(())
}
fn mark(tag:&[u8;8],case:u64,generation:u64)->Result<()>{
    let mut raw=Vec::from(*tag);raw.extend(case.to_le_bytes());raw.extend(generation.to_le_bytes());
    std::io::stderr().lock().write_all(&raw)?;Ok(())
}
fn main()->Result<()>{
    let args=std::env::args().collect::<Vec<_>>();
    ensure!(args.len()==2,"fixture group argument");let group=&args[1];
    let mut input=std::io::stdin().lock();let mut output=std::io::stdout().lock();
    let layout=owned_environment::reserve()?;
    emit(&mut output,&json!({"command":"ready","role":"original","pid":std::process::id(),
        "parent_pid":unsafe{libc::getppid()},"pgid":unsafe{libc::getpgrp()},
        "uid":unsafe{libc::geteuid()},"gid":unsafe{libc::getegid()},"group":group,"layout":layout}))?;
    let mut directory=None;let mut selected=None;let mut last_generation=0_u64;let mut installed=None;
    loop{
        let mut line=String::new();if input.read_line(&mut line)?==0{break;}
        ensure!(line.ends_with('\n')&&line.len()<=16384,"complete owned command line");
        let command:Value=serde_json::from_str(&line)?;
        let kind=command.get("cmd").and_then(Value::as_str).ok_or_else(||anyhow!("command"))?;
        let case=number(&command,"case")?;
        match kind{
            "init"=>{
                ensure!(directory.is_none()&&selected.is_none(),"no replaced borrowed root");
                let path=unhex(command.get("path_hex").and_then(Value::as_str).ok_or_else(||anyhow!("path"))?)?;
                let file=owned_environment::open_root(&path)?;
                let info=file.metadata()?;
                if installed.is_none(){installed=Some(owned_environment::install(group)?);}
                selected=Some(case);last_generation=0;directory=Some(file);
                emit(&mut output,&json!({"command":"init","case":case,"root_fd":96,
                    "root_identity":{"device":info.dev(),"inode":info.ino(),"mode":info.mode()},
                    "environment":installed}))?;
            }
            "run"=>{
                let step=number(&command,"step")?;let generation=number(&command,"generation")?;
                ensure!(selected==Some(case)&&generation>last_generation,"actual original lifetime ordering");
                last_generation=generation;mark(b"NFORGB01",case,generation)?;
                let outcome=target::fixture_fingerprint(directory.as_ref().ok_or_else(||anyhow!("root"))?);
                let (semantic,error)=match outcome{
                    Ok(target::Version::Fingerprint(raw))=>(json!({"kind":0,"errno":0,"digest":hex(&raw)}),Value::Null),
                    Ok(_)=>bail!("fingerprint unexpectedly returned a watcher token"),
                    Err(error)=>{
                        let code=error.downcast_ref::<std::io::Error>().and_then(std::io::Error::raw_os_error)
                            .ok_or_else(||anyhow!("original fingerprint not an OS error"))?;
                        ensure!((0..=4095).contains(&code),"original errno domain");
                        (json!({"kind":1,"errno":code,"digest":"00".repeat(32)}),
                         json!({"display":error.to_string(),"debug":format!("{error:?}"),
                            "chain":error.chain().map(ToString::to_string).collect::<Vec<_>>(),
                            "raw_os_error":code}))
                    }
                };
                mark(b"NFORGE01",case,generation)?;
                emit(&mut output,&json!({"command":"run","case":case,"step":step,"generation":generation,
                    "semantic":semantic,"original_error":error}))?;
            }
            "dispose"=>{
                ensure!(selected==Some(case)&&directory.is_some(),"original owned disposal");
                drop(directory.take());selected=None;
                emit(&mut output,&json!({"command":"dispose","case":case,"closed_root":true}))?;
            }
            _=>bail!("unlisted fixture command"),
        }
    }
    ensure!(selected.is_none()&&directory.is_none(),"EOF after exact original disposal");Ok(())
}

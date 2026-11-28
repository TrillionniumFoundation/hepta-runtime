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
//! Observation wrapper around exact included target functions.
use anyhow::{anyhow,bail,Result};
use serde::{Deserialize,Serialize};
use std::fs::File;
use std::io::Write;
include!("constants.rs.txt");
include!("anchor_type.rs.txt");
include!("root_helpers.rs.txt");
include!("new_id.rs.txt");
include!("publish_archive_anchor.rs.txt");
fn word(raw:&[u8],at:usize)->u64{u64::from_le_bytes(raw[at..at+8].try_into().unwrap())}
fn put(raw:&mut[u8],at:usize,value:u64){raw[at..at+8].copy_from_slice(&value.to_le_bytes());}
fn category(error:&anyhow::Error)->Result<(u64,u64)>{
    if let Some(io)=error.downcast_ref::<std::io::Error>(){
        if let Some(errno)=io.raw_os_error(){return Ok((1,errno.try_into()?));}
        if io.kind()==std::io::ErrorKind::WriteZero{return Ok((4,1));}
    }
    if error.to_string()=="request identity entropy unavailable"{return Ok((2,1));}
    bail!("unclassified actual target error: {error:#}")
}
pub struct State{root:File}
impl State{
    pub fn new(path:&std::path::Path)->Result<Self>{Ok(Self{root:File::open(path)?})}
    pub fn run(&mut self,frame:&[u8])->Result<Vec<u8>>{
        if frame.len()!=128 || &frame[..8]!=b"HAPURQ01" || word(frame,8)!=1 ||
           word(frame,16)==0 || word(frame,24)!=1 || frame[64..].iter().any(|b|*b!=0){bail!("fixture frame");}
        let anchor=ArchiveAnchor{root_device:word(frame,32),root_inode:word(frame,40),
                                 archive_device:word(frame,48),archive_inode:word(frame,56)};
        let actual=publish_archive_anchor(&self.root,&anchor);
        let mut out=vec![0_u8;64];out[..8].copy_from_slice(b"HAPUOR01");put(&mut out,16,1);
        if let Err(error)=actual{
            eprintln!("OBSERVED_ORIGINAL_ERROR {}",serde_json::json!({
                "generation":word(frame,16),"display":error.to_string(),"debug":format!("{error:#?}"),
                "chain":error.chain().map(ToString::to_string).collect::<Vec<_>>()
            }));
            let (family,code)=category(&error)?;put(&mut out,8,1);put(&mut out,24,family);put(&mut out,32,code);
        }
        Ok(out)
    }
}

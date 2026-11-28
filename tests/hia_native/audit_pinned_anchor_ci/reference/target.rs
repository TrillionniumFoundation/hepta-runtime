// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
//! Observation only: policy/type/function bodies are included without edits.
use anyhow::{anyhow,bail,Result};
use serde::{Deserialize,Serialize};
use std::fs::File;
use std::io::Read;
use std::os::{fd::AsRawFd,unix::fs::MetadataExt};
include!("constants.rs.txt");
include!("anchor_type.rs.txt");
include!("root_helpers.rs.txt");
include!("named_stat.rs.txt");
include!("pinned_anchor.rs.txt");
fn word(raw:&[u8],at:usize)->u64 {u64::from_le_bytes(raw[at..at+8].try_into().unwrap())}
fn put(raw:&mut[u8],at:usize,value:u64){raw[at..at+8].copy_from_slice(&value.to_le_bytes());}
fn project(record:&ArchiveAnchor)->Vec<u8>{
    let mut out=vec![0_u8;128];out[..8].copy_from_slice(b"HAJPR001");put(&mut out,8,2);
    for (at,value) in [(64,record.root_device),(72,record.root_inode),(80,record.archive_device),(88,record.archive_inode)] {put(&mut out,at,value);}
    out
}
fn category(error:&anyhow::Error)->Result<(u64,u64)>{
    if let Some(io)=error.downcast_ref::<std::io::Error>(){
        if let Some(errno)=io.raw_os_error(){return Ok((1,errno.try_into()?));}
        if io.kind()==std::io::ErrorKind::UnexpectedEof{return Ok((4,0));}
    }
    if error.downcast_ref::<serde_json::Error>().is_some(){return Ok((3,0));}
    let code=match error.to_string().as_str(){
        "private request archive legacy anchor refused"=>1,
        "request archive legacy anchor disappeared"=>2,
        "request archive legacy anchor size refused"=>3,
        "request archive legacy anchor binding changed"=>4,
        "request archive legacy anchor changed while reading"=>5,
        "request archive legacy anchor bytes changed"=>6,
        _=>bail!("unclassified actual target error: {error:#}"),
    };
    Ok((2,code))
}
pub struct State {root:File,anchor:Option<PinnedAnchor>}
impl State {
    pub fn new(path:&std::path::Path)->Result<Self>{Ok(Self{root:File::open(path)?,anchor:None})}
    pub fn run(&mut self,frame:&[u8])->Result<Vec<u8>>{
        if frame.len()!=128 || &frame[..8]!=b"HAPNRQ01" || word(frame,16)==0 || word(frame,24)!=1 ||
            frame[32..].iter().any(|b|*b!=0){bail!("fixture input");}
        let op=word(frame,8);
        let actual:Result<Option<Vec<u8>>>=match op {
            1=>{
                if self.anchor.is_some(){bail!("fixture already owns anchor");}
                PinnedAnchor::open(&self.root).map(|value|{
                    let result=project(value.record());self.anchor=Some(value);Some(result)
                })
            },
            2=>self.anchor.as_ref().ok_or_else(||anyhow!("fixture missing retained anchor"))?.fence(&self.root).map(|_|None),
            3=>{
                if self.anchor.is_none(){bail!("fixture drop without anchor");}
                drop(self.anchor.take());Ok(None)
            },
            _=>bail!("fixture operation"),
        };
        let mut out=vec![0_u8;64];out[..8].copy_from_slice(b"HAPNOR01");put(&mut out,16,op);
        match actual {
            Ok(Some(payload))=>{put(&mut out,40,payload.len() as u64);out.extend_from_slice(&payload);},
            Ok(None)=>{},
            Err(error)=>{
                eprintln!("OBSERVED_ORIGINAL_ERROR {}",serde_json::json!({
                    "generation":word(frame,16),"display":error.to_string(),"debug":format!("{error:#?}"),
                    "chain":error.chain().map(ToString::to_string).collect::<Vec<_>>()
                }));
                let (family,code)=category(&error)?;put(&mut out,8,1);put(&mut out,24,family);put(&mut out,32,code);
            }
        }
        Ok(out)
    }
}

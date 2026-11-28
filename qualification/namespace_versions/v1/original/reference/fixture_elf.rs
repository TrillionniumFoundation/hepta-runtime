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
//! Test-only actual local static custody. Never replaces original namespace code.
use anyhow::{anyhow,ensure,Result};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::sync::OnceLock;
unsafe extern "C" { static __ehdr_start:u8; }
struct Symbols { rows:Vec<(&'static str,usize,usize,String,u64)>, report:Value }
static SYMBOLS:OnceLock<Symbols>=OnceLock::new();
fn u16at(b:&[u8],at:usize)->Result<u16>{Ok(u16::from_le_bytes(b.get(at..at+2).ok_or_else(||anyhow!("ELF u16"))?.try_into()?))}
fn u32at(b:&[u8],at:usize)->Result<u32>{Ok(u32::from_le_bytes(b.get(at..at+4).ok_or_else(||anyhow!("ELF u32"))?.try_into()?))}
fn u64at(b:&[u8],at:usize)->Result<u64>{Ok(u64::from_le_bytes(b.get(at..at+8).ok_or_else(||anyhow!("ELF u64"))?.try_into()?))}
fn whole(b:&[u8],at:u64,n:u64)->Result<&[u8]>{
    let a=usize::try_from(at)?;let n=usize::try_from(n)?;
    b.get(a..a.checked_add(n).ok_or_else(||anyhow!("ELF range overflow"))?).ok_or_else(||anyhow!("complete ELF range"))
}
fn cstring(table:&[u8],at:usize)->Result<&str>{
    let tail=table.get(at..).ok_or_else(||anyhow!("ELF name offset"))?;
    let n=tail.iter().position(|x|*x==0).ok_or_else(||anyhow!("ELF terminated name"))?;
    Ok(std::str::from_utf8(&tail[..n])?)
}
fn load()->Result<Symbols>{
    let file=std::env::current_exe()?;let raw=std::fs::read(&file)?;
    ensure!(raw.len()>=64&&&raw[..7]==b"\x7fELF\x02\x01\x01","actual complete ELF64 little-endian");
    ensure!([2,3].contains(&u16at(&raw,16)?)&&u16at(&raw,18)?==62,"actual x86-64 executable");
    let phoff=usize::try_from(u64at(&raw,32)?)?;let phsize=usize::from(u16at(&raw,54)?);let phnum=usize::from(u16at(&raw,56)?);
    ensure!(phsize==56&&phnum>0,"actual program headers");
    let mut zero_segment=None;
    for i in 0..phnum{
        let at=phoff.checked_add(i.checked_mul(phsize).ok_or_else(||anyhow!("program multiplication"))?).ok_or_else(||anyhow!("program overflow"))?;
        if u32at(&raw,at)?==1&&u64at(&raw,at+8)?==0 {
            ensure!(zero_segment.is_none(),"unique actual ELF header load segment");zero_segment=Some(u64at(&raw,at+16)?);
        }
    }
    let header=unsafe{std::ptr::addr_of!(__ehdr_start)as usize};
    let bias=header.checked_sub(usize::try_from(zero_segment.ok_or_else(||anyhow!("ELF header load segment"))?)?).ok_or_else(||anyhow!("load bias"))?;
    ensure!(unsafe{std::slice::from_raw_parts(header as*const u8,64)}==&raw[..64],"actual in-memory ELF header equals retained executable");
    let shoff=usize::try_from(u64at(&raw,40)?)?;let shsize=usize::from(u16at(&raw,58)?);let shnum=usize::from(u16at(&raw,60)?);
    ensure!(shsize==64&&shnum>0,"entire actual section table");
    let mut rows=Vec::new();
    for section in 0..shnum{
        let at=shoff+section*shsize;if u32at(&raw,at+4)?!=2{continue;}
        let size=u64at(&raw,at+32)?;let entsize=u64at(&raw,at+56)?;
        ensure!(entsize==24&&size%24==0,"complete local symbol table");
        let symbols=whole(&raw,u64at(&raw,at+24)?,size)?;
        let strings_index=usize::try_from(u32at(&raw,at+40)?)?;ensure!(strings_index<shnum,"actual symbol string table");
        let sa=shoff+strings_index*shsize;ensure!(u32at(&raw,sa+4)?==3,"symbol names are actual string table");
        let strings=whole(&raw,u64at(&raw,sa+24)?,u64at(&raw,sa+32)?)?;
        for symbol in symbols.chunks_exact(24){
            if symbol[4]&15!=1||u16at(symbol,6)?==0{continue;}
            let name=cstring(strings,usize::try_from(u32at(symbol,0)?)?)?;
            let tag=if name.contains("watched_version")&&name.contains("WATCHER"){Some("ordinary")}
                else if name.contains("content_version")&&name.contains("CONTENT"){Some("content")}
                else if name.contains("ContentWatchSet")&&name.contains("new")&&name.contains("NEXT"){Some("next")}
                else{None};
            if let Some(tag)=tag{
                let value=u64at(symbol,8)?;let bytes=usize::try_from(u64at(symbol,16)?)?;
                ensure!(bytes>0&&!rows.iter().any(|r:&(&str,usize,usize,String,u64)|r.0==tag),"unique actual target local static");
                let address=bias.checked_add(usize::try_from(value)?).ok_or_else(||anyhow!("actual static address"))?;
                rows.push((tag,address,bytes,name.to_owned(),value));
            }
        }
    }
    rows.sort_by_key(|r|r.0);ensure!(rows.len()==3,"all three actual original statics");
    let report=json!({"executable":file,"bytes":raw.len(),"sha256":format!("{:x}",Sha256::digest(&raw)),
        "elf_header_address":header,"load_bias":bias,"symbols":rows.iter().map(|r|json!({
            "kind":r.0,"address":r.1,"bytes":r.2,"name":r.3,"elf_value":r.4})).collect::<Vec<_>>()});
    Ok(Symbols{rows,report})
}
pub fn initialize()->Result<Value>{
    let loaded=load()?;ensure!(SYMBOLS.set(loaded).is_ok(),"actual static custody initialized once");
    Ok(SYMBOLS.get().unwrap().report.clone())
}
pub fn address(kind:&str,bytes:usize,alignment:usize)->usize{
    let rows=&SYMBOLS.get().expect("bound full actual ELF").rows;
    let r=rows.iter().find(|r|r.0==kind).expect("exact actual target static");
    assert_eq!(r.2,bytes,"actual Rust type size");assert_eq!(r.1%alignment,0,"actual Rust type alignment");r.1
}

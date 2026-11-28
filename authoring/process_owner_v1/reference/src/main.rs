// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test-owned observer of exact original process typed declarations.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
include!("original.rs");

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
fn main() {
    let mut output=io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let row:Value=serde_json::from_str(&line.unwrap()).unwrap();
        let raw=row["raw_json"].as_str().unwrap();
        let kind=row["kind"].as_u64().unwrap();
        let result=match serde_json::from_str::<Map<String,Value>>(raw) {
            Err(e)=>json!({"value_admitted":false,"value_error":e.to_string()}),
            Ok(map)=>{
                let value=Value::Object(map);
                let canonical=serde_json::to_string(&value).unwrap();
                let typed=match kind {
                    1=>match value.get("command") {
                        None=>Err("Missing required 'command' parameter".into()),
                        Some(v)=>match v.as_str() {
                            Some(s)=>Ok(json!({"command":s})),
                            None=>Err("Command parameter must be a string".into())
                        }
                    },
                    2 => project::<ShellStartParams>(value.clone()),
                    3 => project::<ProcessStartParams>(value.clone()),
                    4 => project::<ProcessRefParams>(value.clone()),
                    5 => project::<ProcessReadParams>(value.clone()),
                    6 => project::<ProcessWaitParams>(value.clone()),
                    7 => project::<ProcessCancelParams>(value.clone()),
                    8 => project::<ProcessListParams>(value.clone()),
                    9 => project::<ProcessListPageParams>(value.clone()),
                    _=>panic!("private kind")
                };
                match typed {
                    Ok(params)=>json!({"value_admitted":true,"canonical":canonical,"ok":true,
                        "normalized":params,"frame_hex":hex(&frame(kind,&params,&value))}),
                    Err(e)=>json!({"value_admitted":true,"canonical":canonical,"ok":false,
                        "error":e,"frame_hex":hex(&error_frame(kind,&e))})
                }
            }
        };
        serde_json::to_writer(&mut output,&json!({"case_id":row["case_id"],"kind":kind,"name":row["name"],"result":result})).unwrap();
        output.write_all(b"\n").unwrap();
    }
    output.flush().unwrap();
}

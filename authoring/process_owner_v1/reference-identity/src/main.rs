// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test-owned observer of exact original process typed declarations.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest,Sha256};
use anyhow::Result;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
include!("original.rs");
include!("identity.rs");

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
        let map:Map<String,Value>=serde_json::from_str(raw).unwrap();
        let value=Value::Object(map);
        let actual:ProcessStartParams=serde_json::from_value(value.clone()).unwrap();
        let normalized=serde_json::to_value(&actual).unwrap();
        let typed=frame(3,&normalized,&value);
        let canonical=serde_json::to_vec(&request_binding(&actual)).unwrap();
        let digest=request_digest(&actual).unwrap();
        let legacy=fingerprint(&digest);
        let mut expected=vec![0u8;64];
        expected[..8].copy_from_slice(b"HPRIDR01");
        word(&mut expected,16,canonical.len() as u64);
        word(&mut expected,24,64);word(&mut expected,32,legacy);
        expected.extend_from_slice(digest.as_bytes());expected.extend_from_slice(&canonical);
        let mut request=vec![0u8;48];
        request[..8].copy_from_slice(b"HPRIDQ01");word(&mut request,8,1);
        word(&mut request,16,typed.len() as u64);request.extend_from_slice(&typed);
        serde_json::to_writer(&mut output,&json!({
            "case_id":row["case_id"],"name":row["name"],"canonical":String::from_utf8(canonical).unwrap(),
            "digest":digest,"fingerprint":legacy,"typed_hex":hex(&typed),
            "request_hex":hex(&request),"expected_hex":hex(&expected),"expected_code":64
        })).unwrap();output.write_all(b"\n").unwrap();
    }
    output.flush().unwrap();
}

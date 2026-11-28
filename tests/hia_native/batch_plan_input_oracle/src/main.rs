// Test-owned binary transport. The original typed deserializer and complete
// EditableContent implementation are included unchanged and verified at build.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, BufRead, Write};
include!("original.rs");
mod editable_original {
    include!("editable_original.rs");
    pub fn normalize(raw: &str) -> String { EditableContent::from_raw(raw).normalized() }
}

fn word(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }
fn header(magic: &[u8;8], words: &[u64]) -> Vec<u8> {
    let mut out=magic.to_vec();for value in words { word(&mut out,*value); }out
}
fn leb(out: &mut Vec<u8>, mut value: usize) {
    while value>=128 { out.push((value as u8 & 127)|128);value>>=7; }out.push(value as u8);
}
fn endpoint(value: &Value) -> Vec<u8> {
    if value.is_null() { return vec![]; }
    let (kind,scalar,payload)=match value {
        Value::Number(number)=>match number.as_i64() {
            Some(signed)=>(0,signed as u64,vec![]),None=>(1,0,vec![]) },
        Value::String(text)=>(2,0,text.as_bytes().to_vec()),
        _=>(3,0,serde_json::to_vec(value).unwrap()),
    };
    let mut out=header(b"HIAEP001",&[kind,payload.len() as u64,scalar]);out.extend(payload);out
}
fn bridge(params: BatchEditParams, original: &str, mode: u64) -> Vec<u8> {
    let normalized=if mode==1 { editable_original::normalize(original) } else { String::new() };
    let lines:Vec<&str>=normalized.lines().collect();let mut line_bytes=vec![];
    for line in &lines { leb(&mut line_bytes,line.len());line_bytes.extend_from_slice(line.as_bytes()); }
    let mut operations=vec![];
    for operation in &params.operations {
        let name=match operation.operation { BatchEditOperationType::Insert=>"insert",BatchEditOperationType::Replace=>"replace" };
        let start=endpoint(&operation.start);let end=operation.end.as_ref().map(endpoint).unwrap_or_default();
        for value in [1,1,u64::from(!start.is_empty()),u64::from(!end.is_empty()),1,
                      name.len() as u64,start.len() as u64,end.len() as u64,operation.content.len() as u64] { word(&mut operations,value); }
        operations.extend_from_slice(name.as_bytes());operations.extend(start);operations.extend(end);operations.extend_from_slice(operation.content.as_bytes());
    }
    let mut packet=header(b"HBPLAN01",&[mode,1,lines.len() as u64,params.operations.len() as u64,
        params.path.len() as u64,line_bytes.len() as u64,operations.len() as u64,0,0]);
    packet.extend_from_slice(params.path.as_bytes());packet.extend(line_bytes);packet.extend(operations);
    let mut out=header(b"HBPIR002",&[0,packet.len() as u64,lines.len() as u64,params.operations.len() as u64,0,0,0]);out.extend(packet);out
}
fn main() {
    let input=io::stdin().lock();let mut output=io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let row:Value=serde_json::from_str(&line.unwrap()).unwrap();
        let cid=row["case_id"].as_u64().unwrap();let mode=row["mode"].as_u64().unwrap();assert!(mode<=1);
        let value:Value=serde_json::from_str(row["raw_json"].as_str().unwrap()).unwrap();
        let (kind,body)=match serde_json::from_value::<BatchEditParams>(value) {
            Ok(params)=>(0,bridge(params,row["original_raw"].as_str().unwrap(),mode)),
            Err(error)=>(1,error.to_string().into_bytes()),
        };
        for value in [cid,mode,kind,body.len() as u64] { output.write_all(&value.to_le_bytes()).unwrap(); }
        output.write_all(&body).unwrap();
    }
    output.flush().unwrap();
}

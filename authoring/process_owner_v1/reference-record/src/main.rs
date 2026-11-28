use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
include!("original.rs");
fn hex(raw: &[u8]) -> String { raw.iter().map(|x|format!("{x:02x}")).collect() }
fn unhex(text: &str) -> Result<Vec<u8>,String> {
 if text.len()%2 != 0 { return Err("odd hex length".into()); }
 text.as_bytes().chunks_exact(2).map(|a| {
  let x=(a[0] as char).to_digit(16).ok_or("bad hex")?;
  let y=(a[1] as char).to_digit(16).ok_or("bad hex")?;
  Ok((x*16+y) as u8)
 }).collect()
}
fn main() {
 let input=io::stdin(); let mut output=io::BufWriter::new(io::stdout().lock());
 for line in input.lock().lines() {
  let line=line.expect("read");let request:serde_json::Value=serde_json::from_str(&line).expect("request");
  let raw=unhex(request["raw_hex"].as_str().expect("raw_hex")).expect("hex");
  let result=match serde_json::from_slice::<JobRecord>(&raw) {
   Ok(value)=>serde_json::json!({"accepted":true,"compact_hex":hex(&serde_json::to_vec(&value).expect("serialize compact")),"pretty_hex":hex(&serde_json::to_vec_pretty(&value).expect("serialize pretty"))}),
   Err(error)=>serde_json::json!({"accepted":false,"error":error.to_string()})
  };
  let row=serde_json::json!({"case_id":request["case_id"],"name":request["name"],"result":result});
  serde_json::to_writer(&mut output,&row).expect("write");output.write_all(b"\n").expect("newline");
 }
 output.flush().expect("flush");
}

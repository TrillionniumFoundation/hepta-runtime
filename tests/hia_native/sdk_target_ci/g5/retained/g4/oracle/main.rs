//! Normal typed response and common cache-exit observations from exact RMCP.
#![allow(deprecated)]
mod typed_reference;
mod g2_reference;
use anyhow::{Context,ensure};
use rmcp::model::*;
use serde_json::{json,Value};
use std::io::{BufRead,Write};
fn classify(result:&ServerResult)->(&'static str,u64){
 match result {
  ServerResult::CallToolResult(_)=>("CallToolResult",1),ServerResult::ReadResourceResult(_)=>("ReadResourceResult",2),
  ServerResult::CustomResult(_)=>("CustomResult",3),ServerResult::ListToolsResult(_)=>("ListToolsResult",4),
  ServerResult::ListPromptsResult(_)=>("ListPromptsResult",5),ServerResult::ListResourcesResult(_)=>("ListResourcesResult",6),
  ServerResult::ListResourceTemplatesResult(_)=>("ListResourceTemplatesResult",7),ServerResult::ListSkillsResult(_)=>("ListSkillsResult",8),
  ServerResult::GetSkillResult(_)=>("GetSkillResult",9),ServerResult::EmptyResult(_)=>("EmptyResult",10),
  ServerResult::TaskAckResult(_)=>("TaskAckResult",11),_ =>("OutsideNormalProfile",99),
 }
}
fn observe(case:&Value)->anyhow::Result<Value>{
 let raw=case["wire"].as_str().context("wire")?;
 let input:Value=serde_json::from_str(raw)?;
 let mut result=match case["type"].as_str().unwrap_or("auto") {
  "auto"=>serde_json::from_str::<ServerResult>(raw)?,
  "call"=>ServerResult::CallToolResult(serde_json::from_str(raw)?),
  "read"=>ServerResult::ReadResourceResult(serde_json::from_str(raw)?),
  "tools"=>ServerResult::ListToolsResult(serde_json::from_str(raw)?),
  "prompts"=>ServerResult::ListPromptsResult(serde_json::from_str(raw)?),
  "resources"=>ServerResult::ListResourcesResult(serde_json::from_str(raw)?),
  "templates"=>ServerResult::ListResourceTemplatesResult(serde_json::from_str(raw)?),
  "skills"=>ServerResult::ListSkillsResult(serde_json::from_str(raw)?),
  _=>anyhow::bail!("ordinary type"),
 };
 let before=serde_json::to_string(&result)?;
 let policy=case["policy"].as_u64().unwrap_or(0);
 match policy {0=>{},1=>result.strip_result_type_for_legacy_peer(),2=>result.fill_missing_cache_hints(),_=>anyhow::bail!("policy")};
 let (variant,kind)=classify(&result);ensure!(kind<99,"ordinary retained response type");
 let mut flags=0;
 if let ServerResult::CallToolResult(call)=&result {
  flags|=u64::from(call.structured_content.is_some());flags|=u64::from(call.meta.is_some())<<1;
  flags|=u64::from(input.get("content").is_none_or(Value::is_null))<<2;
 }else if let ServerResult::ReadResourceResult(read)=&result {flags|=u64::from(read.meta.is_some())<<1;}
 Ok(json!({"mode":"response","label":case["label"],"canonical_input":serde_json::to_string(&input)?,"before_wire":before,
  "wire":serde_json::to_string(&result)?,"projection":serde_json::to_value(&result)?,"kind":kind,"variant":variant,"flags":flags,"policy":policy,
  "direct_call_tool_accepted":serde_json::from_str::<CallToolResult>(raw).is_ok()}))
}
#[tokio::main(flavor="current_thread")]
async fn main()->anyhow::Result<()> {
 let stdin=std::io::stdin();let mut stdout=std::io::BufWriter::new(std::io::stdout().lock());
 for line in stdin.lock().lines(){let case:Value=serde_json::from_str(&line?)?;
  let mut row=match case["mode"].as_str().unwrap_or("response") {
   "response"=>observe(&case)?,"typed-emitter"=>typed_reference::observe(case.clone()),"session"=>g2_reference::observe(case.clone()).await?,_=>anyhow::bail!("mode"),
  };row["mode"]=case["mode"].clone();serde_json::to_writer(&mut stdout,&row)?;stdout.write_all(b"\n")?;stdout.flush()?;
 }Ok(())
}

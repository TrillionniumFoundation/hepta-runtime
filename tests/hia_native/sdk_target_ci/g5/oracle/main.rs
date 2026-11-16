//! Ordinary typed catalog/request observations from the exact target RMCP.
#![allow(deprecated)]
use anyhow::{Context, bail};
use rmcp::model::*;
use serde_json::{Value, json};
use std::io::{BufRead, Write};

fn optional_wire<T: serde::Serialize>(value: &Option<T>) -> anyhow::Result<Option<String>> {
    value.as_ref().map(serde_json::to_string).transpose().map_err(Into::into)
}

fn call_projection(p: &CallToolRequestParams, meta: Option<&RequestMetaObject>, explicit_meta: bool) -> anyhow::Result<Value> {
    let flags = u64::from(explicit_meta) | (u64::from(p.arguments.is_some()) << 1)
        | (u64::from(p.input_responses.is_some()) << 2) | (u64::from(p.request_state.is_some()) << 3);
    Ok(json!({"kind":1,"flags":flags,"typed_params_wire":serde_json::to_string(p)?,
        "selector":p.name,"arguments_wire":optional_wire(&p.arguments)?,
        "meta_wire":meta.map(serde_json::to_string).transpose()?,
        "input_responses_wire":optional_wire(&p.input_responses)?,"request_state":p.request_state,
        "typed_params_meta_is_none":p.meta.is_none()}))
}

fn read_projection(p: &ReadResourceRequestParams, meta: Option<&RequestMetaObject>, explicit_meta: bool) -> anyhow::Result<Value> {
    let flags = u64::from(explicit_meta) | (u64::from(p.input_responses.is_some()) << 2)
        | (u64::from(p.request_state.is_some()) << 3);
    Ok(json!({"kind":2,"flags":flags,"typed_params_wire":serde_json::to_string(p)?,
        "selector":p.uri,"arguments_wire":Value::Null,
        "meta_wire":meta.map(serde_json::to_string).transpose()?,
        "input_responses_wire":optional_wire(&p.input_responses)?,"request_state":p.request_state,
        "typed_params_meta_is_none":p.meta.is_none()}))
}

fn observe(case: &Value) -> anyhow::Result<Value> {
    let wire = case["wire"].as_str().context("wire")?;
    let input: Value = serde_json::from_str(wire)?;
    let canonical = serde_json::to_string(&input)?;
    let mode = case["mode"].as_str().context("mode")?;
    let mut answer = match mode {
        "catalog" => {
            let (kind, mut value) = match case["type"].as_str().context("catalog type")? {
                "tools" => (4, ServerResult::ListToolsResult(serde_json::from_str::<ListToolsResult>(wire)?)),
                "prompts" => (5, ServerResult::ListPromptsResult(serde_json::from_str::<ListPromptsResult>(wire)?)),
                "resources" => (6, ServerResult::ListResourcesResult(serde_json::from_str::<ListResourcesResult>(wire)?)),
                "templates" => (7, ServerResult::ListResourceTemplatesResult(serde_json::from_str::<ListResourceTemplatesResult>(wire)?)),
                "skills" => (8, ServerResult::ListSkillsResult(serde_json::from_str::<ListSkillsResult>(wire)?)),
                other => bail!("unexpected normal catalog type {other}"),
            };
            let before = serde_json::to_string(&value)?;
            match case["policy"].as_u64().context("policy")? {
                0 => {},
                1 => value.strip_result_type_for_legacy_peer(),
                2 => value.fill_missing_cache_hints(),
                other => bail!("unexpected policy {other}"),
            }
            json!({"kind":kind,"canonical_input":canonical,"typed_wire_before_policy":before,
                "wire":serde_json::to_string(&value)?,"projection":serde_json::to_value(&value)?})
        },
        "params" => {
            let mut value = match case["type"].as_str().context("params type")? {
                "call" => {let p: CallToolRequestParams=serde_json::from_str(wire)?;call_projection(&p,p.meta.as_ref(),p.meta.is_some())?},
                "read" => {let p: ReadResourceRequestParams=serde_json::from_str(wire)?;read_projection(&p,p.meta.as_ref(),p.meta.is_some())?},
                other => bail!("unexpected params type {other}"),
            };
            value["canonical_input"]=json!(canonical);
            value["projection_mode"]=json!(0);
            value
        },
        "request" => {
            let message: ClientJsonRpcMessage=serde_json::from_str(wire)?;
            let request = match message {JsonRpcMessage::Request(r)=>r,_=>bail!("normal request expected")};
            let metadata=request.request.get_meta();
            let explicit_meta=input.get("params").and_then(|p|p.get("_meta")).is_some_and(Value::is_object);
            let mut value=match &request.request {
                ClientRequest::CallToolRequest(r)=>{anyhow::ensure!(r.params.meta.is_none());call_projection(&r.params,Some(metadata),explicit_meta)?},
                ClientRequest::ReadResourceRequest(r)=>{anyhow::ensure!(r.params.meta.is_none());read_projection(&r.params,Some(metadata),explicit_meta)?},
                _=>bail!("normal CallTool/ReadResource request expected"),
            };
            value["id"]=serde_json::to_value(&request.id)?;
            value["id_wire"]=json!(serde_json::to_string(&request.id)?);
            value["message_wire"]=json!(serde_json::to_string(&request.request)?);
            value["projection_mode"]=json!(1);
            value
        },
        other => bail!("unexpected case mode {other}"),
    };
    answer["label"]=case["label"].clone();
    answer["mode"]=json!(mode);
    Ok(answer)
}

fn main() -> anyhow::Result<()> {
    let input=std::io::stdin();let mut output=std::io::stdout().lock();
    for line in input.lock().lines() {
        let case:Value=serde_json::from_str(&line?)?;
        let observed=observe(&case).with_context(||format!("case {}",case["label"]))?;
        serde_json::to_writer(&mut output,&observed)?;output.write_all(b"\n")?;output.flush()?;
    }
    Ok(())
}

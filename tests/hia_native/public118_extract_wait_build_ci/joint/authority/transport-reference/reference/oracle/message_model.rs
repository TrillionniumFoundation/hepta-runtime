//! Direct ordinary message observations from the exact target RMCP model.
//! No transport, external service, request execution, or application dispatch.
#![allow(deprecated)]
use anyhow::Context;
use rmcp::model::{ClientJsonRpcMessage,ClientRequest,ClientNotification,GetMeta,ProtocolVersion};
use serde_json::{json,Value};
use std::io::{BufRead,Write};

fn request_variant(value:&ClientRequest)->&'static str {
    match value {
        ClientRequest::PingRequest(_)=>"PingRequest",
        ClientRequest::InitializeRequest(_)=>"InitializeRequest",
        ClientRequest::DiscoverRequest(_)=>"DiscoverRequest",
        ClientRequest::CompleteRequest(_)=>"CompleteRequest",
        ClientRequest::SetLevelRequest(_)=>"SetLevelRequest",
        ClientRequest::GetPromptRequest(_)=>"GetPromptRequest",
        ClientRequest::ListPromptsRequest(_)=>"ListPromptsRequest",
        ClientRequest::ListResourcesRequest(_)=>"ListResourcesRequest",
        ClientRequest::ListResourceTemplatesRequest(_)=>"ListResourceTemplatesRequest",
        ClientRequest::ReadResourceRequest(_)=>"ReadResourceRequest",
        ClientRequest::SubscriptionsListenRequest(_)=>"SubscriptionsListenRequest",
        ClientRequest::SubscribeRequest(_)=>"SubscribeRequest",
        ClientRequest::UnsubscribeRequest(_)=>"UnsubscribeRequest",
        ClientRequest::CallToolRequest(_)=>"CallToolRequest",
        ClientRequest::ListToolsRequest(_)=>"ListToolsRequest",
        ClientRequest::GetTaskRequest(_)=>"GetTaskRequest",
        ClientRequest::UpdateTaskRequest(_)=>"UpdateTaskRequest",
        ClientRequest::CancelTaskRequest(_)=>"CancelTaskRequest",
        ClientRequest::ListSkillsRequest(_)=>"ListSkillsRequest",
        ClientRequest::GetSkillRequest(_)=>"GetSkillRequest",
        ClientRequest::ReadResourceDirectoryRequest(_)=>"ReadResourceDirectoryRequest",
        ClientRequest::CustomRequest(_)=>"CustomRequest",
        _=>"UnmappedTargetRequest",
    }
}
fn notification_variant(value:&ClientNotification)->&'static str {
    match value {
        ClientNotification::CancelledNotification(_)=>"CancelledNotification",
        ClientNotification::ProgressNotification(_)=>"ProgressNotification",
        ClientNotification::InitializedNotification(_)=>"InitializedNotification",
        ClientNotification::RootsListChangedNotification(_)=>"RootsListChangedNotification",
        ClientNotification::CustomNotification(_)=>"CustomNotification",
        _=>"UnmappedTargetNotification",
    }
}
pub fn observe(case:Value)->anyhow::Result<Value>{
    let wire=case["wire"].as_str().context("wire")?;
    let decoded:ClientJsonRpcMessage=serde_json::from_str(wire)?;
    let roundtrip=serde_json::to_string(&decoded)?;
    let mut row=match &decoded {
        ClientJsonRpcMessage::Request(r)=>json!({"kind":"request","variant":request_variant(&r.request),
            "id":r.id,"id_wire":serde_json::to_string(&r.id)?,"message":r.request,
            "message_wire":serde_json::to_string(&r.request)?,"meta":r.request.get_meta(),
            "meta_wire":serde_json::to_string(r.request.get_meta())?,
            "missing":r.request.get_meta().missing_required_keys(&ProtocolVersion::V_2026_07_28)}),
        ClientJsonRpcMessage::Notification(n)=>json!({"kind":"notification","variant":notification_variant(&n.notification),
            "message":n.notification,"message_wire":serde_json::to_string(&n.notification)?,
            "meta":n.notification.get_meta(),"meta_wire":serde_json::to_string(n.notification.get_meta())?}),
        ClientJsonRpcMessage::Response(r)=>json!({"kind":"response","id":r.id,
            "id_wire":serde_json::to_string(&r.id)?,"result":r.result}),
        ClientJsonRpcMessage::Error(e)=>json!({"kind":"error","id":e.id,
            "id_wire":e.id.as_ref().map(serde_json::to_string).transpose()?,
            "error":e.error,"error_wire":serde_json::to_string(&e.error)?}),
    };
    row["label"]=case["label"].clone();
    row["accepted"]=json!(true);
    row["roundtrip_wire"]=json!(roundtrip);
    Ok(row)
}
fn main()->anyhow::Result<()> {
    let input=std::io::stdin();
    let mut output=std::io::BufWriter::new(std::io::stdout().lock());
    for line in input.lock().lines(){
        let row:Value=serde_json::from_str(&line?)?;
        let observed=observe(row)?;
        serde_json::to_writer(&mut output,&observed)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}

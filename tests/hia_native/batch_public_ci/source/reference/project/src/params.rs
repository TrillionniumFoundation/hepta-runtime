// Test-owned harness; the complete original types/deserializer are included unchanged.
// The SDK method body is an observation fixture, never the filesystem batch handler.
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use rmcp::model::{CallToolRequestParams, CallToolResponse};
use rmcp::service::RequestContext;
use rmcp::handler::server::tool::{ToolCallContext, AsyncMethodAdapter};
use rmcp::handler::server::wrapper::Parameters;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
include!("original.rs");

#[derive(Clone)]
struct Probe(Arc<Mutex<Vec<Value>>>, Arc<std::sync::atomic::AtomicUsize>);
impl Probe {
    fn batch_edit(&self, context: RequestContext<RoleServer>, Parameters(params): Parameters<BatchEditParams>)
        -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<String,String>> + Send + '_>> {
        Box::pin(async move {
            let observation = json!({"normalized":serde_json::to_value(&params).unwrap(),
                                    "protocol_version":context.protocol_version(),
                                    "request_id":context.id});
            self.0.lock().unwrap().push(observation.clone());
            Ok(serde_json::to_string(&observation).unwrap())
        })
    }
}
impl ServerHandler for Probe {
    async fn call_tool(&self, request:CallToolRequestParams, context:RequestContext<RoleServer>)
        -> Result<CallToolResponse,ErrorData> {
        self.1.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
        ToolCallContext::new(self,request,context)
            .invoke::<_,AsyncMethodAdapter<(RequestContext<RoleServer>,Parameters<BatchEditParams>),Result<String,String>>>(Self::batch_edit).await
    }
}
async fn sdk(row:&Value)->Value {
    let seen=Arc::new(Mutex::new(Vec::new()));
    let outer=Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handler=Probe(seen.clone(),outer.clone());
    let (client,server)=tokio::io::duplex(65536);
    let service=tokio::spawn(async move {
        match handler.serve(server).await {
            Ok(service)=>{ let done=service.waiting().await; json!({"initialized":true,"terminated":format!("{done:?}")}) },
            Err(error)=>json!({"initialized":false,"error":error.to_string()})
        }
    });
    let(input,mut writer)=tokio::io::split(client);
    let mut reader=tokio::io::BufReader::new(input);
    let mut responses=Vec::new();
    for request in row["messages"].as_array().unwrap() {
        let mut wire=serde_json::to_vec(request).unwrap(); wire.push(b'\n');
        writer.write_all(&wire).await.unwrap();
        if request.get("id").is_none(){continue;}
        let mut line=String::new();
        let size=tokio::time::timeout(Duration::from_secs(5),reader.read_line(&mut line)).await.unwrap().unwrap();
        assert!(size>0,"SDK response absent");
        let reply:Value=serde_json::from_str(&line).unwrap();
        assert_eq!(reply["id"],request["id"]);
        responses.push(reply);
    }
    drop(reader);drop(writer);
    let terminal=tokio::time::timeout(Duration::from_secs(5),service).await.unwrap().unwrap();
    let observations=seen.lock().unwrap().clone();
    json!({"responses":responses,"handler_observations":observations,
           "outer_entries":outer.load(std::sync::atomic::Ordering::SeqCst),"service":terminal,
           "actual_parameters_extractor":true,"actual_method_adapter":true,
           "original_batch_handler_executed":false,"effects_executed":false})
}
#[tokio::main(flavor="current_thread")]
async fn main() {
    let input=io::stdin().lock();let mut output=io::BufWriter::new(io::stdout().lock());
    for line in input.lines(){
        let row:Value=serde_json::from_str(&line.unwrap()).unwrap();
        let result=if row["mode"]=="sdk" { sdk(&row).await } else {
            let value=match row.get("raw_json") {
                Some(raw)=>serde_json::from_str::<Value>(raw.as_str().unwrap()).unwrap(),
                None=>row["value"].clone(),
            };
            let canonical=serde_json::to_string(&value).unwrap();
            match serde_json::from_value::<BatchEditParams>(value) {
                Ok(params)=>json!({"ok":true,"canonical":canonical,"path":params.path,
                                  "normalized":serde_json::to_value(&params).unwrap(),
                                  "normalized_json":serde_json::to_string(&serde_json::to_value(&params).unwrap()).unwrap(),
                                  "operation_count":params.operations.len()}),
                Err(error)=>json!({"ok":false,"canonical":canonical,"error":error.to_string()})
            }
        };
        serde_json::to_writer(&mut output,&json!({"case_id":row["case_id"],"name":row["name"],"domain":row["domain"],"result":result})).unwrap();
        output.write_all(b"\n").unwrap();
    }
    output.flush().unwrap();
}

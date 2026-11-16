//! Exact target tool metadata only; this binary never invokes a tool handler.
use rmcp::{tool, RoleServer, service::RequestContext, handler::server::wrapper::Parameters};
use rmcp::model::{ListToolsResult, ServerResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
include!("original_metadata.rs");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tool = MetadataOnlyServer::text_editor_tool_attr();
    assert_eq!(tool.name.as_ref(), "text_editor");
    assert_eq!(tool.title.as_deref(), Some("Text Editor"));
    let schema = rmcp::handler::server::common::schema_for_input::<TextEditorParams>()?;
    assert_eq!(tool.input_schema, schema);
    let annotation = tool.annotations.as_ref().unwrap();
    assert_eq!(annotation.read_only_hint, Some(false));
    assert_eq!(annotation.destructive_hint, Some(true));
    assert_eq!(annotation.idempotent_hint, Some(false));
    assert_eq!(annotation.open_world_hint, Some(false));
    let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
    for line in std::io::stdin().lock().lines() {
        let case: Value = serde_json::from_str(&line?)?;
        let row = match case["mode"].as_str().ok_or("mode")? {
            "metadata" => json!({"mode":"metadata","label":case["label"],
                "tool":serde_json::to_value(&tool)?,"tool_wire":serde_json::to_string(&tool)?,
                "schema":&*schema,"actual_macro_metadata":true,"handler_executed":false}),
            "catalog" | "constructor" => {
                let raw=case["wire"].as_str().ok_or("wire")?;
                let input:Value=serde_json::from_str(raw)?;
                let typed:ListToolsResult=serde_json::from_str(raw)?;
                assert_eq!(typed.tools.len(),9);
                assert_eq!(typed.tools.last(),Some(&tool));
                let constructor = case["mode"] == "constructor";
                let typed = if constructor {
                    ListToolsResult::with_all_items(typed.tools)
                } else {
                    typed
                };
                let mut result=ServerResult::ListToolsResult(typed);
                let before=serde_json::to_string(&result)?;
                let policy=case["policy"].as_u64().ok_or("policy")?;
                match policy {0=>{},1=>result.strip_result_type_for_legacy_peer(),2=>result.fill_missing_cache_hints(),_=>return Err("policy".into())}
                json!({"mode":case["mode"],"type":"tools","label":case["label"],"kind":4,
                    "policy":policy,"canonical_input":serde_json::to_string(&input)?,
                    "typed_wire_before_policy":before,"wire":serde_json::to_string(&result)?,
                    "original_text_editor_metadata_used":true,"actual_list_constructor_executed":constructor,
                    "handler_executed":false})
            },
            _ => return Err("mode".into()),
        };
        serde_json::to_writer(&mut stdout,&row)?;stdout.write_all(b"\n")?;stdout.flush()?;
    }
    Ok(())
}

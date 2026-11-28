pub async fn execute_batch_edit(call: &McpToolCall) -> Result<String> {
	let operations_vec = match call.parameters.get("operations") {
		Some(Value::Array(ops)) => ops.clone(),
		_ => bail!("Missing or invalid 'operations' parameter for batch_edit - must be an array"),
	};

	text_editing::batch_edit_spec(call, &operations_vec).await
}

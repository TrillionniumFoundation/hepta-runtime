use serde_json::{json, Value};
use std::sync::OnceLock;
pub(super) const RESPONSE_BYTES: usize = 10 * 1024 * 1024;
#[derive(Debug, Clone)]
pub(super) struct Failure(pub Value);

pub(super) fn response_budget() -> Result<usize, Failure> {
	static BUDGET: OnceLock<Result<usize, String>> = OnceLock::new();
	BUDGET.get_or_init(|| {
		let Some(value) = std::env::var_os("REA_MCP_MAX_RESPONSE_BYTES") else { return Ok(RESPONSE_BYTES); };
		let valid = value.to_str().and_then(|text| {
			if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) { return None; }
			text.parse::<u64>().ok().filter(|number| (RESPONSE_BYTES as u64..=9_007_199_254_740_991).contains(number)).and_then(|number| usize::try_from(number).ok())
		});
		valid.ok_or_else(|| "REA_MCP_MAX_RESPONSE_BYTES must be a decimal safe integer at least 10485760 bytes, the default stdio receive-buffer size.".to_owned())
	}).clone().map_err(|reason| Failure(json!({"code":"configuration_invalid","category":"invalid_input",
		"message":format!("REA configuration is invalid: {reason}"),"retryable":false,
		"remediation":{"action":"Correct REA_MCP_MAX_RESPONSE_BYTES in the environment that starts REA (your shell or the MCP client's registration), then rerun."},
		"details":{"settings":[{"setting":"REA_MCP_MAX_RESPONSE_BYTES","constraint":reason}]}})))
}

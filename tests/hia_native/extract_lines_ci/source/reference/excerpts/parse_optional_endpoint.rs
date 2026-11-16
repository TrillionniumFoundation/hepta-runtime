fn parse_optional_endpoint(value: Option<&Value>, name: &str) -> Result<Option<Endpoint>> {
	match value {
		Some(v) if !v.is_null() => Ok(Some(
			line_hash::parse_endpoint(v).map_err(|e| anyhow!("Invalid '{name}': {e}"))?,
		)),
		_ => Ok(None),
	}
}

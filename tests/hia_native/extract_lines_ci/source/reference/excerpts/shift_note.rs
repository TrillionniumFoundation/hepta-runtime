pub(crate) fn shift_note(orig_lines: &[&str], regions: &[(usize, i64)]) -> Option<String> {
	let mut by_end = std::collections::BTreeMap::new();
	for &(end, delta) in regions {
		*by_end.entry(end).or_insert(0i64) += delta;
	}
	let mut total = 0i64;
	let mut parts = Vec::new();
	for (end, delta) in by_end {
		total += delta;
		if delta == 0 || end >= orig_lines.len() {
			continue;
		}
		let anchor = if end == 0 {
			"0".to_string()
		} else {
			line_id_at(orig_lines, end)
		};
		parts.push(format!("after {anchor} {total:+}"));
	}
	(!parts.is_empty()).then(|| format!("shift: lines {}", parts.join(", ")))
}

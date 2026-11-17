pub fn removed_marker(old: &[&str], first: usize, last: usize) -> String {
	if first == last {
		format!("-{} (1 line)", line_id_at(old, first + 1))
	} else {
		format!(
			"-{}..{} ({} lines)",
			line_id_at(old, first + 1),
			line_id_at(old, last + 1),
			last - first + 1
		)
	}
}

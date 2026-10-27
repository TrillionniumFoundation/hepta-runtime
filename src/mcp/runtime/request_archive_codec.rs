// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Compact, versioned derived rows; authoritative receipt JSON never changes.
use super::*;

const MAGIC: &[u8; 4] = b"HAR1";
const FORMAT: &str = "binary-v1";
const FORMAT_KEY: &str = "row_codec";
const FIXED: usize = 167;

pub(super) struct View<'a> {
	pub(super) identity: Id,
	pub(super) owner: Id,
	pub(super) accepted: u128,
	pub(super) elapsed: Option<u64>,
	pub(super) state: DurableState,
	pub(super) stamp: FileStamp,
	pub(super) tool: &'a str,
}
pub(super) fn encode(entry: &Entry) -> Result<Vec<u8>> {
	if !valid_tool(&entry.record.tool_name) {
		bail!("invalid archive index tool");
	}
	let mut raw = vec![0u8; FIXED + entry.record.tool_name.len()];
	raw[..4].copy_from_slice(MAGIC);
	raw[4..36].copy_from_slice(&id(&entry.record.request_id)?);
	raw[36..68].copy_from_slice(&id(&entry.record.owner)?);
	raw[68..84].copy_from_slice(&entry.record.accepted_unix_ms.to_be_bytes());
	if let Some(elapsed) = entry.record.elapsed_ms {
		raw[84] = 1;
		raw[85..93].copy_from_slice(&elapsed.to_be_bytes());
	}
	raw[93] = match entry.record.state {
		DurableState::Unknown => 0,
		DurableState::Completed => 1,
		DurableState::Failed => 2,
	};
	raw[94..166].copy_from_slice(&cold::stamp_value(entry.stamp));
	raw[166] = entry.record.tool_name.len() as u8;
	raw[FIXED..].copy_from_slice(entry.record.tool_name.as_bytes());
	Ok(raw)
}
pub(super) fn view(raw: &[u8]) -> Result<View<'_>> {
	if raw.len() < FIXED
		|| &raw[..4] != MAGIC
		|| raw[166] == 0
		|| raw[166] > 64
		|| raw.len() != FIXED + usize::from(raw[166])
	{
		bail!("invalid compact archive row");
	}
	let elapsed_word = u64::from_be_bytes(raw[85..93].try_into()?);
	let elapsed = match raw[84] {
		0 if elapsed_word == 0 => None,
		1 => Some(elapsed_word),
		_ => bail!("invalid compact archive elapsed"),
	};
	let state = match raw[93] {
		0 => DurableState::Unknown,
		1 => DurableState::Completed,
		2 => DurableState::Failed,
		_ => bail!("invalid compact archive state"),
	};
	let tool = std::str::from_utf8(&raw[FIXED..])?;
	if !valid_tool(tool) {
		bail!("invalid archive index tool");
	}
	Ok(View {
		identity: raw[4..36].try_into()?,
		owner: raw[36..68].try_into()?,
		accepted: u128::from_be_bytes(raw[68..84].try_into()?),
		elapsed,
		state,
		stamp: cold::decode_stamp(&raw[94..166])?,
		tool,
	})
}
// A recognized compact row must pass the complete parser. Corruption cannot
// become absence or fall through to the legacy JSON decoder.
pub(super) fn view_if_compact(raw: &[u8]) -> Result<Option<View<'_>>> {
	if raw.starts_with(MAGIC) {
		view(raw).map(Some)
	} else {
		Ok(None)
	}
}
fn hex(value: &Id) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut result = String::with_capacity(64);
	for byte in value {
		result.push(DIGITS[(byte >> 4) as usize] as char);
		result.push(DIGITS[(byte & 15) as usize] as char);
	}
	result
}
pub(super) fn decode(raw: &[u8]) -> Result<Entry> {
	if !raw.starts_with(MAGIC) {
		return Ok(serde_json::from_slice(raw)?);
	}
	let value = view(raw)?;
	Ok(Entry {
		record: Record {
			request_id: hex(&value.identity),
			owner: hex(&value.owner),
			tool_name: value.tool.into(),
			state: value.state,
			accepted_unix_ms: value.accepted,
			elapsed_ms: value.elapsed,
		},
		stamp: value.stamp,
	})
}
pub(super) fn mark_new(meta: &mut redb::Table<&str, &[u8]>) -> Result<()> {
	meta.insert(FORMAT_KEY, FORMAT.as_bytes())?;
	Ok(())
}
/// Preserve any preexisting row-image mismatch: apply exact old/new hash deltas,
/// never replace the independently stored expected sum with observed contents.
pub(super) fn upgrade(db: &Database, slot: &Slot, deadline: Instant) -> Result<()> {
	{
		let read = db.begin_read()?;
		if read
			.open_table(META)?
			.get(FORMAT_KEY)?
			.is_some_and(|v| v.value() == FORMAT.as_bytes())
		{
			return Ok(());
		}
	}
	let mut cursor: Option<Id> = None;
	loop {
		if Instant::now() >= deadline {
			bail!("archive index preparation deadline");
		}
		let keys = {
			let read = db.begin_read()?;
			let rows = read.open_table(ROWS)?;
			let low = cursor.as_ref().map_or(std::ops::Bound::Unbounded, |v| {
				std::ops::Bound::Excluded(v.as_slice())
			});
			let mut keys = Vec::with_capacity(BUILD_CHUNK);
			for pair in rows
				.range::<&[u8]>((low, std::ops::Bound::Unbounded))?
				.take(BUILD_CHUNK)
			{
				let (key, _) = pair?;
				keys.push(<Id>::try_from(key.value())?);
			}
			keys
		};
		if keys.is_empty() {
			break;
		}
		cursor = keys.last().copied();
		let mut write = db.begin_write()?;
		write.set_durability(Durability::None)?;
		{
			let mut rows = write.open_table(ROWS)?;
			let mut meta = write.open_table(META)?;
			let raw_sum = meta
				.get("row_image_sum")?
				.ok_or_else(|| anyhow!("legacy archive row sum missing"))?
				.value()
				.to_vec();
			let mut sum = Fingerprint::decode(&raw_sum)?;
			for key in keys {
				let raw = rows
					.get(key.as_slice())?
					.ok_or_else(|| anyhow!("archive row missing"))?
					.value()
					.to_vec();
				if raw.starts_with(MAGIC) {
					let value = view(&raw)?;
					if value.identity != key {
						bail!("archive index identity changed");
					}
					continue;
				}
				let entry = decode(&raw)?;
				if id(&entry.record.request_id)? != key {
					bail!("archive index identity changed");
				}
				let compact = encode(&entry)?;
				sum.row(&key, &raw, false)?;
				sum.row(&key, &compact, true)?;
				rows.insert(key.as_slice(), compact.as_slice())?;
			}
			meta.insert("row_image_sum", sum.encode().as_slice())?;
		}
		write.commit()?;
		fold_cache_changes(db, slot, &mut Vec::new())?;
	}
	let mut write = db.begin_write()?;
	write.set_durability(Durability::Immediate)?;
	write.set_quick_repair(true);
	mark_new(&mut write.open_table(META)?)?;
	write.commit()?;
	Ok(())
}

#[cfg(test)]
#[path = "request_archive_codec_tests.rs"]
mod tests;

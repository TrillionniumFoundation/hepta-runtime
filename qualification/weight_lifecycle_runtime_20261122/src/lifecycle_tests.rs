// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Boundary tests for admission and actual value acceptance.

use super::{evaluation, inputs};
use anyhow::Result;
use hepta_semantic_source_adapter_study::{digest, SourcePin};
use serde_json::json;
use std::path::Path;

#[test]
fn acceptance_requires_strict_gain_and_all_preservation_tasks() {
	assert!(evaluation::verdict(0.1, 0.01, &[0.0, 0.02], 0.0));
	assert!(!evaluation::verdict(0.01, 0.01, &[], 0.0));
	assert!(!evaluation::verdict(0.1, 0.01, &[-0.000001], 0.0));
	assert!(!evaluation::verdict(f64::NAN, 0.01, &[], 0.0));
	assert!(!evaluation::verdict(0.1, 0.01, &[f64::INFINITY], 0.0));
}

#[test]
fn pins_check_actual_bytes_and_length() {
	let pin = inputs::Pin {
		path: "/explicit/source".into(),
		sha256: digest(b"abc"),
		bytes: 3,
	};
	assert!(pin.verify(b"abc").is_ok());
	assert!(pin.verify(b"abd").is_err());
	assert!(pin.verify(b"abc\0").is_err());
}

#[test]
fn local_gzip_location_cannot_replace_or_choose_ambiguous_origin() -> Result<()> {
	let file = inputs::Pin {
		path: "/relocated/private/model.gz".into(),
		sha256: digest(b"gzip bytes"),
		bytes: 10,
	};
	let row = json!({"sha256":file.sha256,"bytes":file.bytes,
		"url":"https://reviewed-origin/revision/model.gz"});
	let receipt = serde_json::to_vec(&json!({"files":[row.clone()]}))?;
	let mut receipt_pin = SourcePin {
		source_id: "reviewed-repository-transfer".into(),
		sha256: digest(&receipt),
		size_bytes: receipt.len() as u64,
	};
	let original = evaluation::original_compressed_pin(&file, &receipt_pin, &receipt)?;
	assert_eq!(
		original.source_id,
		"https://reviewed-origin/revision/model.gz"
	);
	assert_ne!(original.source_id, file.path);
	assert_eq!(original.sha256, file.sha256);
	assert_eq!(original.size_bytes, file.bytes as u64);
	let mut second = row.clone();
	second["url"] = json!("https://different-origin/same-bytes.gz");
	let ambiguous = serde_json::to_vec(&json!({"files":[row,second]}))?;
	assert!(evaluation::original_compressed_pin(&file, &receipt_pin, &ambiguous).is_err());
	receipt_pin.sha256 = digest(&ambiguous);
	receipt_pin.size_bytes = ambiguous.len() as u64;
	assert!(evaluation::original_compressed_pin(&file, &receipt_pin, &ambiguous).is_err());
	let absent = serde_json::to_vec(&json!({"files":[]}))?;
	receipt_pin.sha256 = digest(&absent);
	receipt_pin.size_bytes = absent.len() as u64;
	assert!(evaluation::original_compressed_pin(&file, &receipt_pin, &absent).is_err());
	Ok(())
}

#[test]
fn paths_and_output_names_cannot_escape() {
	assert!(inputs::absolute(Path::new("/absolute/source")).is_ok());
	assert!(inputs::absolute(Path::new("/absolute/../source")).is_err());
	assert!(inputs::absolute(Path::new("relative/source")).is_err());
	assert!(inputs::result_name("result-next.json").is_ok());
	assert!(inputs::result_name("../result.json").is_err());
	assert!(inputs::result_name(".hidden.json").is_err());
}

#[test]
fn bounded_reads_refuse_symlinks_and_writes_are_create_only() -> Result<()> {
	let root = std::env::temp_dir().join(format!("hepta-lifecycle-io-test-{}", std::process::id()));
	inputs::new_dir(&root)?;
	let result = (|| -> Result<()> {
		inputs::private_dir(&root)?;
		let file = root.join("data");
		inputs::save(&file, b"abc")?;
		assert!(inputs::save(&file, b"def").is_err());
		assert_eq!(inputs::read(&file, 3)?, b"abc");
		assert!(inputs::read(&file, 2).is_err());
		std::os::unix::fs::symlink(&file, root.join("link"))?;
		assert!(inputs::read(&root.join("link"), 3).is_err());
		Ok(())
	})();
	std::fs::remove_dir_all(root)?;
	result
}

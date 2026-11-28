// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Exact target items; verified by the source extraction manifest.
use super::remote::PathSource;
use std::path::Path;

pub fn lock_key_for(path: &Path) -> String {
	if let Ok(canon) = path.canonicalize() {
		return canon.to_string_lossy().to_string();
	}
	// File may not exist yet (create) or has been removed (delete+undo).
	// Canonicalize the parent and append the file name so the key stays
	// consistent across the file's lifetime.
	if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
		if let Ok(canon_parent) = parent.canonicalize() {
			return canon_parent.join(name).to_string_lossy().to_string();
		}
	}
	path.to_string_lossy().to_string()
}


pub fn lock_key_for_source(source: &PathSource) -> String {
	match source {
		PathSource::Local(p) => lock_key_for(p),
		PathSource::Remote { .. } => source.lock_key(),
	}
}



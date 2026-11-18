// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Version {
	#[cfg(target_os = "linux")]
	Watch(u64, u64),
	Fingerprint([u8; 32]),
}

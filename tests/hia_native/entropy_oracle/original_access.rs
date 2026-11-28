// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Appended only to the complete unchanged original module in the test oracle.
pub(super) fn original_system_entropy(bytes: &mut [u8]) -> bool {
	SystemEntropy.fill(bytes).is_ok()
}

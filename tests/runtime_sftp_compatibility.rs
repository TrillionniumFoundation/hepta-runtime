// Copyright 2026 Muvon Un Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Verify the runtime-only SFTP quarantine does not break legacy Octofs mode.
//!
//! This integration-test executable does not initialize RuntimeConfig, unlike
//! `runtime_sftp_quarantine.rs`. Cargo gives the two files separate processes:
//! their global OnceLock initialization cannot leak across these fixtures.
//! No DNS lookup, authentication or network access is performed.

use hepta_runtime::mcp::runtime::config;

#[test]
fn compatibility_mode_allows_unconfigured_remote_file_paths() {
    assert!(
        config::check_sftp_physical_boundary().is_ok(),
        "the physical-root SFTP quarantine must apply only in runtime mode"
    );

    for write in [false, true] {
        assert!(
            config::check_remote_path(
                "legacy-host",
                "/tmp/octofs-compatibility.txt",
                false,
                false,
                write,
            )
            .is_ok(),
            "unconfigured Octofs path admission must preserve compatibility"
        );
    }
}

#[test]
fn compatibility_mode_keeps_legacy_alias_override_semantics() {
    assert!(
        config::check_remote_path("legacy-host", "/tmp/x", true, true, false).is_ok(),
        "strict registered-host alias policy only activates with RuntimeConfig"
    );
}

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

use super::*;
use tempfile::tempdir;

fn request() -> Value {
    json!({
        "executable": "/usr/local/sbin/qualified-action",
        "fixed_args": ["reboot-test"],
        "args": [],
        "timeout_seconds": 30
    })
}

#[tokio::test]
async fn observed_operation_is_reused_without_a_second_entry() {
    let state = tempdir().unwrap();
    let first = admit(state.path(), "rog", "controlled", "stable-key", &request())
        .await.unwrap();
    let permit = match first {
        Admission::Entered(permit) => permit,
        Admission::Observed(_) => panic!("unexpected previous effect"),
    };
    let response = json!({"exit_code": 0, "stdout": "ok", "stderr": ""});
    assert_eq!(permit.complete(response.clone()).unwrap(), response);
    match admit(state.path(), "rog", "controlled", "stable-key", &request())
        .await.unwrap()
    {
        Admission::Observed(observed) => assert_eq!(observed, response),
        Admission::Entered(_) => panic!("a duplicate privileged action was admitted"),
    }
}

#[tokio::test]
async fn lost_ack_is_indeterminate_and_not_replayed() {
    let state = tempdir().unwrap();
    let admission = admit(state.path(), "rog", "controlled", "lost-ack", &request())
        .await.unwrap();
    assert!(matches!(admission, Admission::Entered(_)));
    drop(admission);
    let result = admit(state.path(), "rog", "controlled", "lost-ack", &request()).await;
    assert!(result.err().unwrap().to_string().contains("indeterminate"));
}

#[tokio::test]
async fn same_key_with_changed_effect_is_rejected() {
    let state = tempdir().unwrap();
    let original = admit(state.path(), "rog", "controlled", "stable", &request())
        .await.unwrap();
    match original {
        Admission::Entered(permit) => {
            permit.complete(json!({"exit_code": 0})).unwrap();
        }
        Admission::Observed(_) => panic!("unexpected prior effect"),
    }
    let changed = json!({"executable": "/usr/local/sbin/qualified-action", "args": ["DIFFERENT"]});
    let result = admit(state.path(), "rog", "controlled", "stable", &changed).await;
    assert!(result.err().unwrap().to_string().contains("conflict"));
    let result = admit(state.path(), "rog", "different", "stable", &request()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn bad_idempotency_keys_fail_before_any_effect() {
    let state = tempdir().unwrap();
    for key in ["", "  ", "a\u{0}b"] {
        assert!(admit(state.path(), "rog", "controlled", key, &request())
            .await.is_err());
    }
    assert!(admit(state.path(), "rog", "controlled", &"a".repeat(257), &request())
        .await.is_err());
    assert!(!state.path().join("privileged-actions").exists());
}

#[tokio::test]
async fn corrupt_ledger_record_is_never_treated_as_new() {
    let state = tempdir().unwrap();
    let admission = admit(state.path(), "rog", "controlled", "corrupt", &request())
        .await.unwrap();
    drop(admission);
    let path = record_path(state.path(), &identity("rog", "corrupt").unwrap()).unwrap();
    std::fs::write(path, b"{truncated").unwrap();
    let result = admit(state.path(), "rog", "controlled", "corrupt", &request()).await;
    assert!(result.err().unwrap().to_string().contains("invalid privileged ledger record"));
}

#[cfg(unix)]
#[tokio::test]
async fn forged_symlink_does_not_authorize_an_effect() {
    let state = tempdir().unwrap();
    let dir = ledger_dir(state.path()).unwrap();
    let target = state.path().join("outside");
    std::fs::write(&target, b"untouched").unwrap();
    std::os::unix::fs::symlink(
        &target,
        dir.join(format!("{}.json", identity("rog", "spoof").unwrap())),
    ).unwrap();
    let result = admit(state.path(), "rog", "controlled", "spoof", &request()).await;
    assert!(result.err().unwrap().to_string().contains("not a regular file"));
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
}

#[tokio::test]
async fn leftover_partial_write_is_not_overwritten() {
    let state = tempdir().unwrap();
    let path = record_path(state.path(), &identity("rog", "partial").unwrap()).unwrap();
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, b"uncommitted").unwrap();
    let result = admit(state.path(), "rog", "controlled", "partial", &request()).await;
    assert!(result.is_err());
    assert_eq!(std::fs::read(tmp).unwrap(), b"uncommitted");
}

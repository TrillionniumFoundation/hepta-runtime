// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
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
//! Access-only runner for the complete, unchanged original acquisition tests.
use std::sync::Arc;

pub fn run_original_acquisition_tests() -> anyhow::Result<Vec<&'static str>> {
    acquisition_cases::run_all()
}

// Qualification injection: panic while the actual original Mutex guard is
// held. The real owner handles the JoinError and every subsequent cache query.
pub fn run_original_cache_poison_control() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("authority");
    let state = temporary.path().join("state");
    let prior = temporary.path().join("prior");
    let jobs = prior.join("jobs");
    for path in [&root, &state, &prior, &jobs] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let record = serde_json::to_vec(&serde_json::json!({
        "schema": SCHEMA, "owner": "v11", "phase": "admitting", "epoch": 7,
        "state_root": state, "predecessor_state_root": prior
    }))?;
    for (name, value) in [(".owner.lock", Vec::new()), (".owner.json", record)] {
        let path = root.join(name);
        fs::write(&path, value)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    let first = acquire_from_root(&root, "v11", &state)?;
    let contender = fs::OpenOptions::new().read(true).write(true).open(root.join(".owner.lock"))?;
    let exclusive = || unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    anyhow::ensure!(exclusive() == -1, "first original permit lost the real shared lock");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let failed = runtime.block_on(run_fence_acquisition(|| {
        let _guard = REPLAY_SNAPSHOT.get_or_init(|| Mutex::new(None)).lock()
            .map_err(|_| anyhow!("qualification cache was already poisoned"))?;
        panic!("declared qualification panic while original cache lock is held");
    })).err().context("original worker panic unexpectedly succeeded")?;
    anyhow::ensure!(failed.to_string() == "effect owner admission worker unavailable",
                    "original panic mapping differs: {failed}");
    let rejected = first.require_new_process_identity("local", Some("fresh"))
        .err().context("original poisoned cache unexpectedly succeeded")?;
    anyhow::ensure!(rejected.to_string() == "predecessor replay cache unavailable",
                    "original cache poison mapping differs: {rejected}");
    let second = acquire_from_root(&root, "v11", &state)?;
    let rejected = second.require_new_process_identity("local", Some("other"))
        .err().context("second original permit bypassed cache poison")?;
    anyhow::ensure!(rejected.to_string() == "predecessor replay cache unavailable",
                    "original process-global poison was lost");
    drop(first);
    anyhow::ensure!(exclusive() == -1, "second original permit lost its shared lock");
    drop(second);
    anyhow::ensure!(exclusive() == 0, "original permit release leaked a shared lock");
    drop(runtime);
    Ok(())
}

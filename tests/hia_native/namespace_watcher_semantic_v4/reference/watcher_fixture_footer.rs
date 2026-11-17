

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

// Test-owned accessors below the exact original module. Original functions above
// remain byte-for-byte unchanged and perform all Watcher policy and real I/O.
pub(super) struct FixtureWatcher {
    inner: Option<Watcher>,
}
pub(super) fn fixture_new(limit: usize, content: bool) -> Result<FixtureWatcher> {
    let mut watcher = Watcher::new(limit)?;
    watcher.content = content;
    Ok(FixtureWatcher { inner: Some(watcher) })
}
pub(super) fn fixture_version(
    watcher: &mut FixtureWatcher,
    directory: &File,
    shared: Option<&std::sync::Arc<File>>,
) -> Result<Version> {
    watcher.inner.as_mut().expect("live fixture Watcher")
        .version_with_pin(directory, shared)
}
pub(super) fn fixture_drain(watcher: &mut FixtureWatcher) -> Result<()> {
    watcher.inner.as_mut().expect("live fixture Watcher").drain()
}
pub(super) fn fixture_changed(watcher: &mut FixtureWatcher, wd: i32, mask: u32) -> Result<()> {
    watcher.inner.as_mut().expect("live fixture Watcher").changed(wd, mask)
}
pub(super) fn fixture_drop(watcher: &mut FixtureWatcher) {
    drop(watcher.inner.take());
}
pub(super) fn fixture_seed_serial(watcher: &mut FixtureWatcher, next: u64) {
    // Explicit private state-boundary controls only; never a public selector.
    watcher.inner.as_mut().expect("live fixture Watcher").next = next;
}
pub(super) fn fixture_snapshot(watcher: &FixtureWatcher) -> serde_json::Value {
    use serde_json::json;
    match &watcher.inner {
        None => serde_json::Value::Null,
        Some(value) => json!({
            "event_fd": value.events.as_raw_fd(),
            "next": value.next,
            "limit": value.limit,
            "content": value.content,
            "watches": value.watches.iter().map(|watch|json!({
                "device": watch.identity.0,
                "inode": watch.identity.1,
                "wd": watch.wd,
                "id": watch.id,
                "generation": watch.generation,
                "dead": watch.dead,
                "pin_fd": watch._pin.as_raw_fd(),
                "strong_count": std::sync::Arc::strong_count(&watch._pin),
            })).collect::<Vec<_>>(),
        }),
    }
}
pub(super) fn fixture_callback(
    watcher: &mut FixtureWatcher,
    directory: Option<(&File, Option<&std::sync::Arc<File>>)>,
    script: &serde_json::Value,
) -> (Result<Option<Version>>, serde_json::Value) {
    use serde_json::json;
    let hex = |raw: &[u8]| raw.iter().map(|v|format!("{v:02x}")).collect::<String>();
    let rows = script["reads"].as_array().expect("frozen callback rows");
    let repeat = script["repeat_last"].as_bool().expect("frozen callback repeat");
    let mut captured = Vec::new();
    let mut index = 0usize;
    let read = |_: &File, buffer: &mut [u8]| -> std::io::Result<usize> {
        let selected = if index < rows.len() { index } else {
            assert!(repeat && !rows.is_empty(), "complete callback script");
            rows.len() - 1
        };
        let row = &rows[selected];
        let before = buffer.to_vec();
        let outcome = if let Some(errno) = row.get("errno") {
            let errno = i32::try_from(errno.as_u64().expect("callback errno")).expect("i32 errno");
            Err(std::io::Error::from_raw_os_error(errno))
        } else if let Some(kind) = row.get("kind") {
            match kind.as_str().expect("callback kind") {
                "Interrupted" => Err(std::io::ErrorKind::Interrupted.into()),
                "WouldBlock" => Err(std::io::ErrorKind::WouldBlock.into()),
                _ => panic!("unlisted callback error kind"),
            }
        } else {
            let hex = row["bytes"].as_str().expect("callback payload");
            assert!(hex.is_ascii() && hex.len() % 2 == 0);
            let raw = (0..hex.len()).step_by(2)
                .map(|at|u8::from_str_radix(&hex[at..at+2],16).unwrap()).collect::<Vec<_>>();
            assert!(raw.len() <= buffer.len(), "bounded original callback copy");
            buffer[..raw.len()].copy_from_slice(&raw);
            Ok(usize::try_from(row["count"].as_u64().expect("callback count")).expect("usize"))
        };
        let result = match &outcome {
            Ok(count) => json!({"count": count}),
            Err(error) => json!({
                "raw_os_error": error.raw_os_error(),
                "kind": format!("{:?}", error.kind()),
                "display": error.to_string(),
                "debug": format!("{error:?}"),
            }),
        };
        captured.push(json!({
            "index": index,
            "script_row": selected,
            "before_hex": hex(&before),
            "after_hex": hex(buffer),
            "result": result,
        }));
        index += 1;
        outcome
    };
    let value = watcher.inner.as_mut().expect("live fixture Watcher");
    let outcome = match directory {
        Some((directory, shared)) => value.version_with_reader(directory, shared, read).map(Some),
        None => value.drain_with_reader(read).map(|()|None),
    };
    (outcome, serde_json::Value::Array(captured))
}

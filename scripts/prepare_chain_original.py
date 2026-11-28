"""Create-only reference project for the complete original local history caller.

No production semantics live here.  All original owners below are extracted
byte-for-byte, and the full source identities are recorded before Cargo runs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path


PINS = {
    'src/mcp/fs/core.rs': '51c9a864c6b18ac43957cf3e6c74b07d8ee8952e0589b68e1051e976c1dd09ec',
    'src/mcp/fs/text_editing.rs': 'e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590',
    'src/mcp/fs/remote.rs': 'd87cae1d18cfaf3479cc94e0df8c8c6eefe5d2eec34f62b7ba0f0c4693704d8c',
    'src/mcp/request_ctx.rs': '81ebf6e68bcf8c119c83274a090b5e4796d00b3ca6d889c92e9922be0612e943',
    'src/mcp/fs/delta.rs': 'a21e86bc959ce79f35cb7695e908fa37d5fd5fb56e00673ecf4a8cd291c080e1',
}
QUALIFICATION_PINS = {
    'tests/hia_native/file_lock_service_oracle/Cargo.toml': '0e04c3818e74eb5c0864b2fbef07036fb42534b9d7f713ad8c61630b7a198602',
    'tests/hia_native/file_lock_service_oracle/Cargo.lock': 'f9511f4ccf9300cc5e0203570948e8c97a5998c00c50aed2700a76bc100133d0',
    'rustfmt.toml': 'bce79651b2e2ff42e1c54b9a26c5e17af5222f9f65ab51d9563a48fd159dae84',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        handle.write(raw)


def cut(text, first, last):
    assert text.count(first) == 1, first
    start = text.index(first)
    stop = text.index(last, start)
    return text[start:stop]


def inputs(runtime, source):
    texts = {}
    identities = {}
    for name, want in PINS.items():
        raw = (runtime / name).read_bytes()
        assert sha(raw) == want, (name, sha(raw), want)
        texts[name] = raw.decode()
        identities[name] = dict(bytes=len(raw), sha256=want)
    dependencies = {}
    for name, want in QUALIFICATION_PINS.items():
        raw = (runtime / name).read_bytes()
        assert sha(raw) == want, (name, sha(raw), want)
        dependencies[name] = dict(bytes=len(raw), sha256=want)
    request_name = 'src/mcp/request_ctx.rs'
    request_raw = (runtime / request_name).read_bytes()
    identities[request_name] = dict(bytes=len(request_raw), sha256=sha(request_raw))
    remote, edit, core, delta = [texts['src/mcp/fs/' + name + '.rs'] for name in
                               ('remote', 'text_editing', 'core', 'delta')]
    fragments = {
        'path_source_original.rs': cut(remote, '#[derive(Debug, Clone)]\npub enum PathSource {', '\nimpl PathSource {'),
        'path_key_original.rs': cut(remote, '\tpub fn lock_key(&self) -> String {', '\n\t/// Human-readable path'),
        'path_display_original.rs': cut(remote, '\tpub fn display(&self) -> String {', '\n\t/// Returns the local Path'),
        'io_read_original.rs': cut(remote, 'pub async fn io_read_to_string(', '\n/// Read a file as raw bytes.'),
        'io_write_original.rs': cut(remote, 'pub async fn io_write(', '\n/// Check if a path exists.'),
        'io_exists_original.rs': cut(remote, 'pub async fn io_exists(', '\n/// Check if a path is a directory.'),
        'file_lock_original.rs': cut(edit, '// Thread-safe file locking infrastructure', '/// Test-only visibility'),
        'atomic_write_original.rs': cut(edit, 'pub async fn atomic_write(', '\nconst LF_ENDING:'),
        'history_callers_original.rs': cut(core, '// Undo history:', '// Main execution functions'),
        'view_cache_original.rs': cut(delta, '/// Files above this size', '/// Line-ending agnostic form:'),
        'forget_original.rs': cut(delta, 'pub fn forget(source: &PathSource)', '\n/// Invalidate the directory'),
        'request_context_original.rs': cut(request_raw.decode(), 'struct RequestContext {', '/// Push a hint for the current tool call.'),
    }
    files = {'original/' + name: text.encode() for name, text in fragments.items()}
    envelope = (source / 'tests/hia_native/oracle_write_chain.rs').read_bytes()
    files['src/main.rs'] = envelope
    cargo = (runtime / 'tests/hia_native/file_lock_service_oracle/Cargo.toml').read_bytes()
    cargo = cargo.replace(b'hia-file-lock-service-original', b'hia-write-chain-callers-original')
    cargo = cargo.replace(b'build = "build.rs"\n', b'')
    cargo = cargo.replace(b'path = "../oracle_file_lock_service.rs"', b'path = "src/main.rs"')
    files['Cargo.toml'] = cargo
    lock = (runtime / 'tests/hia_native/file_lock_service_oracle/Cargo.lock').read_bytes()
    assert lock.count(b'name = "hia-file-lock-service-original"') == 1
    lock = lock.replace(b'name = "hia-file-lock-service-original"', b'name = "hia-write-chain-callers-original"')
    files['Cargo.lock'] = lock
    # include! cannot appear in an inherent impl; preserve both method bodies
    # inside a qualification-only wrapper whose bytes are separately recorded.
    path_methods = 'impl PathSource {\n' + fragments['path_key_original.rs'] + '\n' + fragments['path_display_original.rs'] + '\n}\n'
    files['original/path_methods_wrapper.rs'] = path_methods.encode()
    report = dict(schema='hepta.runtime.write-chain-original-inputs.v2',
        runtime=str(runtime), source=str(source), original_sources=identities, qualification_dependencies=dependencies,
        fragments={name: dict(bytes=len(raw.encode()), sha256=sha(raw.encode())) for name, raw in fragments.items()},
        envelope=dict(bytes=len(envelope), sha256=sha(envelope)),
        path_methods_wrapper_sha256=sha(path_methods.encode()), cargo_lock_sha256=sha(lock),
        admitted_domain='Local PathSource; unchanged save_file_history and undo_edit',
        remote_ssh_qualified=False, public_mcp_qualified=False)
    files['inputs.json'] = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    return files, report


def prepare(runtime, source, destination):
    files, report = inputs(runtime, source)
    destination.mkdir(mode=0o700)
    for name, raw in files.items(): save(destination / name, raw)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = prepare(args.runtime.resolve(strict=True), args.source.resolve(strict=True), args.output)
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()

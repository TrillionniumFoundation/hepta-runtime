# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Extract exact archive_stamp and metadata methods with the complete Namespace module."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    audit = (ROOT / 'original/request_audit.rs').read_bytes()
    namespace = (ROOT / 'original/namespace_version.rs').read_bytes()
    assert SHA(audit) == 'b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da'
    assert SHA(namespace) == '7dd63c53bc1a85995a353bedc9643e7e4eb864cc7a5603dc331f0b4dd12576db'
    target = ROOT / 'reference-v1';target.mkdir(mode=0o700, exist_ok=False)
    header = b'// Copyright 2026 Muvon Un Limited\n// SPDX-License-Identifier: Apache-2.0\n'
    data = bytearray(header + b'mod audit {\nuse super::*;\n')
    proof = []
    for marker in (b'struct ArchiveStamp {', b'fn private_directory_metadata(', b'fn archive_stamp('):
        start = audit.index(marker)
        end = audit.index(b'\n}', start) + 2
        if marker.startswith(b'struct'):
            start = audit.rfind(b'#[derive(', 0, start)
        part = audit[start:end]
        proof.append(dict(source='request_audit.rs', source_sha256=SHA(audit), offset=start,
            bytes=len(part), sha256=SHA(part), target='original_stamp.rs', target_offset=len(data)))
        data.extend(part + b'\n')
    data.extend(b'''
pub(super) fn observed_stamp(directory: &File) -> Result<Vec<u8>> {
    let stamp = archive_stamp(directory)?;
    let mut raw = vec![0;112];
    raw[..8].copy_from_slice(b"HRAST001");
    for (index,value) in [stamp.device,stamp.inode,stamp.modified.0 as u64,stamp.modified.1 as u64,
        stamp.changed.0 as u64,stamp.changed.1 as u64].into_iter().enumerate() {
        put(&mut raw,8+index*8,value);
    }
    match stamp.namespace {
        namespace_version::Version::Watch(first,second) => {
            put(&mut raw,56,1);put(&mut raw,64,first);put(&mut raw,72,second);
        }
        namespace_version::Version::Fingerprint(digest) => {
            put(&mut raw,56,2);raw[80..].copy_from_slice(&digest);
        }
    }
    Ok(raw)
}
}
''')
    (target / 'original_stamp.rs').write_bytes(data)
    (target / 'original_namespace.rs').write_bytes(namespace)
    (target / 'oracle.rs').write_bytes((ROOT / 'scripts/audit_stamp_oracle.rs.txt').read_bytes())
    for name in ('Cargo.toml', 'Cargo.lock'):
        raw = (ROOT / 'dependencies' / ('reference-' + name)).read_bytes()
        assert b'hia-audit-namespace-reference' in raw
        (target / name).write_bytes(raw.replace(b'hia-audit-namespace-reference', b'hia-audit-stamp-reference'))
    package_reference = json.loads((ROOT / 'dependencies/namespace-reference-inputs.json').read_bytes())
    packages = package_reference['original_registry_packages']
    assert len(packages) == 22
    proof.append(dict(source='namespace_version.rs', source_sha256=SHA(namespace), offset=0, bytes=len(namespace),
        sha256=SHA(namespace), target='original_namespace.rs', target_offset=0))
    pins = {p.name: dict(bytes=p.stat().st_size, sha256=SHA(p.read_bytes())) for p in sorted(target.iterdir())}
    record = dict(schema='hepta.request-audit.original-stamp.v1', files=pins, original_blocks=proof,
        original_registry_packages=packages, original_functions_unmodified=True,
        original_namespace_full_module=True, actual_filesystem_effects=True,
        semantic_execution_during_preparation=False, public_error_display_qualified=False,
        production_activated=False, whole_runtime_replaced=False)
    (target / 'reference-inputs.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    print(json.dumps(dict(files=len(pins), exact_blocks=len(proof), locked_packages=len(packages))))


if __name__ == '__main__':main()

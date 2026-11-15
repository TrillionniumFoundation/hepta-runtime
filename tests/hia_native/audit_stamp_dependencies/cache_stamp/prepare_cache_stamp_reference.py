# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Bind unchanged cache methods, real ArchiveStamp, complete Namespace and exact lock graph."""
from pathlib import Path
import hashlib
import json
import tomllib

ROOT=Path(__file__).resolve().parents[1]
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def main():
    target=ROOT/'reference-v1';target.mkdir(mode=0o700,exist_ok=False)
    audit=(ROOT/'original/request_audit.rs').read_bytes();namespace=(ROOT/'original/namespace_version.rs').read_bytes()
    assert SHA(audit)=='b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da'
    assert SHA(namespace)=='7dd63c53bc1a85995a353bedc9643e7e4eb864cc7a5603dc331f0b4dd12576db'
    data=bytearray(b'// Copyright 2026 Muvon Un Limited\n// SPDX-License-Identifier: Apache-2.0\n');proof=[]
    markers=[(b'enum DurableState {',True,False),(b'mod record_schema {',False,False),
        (b'type RecordFields<S> =',False,True),(b'type Record =',False,True),
        (b'struct ArchiveStamp {',True,False),(b'struct HotSnapshot {',False,False),(b'static HOT_CACHE:',False,True),
        (b'fn private_directory_metadata(',False,False),(b'fn archive_stamp(',False,False),
        (b'fn cache_hot(',False,False),(b'fn cache_hot_owned(',False,False),(b'fn hot_snapshot_cached(',False,False),
        (b'fn update_cached_completion(',False,False)]
    for marker,derived,line in markers:
        at=audit.index(marker);end=audit.index(b'\n',at) if line else audit.index(b'\n}',at)+2
        if derived:at=audit.rfind(b'#[derive(',0,at)
        part=audit[at:end];proof.append(dict(source='request_audit.rs',source_sha256=SHA(audit),offset=at,bytes=len(part),
            sha256=SHA(part),target='original_policy.rs',target_offset=len(data)));data.extend(part+b'\n')
    (target/'original_policy.rs').write_bytes(data);(target/'original_namespace.rs').write_bytes(namespace)
    proof.append(dict(source='namespace_version.rs',source_sha256=SHA(namespace),offset=0,bytes=len(namespace),
        sha256=SHA(namespace),target='original_namespace.rs',target_offset=0))
    (target/'oracle.rs').write_bytes((ROOT/'scripts/cache_stamp_oracle.rs.txt').read_bytes())
    manifest=(ROOT/'dependencies/reference-Cargo.toml').read_text().replace('hia-audit-legacy-reference','hia-audit-cache-stamp-reference')
    manifest='\n'.join(line for line in manifest.splitlines() if not line.startswith('ring ='))+'\n'
    (target/'Cargo.toml').write_text(manifest)
    old=(ROOT/'dependencies/reference-Cargo.lock').read_text();chunks=old.split('[[package]]');packages=[]
    for text in chunks[1:]:
        item=tomllib.loads('[[package]]'+text)['package'][0];packages.append((item,text))
    direct=tomllib.loads(manifest)['dependencies'];wanted=set();pending=list(direct)
    while pending:
        name=pending.pop();parts=name.split();matches=[p for p,_ in packages if p['name']==parts[0] and (len(parts)==1 or p['version']==parts[1])]
        assert len(matches)==1,(name,matches)
        package=matches[0];key=(package['name'],package['version'])
        if key in wanted:continue
        wanted.add(key);pending.extend(package.get('dependencies',[]))
    selected=[p for p,_ in packages if (p['name'],p['version']) in wanted]
    lock=chunks[0]
    for package,text in packages:
        if (package['name'],package['version']) in wanted:lock+='[[package]]'+text
        elif package['name']=='hia-audit-legacy-reference':
            text=text.replace('hia-audit-legacy-reference','hia-audit-cache-stamp-reference').replace(' "ring",\n','')
            lock+='[[package]]'+text
    (target/'Cargo.lock').write_text(lock)
    assert all(p.get('source') for p in selected)
    previous=json.loads((ROOT/'dependencies/legacy-reference-inputs.json').read_bytes())['original_registry_packages']
    for p in selected:
        assert p==next(q for q in previous if (q['name'],q['version'])==(p['name'],p['version']))
    files={p.name:dict(bytes=p.stat().st_size,sha256=SHA(p.read_bytes())) for p in sorted(target.iterdir())}
    record=dict(schema='hepta.request-audit.original-cache-stamp.v1',files=files,original_blocks=proof,
        original_registry_packages=selected,original_cache_methods_unmodified=True,original_namespace_full_module=True,
        real_filesystem_effects=True,child_contracts_scripted=False,cold_snapshot_admitted=False,
        semantic_execution_during_preparation=False,whole_runtime_replaced=False,production_activated=False)
    (target/'reference-inputs.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    print(json.dumps(dict(files=len(files),original_blocks=len(proof),locked_packages=len(selected))))


if __name__=='__main__':main()

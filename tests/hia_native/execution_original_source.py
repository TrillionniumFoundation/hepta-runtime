"""Reproduce both references from exact original owner bytes and locked crates."""
from pathlib import Path
import argparse,hashlib,json,tomllib
ROOT=Path(__file__).resolve().parents[2]
LOCK_SHA='df1130e3823a3ddb704f74a8267530922a27fb9169c187cefeab8ac562d4907f'
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def locked_dependencies(root):
    original=tomllib.loads((root/'Cargo.lock').read_text())
    allowed={(p['name'],p['version']):p for p in original['package']}
    raw=(root/'tests/hia_native/execution_original/Cargo.lock').read_bytes()
    if sha(raw)!=LOCK_SHA:raise ValueError('execution reference lock changed')
    rows=tomllib.loads(raw.decode())['package'];selected={};package=None
    for row in rows:
        key=(row['name'],row['version'])
        if key==('hepta-execution-shadow-original','0.0.0'):
            if package is not None:raise ValueError('duplicate reference root')
            package=row;continue
        if key in selected or key not in allowed:raise ValueError('reference dependency absent from original lock')
        if any(row.get(k)!=allowed[key].get(k) for k in ('name','version','source','checksum')):
            raise ValueError('reference dependency identity differs')
        selected[key]=row
    wanted={'name':'hepta-execution-shadow-original','version':'0.0.0','dependencies':['anyhow','schemars','serde','serde_json','sha2']}
    if package!=wanted or len(selected)!=28:raise ValueError('reference closure is incomplete')
    for row in selected.values():
        for dependency in row.get('dependencies',[]):
            parts=dependency.split()
            matches=[p for p in selected.values() if p['name']==parts[0] and (len(parts)==1 or p['version']==parts[1])]
            if len(matches)!=1:raise ValueError('ambiguous reference dependency edge')
    return raw,list(selected.values())

def original_files(root):
    raw=(root/'src/mcp/runtime/execution.rs').read_text()
    tests=(root/'src/mcp/runtime/execution_tests.rs').read_bytes()
    header=raw.split('//!',1)[0]
    start=raw.index('const MAX_RECORD_BYTES:');end=raw.index('/// Non-executing inspection')
    owner=raw[start:end]
    projection_start=raw.index('\tOk(serde_json::json!({',end)
    projection=raw[projection_start:raw.index('\n}\n',projection_start)]
    projection=projection.replace('\tOk(serde_json::json!({','serde_json::json!({',1)
    projection=projection.replace('\n\t.to_string())','\n\t.to_string()')
    adapter=(root/'tests/hia_native/execution_core_adapter.rs.txt').read_text().replace('ORIGINAL_PROJECTION_EXPRESSION',projection)
    first=adapter.index('mod original {');last=adapter.index('\n}\n',first)+2
    inner=adapter[first+len('mod original {'):last-1].strip()
    if inner.count('include!("exact_owner.rs");')!=1:raise ValueError('original inclusion changed')
    inner=inner.replace('include!("exact_owner.rs");',owner)
    core=adapter[:first]+'#[path = "exact_owner.rs"]\nmod original;'+adapter[last:]
    json_adapter=(root/'tests/hia_native/execution_json_adapter.rs.txt').read_text()
    lock,dependencies=locked_dependencies(root)
    manifest='''[package]
name = "hepta-execution-shadow-original"
version = "0.0.0"
edition = "2021"

[dependencies]
anyhow = "=1.0.104"
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = { version = "=1.0.151", features = ["float_roundtrip", "raw_value"] }
sha2 = "=0.11.0"
schemars = "=1.2.2"

[[bin]]
name = "execution-core-original"
path = "src/main.rs"

[[bin]]
name = "execution-json-original"
path = "src/json_main.rs"
'''
    files={'Cargo.toml':manifest.encode(),'Cargo.lock':lock,'src/original_tests.rs':tests,
      'src/exact_owner.rs':(header+'//! Exact original owner with an independent qualification entry.\n\n'+inner+'\n').encode(),
      'src/main.rs':(header+'//! Qualification framing around the unchanged original shadow owner.\n\n'+core).encode(),
      'src/json_main.rs':(header+'//! Independent original JSON and Value type qualification.\n\n'+json_adapter).encode()}
    proof={'schema':'hepta.runtime.execution-original-source.v1','owner_sha256':sha(raw.encode()),
      'owner_span_sha256':sha(owner.encode()),'projection_sha256':sha(projection.encode()),
      'original_tests_sha256':sha(tests),'lock_sha256':sha(lock),'dependency_count':len(dependencies),
      'dependencies':dependencies,'files':{name:sha(data) for name,data in files.items()},
      'installed_host_lookup_included':False,'production_activated':False}
    files['source-recipe.json']=(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode()
    return files

def prepare(root,output):
    files=original_files(root);output.mkdir(parents=True,exist_ok=False,mode=0o700)
    for name,raw in files.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with path.open('xb') as stream:stream.write(raw)
    return json.loads(files['source-recipe.json'])

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',type=Path,default=ROOT);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(json.dumps(prepare(a.runtime,a.output),sort_keys=True))

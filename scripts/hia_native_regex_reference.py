"""Prepare the locked original regex reference without executing Rust."""
from pathlib import Path
import hashlib,json,shutil,tomllib

sha=lambda raw:hashlib.sha256(raw).hexdigest()
REFERENCE_FILES=('Cargo.toml','Cargo.lock','oracle.rs','ast_projection.rs','hir_projection.rs','original-runtime.lock','source-identity.json')
REMOVED_ENV=('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','CARGO_TARGET_DIR','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC_BOOTSTRAP')


def prepare_reference(repo,output):
    repo=Path(repo).resolve(strict=True);output=Path(output)
    folder=repo/'tests/hia_native/regex_reference'
    inputs={name:sha((folder/name).read_bytes())for name in REFERENCE_FILES}
    spec=json.loads((folder/'source-identity.json').read_bytes())
    original=(repo/'Cargo.lock').read_bytes()
    if (folder/'original-runtime.lock').read_bytes()!=original or sha(original)!=spec['runtime_lock_sha256']:
        raise ValueError('original runtime regex lock changed')
    registry={(p['name'],p['version']):p for p in tomllib.loads(original.decode())['package']if 'checksum'in p}
    packages=[]
    for row in tomllib.loads((folder/'Cargo.lock').read_text())['package']:
        if 'checksum'not in row:continue
        old=registry[(row['name'],row['version'])]
        if any(row[k]!=old[k]for k in ['source','checksum']):raise ValueError('regex original dependency changed')
        if {k:row[k]for k in ['version','source','checksum']}!=spec['registry_packages'][row['name']]:raise ValueError('regex declared dependency changed')
        packages.append({k:row[k]for k in ['name','version','source','checksum']})
    if len(packages)!=5:raise ValueError('regex original dependency closure changed')
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    for name in REFERENCE_FILES:shutil.copyfile(folder/name,output/name)
    receipt={'schema':'hepta.runtime.regex-reference-preparation.v1','files':inputs,'packages':packages,
             'runtime_lock_sha256':sha(original),'source_identity_sha256':inputs['source-identity.json'],'single_shared_build':True}
    (output/'reference-inputs.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    check_reference(output,receipt)
    return receipt


def check_reference(project,receipt):
    for name,digest in receipt['files'].items():
        path=Path(project)/name
        if path.is_symlink()or not path.is_file()or sha(path.read_bytes())!=digest:raise ValueError('reference source changed: '+name)

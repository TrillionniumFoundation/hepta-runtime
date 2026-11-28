"""Create the reviewable complete source manifest exactly once."""
from pathlib import Path
import argparse, ast, hashlib, json


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True); a=p.parse_args()
    source=a.source.resolve(strict=True); destination=source/'SOURCE_MANIFEST.json'
    assert not destination.exists()
    files={}
    for path in sorted(source.rglob('*')):
        assert not path.is_symlink()
        if not path.is_file(): continue
        raw=path.read_bytes(); name=path.relative_to(source).as_posix()
        if name.endswith('.py'): ast.parse(raw, filename=name)
        files[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
            git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
    receipt=dict(schema='hepta.sdk-request-tasks.source-manifest.v1',files=files,
        public_registry_integrated=False,full_async_runtime_qualified=False,full_sdk_qualified=False,
        production_activated=False,old_path_removed=False)
    destination.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    print(json.dumps(dict(files=len(files),bytes=sum(x['bytes'] for x in files.values()),
        manifest_sha256=hashlib.sha256(destination.read_bytes()).hexdigest()),sort_keys=True))


if __name__=='__main__': main()

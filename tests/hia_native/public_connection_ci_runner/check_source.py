"""Check the immutable public83 source checkpoint without execution."""
from pathlib import Path
import ast,hashlib,json
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
SOURCE_MANIFEST="b53aaa91b6b229c3d4b6620c9cb57b56a19cf44f470af57cd80f57370a8f4b6d"
def check(source):
    source=Path(source).resolve(strict=True)
    raw=(source/"source-manifest.json").read_bytes();assert SHA(raw)==SOURCE_MANIFEST
    manifest=json.loads(raw);assert len(manifest["files"])==248
    actual={}
    for path in sorted(source.rglob("*")):
        assert not path.is_symlink()
        if path.is_dir():continue
        assert path.is_file()
        name=path.relative_to(source).as_posix()
        if name=="source-manifest.json":continue
        data=path.read_bytes()
        actual[name]=dict(bytes=len(data),sha256=SHA(data),
            git_blob=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest())
        if path.suffix==".py":ast.parse(data,filename=name)
    assert actual==manifest["files"]
    return dict(source_files=249,source_manifest_sha256=SHA(raw),
        checkpoint_commit="3aada51f16d4604b6d7daa7d79a6b680ef067012")

def check_runner(root):
    raw=(root/"runner-manifest.json").read_bytes();manifest=json.loads(raw)
    assert manifest["schema"]=="hepta.public83.ci-runner-source.v1"
    actual={}
    for path in sorted(root.rglob("*")):
        assert not path.is_symlink()
        if path.is_dir():continue
        name=path.relative_to(root).as_posix()
        if name=="runner-manifest.json":continue
        data=path.read_bytes()
        actual[name]=dict(bytes=len(data),sha256=SHA(data),git_blob=hashlib.sha1(
            b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest())
        if path.suffix==".py":ast.parse(data,filename=name)
    assert actual==manifest["files"]
    return dict(files=len(actual)+1,manifest_sha256=SHA(raw))


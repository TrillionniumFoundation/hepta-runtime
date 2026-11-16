"""Read exact package bytes and parse Python sources without execution."""
from pathlib import Path
import ast, hashlib, json
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
SCHEMA="hepta.runtime.public-constructor-source-package.v1"

def verify_source(source):
    source=Path(source).resolve(strict=True)
    manifest=json.loads((source/"source-manifest.json").read_bytes())
    assert manifest["schema"]==SCHEMA
    actual=set()
    for path in source.rglob("*"):
        assert not path.is_symlink(),str(path)
        if path.is_file():
            actual.add(str(path.relative_to(source)))
    assert actual==set(manifest["files"])|{"source-manifest.json"}
    for relative,pin in manifest["files"].items():
        name=Path(relative)
        assert not name.is_absolute() and ".." not in name.parts
        raw=(source/name).read_bytes()
        assert pin==dict(bytes=len(raw),sha256=SHA(raw)),relative
        if name.suffix==".py":ast.parse(raw,filename=relative)
    binding=json.loads((source/"source/native/runtime_mcp_sources.json").read_bytes())
    for relative,pin in binding["sources"].items():
        raw=(source/"source"/relative).read_bytes()
        assert pin==dict(bytes=len(raw),sha256=SHA(raw)),relative
    return manifest


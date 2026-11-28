"""Read the complete frozen source closure; do not generate or execute owners."""
from pathlib import Path
import ast, hashlib, json, stat
def pin(raw): return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def check(source):
    source = Path(source).resolve(strict=True)
    document = json.loads((source/"source_manifest.json").read_bytes())
    assert document["schema"] == "hepta.current-get-info.source-package.v1"
    expected = document["files"]
    actual = {}
    for path in sorted(source.rglob("*")):
        if path.is_dir(): continue
        assert path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode)
        name = path.relative_to(source).as_posix()
        if name == "source_manifest.json": continue
        raw = path.read_bytes(); actual[name]=pin(raw)
        if path.suffix == ".py": ast.parse(raw,filename=name)
    assert actual == expected
    assert document["target_commit"] == "d3d75c30719db966b004756f610007a7c723729e"
    assert document["source_only_candidate"] is True
    return dict(status="SOURCE_CLOSURE_PASS",files=len(actual),bytes=sum(v["bytes"] for v in actual.values()),
                source_manifest=pin((source/"source_manifest.json").read_bytes()))

"""Verify the complete thin source package and immutable public80 input bytes."""
from pathlib import Path
import ast,hashlib,json,stat
SHA=lambda b:hashlib.sha256(b).hexdigest()
BASE_MANIFEST="be0711701ed9d1e63bfdd5a3df4e4a1af2fe840ddcf7669a2b1f9d53ddedd0ef"
BASE_BINDING="7701165fceeaebdb9272d76e44c57985e0bc478b5ec8b96b7891c79e9d607d46"
INSTALLED_BINDING="70e7848820d2a254d31f70d1a17e674b78884d8d22494c285c4baaeeb4de4a56"
# These three immutable authoring/metadata files are in the full public80
# package but intentionally absent from its native build binding.
INHERITED_METADATA={'authoring/view_call/text_editor_local_body.pseudo': {'bytes': 8338, 'sha256': 'f489270f96cb7a6c2c6dcf56c3267d1ed97bc77ec7f206a1aa17326ae0056dc2'}, 'authoring/view_call/text_editor_local_body_names.json': {'bytes': 291, 'sha256': '3ac449a9d3da983630b16d6ce91cea61d0db0adbdf7b4d56da0ef6720879c7c4'}, 'native/text_editor_local_body_composition.json': {'bytes': 1139, 'sha256': 'b49a2e80830096699d5a2072a87f597ccd7e8ef8a719c7cc1dc4a8ab716f5e89'}}
def pin(raw):return dict(bytes=len(raw),sha256=SHA(raw))
def check_files(root,manifest_name,expected):
    actual={}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():raise ValueError("symbolic source input")
        if path.is_dir():continue
        assert stat.S_ISREG(path.lstat().st_mode)
        rel=path.relative_to(root).as_posix()
        if rel==manifest_name:continue
        raw=path.read_bytes();actual[rel]=pin(raw)
        if path.suffix==".py":ast.parse(raw,filename=rel)
    assert actual==expected
def check(source):
    source=Path(source).resolve(strict=True);raw=(source/"source-manifest.json").read_bytes()
    manifest=json.loads(raw)
    assert manifest["schema"]=="hepta.public-serial81.source-package.v1"
    check_files(source,"source-manifest.json",manifest["files"])
    assert manifest["target_commit"]=="d3d75c30719db966b004756f610007a7c723729e"
    assert manifest["native_graph_revision"]==2 and manifest["actual_current_sdk_comparison_complete"] is False
    return dict(files=len(manifest["files"]),source_manifest=pin(raw))
def base(source):
    source=Path(source).resolve(strict=True);raw=(source/"source-manifest.json").read_bytes()
    assert SHA(raw)==BASE_MANIFEST
    document=json.loads(raw);assert len(document["files"])==191
    check_files(source,"source-manifest.json",document["files"])
    assert SHA((source/"source/native/runtime_mcp_sources.json").read_bytes())==BASE_BINDING
    return dict(files=192,source_manifest=pin(raw))
def installed(source):
    source=Path(source).resolve(strict=True);raw=(source/"native/runtime_mcp_sources.json").read_bytes()
    assert SHA(raw)==INSTALLED_BINDING
    binding=json.loads(raw);actual={}
    for p in sorted(source.rglob("*")):
        if p.is_symlink():raise ValueError("symbolic installed source")
        if not p.is_file():continue
        name=p.relative_to(source).as_posix()
        if name=="native/runtime_mcp_sources.json":continue
        actual[name]=pin(p.read_bytes())
    expected=dict(binding["sources"])
    assert not (set(expected)&set(INHERITED_METADATA))
    expected.update(INHERITED_METADATA)
    assert actual==expected
    return dict(files=len(actual)+1,source_binding=pin(raw))

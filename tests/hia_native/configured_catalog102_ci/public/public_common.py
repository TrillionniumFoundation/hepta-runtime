"""Exact source admission shared by the configured public capture and reader."""
from pathlib import Path
import hashlib,json,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
TRUSTED_PROFILE=(ROOT/'public-source-profile.json').read_bytes() if (ROOT/'public-source-profile.json').exists() else None
COMPONENT_PROFILE='185985fa09b9260405ede5eef335d8b5a703a80951783a171c846ceb57742bc3'
GRAPH_PROFILE='2333590e3fab06f254508e7800441346eea281030a89e3a4675dc7d8a6f65ab4'
sha=lambda raw:hashlib.sha256(raw).hexdigest()
pin=lambda raw:{'bytes':len(raw),'sha256':sha(raw)}

def source_check(source,component,graph):
    raw=(source/'public-source-profile.json').read_bytes()
    assert raw==TRUSTED_PROFILE
    profile=json.loads(raw)
    assert profile['schema']=='hepta.runtime.configured-catalog-public-source.v1'
    assert profile['component_profile_sha256']==COMPONENT_PROFILE
    assert profile['graph_profile_sha256']==GRAPH_PROFILE
    for name,expected in profile['files'].items():
        path=source/name;info=path.lstat()
        assert not path.is_symlink() and stat.S_ISREG(info.st_mode)
        assert pin(path.read_bytes())==expected
    assert sha((component/'source-profile.json').read_bytes())==COMPONENT_PROFILE
    raw=(graph/'native/runtime_mcp_sources.json').read_bytes()
    assert sha(raw)==GRAPH_PROFILE
    binding=json.loads(raw)
    for name,expected in binding['files'].items():
        path=graph/name;info=path.lstat()
        assert not path.is_symlink() and stat.S_ISREG(info.st_mode)
        assert pin(path.read_bytes())==expected
    return profile,binding

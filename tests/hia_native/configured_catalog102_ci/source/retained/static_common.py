"""Fixed source and buffer contracts for the static 11-tool catalog."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'pipeline'))
import common as pipeline
from domain import frame, retained_non_list, SELECTED_TOOLS
sha, pin, put, encoded = pipeline.sha, pipeline.pin, pipeline.put, pipeline.encoded
TRUSTED_PROFILE = (ROOT / 'source-profile.json').read_bytes() if (ROOT / 'source-profile.json').exists() else None
BASE = pipeline.base_reader(ROOT / 'pipeline')

def source_check(source=ROOT):
    r = BASE.Reader(source)
    raw = r.raw('source-profile.json'); assert raw == TRUSTED_PROFILE
    profile = BASE.parse(raw)
    assert profile['schema'] == 'hepta.runtime.catalog-eleven-static-source.v1'
    actual = {p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file()}
    assert actual == set(profile['files']) | {'source-profile.json'}
    for name, expected in profile['files'].items(): r.raw(name, expected)
    pipeline.source_check(source / 'pipeline')
    proof = r.document('native/catalog-eleven-composition.json')
    assert proof['source_sha256'] == sha(r.raw('native/runtime_mcp_catalog_eleven.hepta'))
    assert proof['author_sha256'] == sha(r.raw('author_slot0.py'))
    assert proof['fixed_runtime_enabled'] is True and proof['declared_tools'] == list(SELECTED_TOOLS)
    assert proof['entry_inverse_restores_exact_baseline'] is True
    assert proof['expected_original_wire_used_as_implementation'] is False
    assert proof['pipeline_source_profile_sha256'] == sha(r.raw('pipeline/source-profile.json'))
    for row in proof['assets']:
        assert pin(r.raw('native/catalog-mode-' + str(row['mode']) + '.bin')) == {k: row[k] for k in ('bytes','sha256')}
    packed = r.raw('native/catalog-common.lzss')
    assert len(packed) == proof['compressed_bytes'] and sha(packed) == proof['compressed_sha256']
    return r, proof

def source_pins(source=ROOT):
    return {
        'catalog-nine': ('pipeline/baseline/runtime_mcp_catalog_ninth.hepta',
            'b9a62c6e24d171c08b8138d3116aa3f7cd709e4c44b9a163a62e32b6a50fe089', 'history.v1'),
        'catalog-eleven': ('native/runtime_mcp_catalog_eleven.hepta',
            'a06073afcfbd748dfcb5bceeec8ed2fff1f44a6cfda3bec2ec0e9af443c0e258', 'history.v1'),
    }

def cases(source=ROOT):
    proof = json.loads((source / 'native/catalog-eleven-composition.json').read_bytes())
    wc = proof['workspace_required']; sizes = [row['bytes'] + 32 for row in proof['assets']]
    result = []
    def add(name, wire, oc, work, outcome, pair=False, group=None):
        result.append(dict(name=name, wire=wire, output_capacity=oc,
            workspace_capacity=work, outcome=outcome, paired=pair, group=group))
    for name, wire in retained_non_list(): add(name, wire, 4096, wc + 17, 'retained', True)
    for mode in (0,1):
        add('baseline-list-' + str(mode), frame(1,mode), sizes[mode]+17,wc+17,'baseline-list',True)
        for cap in sorted(set((0,31,32,33,sizes[mode]-1,sizes[mode],sizes[mode]+1))):
            add(f'list-{mode}-output-{cap}',frame(1,mode),cap,wc+17,'list')
        for cap in sorted(set((0,4095,4096,wc-1,wc,wc+1))):
            add(f'list-{mode}-workspace-{cap}',frame(1,mode),sizes[mode]+17,cap,'list')
    for size in range(24): add(f'truncated-{size}',frame(1,0)[:size],20000,wc+17,'retained',True)
    for byte in range(8):
        raw=bytearray(frame(1,0));raw[byte]^=128
        add(f'magic-byte-{byte}',bytes(raw),20000,wc+17,'retained',True)
    for value in (2,255,1<<63,(1<<64)-1): add(f'modern-{value}',frame(1,value),20000,wc+17,'retained',True)
    add('extra-input-byte',frame(1,0)+b'\0',20000,wc+17,'retained',True)
    for ordinal, mode in enumerate((0,2,1,0)):
        add(f'same-session-{ordinal}',frame(1,mode),20000,wc+17,'invalid' if mode==2 else 'list',False,'dirty-session')
    return result

def document_cases(source=ROOT):
    return [{**{k:v for k,v in row.items() if k!='wire'},'wire_hex':row['wire'].hex()} for row in cases(source)]

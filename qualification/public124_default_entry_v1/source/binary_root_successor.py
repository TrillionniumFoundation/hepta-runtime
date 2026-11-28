"""Exact op9 successor of the retained default124 source and binary identity.

This module reverses only the qualified owner, two bridge edits and source
binding extension. The retained entry checks every original source byte and
every fresh-image/process/publication requirement after that inverse. No
original receipt or source row is rewritten as a successor result.
"""
from pathlib import Path
import copy, hashlib, json, re
from common import require

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
COMPOSITION = 'native/runtime_mcp_binary_root_integration.json'
PUBLIC = dict(bytes=26288128, sha256='65e34dfe467405beb4f00245bd5d94d4f0467934c28c93ed680b89cc15b5328e')
BASE = {
    'native/config_directory_owner_span.hepta': (288259, '6a0e7817013c32bd7189864c91dc768764ae44988cabe4391446ceafea9b5d81'),
    'scripts/runtime_mcp_extra_engine.S': (58628, '5a60c6f2b103f48f51cec92a9a4637f1237ab7cbffc961c3e9619b4cce13e917'),
    'native/runtime_mcp_sources.json': (127441, '9b5776d0bbfe51b3ba032be6ba402899ea20f9dd263a8d3fa379c8dc6519a890')}
CURRENT = {
    'native/config_directory_owner_span.hepta': (319711, 'cb22aa72a33b4a429356fdb7d70dd33828492676de1a89c11837d9d8f68a55b5'),
    'scripts/runtime_mcp_extra_engine.S': (58697, '2850c36e059efbbcba47145303bcb371dbf6ca104f4fc1519c6a9c904467fc9a'),
    'native/runtime_mcp_sources.json': (127962, '3b36dc20a77471c62b1cc12156ebcad6e2d6cd04701cdb5537b4bfa3638110be'),
    COMPOSITION: (3454, '242e17d878aa93470453d6e2249352ef523c78b78ea6356cc7377ec30558ce21')}

def ordinary(root, name):
    path = root / name
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary successor input')
    return path.read_bytes()

def profile(root):
    if not (root / COMPOSITION).exists():
        return {'active': False, 'originals': {}}
    current = {}
    for name, expected in CURRENT.items():
        raw = ordinary(root, name)
        require((len(raw), SHA(raw)) == expected, 'exact binary-root product source: ' + name)
        current[name] = raw
    composition = json.loads(current[COMPOSITION])
    require(composition['base_commit'] == '328953dc96d26ceb5ab02a172172deb7916873c7'
            and composition['public_binary_write_registered'] is False
            and composition['old_path_removed'] is False, 'exact integration scope')
    owner = current['native/config_directory_owner_span.hepta'].decode()
    parts = re.split(r'(?=^fn f[0-9]+\()', owner, flags=re.M)
    require(len(parts) == 61 and all(part.startswith('fn f' + str(i) + '(')
            for i, part in enumerate(parts[1:])), 'complete qualified owner function sequence')
    header = parts[0].replace('config_binary_root_span', 'runtime_config_owner_growing')
    functions = parts[1:53]
    functions[8] = parts[53].replace('fn f52(', 'fn f8(', 1)
    extension = ('  v641:u64 = const() {"value":9}\n'
        '  v642:bool = compare.eq(v369,v368)\n'
        '  v643:bool = compare.eq(v369,v641)\n'
        '  v370:bool = bool.or(v642,v643)')
    require(functions[0].count(extension) == 1, 'one entry extension')
    functions[0] = functions[0].replace(extension, '  v370:bool = compare.eq(v369,v368)', 1)
    originals = {'native/config_directory_owner_span.hepta': (header + ''.join(functions)).encode()}
    bridge = current['scripts/runtime_mcp_extra_engine.S'].decode()
    for before, after in reversed(composition['bridge']['exact_replacements']):
        require(bridge.count(after) == 1, 'one exact bridge inverse')
        bridge = bridge.replace(after, before, 1)
    originals['scripts/runtime_mcp_extra_engine.S'] = bridge.encode()
    binding = json.loads(current['native/runtime_mcp_sources.json'])
    require(len(binding['sources']) == 536 and binding['binary_root_extension']['operation'] == 9,
            'complete current binary-root source binding')
    del binding['binary_root_extension']
    del binding['sources'][COMPOSITION]
    for name in ('native/config_directory_owner_span.hepta', 'scripts/runtime_mcp_extra_engine.S'):
        size, digest = BASE[name]; binding['sources'][name] = dict(bytes=size, sha256=digest)
    originals['native/runtime_mcp_sources.json'] = (json.dumps(binding, sort_keys=True, indent=2) + '\n').encode()
    for name, raw in originals.items():
        require((len(raw), SHA(raw)) == BASE[name], 'whole retained source inverse: ' + name)
    return {'active': True, 'originals': originals}

def verify_recipe(root):
    before = (root / 'before-entry-v1.py.txt').read_bytes()
    require(len(before) == 9625 and SHA(before) == '995a5f566934b87a2955dc84785a7b27a3c0f996cf93a36e44f08e776adc0918',
            'unaltered retained entry reader')
    proof = json.loads((root / 'ENTRY_SUCCESSOR.json').read_bytes())
    require(proof['schema'] == 'hepta.runtime.default124.binary-root-reader-successor.v1', 'reader successor schema')
    restored = (root / 'entry.py').read_text()
    for previous, current in reversed(proof['exact_replacements']):
        require(restored.count(current) == 1, 'one exact reader inverse')
        restored = restored.replace(current, previous, 1)
    require(restored.encode() == before, 'whole retained default reader inverse')

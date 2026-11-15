"""Retire only the 119 completely admitted original Text fixture trees.

Normal execution archives the actual final inodes before removing them. Pure
admission reads complete retained bytes and never restores a live fixture.
"""
from pathlib import Path
import os

import hia_native_text_publication_pipeline as p
import hia_native_text_publication_qualification as q
import hia_native_text_publication_retirement as archive

FOLDER = 'text-publication-original'
ARCHIVE = FOLDER + '/fixture-archive'
SCHEMA = 'hepta.runtime.text-publication-original-fixtures.v1'


def specifications(output, binding, proof):
    output = Path(output).absolute()
    expected = {}
    groups = [('ordinary/domains/' + name, count) for name, count in
              (('ordinary', 38), ('paths', 23), ('metadata', 29), ('wide', 9))]
    groups.append(('races', 20))
    for suffix, count in groups:
        folder = FOLDER + '/group/' + suffix
        descriptions = p.read_json(p.contained(output, folder + '/corpus.json'))
        q.same(len(descriptions), count, 'all original fixture descriptions')
        for ordinal, desc in enumerate(descriptions):
            rows = p.read_json(p.contained(output, folder + '/cases/' + desc['name'] + '/after.json'))
            nodes = {q.unb64(row['path_base64']): dict(row) for row in rows}
            q.same(len(nodes), len(rows), 'unique original fixture paths')
            for rel, node in nodes.items():
                q.require(not rel.startswith(b'/') and b'..' not in rel.split(b'/')
                          and b'\0' not in rel, 'owned raw original fixture path')
                if node['kind'] == 'file' and 'data' not in node:
                    setup = [item for item in desc['setup'] if item['kind'] == 'file'
                             and q.unb64(item['path_base64']) == rel]
                    q.same(len(setup), 1, 'unreadable original file has one exact input')
                    from hia_native_text_publication_fixtures import materialize
                    node['data'] = q.pin(materialize(setup[0]['data']))
                elif 'data' in node:
                    node['data'] = {key: node['data'][key] for key in ('bytes', 'sha256')}
                node.pop('read_errno', None)
                node.pop('path_base64', None)
            q.require(b'' in nodes, 'complete original fixture root')
            expected[folder + '/fixtures/' + str(ordinal)] = nodes
    q.same(len(expected), 119, 'all original fixture roots')
    recorded = [str(Path(binding['execution_output_root']) / name) for name in expected]
    q.same(sorted(recorded), sorted(proof['transient_fixture_directories']),
           'exact roots from complete original admission')
    return expected


def create(output, binding, proof, source_pins):
    output = Path(output).absolute()
    q.same(str(output), binding['execution_output_root'], 'retire only this actual owned execution')
    directory = output / ARCHIVE
    q.require(not os.path.lexists(directory), 'new original fixture retirement transaction')
    expected = specifications(output, binding, proof)
    directory.mkdir(parents=True)
    trees = [archive.capture_tree(output, name, nodes, directory)
             for name, nodes in sorted(expected.items())]
    archive.closed_links(trees)
    index = {'schema': SCHEMA, 'execution_output_root': binding['execution_output_root'],
             'reference_evidence': q.pin(p.encoded(proof)), 'source_sha256': source_pins,
             'roots': trees, 'restoration_performed': False}
    p.write_new(directory / 'archive.json', index)
    evidence(output, binding, proof, source_pins, require_retired=False)
    for tree in trees:
        archive.remove_owned(output / tree['root'], tree)
    p.write_new(directory / 'retired.json', {
        'status': 'PASS', 'archive': p.file_pin(directory / 'archive.json'),
        'roots': sorted(expected), 'all_owned_roots_absent': True,
        'reference_evidence': q.pin(p.encoded(proof)), 'restoration_performed': False})
    return evidence(output, binding, proof, source_pins)


def evidence(output, binding, proof, source_pins, *, require_retired=True):
    """Verify retained original trees without opening or reconstructing them."""
    output = Path(output).absolute()
    directory = output / ARCHIVE
    index = p.read_json(p.contained(output, ARCHIVE + '/archive.json'))
    q.same(set(index), {'schema', 'execution_output_root', 'reference_evidence',
                       'source_sha256', 'roots', 'restoration_performed'}, 'exact archive fields')
    q.same(index['schema'], SCHEMA, 'original archive schema')
    q.same(index['execution_output_root'], binding['execution_output_root'], 'actual original origin')
    q.same(index['reference_evidence'], q.pin(p.encoded(proof)), 'complete original predecessor')
    q.same(index['source_sha256'], source_pins, 'source-owned archive producer and readers')
    q.same(index['restoration_performed'], False, 'no fixture restoration claim')
    expected = specifications(output, binding, proof)
    q.same([tree['root'] for tree in index['roots']], sorted(expected), 'exact original archive root set')
    artifacts = {ARCHIVE + '/archive.json': p.file_pin(directory / 'archive.json')}
    grants = 0
    for tree in index['roots']:
        q.same(set(tree), {'root', 'nodes', 'permission_grants'}, 'exact archived tree fields')
        names = {q.unb64(node['path_base64']): node for node in tree['nodes']}
        q.same(len(names), len(tree['nodes']), 'no repeated archived raw path')
        q.same(set(names), set(expected[tree['root']]), 'complete original tree membership')
        granted = set()
        for grant in tree['permission_grants']:
            q.same(set(grant), {'path_base64', 'before', 'granted', 'restored'}, 'complete actual permission journal')
            rel = q.unb64(grant['path_base64'])
            q.require(rel not in granted and rel in names, 'unique owned permission grant')
            granted.add(rel)
            fields = ('kind', 'mode', 'uid', 'gid', 'nlink', 'identity')
            before = {key: names[rel][key] for key in fields}
            q.same(grant['before'], before, 'actual permission preimage')
            q.require(before['kind'] == 'file' and not before['mode'] & 0o400,
                      'only necessary owner-read grant')
            q.same(set(grant['granted']), set(fields), 'complete granted inode metadata')
            q.same(set(grant['restored']), set(fields), 'complete restored inode metadata')
            adjusted = dict(grant['granted'], mode=before['mode'])
            q.same(grant['granted']['mode'], before['mode'] | 0o400, 'only owner-read bit changes')
            archive.exact_inode(before, adjusted, ctime=True)
            archive.exact_inode(before, grant['restored'], ctime=True)
        q.same(granted, {rel for rel, node in names.items()
                        if node['kind'] == 'file' and not node['mode'] & 0o400},
               'every unreadable actual inode has its full grant journal')
        grants += len(granted)
        for rel, node in names.items():
            want = expected[tree['root']][rel]
            q.same(set(node), set(want) | {'path_base64'}, 'exact archived original node fields')
            for key, value in want.items():
                if key == 'data':
                    q.same({k: node['data'][k] for k in ('bytes', 'sha256')}, value,
                           'complete original file content pin')
                else:
                    q.same(node[key], value, 'exact original final metadata ' + key)
            if node['kind'] == 'file':
                item = node['data']
                q.same(set(item), {'bytes', 'sha256', 'file'}, 'complete archived file reference')
                q.same(item['file'], 'blobs/' + item['sha256'] + '.bin', 'content-addressed full bytes')
                path = p.contained(output, ARCHIVE + '/' + item['file'])
                q.same(p.file_pin(path), {key: item[key] for key in ('bytes', 'sha256')}, 'full archived body')
                artifacts[ARCHIVE + '/' + item['file']] = p.file_pin(path)
    archive.closed_links(index['roots'])
    if require_retired:
        receipt = p.read_json(p.contained(output, ARCHIVE + '/retired.json'))
        q.same(receipt, {'status': 'PASS', 'archive': artifacts[ARCHIVE + '/archive.json'],
            'roots': sorted(expected), 'all_owned_roots_absent': True,
            'reference_evidence': q.pin(p.encoded(proof)), 'restoration_performed': False},
            'complete original fixture retirement receipt')
        q.require(all(not os.path.lexists(output / name) for name in expected), 'original fixtures retired')
        artifacts[ARCHIVE + '/retired.json'] = p.file_pin(directory / 'retired.json')
    return {'schema': SCHEMA, 'status': 'PASS', 'fixture_roots': 119,
            'permission_grants': grants, 'reference_evidence': q.pin(p.encoded(proof)),
            'artifact_sha256': {name: value['sha256'] for name, value in sorted(artifacts.items())},
            'artifact_pins': dict(sorted(artifacts.items())), 'native_execution': 0,
            'original_execution': 0, 'fixtures_restored': False,
            'public_handler_complete': False, 'whole_runtime_replaced': False}

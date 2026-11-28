"""Inputs only for three real SDK filesystem methods; no expected responses."""
from pathlib import Path
import copy
import json
import os

SCHEMA = 'hepta.runtime.filesystem-sdk-original-input.v1'
CAPABILITIES = 'io.modelcontextprotocol/clientCapabilities'
PROTOCOL = 'io.modelcontextprotocol/protocolVersion'
TOOLS = ('directory_create', 'file_move', 'directory_move')


def canonical(value): return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()+b'\n'
def path_hex(path): return os.fsencode(path).hex()
def action(kind, path, **extra): return {'kind': kind, 'path_hex': path_hex(path), **extra}


def materialized(fixture_root):
    root = Path(fixture_root).absolute(); allowed, outside = root/'allowed', root/'outside'
    stale, state = root/'stale-policy-root', root/'controller-state'
    host = {'ssh_target': 'uncontacted-filesystem-reference', 'remote_state_dir': '/unused-state', 'allow_write': True,
            'allowed_read_path_prefixes': ['/allowed'], 'allowed_write_path_prefixes': ['/allowed'], 'protected_path_prefixes': ['/allowed/protected']}
    def config(roots, hosts=None): return {'state_dir': str(state), 'controller_workspace_roots': list(map(str, roots)), 'hosts': {'configured': host} if hosts is None else hosts}
    policies = {'disabled': None, 'allowed': config([allowed]), 'denied': config([]), 'missing-first': config([stale, allowed]),
                'allowed-first': config([allowed, stale]), 'missing-only': config([stale]), 'remote': config([allowed])}
    fences = {'legacy': {}, 'required': {'HEPTA_EFFECT_OWNER_FENCE_REQUIRED': '1'},
        'invalid-switch': {'HEPTA_EFFECT_OWNER_FENCE_REQUIRED': '0'},
        'directory-only': {'HEPTA_EFFECT_OWNER_FENCE_DIR': str(root/'unopened-fence')},
        'owner-only': {'HEPTA_EFFECT_OWNER_SELF': 'v4'},
        'both-without-config': {'HEPTA_EFFECT_OWNER_FENCE_DIR': str(root/'unopened-fence'), 'HEPTA_EFFECT_OWNER_SELF': 'v4'}}
    common_setup = [action('mkdir', p) for p in (allowed, outside, stale, state)]
    scenarios = []; next_id = 70000
    def add(name, policy='allowed', fence='legacy', era='modern', capabilities=None, raw_root=False):
        index = len(scenarios); base, exterior = allowed/('s-%03d'%index), outside/('s-%03d'%index)
        workdir = base/('root-\udcff' if raw_root else 'root')
        setup = [action('mkdir', p) for p in (workdir, workdir/'a', workdir/'b', workdir/'tree', workdir/'tree/sub',
            workdir/'keep-tree', workdir/'keep-tree/sub', workdir/'tree2', workdir/'exists-dir', workdir/'left', workdir/'right',
            workdir/'left|right', workdir/' spaced ', workdir/'中🙂', workdir/'raw-\udcff', exterior/'escape')]
        setup += [action('write', workdir/name, data_hex=(b'original '+os.fsencode(name)+b'\x00\n').hex())
            for name in ('file-a', 'file-b', 'exists-file', 'tree/child', 'tree/sub/deep', 'keep-tree/child', 'tree2/child')]
        setup += [action('hardlink', workdir/'hard-file', target_hex=path_hex(workdir/'file-b')),
            action('symlink', workdir/'link-tree', target_hex=path_hex('keep-tree')),
            action('symlink', workdir/'link-file', target_hex=path_hex('file-b')),
            action('symlink', workdir/'dangling', target_hex=path_hex('absent')),
            action('symlink', workdir/'loop-a', target_hex=path_hex('loop-b')),
            action('symlink', workdir/'loop-b', target_hex=path_hex('loop-a')),
            action('symlink', workdir/'escape', target_hex=path_hex(exterior/'escape')),
            action('fifo', workdir/'pipe')]
        row = {'schema': SCHEMA, 'scenario_id': index, 'name': name, 'policy_id': policy, 'fence_id': fence,
               'setup': setup, 'observed_roots': [path_hex(base), path_hex(exterior)], 'sessions': [], 'steps': []}
        scenarios.append(row)
        def session(identifier='a', current_root=None, caps=capabilities):
            initial = []
            if era == 'legacy':
                initial = [{'jsonrpc': '2.0', 'id': 200000+index*10+len(row['sessions']), 'method': 'initialize', 'params': {
                    'protocolVersion': '2025-11-25', 'capabilities': copy.deepcopy(caps or {}),
                    'clientInfo': {'name': 'filesystem-sdk-original', 'version': '1'}}}, {'jsonrpc': '2.0', 'method': 'notifications/initialized'}]
            row['sessions'].append({'id': identifier, 'root_hex': path_hex(current_root or workdir), 'initial_messages': initial})
        session()
        def step(name, kind, identifier='a', domain=None, **fields):
            nonlocal next_id
            entry = {'case_id': next_id, 'name': name, 'session': identifier,
                'domain': domain or ('public-sdk-original-method' if kind == 'public' else 'private-fixture-control'),
                'action': {'kind': kind, **fields}}
            next_id += 1; row['steps'].append(entry); return entry
        def public(label, tool, args, caps=capabilities, metadata=None, identifier='a', omit=False):
            entry = step(label, 'public', identifier); params = {'name': tool}
            if not omit: params['arguments'] = copy.deepcopy(args)
            if metadata is not None: params['_meta'] = copy.deepcopy(metadata)
            elif era == 'modern': params['_meta'] = {PROTOCOL: '2026-07-28', CAPABILITIES: copy.deepcopy(caps or {})}
            entry['action']['message'] = {'jsonrpc': '2.0', 'id': entry['case_id'], 'method': 'tools/call', 'params': params}
            return entry
        return row, workdir, exterior, step, public, session
    def params(tool, source='file-b', destination='new-file'):
        return {'path': source} if tool == 'directory_create' else {'source': source, 'destination': destination}
    for era in ('modern', 'legacy'):
        row, workdir, _, _, public, _ = add(era+'-actual-typed-extraction', era=era)
        for tool in TOOLS:
            public(tool+'-missing-all', tool, {})
            public(tool+'-arguments-omitted', tool, {}, omit=True)
            for i, value in enumerate((None, False, 0, -1, 1.5, 1e-7, [], {}, [1], {'x': '中🙂'})):
                argument = params(tool); argument['path' if tool == 'directory_create' else 'source'] = value
                public(tool+'-wrong-source-%d'%i, tool, argument)
            if tool != 'directory_create':
                public(tool+'-missing-destination', tool, {'source': 'file-b'})
                public(tool+'-both-fields-wrong', tool, {'source': False, 'destination': False})
                public(tool+'-wrong-destination', tool, {'source': 'file-b', 'destination': 17})
        public('first-valid-after-typed-failures', 'directory_create', {'path': 'latched-child'}, caps={'experimental': {'session': {'workdir': str(workdir/'b')}}})
    for era in ('modern', 'legacy'):
        _, workdir, _, _, public, _ = add(era+'-directory-create-real-files', era=era)
        for name, path in [('new-chain', 'new/a/b'), ('repeat-existing', 'new/a/b'), ('existing-directory', 'a'), ('regular-leaf', 'file-b'),
            ('symlink-leaf', 'link-tree'), ('dangling-leaf', 'dangling'), ('fifo-leaf', 'pipe'), ('symlink-parent', 'link-tree/new'),
            ('regular-parent', 'file-b/new'), ('empty', ''), ('blank', ' \t\u3000'), ('NUL', 'new\x00tail'),
            ('interior-dot', 'new/./interior'), ('parent-component', 'a/../new'), ('unicode', '中🙂/created'),
            ('pipe-literal', 'left|right'), ('empty-pipe-alternative', 'left||right'), ('trim-enforce-only', ' spaced '),
            ('outside-symlink', 'escape/new'), ('too-long-component', 'x'*256), ('loop-parent', 'loop-a/new')]:
            public(name, 'directory_create', {'path': path})
        public('unknown-ignored', 'directory_create', {'path': 'unknown-accepted', 'unexpected': {'nested': [False, None, {'x': '中🙂'}]}})
        entry = public('duplicate-key-last-wins', 'directory_create', {'path': 'unused'})
        wire = json.dumps(entry['action']['message'], sort_keys=True, ensure_ascii=True)
        wire = wire.replace('"arguments": {"path": "unused"}', '"arguments": {"path": 13, "path": "duplicate-final"}')
        assert 'duplicate-final' in wire
        entry['action'] = {'kind': 'public', 'wire_hex': (wire+'\n').encode().hex()}
    for tool in ('file_move', 'directory_move'):
        for era in ('modern', 'legacy'):
            _, _, _, _, public, _ = add(era+'-'+tool+'-real-files', era=era)
            source = 'file-a' if tool == 'file_move' else 'tree'; fixed = 'file-b' if tool == 'file_move' else 'keep-tree'
            public('actual-noreplace-success', tool, params(tool, source, 'moved'))
            public('repeat-old-source', tool, params(tool, source, 'moved-again'))
            for name, src, dst in [('equal-path', fixed, fixed), ('destination-file', fixed, 'exists-file'), ('destination-directory', fixed, 'exists-dir'),
                ('destination-symlink', fixed, 'link-file'), ('destination-dangling', fixed, 'dangling'), ('destination-fifo', fixed, 'pipe'),
                ('missing-destination-parent', fixed, 'absent/child'), ('symlink-source', 'link-file' if tool == 'file_move' else 'link-tree', 'refused-link'),
                ('symlink-source-parent', 'link-tree/child', 'refused-parent'), ('symlink-destination-parent', fixed, 'link-tree/new'),
                ('wrong-source-kind', 'keep-tree' if tool == 'file_move' else 'file-b', 'wrong-kind'), ('source-NUL', fixed+'\x00x', 'nul-dest'),
                ('destination-NUL', fixed, 'nul\x00dest'), ('source-parent-component', 'a/../'+fixed, 'dot-dest'),
                ('destination-parent-component', fixed, 'a/../dot-dest'), ('source-outside-symlink', 'escape/item', 'inside'),
                ('destination-outside-symlink', fixed, 'escape/new')]: public(name, tool, params(tool, src, dst))
            if tool == 'file_move': public('regular-hardlink-name', tool, params(tool, 'hard-file', 'hard-moved'))
            else: public('directory-into-own-descendant', tool, params(tool, 'keep-tree', 'keep-tree/sub/new'))
    for tool in ('file_move', 'directory_move'):
        row, workdir, _, step, public, session = add(tool+'-actual-cache-two-sessions'); session('b')
        source = 'file-a' if tool == 'file_move' else 'tree'; destination = 'moved'
        suffixes = [source, destination, 'tree2/child', 'unrelated'] if tool == 'file_move' else [source, source+'/child', source+'/sub/deep', destination+'/child', 'tree2/child', 'unrelated']
        seeds = [{'path_hex': path_hex(workdir/path), 'content': 'cached '+path+'\r\n'} for path in suffixes]
        step('seed-session-a', 'cache_seed', entries=seeds); step('seed-session-b', 'cache_seed', identifier='b', entries=seeds)
        public('move-invalidates-only-own-cache', tool, params(tool, source, destination))
        public('other-session-error-keeps-cache', tool, params(tool, source, 'second-destination'), identifier='b')
        public('same-session-error-keeps-cache', tool, params(tool, source, 'third-destination'))
    _, workdir, exterior, _, public, _ = add('policy-source-destination-and-latch-order')
    public('typed-error-precedes-latch', 'file_move', {'source': False, 'destination': str(exterior/'bad')}, caps={'experimental': {'session': {'workdir': str(workdir/'b')}}})
    public('first-path-error-after-latch', 'file_move', {'source': str(exterior/'outside'), 'destination': ''}, caps={'experimental': {'session': {'workdir': str(workdir/'b')}}})
    public('second-path-error-after-source', 'file_move', {'source': str(workdir/'file-b'), 'destination': ''}, caps={'experimental': {'session': {'workdir': str(workdir/'a')}}})
    public('latched-workdir-persists', 'directory_create', {'path': 'relative-latched'})
    public('source-octofs-before-destination', 'file_move', {'source': 'octofs://resource', 'destination': ''})
    public('destination-octofs-after-source', 'file_move', {'source': str(workdir/'file-b'), 'destination': 'octofs://resource'})
    _, workdir, _, _, public, _ = add('first-no-capabilities-latches')
    public('first-no-caps', 'directory_create', {'path': 'first'})
    public('later-caps-ignored', 'directory_create', {'path': 'second'}, caps={'experimental': {'session': {'workdir': str(workdir/'b')}}})
    _, workdir, _, _, public, _ = add('metadata-before-typed-and-effect')
    public('bad-caps-and-bad-typed', 'directory_create', {'path': False}, metadata={PROTOCOL:'2026-07-28',CAPABILITIES:{'roots':{'listChanged':'wrong'}}})
    public('valid-after-bad-caps', 'directory_create', {'path':'after-meta'}, caps={'experimental':{'session':{'workdir':str(workdir/'b')}}})
    for policy in ('disabled', 'denied', 'missing-first', 'allowed-first', 'missing-only'):
        row, workdir, exterior, step, public, _ = add('actual-'+policy+'-policy-order', policy=policy)
        if 'missing' in policy or policy == 'allowed-first':
            # Each group has its own process; the input action makes a once-present
            # root unavailable before the observed guard calls.
            row['setup'].append(action('mkdir', stale)); step('remove-runtime-root', 'filesystem', actions=[action('remove_dir', stale)])
        for tool in TOOLS:
            public(tool+'-invalid-empty-before-helper', tool, params(tool, '', ''))
            public(tool+'-ordinary-path', tool, params(tool, 'policy-new' if tool == 'directory_create' else 'file-b' if tool == 'file_move' else 'keep-tree', 'policy-dest'))
            public(tool+'-outside-first', tool, params(tool, str(exterior/'escape'), ''))
    _, workdir, _, _, public, _ = add('remote-policy-then-controller-local-helper', policy='remote')
    for tool in TOOLS:
        public(tool+'-configured-write-allowed', tool, params(tool, 'ssh://configured/allowed/item', 'ssh://configured/allowed/dest'))
        public(tool+'-protected-before-helper', tool, params(tool, 'ssh://configured/allowed/protected/item', ''))
        public(tool+'-explicit-user-before-helper', tool, params(tool, 'ssh://u@configured/allowed/item', ''))
    row, workdir, _, _, public, _ = add('directory-root-identity-protection')
    public('configured-controller-root-cannot-move', 'directory_move', {'source': str(allowed), 'destination': str(allowed/'uncreated-root-target')})
    public('nonexistent-source-after-policy', 'directory_move', {'source': 'absent', 'destination': 'new'})
    public('root-containing-sibling-prefix-is-distinct', 'directory_move', {'source': 'keep-tree', 'destination': 'keep-tree2'})
    _, workdir, _, _, public, _ = add('raw-session-root-actual-path-display', raw_root=True)
    public('raw-parent-directory-create', 'directory_create', {'path':'raw-created'})
    public('raw-parent-file-move', 'file_move', {'source':'file-a','destination':'raw-moved'})
    public('raw-parent-directory-move', 'directory_move', {'source':'tree','destination':'raw-tree-moved'})
    row, workdir, _, step, public, _ = add('actual-permission-and-partial-success')
    step('prepare-denied-parent', 'filesystem', actions=[action('mkdir', workdir/'denied/child'), action('chmod', workdir/'denied', mode=0)])
    public('permission-denied', 'directory_create', {'path':'denied/child/new'})
    step('restore-parent-permission', 'filesystem', actions=[action('chmod', workdir/'denied', mode=0o700)])
    public('mkdir-partial-before-long-leaf', 'directory_create', {'path':'partial/new/'+'x'*256})
    public('observe-partial-tree-existing', 'directory_create', {'path':'partial/new'})
    for fence in ('required','invalid-switch','directory-only','owner-only','both-without-config'):
        _, workdir, _, _, public, _ = add('actual-effect-fence-'+fence, policy='disabled' if fence=='both-without-config' else 'allowed', fence=fence)
        for tool in TOOLS:
            argument = params(tool); argument['path' if tool=='directory_create' else 'source'] = False
            public(tool+'-typed-error-before-fence', tool, argument, caps={'experimental':{'session':{'workdir':str(workdir/'b')}}})
            public(tool+'-fence-before-latch-policy-helper', tool, params(tool, '', ''), caps={'experimental':{'session':{'workdir':str(workdir/'b')}}})
    _, workdir, _, _, public, _ = add('wide-public-inputs-without-new-quota')
    public('valid-path-over-eight-MiB', 'directory_create', {'path':'/'*(8*1024*1024+17)+str(workdir/'a').lstrip('/')})
    public('ignored-field-over-eight-MiB', 'directory_create', {'path':'wide-unknown-created','unknown':'u'*(8*1024*1024+31)})
    groups = []
    for row in scenarios:
        key = row['policy_id']+'--'+row['fence_id']
        group = next((g for g in groups if g['name'] == key), None)
        if group is None:
            group = {'name': key, 'policy_id': row['policy_id'], 'fence_id': row['fence_id'], 'scenarios': []}; groups.append(group)
        group['scenarios'].append(row)
    return {'schema': 'hepta.runtime.filesystem-sdk-original-corpus.v1', 'fixture_root': str(root), 'common_setup': common_setup,
            'policies': policies, 'fence_environments': fences, 'groups': groups,
            'counts': {'groups': len(groups), 'scenarios': len(scenarios), 'steps': sum(len(r['steps']) for r in scenarios),
                'public_calls': sum(s['action']['kind']=='public' for r in scenarios for s in r['steps']),
                'private_controls': sum(s['action']['kind']!='public' for r in scenarios for s in r['steps'])}}

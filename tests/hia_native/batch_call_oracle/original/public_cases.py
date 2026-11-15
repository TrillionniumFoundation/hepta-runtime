"""Inputs for the unchanged public Batch method, not expected responses.

These scenarios remain unexecuted until corresponding complete native public
captures are available. Configuration installation and cache seeding are
explicit fixture controls; the method's effect admission/policy/I/O are real.
"""
from pathlib import Path
import copy
import json
import os

CAPABILITIES = 'io.modelcontextprotocol/clientCapabilities'
PROTOCOL = 'io.modelcontextprotocol/protocolVersion'
SCHEMA = 'hepta.runtime.batch-call-sdk-input.v1'


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode() + b'\n'


def materialized(fixture_root):
    root = Path(fixture_root).absolute()
    allowed, outside, missing, state = [root / name for name in
                                      ('allowed', 'outside', 'missing-root', 'state')]
    def config(roots):
        return {'state_dir': str(state), 'controller_workspace_roots': list(map(str, roots)), 'hosts': {}}
    policies = {'disabled': None, 'allowed': config([allowed]), 'empty': config([]),
                'missing-first': config([missing, allowed]), 'allowed-first': config([allowed, missing])}
    fences = {'legacy': {}, 'required': {'HEPTA_EFFECT_OWNER_FENCE_REQUIRED': '1'},
              'invalid-switch': {'HEPTA_EFFECT_OWNER_FENCE_REQUIRED': '0'},
              'directory-only': {'HEPTA_EFFECT_OWNER_FENCE_DIR': str(root / 'unopened-fence')},
              'owner-only': {'HEPTA_EFFECT_OWNER_SELF': 'v4'}}
    scenarios = []
    next_id = 90000

    def action(kind, path, **fields):
        return {'kind': kind, 'path_hex': os.fsencode(path).hex(), **fields}

    def add(name, *, era='modern', policy='allowed', fence='legacy', raw_cwd=False):
        index = len(scenarios)
        base = allowed / ('sdk-%03d' % index)
        cwd = base / ('raw-\udcff' if raw_cwd else 'root')
        other = outside / ('sdk-%03d' % index)
        setup = [action('mkdir', p) for p in (cwd, cwd/'a', cwd/'b', other)]
        for p in (cwd/'file', cwd/'a/file', cwd/'b/file', cwd/' spaced ', cwd/'left|right', other/'file'):
            setup.append(action('write', p, data_hex=b'alpha\nbeta\ngamma\n'.hex(), mode=0o640))
        setup += [action('symlink', cwd/'alias', target_hex=os.fsencode('file').hex()),
                  action('hardlink', cwd/'hardlink', target_hex=os.fsencode(cwd/'file').hex()),
                  action('mkdir', cwd/'directory')]
        row = {'schema': SCHEMA, 'scenario_id': index, 'name': name, 'policy_id': policy,
               'fence_id': fence, 'setup': setup, 'observed_roots': [os.fsencode(base).hex(), os.fsencode(other).hex()],
               'sessions': [], 'steps': []}
        scenarios.append(row)

        def session(identifier='a'):
            initial = []
            if era == 'legacy':
                initial = [{'jsonrpc': '2.0', 'id': 800000 + index*10 + len(row['sessions']),
                            'method': 'initialize', 'params': {'protocolVersion': '2025-11-25',
                            'capabilities': {}, 'clientInfo': {'name': 'batch-original', 'version': '1'}}},
                           {'jsonrpc': '2.0', 'method': 'notifications/initialized'}]
            row['sessions'].append({'id': identifier, 'root_hex': os.fsencode(cwd).hex(), 'initial_messages': initial})
        session()

        def step(label, kind, identifier='a', **fields):
            nonlocal next_id
            entry = {'case_id': next_id, 'name': label, 'session': identifier,
                     'domain': 'public-sdk-original-batch-method' if kind == 'public' else 'private-fixture-control',
                     'action': {'kind': kind, **fields}}
            next_id += 1
            row['steps'].append(entry)
            return entry

        def call(label, args, *, identifier='a', caps=None, metadata=None, omit=False):
            entry = step(label, 'public', identifier)
            params = {'name': 'batch_edit'}
            if not omit: params['arguments'] = copy.deepcopy(args)
            if metadata is not None: params['_meta'] = copy.deepcopy(metadata)
            elif era == 'modern': params['_meta'] = {PROTOCOL: '2026-07-28', CAPABILITIES: copy.deepcopy(caps or {})}
            entry['action']['message'] = {'jsonrpc': '2.0', 'id': entry['case_id'], 'method': 'tools/call', 'params': params}
            return entry
        return row, cwd, other, call, step, session

    def params(path='file', content='prefix', start=0):
        return {'path': path, 'operations': [{'operation': 'insert', 'start': start, 'content': content}]}

    for era in ('modern', 'legacy'):
        row, cwd, other, call, step, session = add(era+'-typed-extraction', era=era)
        call('arguments-omitted', {}, omit=True)
        call('missing-all', {})
        for value in (None, False, 0, 1.5, [], {}):
            value_params = params(); value_params['path'] = value
            call('wrong-path-'+str(len(row['steps'])), value_params)
        for operations in (None, False, 0, 'x', {}, [None], [{}], [{'operation': 'insert', 'start': 0, 'content': [False]}]):
            call('wrong-operations-'+str(len(row['steps'])), {'path': 'file', 'operations': operations})
        call('different-per-operation-paths', {'operations': [dict(params()['operations'][0], path='file'),
                                                           dict(params()['operations'][0], path='other')]})
        call('successful-hoisted-path', {'operations': [dict(params(content='hoisted')['operations'][0], path='file')]},
             caps={'experimental': {'session': {'workdir': str(cwd/'b')}}})
        call('later-capability-does-not-relatch', params(content='later', start=-1),
             caps={'experimental': {'session': {'workdir': str(cwd/'a')}}})

    for policy in policies:
        row, cwd, other, call, step, session = add('policy-order-'+policy, policy=policy)
        if policy in ('missing-first', 'allowed-first'):
            # The configured root exists at installation and becomes missing
            # through an observed real mutation before the method is invoked.
            step('remove-initially-valid-configured-root', 'filesystem',
                 actions=[action('remove_dir', missing)])
        call('typed-before-latch-and-policy', {'path': False, 'operations': []},
             caps={'experimental': {'session': {'workdir': str(cwd/'b')}}})
        call('outer-policy-before-empty-operations', {'path': str(other/'file'), 'operations': []},
             caps={'experimental': {'session': {'workdir': str(cwd/'b')}}})
        call('empty-operation-preflight', {'path': 'absent', 'operations': []})
        call('fifty-one-preflight', {'path': 'absent', 'operations': params()['operations']*51})
        call('ordinary-complete-edit', params(content='policy case'))
        call('empty-tool-path', params(path=''))
        call('literal-pipe-policy-split', params(path='left|right'))
        call('trim-policy-original-path', params(path=' spaced '))
        call('empty-pipe-alternative', params(path='left||right'))
        call('disabled-background-resource', params(path='octofs://resource'))

    for fence in ('required', 'invalid-switch', 'directory-only', 'owner-only'):
        row, cwd, other, call, step, session = add('effect-before-latch-'+fence, fence=fence)
        call('typed-error-before-effect', {'path': False, 'operations': []},
             caps={'experimental': {'session': {'workdir': str(cwd/'b')}}})
        call('effect-before-latch-policy-helper', params(path=str(other/'file')),
             caps={'experimental': {'session': {'workdir': str(cwd/'b')}}})
        call('effect-before-empty-preflight', {'path': 'absent', 'operations': []})

    row, cwd, other, call, step, session = add('metadata-before-typed')
    call('bad-full-capabilities-before-bad-params', {'path': False},
         metadata={PROTOCOL: '2026-07-28', CAPABILITIES: {'roots': {'listChanged': 'wrong'}}})
    call('valid-after-metadata-error', params(), caps={'experimental': {'session': {'workdir': str(cwd/'b')}}})

    for era in ('modern', 'legacy'):
        row, cwd, other, call, step, session = add(era+'-full-local-chain-and-two-session-cache', era=era)
        session('b')
        seeds = [{'path_hex': os.fsencode(cwd/'file').hex(), 'content': 'alpha\nbeta\ngamma\n'}]
        step('seed-session-a', 'cache_seed', entries=seeds)
        step('seed-session-b', 'cache_seed', identifier='b', entries=seeds)
        call('write-updates-own-cache', params())
        call('second-session-writes-and-evicts-stale', params(content='session-b', start=-1), identifier='b')
        call('first-session-stale-cache-evicted', params(content=['array', 'lines'], start=-1))
        call('strict-missing-read', params(path='missing'))
        call('directory-read-error', params(path='directory'))
        call('empty-before-missing', {'path': 'missing', 'operations': []})
        step('prepare-temp-directory', 'filesystem', actions=[action('mkdir', cwd/'.octofs_tmp_file.tmp')])
        call('history-kept-on-atomic-failure', params(content='failure', start=-1))
        step('remove-temp-directory', 'filesystem', actions=[action('remove_dir', cwd/'.octofs_tmp_file.tmp')])
        call('scope-reuse-after-error', params(content='after-error', start=-1))
        call('symlink-replacement', params(path='alias', content='alias-write', start=-1))
        call('hardlink-retains-old-inode', params(path='hardlink', content='hardlink-write', start=-1))

    row, cwd, other, call, step, session = add('raw-unix-workdir', raw_cwd=True)
    call('raw-cwd-complete-local-edit', params())
    grouped = {}
    for row in scenarios:
        key = row['policy_id']+'--'+row['fence_id']
        grouped.setdefault(key, {'name': key, 'policy_id': row['policy_id'], 'fence_id': row['fence_id'], 'scenarios': []})['scenarios'].append(row)
    return {'schema': SCHEMA, 'fixture_root_hex': os.fsencode(root).hex(),
            'common_setup': [action('mkdir', p) for p in (allowed, outside, missing, state)],
            'policies': policies, 'fence_environments': fences, 'groups': list(grouped.values()),
            'original_full_router_executed': False, 'configured_authority_fence_success_domain': 'not-yet-declared'}

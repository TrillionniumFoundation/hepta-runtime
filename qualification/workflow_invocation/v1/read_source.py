"""Read the exact workflow successor, its inverse and retained reporting evidence."""
from pathlib import Path
import ast, copy, hashlib, importlib.util, json, re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())

def read(relative):
    path = HERE / relative
    assert path.is_file() and not path.is_symlink()
    return path.read_bytes()

def inverse(text, row):
    scope = row.get('scope')
    before = after = ''
    middle = text
    if scope == 'after-native':
        before, middle = text.split('\n  native:\n', 1)
        before += '\n  native:\n'
    elif scope == 'native-through-originals':
        before, middle = text.split('\n  native:\n', 1)
        middle, after = middle.split('\n  qualify:\n', 1)
        before += '\n  native:\n'
        after = '\n  qualify:\n' + after
    elif scope == 'qualify':
        before, middle = text.split('\n  qualify:\n', 1)
        before += '\n  qualify:\n'
    elif scope == 'before-qualify':
        middle, after = text.split('\n  qualify:\n', 1)
        after = '\n  qualify:\n' + after
    else:
        assert scope is None
    assert middle.count(row['new']) == row['count']
    return before + middle.replace(row['new'], row['old']) + after

def main():
    package = json.loads(read('MANIFEST.json'))
    actual = {p.relative_to(HERE).as_posix() for p in HERE.rglob('*') if p.is_file()}
    assert actual == set(package['files']) | {'MANIFEST.json'}
    for name, expected in package['files'].items():
        assert pin(read(name)) == expected, name
    changes = json.loads(read('SOURCE_CHANGE.json'))
    workflows = json.loads(read('WORKFLOW_CHANGE.json'))
    for name, row in changes.items():
        path = ROOT / name
        assert path.is_file() and not path.is_symlink()
        old = read('before/' + name)
        raw = path.read_bytes()
        assert pin(old) == row['before'] and pin(raw) == row['after'], name
        if name.endswith('.yml'):
            restored = raw.decode()
            for edit in reversed(workflows[name]['replacements']):
                restored = inverse(restored, edit)
            assert restored.encode() == old
            assert re.findall(r'timeout-minutes: (\d+)', raw.decode()) == re.findall(r'timeout-minutes: (\d+)', old.decode())
        elif name.endswith('/PROFILE.json'):
            current = json.loads(raw)
            prior = json.loads(old)
            restored = copy.deepcopy(current)
            for path in ('.github/workflows/hia-runtime-native.yml', '.github/workflows/hia-runtime-original-shard.yml'):
                restored['current_workflow_files'][path] = prior['current_workflow_files'][path]
            assert (json.dumps(restored, sort_keys=True, indent=2) + '\n').encode() == old
            assert len(current['current_graph_files']) == 544 and len(current['restore']) == 120
            assert current['full_sdk_qualified'] is False and current['production_activated'] is False
        else:
            text = raw.decode()
            start = text.index('    def replay_workflow_artifact_bindings(')
            end = text.index('    def test_batch_families_cannot_be_recombined_or_move_evidence_across_jobs(', start)
            assert pin(text[start:end].encode()) == row['addition']
            restored = text[:start] + text[end:]
            for before, after in row['replacements']:
                assert restored.count(after) == 1
                restored = restored.replace(after, before)
            assert restored.encode() == old
            ast.parse(raw)
            original = set(re.findall(r'^    def (test_\w+)', old.decode(), re.MULTILINE))
            new = set(re.findall(r'^    def (test_\w+)', text, re.MULTILINE))
            assert len(original) == 55 and new - original == set(row['added_methods'])
    for name, expected in json.loads(read('UNCHANGED.json')).items():
        assert pin((ROOT / name).read_bytes()) == expected, name
    for prefix, count in (('NATIVE', 64), ('ORIGINAL', 70)):
        record = json.loads(read('validation/' + prefix + '_CONTROLS.json'))
        assert record['exit_code'] == 0 and record['timed_out'] is False and record['whole_group_gone'] is True
        assert record['timeout_seconds'] == 180 and record['cleanup_seconds'] == 5
        assert record['elapsed_seconds'] < 180
        assert record['source_receipt'] == {key: pin(read('HISTORICAL_PUBLIC_SOURCE.json'))[key] for key in ('bytes', 'sha256')}
        for stream in ('stdout', 'stderr'):
            data = read('validation/' + prefix.lower() + '-controls.' + stream)
            assert record[stream] == {key: pin(data)[key] for key in ('bytes', 'sha256')}
            if stream == 'stderr':
                assert ('Ran ' + str(count) + ' tests in ').encode() in data and data.endswith(b'\nOK\n')
    profile_path = ROOT / 'tests/hia_native/historical_public58/materialize.py'
    spec = importlib.util.spec_from_file_location('workflow_identity_materializer', profile_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    profile, profile_sha = module.check(ROOT)
    historical = json.loads(read('HISTORICAL_PUBLIC_SOURCE.json'))
    assert historical['profile_sha256'] == profile_sha
    assert historical['restored_paths'] == sorted(profile['restore'])
    assert historical['excluded_current_only_paths'] == profile['remove_current_public_only']
    # Reconstruct the source file identities only, without materializing or
    # executing a product. The recorded historical absolute paths stay intact.
    expected = {name: pin(path.read_bytes()) for name, path in module.selected(ROOT).items()}
    for name in profile['remove_current_public_only']:
        del expected[name]
    expected.update(profile['restore'])
    assert expected == historical['files']
    print(json.dumps(dict(status='WORKFLOW_PRODUCER_IDENTITY_SOURCE_AND_RECORDED_CONTROLS_PASS',
        modified_source_paths=len(changes), original_native_reporting_controls=61,
        added_invocation_controls=3, original_recipe_reporting_controls=70,
        whole_runtime_replaced=False, production_activated=False,
        original_45_minute_timeout_root_cause_resolved=False,
        actual_new_github_retry_executed=False), sort_keys=True))

if __name__ == '__main__':
    main()

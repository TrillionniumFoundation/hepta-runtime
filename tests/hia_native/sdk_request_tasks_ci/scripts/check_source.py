"""Check the complete immutable task-registry source package without execution."""
from pathlib import Path
import argparse, ast, hashlib, json, stat

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def check(source):
    source = Path(source).resolve(strict=True)
    raw = (source / 'SOURCE_MANIFEST.json').read_bytes()
    manifest = json.loads(raw)
    assert manifest['schema'] == 'hepta.sdk-request-tasks.source-manifest.v1'
    paths = {str(p.relative_to(source)) for p in source.rglob('*') if p.is_file()}
    assert paths == set(manifest['files']) | {'SOURCE_MANIFEST.json'}
    for name, pin in manifest['files'].items():
        path = source / name
        assert stat.S_ISREG(path.lstat().st_mode) and path.resolve() == path
        value = path.read_bytes()
        assert len(value) == pin['bytes'] and SHA(value) == pin['sha256'], name
        assert hashlib.sha1(b'blob ' + str(len(value)).encode() + b'\0' + value).hexdigest() == pin['git_blob']
        if name.endswith('.py'):
            ast.parse(value, filename=name)
    inputs = json.loads((source / 'SOURCE_INPUTS.json').read_bytes())
    for name, pin in inputs['origins'].items():
        assert manifest['files'][name]['sha256'] == pin['sha256']
        assert manifest['files'][name]['bytes'] == pin['bytes']
    assert inputs['target_commit'] == 'd3d75c30719db966b004756f610007a7c723729e'
    assert inputs['sdk'] == '3.9.0'
    assert inputs['registry_checksum'] == 'd24a7e92f4bcaa36b97fa93c4fa7ca8f3e669eced949345b3462dba333c7f909'
    assert SHA((source / 'reference/target/Cargo.lock').read_bytes()) == '1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631'
    composition = json.loads((source / 'native/sdk_request_task_composition.json').read_bytes())
    for key, name in [('source_sha256', 'native/sdk_request_task_registry.hepta'),
            ('author_sha256', 'authoring/author_registry.py'), ('pseudo_sha256', 'authoring/request_tasks.txt'),
            ('lower_support_sha256', 'authoring/lower_support.py')]:
        assert composition[key] == manifest['files'][name]['sha256']
    assert composition['function_count'] == 37
    assert SHA((source / 'tests/cases.py').read_bytes()) == 'bb8864a410587b75ce6b7902091d70389e34942d4ef001e59863823cda613124'
    assert SHA((source / 'authoring/request_tasks_v1.txt').read_bytes()) == '0fededa03fbc786bce760ee71fbc675543a25cfaf0d2acc6a2dbaac2bb071cbf'
    old_nodes = {n.name:ast.dump(n, include_attributes=False) for n in ast.parse((source / 'authoring/request_tasks_v1.txt').read_bytes()).body}
    new_nodes = {n.name:ast.dump(n, include_attributes=False) for n in ast.parse((source / 'authoring/request_tasks.txt').read_bytes()).body}
    delta = json.loads((source / 'authoring/QUEUE_DELTA.json').read_bytes())
    assert delta['retained_exact_ast'] == sorted(n for n in old_nodes if old_nodes[n] == new_nodes[n])
    assert delta['changed_functions'] == sorted(n for n in old_nodes if old_nodes[n] != new_nodes[n])
    assert set(delta['added_functions']) == set(new_nodes) - set(old_nodes)
    for name in ('full_async_runtime_qualified', 'full_sdk_qualified', 'production_activated',
                 'old_path_removed', 'public_registry_integrated'):
        assert manifest[name] is False and composition[name] is False
    return dict(bytes=len(raw), sha256=SHA(raw), files=len(manifest['files']))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    print(json.dumps(dict(status='SOURCE_CHECK_PASS', source=check(p.parse_args().source)), sort_keys=True))

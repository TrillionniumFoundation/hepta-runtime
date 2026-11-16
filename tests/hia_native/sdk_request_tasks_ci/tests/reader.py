"""Read complete original and native custody; no subprocess or native imports."""
from pathlib import Path
import gzip, hashlib, io, json, tarfile, tomllib
from compare import qualify, same_id
from replay import Replay
from cases import cases

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
COMPILER = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
COMPILER_TREE = '8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49'
B3 = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'


def doc(path):
    return json.loads(path.read_bytes())


def pin(raw):
    return dict(bytes=len(raw), sha256=SHA(raw))


def verify_native(source, build):
    receipt = doc(build / 'BUILD.json')
    assert receipt['status'] == 'PASS' and receipt['fresh_member_compiles'] == 2
    assert receipt['reused_candidate_members'] == 0 and receipt['bootstrap_reused'] is False
    bootstrap = doc(build / 'build/bootstrap/bootstrap.json')
    assert bootstrap['dependency']['commit'] == COMPILER and bootstrap['dependency']['tree'] == COMPILER_TREE
    assert bootstrap['generation_sha256'] == B3
    for generation in ('B1', 'B2', 'B3'):
        assert SHA((build / ('build/bootstrap/' + generation + '.image.bin')).read_bytes()) == B3
    rows = []
    for name, filename in [('request-tasks', 'sdk_request_task_registry.hepta'),
                           ('request-tasks-message', 'sdk_message_target.hepta')]:
        item = receipt['members'][name]
        path = build / item['manifest']; raw = path.read_bytes(); metadata = json.loads(raw)
        assert SHA(raw) == item['manifest_sha256'] and metadata == item['metadata']
        module = path.parent
        source_raw = (source / 'native' / filename).read_bytes()
        assert (module / metadata['source']).read_bytes() == source_raw
        assert (module / 'module.input.bin').read_bytes() == source_raw
        assert metadata['source_sha256'] == SHA(source_raw)
        image = (module / metadata['image']).read_bytes()
        assert metadata['image_sha256'] == SHA(image)
        assert metadata['compiler_commit'] == COMPILER and metadata['compiler_sha256'] == B3
        compile_receipt = doc(module / 'module.receipt.json')
        compile_build = doc(module / 'build.json')
        assert compile_build['compile_receipt'] == compile_receipt
        assert compile_build['compiler_dependency'] == bootstrap['dependency']
        assert compile_receipt['status'] == 'returned' and compile_receipt['abi_status'] == 0
        assert compile_receipt['source_unchanged'] and not compile_receipt['forbidden_compiler_modules_loaded']
        assert compile_receipt['input_sha256'] == compile_receipt['source_sha256'] == SHA(source_raw)
        assert compile_receipt['produced_sha256'] == SHA(image)
        assert compile_receipt['produced_bytes'] == compile_receipt['result_u64'] == len(image)
        output = (module / 'module.output.bin').read_bytes()
        assert output[:len(image)] == image and SHA(output) == compile_receipt['output_sha256']
        rows.append(dict(name=name, manifest_sha256=SHA(raw), image=pin(image), source=pin(source_raw)))
    return rows


def verify_reference_build(source, original):
    summary = doc(original / 'SUMMARY.json'); build = doc(original / 'BUILD.json')
    assert summary['status'] == 'CAPTURED' and summary['cases_completed'] == summary['cases_expected'] == 110
    assert build['fresh_target_dir'] and build['actual_target_sdk_built'] and build['actual_target_sdk_executed']
    assert build['offline_resolution'] and build['all_retained_exactly_match_target']
    assert build['rust_version'].splitlines()[0].startswith('rustc 1.95.0 ')
    assert SHA((original / build['retained_binary_relative_path']).read_bytes()) == build['binary_sha256']
    for name in ('Cargo.toml', 'main.rs'):
        raw = (original / 'oracle' / name).read_bytes()
        assert raw == (source / 'reference/oracle' / name).read_bytes()
        assert build['project_files'][name] == SHA(raw)
    assert build['source_sha256'] == SHA((source / 'reference/oracle/main.rs').read_bytes())
    target_raw = (source / 'reference/target/Cargo.lock').read_bytes()
    assert (original / 'target/Cargo.lock').read_bytes() == target_raw
    target = {(p['name'], p['version'], p.get('source')): p.get('checksum')
              for p in tomllib.loads(target_raw.decode())['package'] if p.get('source')}
    subset = doc(original / 'evidence/target-lock-subset.json')
    assert subset['all_retained_exactly_match_target'] and subset['offline_resolution']
    lock = (original / 'oracle/Cargo.lock').read_bytes()
    assert SHA(lock) == build['fixture_lock_sha256'] == subset['fixture_lock_sha256']
    retained = [{k:p[k] for k in ('name', 'version', 'source', 'checksum')}
                for p in tomllib.loads(lock.decode())['package'] if p.get('source')]
    for package in retained:
        assert target[(package['name'], package['version'], package['source'])] == package['checksum']
    assert retained == subset['retained_registry_packages']
    assert subset['target_lock_sha256'] == SHA(target_raw)
    verified = {}
    for item in build['registry_archive_custody']:
        raw = (original / item['path']).read_bytes(); assert pin(raw) == {k:item[k] for k in ('bytes', 'sha256')}
        assert item['sha256'] == target[(item['name'], item['version'], item['source'])]
        row = next(v for v in subset['registry_source_verification'] if v['name'] == item['name'] and v['version'] == item['version'])
        files = {}
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            for member in archive:
                parts = Path(member.name).parts
                assert parts[0] == item['name'] + '-' + item['version'] and '..' not in parts
                if member.isdir():
                    continue
                assert member.isfile()
                files[Path(*parts[1:]).as_posix()] = SHA(archive.extractfile(member).read())
        assert files == row['source_files'] and len(files) == row['files_verified']
        assert row['archive_sha256'] == row['checksum'] == item['sha256']
        verified[item['name'], item['version']] = row
    assert len(verified) == len(retained)
    sdk = verified['rmcp', '3.9.0']
    assert verified['tokio', '1.53.3']['version'] == '1.53.3'
    inputs = doc(source / 'SOURCE_INPUTS.json')
    for name, origin in inputs['origins'].items():
        prefix = 'reference/original-sdk/'
        if name.startswith(prefix):
            assert sdk['source_files'][name[len(prefix):]] == origin['sha256']
    for directory in ('evidence/cache-prefetch', 'evidence/rust-build-processes'):
        for row in doc(original / directory / 'processes.json'):
            assert row['exit_code'] == 0 and row['timed_out'] is False and row['timeout_seconds'] == 180
            for stream in ('stdout', 'stderr'):
                raw = (original / directory / (row['label'] + '.' + stream)).read_bytes()
                assert len(raw) == row[stream + '_bytes'] and SHA(raw) == row[stream + '_sha256']
    return dict(binary_sha256=build['binary_sha256'], retained_registry_packages=len(retained),
        fixture_lock_sha256=SHA(lock), rmcp_source_sha256=sdk['source_files']['src/service.rs'])


def verify_original(case, original):
    trace = original['trace']
    assert [row['index'] for row in trace] == list(range(len(trace)))
    assert [row['time_ns'] for row in trace] == sorted(row['time_ns'] for row in trace)
    starts = [row['event'] for row in trace if row['event']['kind'] == 'handler_start']
    final = original['final']
    assert [row['label'] for row in starts] == [row['label'] for row in final['tasks']]
    assert all(same_id(row['id'], task['id']) for row, task in zip(starts, final['tasks'], strict=True))
    assert all(row['cancelled'] is False for row in starts)
    sends = [row['event'] for row in trace if row['event']['kind'] == 'send_start']
    assert len(sends) == len(final['sends'])
    for index, (event, send) in enumerate(zip(sends, final['sends'], strict=True)):
        assert event['index'] == send['index'] == index and event['wire'] == send['wire']
        value = json.loads(send['wire'])
        assert value['jsonrpc'] == '2.0' and same_id(value['id'], send['id']) and same_id(send['id'], event['id'])
        terminal = [row['event'] for row in trace if row['event']['kind'] in ('send_done', 'send_aborted')
                    and row['event']['index'] == index]
        assert len(terminal) == 1
        actual_status = 'aborted' if terminal[0]['kind'] == 'send_aborted' else ('done' if terminal[0]['success'] else 'failed')
        assert send['status'] == actual_status
    closes = [row for row in trace if row['event']['kind'] == 'transport_close']
    assert len(closes) == 1 and final['closed']
    drain = next(event for event in original['events'] if event['action']['op'] == 'begin_drain')
    is_cancel = drain['action']['reason'] == 'service_cancel'
    assert final['outer_cancelled'] is is_cancel and closes[0]['event']['outer_cancelled'] is is_cancel
    assert original['quit'] == ('Cancelled' if is_cancel else 'Closed')
    if case['label'].endswith('-deadline'):
        duration = closes[0]['time_ns'] - drain['extra']['begin_ns']
        assert duration >= (2_000_000_000 if is_cancel else 5_000_000_000)
        assert duration < 7_000_000_000
    notifications = [row for row in trace if row['event']['kind'] == 'notification_handler']
    assert len(notifications) == final['notifications'] == sum(e['op'] == 'notify' for e in case['events'])
    assert all(row['event']['kind'] in ('handler_start', 'handler_return', 'send_start', 'send_done',
        'send_aborted', 'receive_eof', 'transport_close', 'notification_handler') for row in trace)
    return dict(trace_events=len(trace), actual_handlers=len(starts), actual_sends=len(sends),
        actual_notifications=len(notifications), actual_drain_ns=closes[0]['time_ns'] - drain['extra']['begin_ns'])


def verify_case(case, original, native):
    original_result = verify_original(case, original)
    replay = Replay(native)
    result = qualify(case, original, replay)
    replay.close()
    result.update(native_calls=len(replay.calls), g1_projections=len(replay.projections))
    return result, original_result


def verify(source, run, *, require_recipe=False):
    corpus = doc(source / 'tests/CORPUS.json')
    assert corpus == cases() == doc(run / 'reference/CORPUS.json')
    native_build = verify_native(source, run / 'native-build')
    original_build = verify_reference_build(source, run / 'reference')
    processes = doc(run / 'reference/processes.json')
    native_processes = doc(run / 'native-processes.json')
    assert len(processes) == len(native_processes) == len(corpus) == 110
    results, original_results = [], []
    for index, (case, process, native_process) in enumerate(zip(corpus, processes, native_processes, strict=True)):
        assert process['index'] == native_process['index'] == index
        assert process['label'] == native_process['label'] == case['label']
        assert process['exit_code'] == native_process['exit_code'] == 0
        assert process['timed_out'] is native_process['timed_out'] is False
        assert process['deadline_seconds'] == native_process['deadline_seconds'] == 60
        assert process['executable_sha256'] == original_build['binary_sha256']
        folder = run / 'reference' / ('case-' + str(index).zfill(3))
        assert process['folder'] == folder.name
        stdin = (folder / 'stdin.jsonl').read_bytes()
        assert stdin == (json.dumps(case, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
        stdout = (folder / 'stdout.jsonl').read_bytes(); stderr = (folder / 'stderr.txt').read_bytes()
        assert not stderr and len(stdout.splitlines()) == 1
        assert process['stdin'] == pin(stdin) and process['stdout'] == pin(stdout) and process['stderr'] == pin(stderr)
        original = json.loads(stdout)
        native = run / 'native' / folder.name
        result, original_result = verify_case(case, original, native)
        result['original_sha256'] = SHA(stdout)
        out = (run / 'native-processes' / (folder.name + '.stdout')).read_bytes()
        err = (run / 'native-processes' / (folder.name + '.stderr')).read_bytes()
        assert not err and pin(out) == native_process['stdout'] and pin(err) == native_process['stderr']
        assert json.loads(out) == result
        assert native_process['runner_sha256'] == SHA((source / 'scripts/run_native.py').read_bytes())
        results.append(result); original_results.append(original_result)
    from evidence_controls import verify_controls
    controls = verify_controls(source, run)
    expected_handlers = sum(e['op'] in ('request', 'finish') for case in corpus for e in case['events'])
    assert sum(r['actual_handlers'] for r in original_results) == expected_handlers
    result = dict(schema='hepta.sdk-request-tasks.complete-readonly.v1', status='READONLY_CURRENT_SDK_TASKS110_PASS',
        cases=len(results), actions=sum(r['actions'] for r in results),
        native_calls=sum(r['native_calls'] for r in results), g1_projections=sum(r['g1_projections'] for r in results),
        actual_handlers=sum(r['actual_handlers'] for r in original_results),
        actual_send_attempts=sum(r['actual_sends'] for r in original_results),
        actual_notifications=sum(r['actual_notifications'] for r in original_results),
        native_build=native_build, original_build=original_build, results=results,
        original_results=original_results, evidence_controls=controls,
        complete_mutable_buffers_verified=True, actual_growth_relocation_verified=True,
        actual_current_sdk_task_map_compared=True, custom_in_process_transport=True,
        public_registry_integrated=False, full_async_runtime_qualified=False, full_sdk_qualified=False,
        async_rw_transport_qualified=False, real_worker_executed=False,
        production_activated=False, old_path_removed=False)
    if require_recipe:
        recipe = doc(run / 'RECIPE.json')
        assert recipe['status'] == 'PASS' and recipe['verification'] == result
        assert recipe['native_cases_completed'] == 110
        assert [r['label'] for r in recipe['stages']] == ['reproduce-author', 'fresh-native-build',
            'fresh-current-reference', 'physical-reader-controls', 'complete-readonly']
        for stage in recipe['stages']:
            assert stage['exit_code'] == 0
            for stream in ('stdout', 'stderr'):
                raw = (run / 'processes' / (stage['label'] + '.' + stream)).read_bytes()
                assert len(raw) == stage[stream + '_bytes'] and SHA(raw) == stage[stream + '_sha256']
    return result

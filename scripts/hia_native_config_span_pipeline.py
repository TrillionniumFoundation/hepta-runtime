"""Bind formal native suites, owned fixture transport and fresh original replay."""
from pathlib import Path
import argparse
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hia_native_config_span_qualification as reader
import hia_native_config_span_fixtures as fixtures

KEY = 'runtime_config_span'
MANIFEST = 'build/config-span-bundle/result.json'
FOLDER = 'config-span'
TESTS = ('test_config_span.py', 'test_config_span_evidence.py')
ORIGINAL_CHECK = 'config-span-guard-original'
ORIGINAL_CONTROLS = 'test_config_span_original_evidence.py'
SOURCE_FILES = (
    'scripts/hia_native_config_span_build.py', 'scripts/hia_native_config_span_qualification.py',
    'scripts/hia_native_config_span_pipeline.py', 'scripts/hia_native_config_span_fixtures.py',
    'scripts/hia_native_runtime_mcp_fixtures.py', 'tests/hia_native/test_config_span.py',
    'tests/hia_native/test_config_span_evidence.py', 'tests/hia_native/test_config_span_original_evidence.py',
    'tests/hia_native/config_span/test_evidence.py',
)


def test_commands(root, output, report):
    root, output = Path(root), Path(output)
    row = report['modules'][KEY]
    reader.same(row.get('manifest'), MANIFEST, 'formal config span manifest location')
    manifest = str(output / MANIFEST)
    base = output / FOLDER
    return {
        TESTS[0]: [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / TESTS[0]),
                   '--manifest', manifest, '--output', str(base / 'native')],
        TESTS[1]: [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / TESTS[1]),
                   '--manifest', manifest, '--native', str(base / 'native'), '--output', str(base / 'controls')],
    }


def wrapper(output, report, completed, name, command, expected):
    rows = [row for row in report.get('checks', ()) if row.get('name') == name]
    reader.need(len(rows) == 1, 'one complete actual wrapper: ' + name)
    row = rows[0]
    reader.same(row.get('command'), command, 'actual wrapper invocation: ' + name)
    reader.same([row.get('exit_code'), row.get('timed_out'), row.get('timeout_seconds')],
                [0, False, 180], 'actual wrapper completion and deadline: ' + name)
    reader.need(not row.get('start_error'), 'actual wrapper startup: ' + name)
    reader.elapsed(row.get('elapsed_seconds'), 180, 'actual wrapper elapsed: ' + name)
    streams = {}
    for kind in ('stdout', 'stderr'):
        raw = reader.inside(output, name + '.' + kind).read_bytes()
        reader.same(reader.bytes_pin(raw), dict(bytes=row.get(kind + '_bytes'), sha256=row.get(kind + '_sha256')),
                    'complete actual wrapper stream: ' + name)
        streams[kind] = raw
    summary = reader.strict_json(streams['stdout'])
    reader.same(summary, expected, 'complete wrapper stdout: ' + name)
    reader.same(row.get('summary'), summary, 'wrapper retained summary: ' + name)
    if completed is not None:
        reader.same(list(completed(output, report, name)), [row, summary], 'completed wrapper callback: ' + name)
    return row, {name + '.' + kind:reader.file_pin(reader.inside(output, name + '.' + kind))
                 for kind in ('stdout', 'stderr')}


def control_evidence(root, output, raw):
    base = output / FOLDER / 'controls'
    binder = reader.Binder(base, 'config-span-controls')
    result = binder.json('RESULT.json')
    expected = dict(schema='hepta.runtime.config-span-evidence-controls.v1', status='PASS', tests_run=8,
                    groups=8, rejected_controls=45, actual_relocation_reader_processes=2,
                    failures=0, errors=0, skipped=0, new_native_calls=0, new_rust_processes=0)
    reader.same({key:result.get(key) for key in expected}, expected, 'all native evidence controls')
    reader.elapsed(result.get('elapsed_seconds'), 180, 'native controls elapsed')
    reader.same(binder.json('BASELINE.json'), raw, 'controls consumed the complete native capture')
    controls = binder.json('controls.json')
    reader.need(len(controls) == len({row['name'] for row in controls}) == 45, 'all distinct physical refusals')
    for row in controls:
        reader.need(row.get('status') == 'REJECTED' and type(row.get('error')) is str and row['error'], 'actual refusal result')
        for name,pin in row['files'].items():binder.file(name, pin)
    processes = binder.json('processes.json')
    reader.need(len(processes) == 2 and processes[0]['pid'] != processes[1]['pid'], 'two actual relocated reader processes')
    binding = binder.json('SOURCE.json')
    capture_source = reader.strict_json(reader.inside(output, FOLDER + '/native/SOURCE.json').read_bytes())
    old_source = Path(capture_source['source_root'])
    old_output = Path(capture_source['build_root']).parents[1]
    for key,name in (('reader','scripts/hia_native_config_span_qualification.py'),
                     ('test','tests/hia_native/config_span/test_evidence.py')):
        reader.same(binding[key], dict(path=str(old_source/name), **reader.file_pin(reader.inside(root,name))), 'actual control source')
    roots = dict(source=str(old_source), build=capture_source['build_root'], capture=str(old_output/FOLDER/'native'))
    reader.same(binding['roots'], roots, 'actual controls original roots')
    reader.same(reader.strict_json(reader.inside(output,FOLDER+'/roots.json').read_bytes()), roots, 'complete roots declaration')
    for suffix,row in zip(('a','b'),processes,strict=True):
        location = old_output / FOLDER / 'controls' / ('relocation-' + suffix)
        relocated = old_output / FOLDER / 'controls' / ('relocated-' + suffix)
        argv = [capture_source['python'],'-I','-B',str(old_source/'scripts/hia_native_config_span_qualification.py'),
                '--roots',str(location/'roots.json'),'--output',str(location/'EVIDENCE.json')]
        reader.process(row, argv, location, 180)
        for stream in ('stdout','stderr'):binder.file('relocation-'+suffix+'/'+stream,row[stream])
        reader.need(binder.data('relocation-'+suffix+'/stderr') == b'', 'relocated reader diagnostics')
        reader.same(binder.json('relocation-'+suffix+'/EVIDENCE.json'), raw, 'complete relocated native evidence')
        reader.same(binder.json('relocation-'+suffix+'/roots.json'),
                    {key:str(relocated/key) for key in ('source','build','capture')}, 'independent relocated owned roots')
        summary = binder.json('relocation-'+suffix+'/stdout')
        reader.same(summary, dict(status='PASS',artifacts=raw['artifacts'],guard_cases=81,private_state_calls=60,
                    semantic_cases=8554,actual_elf_processes=41,new_native_calls=0,new_rust_processes=0,
                    evidence=reader.file_pin(binder.file('relocation-'+suffix+'/EVIDENCE.json'))), 'relocated reader complete result')
    reader.same(binder.json('RELOCATION.json'), dict(complete_equal=True,roots_moved=3,
                actual_reader_processes=2,live_fixture_copied=False), 'complete relocation scope')
    return result, {FOLDER+'/controls/'+name:value for name,value in binder.artifacts.items()}


def qualification_evidence(root, output, report, completed):
    root, output = Path(root), Path(output)
    module = report['modules'][KEY]
    reader.same([module.get('manifest'),module.get('source'),module.get('builder')],
                [MANIFEST,'native/config_directory_owner_span.hepta',KEY], 'registered native span owner')
    reader.same(reader.file_pin(reader.inside(output,MANIFEST))['sha256'],module.get('sha256'),'registered native build')
    roots = dict(source=root,build=(output/MANIFEST).parent,capture=output/FOLDER/'native')
    raw = reader.native_evidence(roots)
    evidence = reader.Evidence(roots)
    old_source,old_output = evidence.old['source'],evidence.old['capture'].parent.parent
    reader.same(str(evidence.old['build']),str(old_output/Path(MANIFEST).parent),'formal build execution root')
    reader.same(str(evidence.old['capture']),str(old_output/FOLDER/'native'),'formal native execution root')
    artifacts, sources = {}, {}
    for name,digest in raw['artifact_sha256'].items():
        kind,relative = name.split('/',1)
        if kind == 'source':sources[relative] = digest;continue
        prefix = Path(MANIFEST).parent if kind == 'build' else Path(FOLDER)/'native'
        artifacts[(prefix/relative).as_posix()] = dict(bytes=raw['artifact_bytes'][name],sha256=digest)
    for name in SOURCE_FILES:
        sources[name] = reader.file_pin(reader.inside(root,name))['sha256']
    reader.same({name:report.get('source_sha256',{}).get(name) for name in sources}, sources,'source-owned complete formal inputs')
    controls,control_artifacts = control_evidence(root,output,raw)
    artifacts.update(control_artifacts)
    artifacts[FOLDER+'/roots.json'] = reader.file_pin(reader.inside(output,FOLDER+'/roots.json'))
    commands = test_commands(old_source,old_output,report)
    invocations = []
    for name,expected in ((TESTS[0],evidence.b['capture'].json('RESULT.json')),(TESTS[1],controls)):
        row,files = wrapper(output,report,completed,name,commands[name],expected)
        invocations.append(row);artifacts.update(files)
    return dict(schema='hepta.runtime.config-span-qualification.v1',status='PASS',native=raw,
                controls=controls,actual_invocations=invocations,source_sha256=dict(sorted(sources.items())),
                execution_source_root=str(old_source),execution_output_root=str(old_output),
                artifact_sha256={name:value['sha256'] for name,value in sorted(artifacts.items())},
                artifact_bytes={name:value['bytes'] for name,value in sorted(artifacts.items())},
                fresh_original_comparison_complete=False,new_native_calls=0,new_rust_processes=0,
                live_fixture_required=False,whole_runtime_replaced=False)


def native_fixture_evidence(root,output,report,completed,*,create=False,native=None):
    native = qualification_evidence(root,output,report,completed) if native is None else native
    return fixtures.retirement(root,output,native,native['execution_output_root'],create=create)


def retained_original(root,output,report,completed):
    root,output = Path(root),Path(output)
    native = qualification_evidence(root,output,report,completed)
    reader.same(native,report.get('config_span_evidence'),'native span evidence before fresh original admission')
    retired = native_fixture_evidence(root,output,report,completed,native=native)
    reader.same(retired,report.get('config_span_fixture_retirement'),'native span fixture retirement')
    restored = fixtures.retained_reconstruction(root,output,retired,native['execution_output_root'])
    oracle = root/'tests/hia_native/config_span/guard_original'
    original_reader = reader.load(oracle/'strict_reference.py','_config_span_fresh_original')
    capture = output/FOLDER/'original'
    original = original_reader.reference_evidence(oracle,capture)
    old_root = Path(native['execution_source_root'])
    old_output = Path(native['execution_output_root'])
    record = reader.strict_json(reader.inside(capture,'RESULT.json').read_bytes())
    reader.same(record['fixture_mode'],'existing-owned','original used the reconstructed native fixture')
    reader.same(original['actual_execution_roots'],dict(source=str(old_root/'tests/hia_native/config_span/guard_original'),
                capture=str(old_output/FOLDER/'original'),fixture=str(old_output/fixtures.ROOTS[0])),'fresh original exact execution roots')
    for left,right in (('input.bin','complete-original-domain-input.bin'),('original.stdout','complete-original-golden-output.bin')):
        reader.need(reader.inside(capture,left).read_bytes() == reader.inside(output,FOLDER+'/native/guard/'+right).read_bytes(),
                    'fresh complete original bytes differ: '+left)
    reconstruction = reader.strict_json(reader.inside(output,fixtures.RESTORE).read_bytes())
    for part in ('before','after'):
        reader.same(reader.strict_json(reader.inside(capture,'fixture-'+part+'.json').read_bytes()),
                    reconstruction[part],'fresh original same reconstructed inode state')
    rustc = record['rustc_executable']['path']
    reader.same(rustc,report['rust_compiler']['invocation_path'],'same selected original compiler')
    command = [sys.executable,'-I','-B',str(old_root/'tests/hia_native/config_span/guard_original/run.py'),
               '--root',str(old_root/'tests/hia_native/config_span/guard_original'),'--output',str(old_output/FOLDER/'original'),
               '--rustc',rustc,'--cargo',str(Path(rustc).with_name('cargo')),'--strace','/usr/bin/strace',
               '--fixture-root',str(old_output/fixtures.ROOTS[0])]
    row,artifacts = wrapper(output,report,completed,ORIGINAL_CHECK,command,
                            {key:value for key,value in record.items() if key not in ('artifact_sha256','artifact_bytes')})
    controls = reader.strict_json(reader.inside(output,FOLDER+'/original-controls/RESULT.json').read_bytes())
    wanted = dict(schema='hepta.runtime.directory-move-guard-reference-evidence-controls.v1',status='PASS',
                  groups=8,refusal_controls=50,physical_relocations=2,relocation_objects_equal=True,
                  original_evidence_unchanged=True,relocated_live_fixtures=0,new_rust_processes=0,new_native_calls=0,
                  filesystem_operations_under_test_executed=False)
    reader.same({key:controls.get(key) for key in wanted},wanted,'all original evidence controls')
    reader.elapsed(controls['elapsed_seconds'],180,'original controls elapsed')
    reader.same(controls['baseline_canonical_sha256'],reader.sha(original_reader.canonical(original)),'controls original evidence binding')
    reader.same(reader.strict_json(reader.inside(output,FOLDER+'/original-controls/BASELINE.json').read_bytes()),original,'complete original controls baseline')
    reader.same(controls['source_sha256'], {str(old_root/'tests/hia_native/config_span/guard_original'/name):
                reader.file_pin(reader.inside(oracle,name)) for name in ('test_reference_evidence.py','strict_reference.py')},
                'actual original evidence control sources')
    reader.need(len(controls['controls']) == len({item['name'] for item in controls['controls']}) == 50
                and all(item['status']=='REJECTED' for item in controls['controls']),'all actual original refusal observations')
    control_command = [sys.executable,'-I','-B',str(old_root/'tests/hia_native'/ORIGINAL_CONTROLS),
                       '--capture',str(old_output/FOLDER/'original'),'--output',str(old_output/FOLDER/'original-controls')]
    control_row,files = wrapper(output,report,completed,ORIGINAL_CONTROLS,control_command,
                                {key:value for key,value in controls.items() if key not in ('controls','source_sha256')})
    artifacts.update(files)
    for name,digest in original['artifact_sha256'].items():
        kind,relative = name.split('/',1)
        if kind=='capture':artifacts[(Path(FOLDER)/'original'/relative).as_posix()] = dict(bytes=original['artifact_bytes'][name],sha256=digest)
    for item in (retired,restored):
        for name,digest in item['artifact_sha256'].items():
            pin = reader.file_pin(reader.inside(output,name));reader.same(pin['sha256'],digest,'fixture artifact unchanged');artifacts[name]=pin
    for name in ('RESULT.json','BASELINE.json'):
        relative = FOLDER+'/original-controls/'+name;artifacts[relative]=reader.file_pin(reader.inside(output,relative))
    return dict(schema='hepta.runtime.config-span-original-comparison.v1',status='PASS',
                guard_cases=81,complete_original_cases=92,excluded_private_abi_cases=11,
                fresh_original_comparison_complete=True,complete_input_bytes_identical=True,
                complete_output_bytes_identical=True,actual_original_wrapper=row,actual_controls_wrapper=control_row,
                original=original,controls=controls,native_fixture_retirement=retired,reconstruction=restored,
                artifact_sha256={name:value['sha256'] for name,value in sorted(artifacts.items())},
                artifact_bytes={name:value['bytes'] for name,value in sorted(artifacts.items())},
                new_native_calls=0,new_rust_processes=0,live_fixture_required=False,whole_runtime_replaced=False)


def execute_original(root,output,report,rustc,record_check,completed):
    root,output,rustc = Path(root),Path(output),Path(rustc)
    native = qualification_evidence(root,output,report,completed)
    reader.same(native,report.get('config_span_evidence'),'native span evidence before original execution')
    retired = native_fixture_evidence(root,output,report,completed,native=native)
    reader.same(retired,report.get('config_span_fixture_retirement'),'admitted native span fixture')
    oracle = root/'tests/hia_native/config_span/guard_original'
    with fixtures.restored(root,output,native,retired,native['execution_output_root']) as fixture:
        command = [sys.executable,'-I','-B',str(oracle/'run.py'),'--root',str(oracle),'--output',str(output/FOLDER/'original'),
                   '--rustc',str(rustc),'--cargo',str(rustc.with_name('cargo')),'--strace','/usr/bin/strace','--fixture-root',str(fixture)]
        record_check(output,report,name=ORIGINAL_CHECK,command=command,timeout=180)
    command = [sys.executable,'-I','-B',str(root/'tests/hia_native'/ORIGINAL_CONTROLS),
               '--capture',str(output/FOLDER/'original'),'--output',str(output/FOLDER/'original-controls')]
    record_check(output,report,name=ORIGINAL_CONTROLS,command=command,timeout=180)
    return retained_original(root,output,report,completed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Read complete formal configuration evidence without executing native or original code.')
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    report = reader.strict_json(args.report.read_bytes())
    native = qualification_evidence(args.root,args.output,report,None)
    reader.same(native,report['config_span_evidence'],'retained formal native report')
    retired = native_fixture_evidence(args.root,args.output,report,None,native=native)
    reader.same(retired,report['config_span_fixture_retirement'],'retained formal fixture report')
    original = retained_original(args.root,args.output,report,None)
    reader.same(original,report['original_rust_comparisons'][KEY],'retained formal original report')
    result = dict(schema='hepta.runtime.config-span-complete-evidence.v1',status='PASS',native=native,
                  retirement=retired,original=original,new_native_calls=0,new_rust_processes=0,
                  live_fixture_required=False,whole_runtime_replaced=False)
    with args.result.open('x') as stream:
        json.dump(result,stream,sort_keys=True,indent=2,allow_nan=False)
        stream.write('\n')
    print(json.dumps(dict(status='PASS',guard_cases=81,original_cases=92,new_native_calls=0,
                          new_rust_processes=0,result=reader.file_pin(args.result)),sort_keys=True),flush=True)

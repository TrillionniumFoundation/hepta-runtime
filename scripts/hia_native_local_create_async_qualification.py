"""Strict held-syscall/poll evidence for the private create_local_file profile.

The ordinary native phase captures the fixed native corpus. Only the explicitly
registered original phase freshly builds the unchanged locked Rust function and
executes its matching corpus. Readers never execute either implementation.
"""
from __future__ import annotations
import importlib.util
import json
import os
import re
from pathlib import Path,PurePosixPath
import sys
import tomllib

import hia_native_local_create_qualification as base
from hia_native_local_create_build import verify_build,source_evidence as build_sources

ROOT=Path(__file__).resolve().parents[1]
FOLDER='local-create/async-held'
DRIVERS='tests/hia_native/local_create/async'
REFERENCE=DRIVERS+'/reference'
TESTS=('test_local_create_async_held.py','test_local_create_async_held_evidence.py')
PROCESS_NAMES=('local-create-async-rust-version','local-create-async-cargo-version',
               'local-create-async-cargo-metadata','local-create-async-rust-build',
               'local-create-async-held-original')
CORPUS_SHA='069ba8299eff7b39583ef8f1be54ff855a7c038f2b5f817f0039659cf77a906e'
FUNCTION_SHA='c0b4807c4ba4ebd00a41987cbfb95d802f17ab391802314f6fdcc6e685aa22fc'
REFERENCE_PINS={
 'Cargo.toml':'5455b86b260ca27a2721ef115b2135bb00b1e88f58380b2db86aa17ffa077b44',
 'Cargo.lock':'e406efc4da7bc4ceff2cdf2a4ff01e942cc6b85695e7556b0a6c1a168c62de0a',
 'file_ops.rs':'487524ea40ebc2fd7ddec1676d927237127b768804a73bddeff0d4dc510d206a',
 'src/main.rs':'b5c43d226a7aebff600b0f83ca2e470d8195ffa0b172b7567ac7fc547e44934e',
 'src/original_function.rs':'42655abb492f1e59f5636f0e0c4316496e54a94966631578eec4e9081610d360',
}
DRIVER_FILES=('owned_trace.py','held_cases.py','run_held.py','held_evidence.py','original_controls.py',
              'cases.json','verify_reference.py','source-extraction.json','PROTOCOL.md')
SOURCE_FILES=(
 'native/local_create_file.hepta','native/local_create_packer.hepta',
 'native/local_create_file_component.json','native/local_create_file_abi.md',
 'scripts/local_create_adapter.S','scripts/hia_native_local_create_build.py',
 'scripts/hia_native_local_create_qualification.py',
 'scripts/hia_native_local_create_async_qualification.py',
 'scripts/hia_native_build.py','scripts/hia_native_loader.py',
 'tests/hia_native/evidence_snapshot.py',
 *('tests/hia_native/'+name for name in TESTS),
 *(DRIVERS+'/'+name for name in DRIVER_FILES),
 *(REFERENCE+'/'+name for name in REFERENCE_PINS),
)
SCOPE=dict(private_create_local_file=True,private_scheduling_profile_only=True,
          async_cancellation_qualified=False,runtime_shutdown_qualified=False,
          arbitrary_tokio_budget_qualified=False,public_handler_qualified=False,
          full_create_file_spec_qualified=False,production_activated=False,
          whole_runtime_replaced=False,old_stack_removal_qualified=False)
COUNTS=dict(held_cases=43,actual_native_root_processes=43,original_process_deadline_seconds=60)
CONTROL_COUNTS=dict(actual_captures=2,process_refusals=10,source_refusals=8,artifact_refusals=20)
ORIGINAL_CONTROL_COUNTS=dict(actual_captures=2,process_refusals=10,source_refusals=4,reference_refusals=8,stream_refusals=4)
sha=base.sha;pin=base.pin;compact=base.compact;exact=base.exact;require=base.require
decode=base.decode;owned=base.owned;finite=base.finite
_READER=None


def driver(name,source_root=ROOT):
    path=owned(source_root,DRIVERS+'/'+name)
    sys.path.insert(0,str(path.parent))
    spec=importlib.util.spec_from_file_location('_local_create_async_'+path.stem,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def reader():
    global _READER
    if _READER is None:_READER=driver('held_evidence.py')
    return _READER


def source_evidence(source_root=ROOT):
    root=Path(source_root).resolve(strict=True);component=build_sources(root)
    files={name:pin(owned(root,name).read_bytes())for name in SOURCE_FILES}
    require(files[DRIVERS+'/cases.json']['sha256']==CORPUS_SHA,'fixed held case corpus changed')
    for name,expected in REFERENCE_PINS.items():
        require(files[REFERENCE+'/'+name]['sha256']==expected,'locked async original differs: '+name)
    identity=decode(owned(root,DRIVERS+'/source-extraction.json').read_bytes())
    original=owned(root,REFERENCE+'/file_ops.rs').read_bytes()
    body=original[identity['function_start']:identity['function_end']]
    require(identity['target_commit']=='737acf6f901e46c57b0b4374e323e0d1132e0d49'
        and len(body)==identity['original_function_bytes']==242
        and sha(body)==identity['function_sha256']==FUNCTION_SHA
        and sha(original)==identity['target_sha256']==REFERENCE_PINS['file_ops.rs'],
        'held reference lost its exact current-target function')
    require(owned(root,REFERENCE+'/src/original_function.rs').read_bytes()
            ==bytes.fromhex(identity['wrapper_prefix_hex'])+body+b'\n',
            'held original include changed the function body')
    require(owned(root,REFERENCE+'/src/main.rs').read_bytes().count(b'include!("original_function.rs");')==1,
            'held driver does not include the exact original function once')
    target=component['target_reference']
    require(target['target_commit']==identity['target_commit']and target['function_sha256']==FUNCTION_SHA,
            'native/original target binding differs')
    lock=tomllib.loads(owned(root,REFERENCE+'/Cargo.lock').read_text())
    registry=[{key:package[key]for key in('name','version','source','checksum')}
              for package in lock['package']if'source'in package]
    require(len(registry)==3,'held reference dependency closure changed')
    return dict(component=component,files=files,reference_registry=registry,
                target_reference=identity,scope=SCOPE)


def execution(output,manifest_path,source_root=ROOT):
    return dict(source_root=str(Path(source_root).resolve()),output=str(Path(output).resolve()),
                manifest=str(Path(manifest_path).resolve()))


def native_capture(output,manifest_path,*,source_root=ROOT,origin=None):
    output=Path(output).resolve(strict=True);root=Path(source_root).resolve(strict=True)
    manifest=Path(manifest_path).resolve(strict=True);verify_build(manifest,source_root=root)
    origin=origin or execution(output,manifest,root)
    require(set(origin)=={'source_root','output','manifest'}and all(reader().absolute(value)for value in origin.values()),
            'held native execution origin differs')
    binary=manifest.parent/'local-create.elf'
    binding=dict(manifest=str(manifest.relative_to(output)),manifest_sha256=sha(manifest.read_bytes()),
                 executable=str(binary.relative_to(output)),executable_identity=pin(binary.read_bytes()))
    captured=reader().capture(output/FOLDER/'native',root/DRIVERS,'native',
        binary_identity=binding['executable_identity'],
        execution=dict(output=origin['output']+'/'+FOLDER+'/native',
                       source=origin['source_root']+'/'+DRIVERS,
                       binary=str(Path(origin['manifest']).parent/'local-create.elf')))
    return dict(schema='hepta.runtime.local-create-held-native-admission.v1',status='PASS',
                source_inputs=source_evidence(root),execution=origin,module=binding,capture=captured,scope=SCOPE)


def core_native_evidence(output,report,*,source_root=ROOT):
    output=Path(output).resolve(strict=True);root=Path(source_root).resolve(strict=True)
    evidence=base.Evidence(output)
    module=base.module_evidence(evidence,report,root)
    summary=evidence.object(FOLDER+'/native-suite.json');origin=summary.get('execution')
    require(type(origin)is dict and set(origin)=={'source_root','output','manifest'}
            and all(reader().absolute(value)for value in origin.values()),'held suite origin differs')
    admission=native_capture(output,owned(output,module['manifest']),source_root=root,origin=origin)
    exact(admission['module'],dict(manifest=module['manifest'],manifest_sha256=module['manifest_sha256'],
          executable=module['executable'],executable_identity=pin(evidence.read(module['executable']))),
          'held native corpus did not execute the registered compiled ELF')
    progress=evidence.read(FOLDER+'/native.driver.stdout').splitlines()
    require(len(progress)==44,'complete held native progress differs')
    for index,(line,spec)in enumerate(zip(progress[:-1],reader().corpus(root/DRIVERS)['cases'],strict=True)):
        exact(decode(line),dict(case=index+1,name=spec['name'],mode='native',status='PASS'),
              'held native progress does not cover every fixed case')
    exact(decode(progress[-1]),evidence.object(FOLDER+'/native/summary.json'),'actual held native driver summary differs')
    stdout,stderr,row=base.process(evidence,report,TESTS[0],
        base.suite_command(report,TESTS[0],origin['source_root']),'native_components')
    text=stderr.decode('utf-8')
    require(len(re.findall(r'\.\.\. ok\n',text))==1
            and re.search(r'\nRan 1 test in [0-9.]+s\n\nOK\n\Z',text),
            'the one complete held native unittest did not pass')
    actual=decode(stdout)
    exact(row.get('summary'),actual,'held native actual process summary differs')
    expected=dict(schema='hepta.runtime.local-create-held-native-suite.v1',status='PASS',
        tests_run=1,expected_tests=1,failures=0,errors=0,skipped=0,expected_failures=0,unexpected_successes=0,
        counts=COUNTS,source_inputs=source_evidence(root),execution=origin,sources_unchanged=True,
        manifest_sha256=module['manifest_sha256'],capture_sha256=sha(compact(admission)),scope=SCOPE)
    exact(summary,expected,'held native suite source/domain/counts differ')
    exact(actual,summary,'held native suite complete stdout differs')
    artifacts=dict(evidence.artifact_sha256)
    artifacts.update({FOLDER+'/native/'+name:value for name,value in admission['capture']['artifact_sha256'].items()})
    return dict(status='PASS',counts=COUNTS,source_inputs=admission['source_inputs'],module=admission['module'],
                execution=origin,capture=admission['capture'],artifact_sha256=dict(sorted(artifacts.items())),scope=SCOPE)


def native_evidence(output,report,*,source_root=ROOT):
    result=core_native_evidence(output,report,source_root=source_root)
    evidence=base.Evidence(output);origin=result['execution']['source_root']
    summary=base.process(evidence,report,TESTS[1],base.suite_command(report,TESTS[1],origin),
                         'native_components',groups=4)
    exact(evidence.object(FOLDER+'/evidence-controls.json'),summary,'held control stdout differs')
    expected=dict(schema='hepta.runtime.local-create-held-evidence-controls.v1',status='PASS',
        tests_run=4,expected_tests=4,failures=0,errors=0,skipped=0,expected_failures=0,unexpected_successes=0,
        counts=CONTROL_COUNTS,source_inputs=source_evidence(source_root),native_evidence_sha256=sha(compact(result)),
        new_native_calls=0,synthetic_receipt_controls=True,scope=SCOPE)
    exact(summary,expected,'held evidence refusal domain/source/scope differs')
    result['evidence_controls']=CONTROL_COUNTS
    result['artifact_sha256'].update(evidence.artifact_sha256)
    result['artifact_sha256']=dict(sorted(result['artifact_sha256'].items()))
    return result


BUILD_VARIABLES=tuple(sorted(set(base.BUILD_VARIABLES)|{'RUSTC'}))


def build_override(key):
    return key in BUILD_VARIABLES or key.startswith('CARGO_PROFILE_')or(
        key.startswith('CARGO_TARGET_')and key.endswith(('_RUSTFLAGS','_LINKER','_RUNNER')))


def reference_environment(inherited,rustc):
    env=dict(inherited);removed=sorted(key for key in env if build_override(key))
    for key in removed:env.pop(key,None)
    selected=dict(RUSTC=str(rustc),CARGO_ENCODED_RUSTFLAGS='',RUSTC_WRAPPER='',RUSTC_WORKSPACE_WRAPPER='')
    env.update(selected)
    return env,dict(selected=selected,removed_inherited_variables=removed,
        removal_policy=dict(names=list(BUILD_VARIABLES),cargo_profile_prefix=True,
                            cargo_target_suffixes=['_RUSTFLAGS','_LINKER','_RUNNER']))


def original_commands(output,rustc,*,source_root=ROOT,python=None):
    output=Path(output);folder=output/FOLDER/'reference';rustc=Path(rustc);cargo=rustc.with_name('cargo')
    python=python or sys.executable;config=['--config','build.rustc='+json.dumps(str(rustc))]
    target='x86_64-unknown-linux-gnu'
    binary=folder/'target'/target/'release/hepta-local-create-original-oracle'
    return {
        PROCESS_NAMES[0]:[str(rustc),'--version','--verbose'],
        PROCESS_NAMES[1]:[str(cargo),'--version'],
        PROCESS_NAMES[2]:[str(cargo),*config,'metadata','--locked','--format-version=1',
                         '--filter-platform',target,'--manifest-path',str(folder/'source/Cargo.toml')],
        PROCESS_NAMES[3]:[str(cargo),*config,'build','--locked','--release','--target',target,
                         '--manifest-path',str(folder/'source/Cargo.toml'),'--target-dir',str(folder/'target')],
        PROCESS_NAMES[4]:[python,'-I','-B',str(Path(source_root)/DRIVERS/'run_held.py'),
                         '--binary',str(binary),'--output',str(output/FOLDER/'original'),'--mode','rust'],
    }


def original_capture(output,report,rustc,*,source_root=ROOT):
    output=Path(output).resolve(strict=True);root=Path(source_root).resolve(strict=True)
    evidence=base.Evidence(output);source=source_evidence(root)
    native=native_evidence(output,report,source_root=root)
    receipt=evidence.object(FOLDER+'/reference/reference-build.json')
    require(receipt.get('status')in('REFERENCE_EXECUTED','PASS'),'fresh held original build/replay did not complete')
    exact(receipt.get('source_inputs'),source,'held original source custody differs')
    exact(receipt.get('scope'),SCOPE,'held original scope differs')
    exact((receipt.get('fresh_target_directory'),receipt.get('fresh_locked_builds')),(True,1),
          'held original did not use one fresh locked target')
    for name in REFERENCE_PINS:
        require(evidence.read(FOLDER+'/reference/source/'+name)==owned(root,REFERENCE+'/'+name).read_bytes(),
                'fresh held original source differs: '+name)
    origin=receipt['execution']
    require(type(origin)is dict and set(origin)=={'source_root','output','python'}
            and all(reader().absolute(value)for value in origin.values()),'held original origin differs')
    commands=original_commands(origin['output'],rustc,source_root=Path(origin['source_root']),python=origin['python'])
    exact(receipt['commands'],commands,'held original exact process inventory differs')
    compilers={'rustc':base.compiler_identity(rustc),'cargo':base.compiler_identity(Path(rustc).with_name('cargo'))}
    exact(receipt.get('compiler_before'),compilers,'held original compiler bytes changed before capture')
    exact(receipt.get('compiler_after'),compilers,'held original compiler bytes changed after capture')
    binding=receipt['environment_binding'];removed=binding.get('removed_inherited_variables')
    require(type(removed)is list and removed==sorted(set(removed))and all(type(key)is str and build_override(key)for key in removed),
            'held original environment removal receipt differs')
    _,want_binding=reference_environment({name:'removed'for name in removed},rustc)
    exact(binding,want_binding,'held original controlled compiler environment differs')
    replay_summary=None
    for name in PROCESS_NAMES:
        stdout,stderr,row=base.process(evidence,report,name,commands[name],'original_rust_comparison')
        exact(row.get('environment_binding'),binding,'actual held original process environment differs')
        if name==PROCESS_NAMES[0]:
            require(stdout.startswith(b'rustc 1.95.0 ')and b'host: x86_64-unknown-linux-gnu\n'in stdout and not stderr,
                    'held original Rust release/platform differs')
        elif name==PROCESS_NAMES[1]:require(stdout.startswith(b'cargo 1.95.0 ')and not stderr,'held original Cargo release differs')
        elif name==PROCESS_NAMES[2]:base.metadata_evidence(stdout,source)
        elif name==PROCESS_NAMES[3]:require(stdout==b'','held original build wrote unexpected stdout')
        else:
            require(not stderr,'held original driver leaked diagnostics')
            lines=stdout.splitlines();require(len(lines)==44,'complete held original replay progress is missing')
            for index,(line,spec)in enumerate(zip(lines[:-1],reader().corpus(root/DRIVERS)['cases'],strict=True)):
                exact(decode(line),dict(case=index+1,name=spec['name'],mode='rust',status='PASS'),
                      'held original replay case progress differs')
            replay_summary=decode(lines[-1])
    binary_relative=FOLDER+'/reference/target/x86_64-unknown-linux-gnu/release/hepta-local-create-original-oracle'
    binary_bytes=evidence.read(binary_relative)
    require(binary_bytes.startswith(b'\x7fELF'),'fresh held original executable is not retained')
    exact(receipt.get('executable'),dict(path=binary_relative,**pin(binary_bytes)),'fresh held original executable custody differs')
    original=reader().capture(output/FOLDER/'original',root/DRIVERS,'rust',binary_identity=pin(binary_bytes),
        execution=dict(output=origin['output']+'/'+FOLDER+'/original',source=origin['source_root']+'/'+DRIVERS,
                       binary=origin['output']+'/'+binary_relative))
    exact(replay_summary,evidence.object(FOLDER+'/original/summary.json'),'held original actual complete stdout differs')
    pair=reader().compare(output/FOLDER/'native',output/FOLDER/'original',root/DRIVERS,
        native_identity=native['module']['executable_identity'],rust_identity=pin(binary_bytes),
        native_execution=dict(output=native['execution']['output']+'/'+FOLDER+'/native',
            source=native['execution']['source_root']+'/'+DRIVERS,
            binary=str(Path(native['execution']['manifest']).parent/'local-create.elf')),
        rust_execution=dict(output=origin['output']+'/'+FOLDER+'/original',source=origin['source_root']+'/'+DRIVERS,
            binary=origin['output']+'/'+binary_relative))
    exact(pair['native'],native['capture'],'paired comparison did not consume the admitted native capture')
    exact(pair['rust'],original,'paired comparison did not consume the fresh original capture')
    artifacts=dict(native['artifact_sha256']);artifacts.update(evidence.artifact_sha256)
    artifacts.update({FOLDER+'/original/'+name:value for name,value in original['artifact_sha256'].items()})
    return dict(status='PASS',case_count=43,actual_native_root_processes=43,actual_original_root_processes=43,
        complete_compared_bytes=pair['complete_compared_bytes'],source_inputs=source,
        native_capture_sha256=sha(compact(native['capture'])),original_capture_sha256=sha(compact(original)),
        actual_original_processes=list(PROCESS_NAMES),fresh_locked_builds=1,
        artifact_sha256=dict(sorted(artifacts.items())),scope=SCOPE)


def original_evidence(output,report,rustc,*,source_root=ROOT):
    result=original_capture(output,report,rustc,source_root=source_root)
    evidence=base.Evidence(output);summary=evidence.object(FOLDER+'/original-controls.json')
    expected=dict(schema='hepta.runtime.local-create-held-original-controls.v1',status='PASS',
        counts=ORIGINAL_CONTROL_COUNTS,source_inputs=source_evidence(source_root),
        original_evidence_sha256=sha(compact(result)),new_native_or_rust_processes=0,
        synthetic_receipt_controls=True,scope=SCOPE)
    exact(summary,expected,'held original strict refusal domain/source/scope differs')
    result['original_evidence_controls']=ORIGINAL_CONTROL_COUNTS
    result['artifact_sha256'].update(evidence.artifact_sha256)
    result['artifact_sha256']=dict(sorted(result['artifact_sha256'].items()))
    return result


def compare_original(output,report,rustc):
    import qualify_hia_runtime_native as q
    output=Path(output).resolve(strict=True);rustc=Path(rustc)
    native=native_evidence(output,report)
    folder=output/FOLDER/'reference';folder.mkdir(exist_ok=False)
    source=source_evidence();before={'rustc':base.compiler_identity(rustc),'cargo':base.compiler_identity(rustc.with_name('cargo'))}
    environment,binding=reference_environment(q.qualification_env(),rustc)
    for name in REFERENCE_PINS:
        path=folder/'source'/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as stream:stream.write(owned(ROOT,REFERENCE+'/'+name).read_bytes())
    require(not(folder/'target').exists(),'held original target directory was not fresh')
    commands=original_commands(output,rustc)
    receipt=dict(schema='hepta.runtime.local-create-held-reference-build.v1',status='BUILDING',source_inputs=source,
        scope=SCOPE,fresh_target_directory=True,fresh_locked_builds=1,compiler_before=before,compiler_after=None,
        environment_binding=binding,commands=commands,
        execution=dict(source_root=str(ROOT),output=str(output),python=sys.executable))
    def save():(folder/'reference-build.json').write_bytes(compact(receipt)+b'\n')
    save()
    try:
        for name in PROCESS_NAMES:
            q.record_check(output,report,name=name,command=commands[name],timeout=180,env=environment)
            report['checks'][-1]['environment_binding']=binding;q.save_report(output/'result.json',report)
        receipt['compiler_after']={'rustc':base.compiler_identity(rustc),'cargo':base.compiler_identity(rustc.with_name('cargo'))}
        exact(receipt['compiler_after'],before,'held original compiler changed during actual build/replay')
        binary=folder/'target/x86_64-unknown-linux-gnu/release/hepta-local-create-original-oracle'
        receipt['executable']=dict(path=str(binary.relative_to(output)),**pin(binary.read_bytes()))
        receipt['status']='REFERENCE_EXECUTED';save()
        result=original_capture(output,report,rustc)
        exact(source_evidence(),source,'held source closure changed during actual original replay')
        receipt['status']='PASS';save()
        sys.path.insert(0,str(ROOT/'tests/hia_native'))
        driver('original_controls.py').run(output,report,rustc,sys.modules[__name__],ROOT)
        return original_evidence(output,report,rustc)
    except BaseException as error:
        receipt['status']='FAIL';receipt['error']=repr(error);save();raise

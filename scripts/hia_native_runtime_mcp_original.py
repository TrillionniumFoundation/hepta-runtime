"""Shared unchanged Rust reference admission for the public capacity consumer.

No Rust process is started here. The ten-command explicit 1.95 development
capture and the existing nine-command CI capture keep their actual receipts;
only the field lookup below is normalized in memory for a common comparator.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path
import tempfile
from hia_native_runtime_mcp_evidence import Evidence, compact, decode, exact, finite, owned, require, sha

RUSTC_SHA='bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6'
CARGO_SHA='841072d1d92f9e841d9ba5b0814182a0adf064acf4527cd120967b7bc49dcb66'
RUST_VERSION=b'rustc 1.95.0 (59807616e 2026-04-14)\n'
CLEARED=('RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC_BOOTSTRAP','RUSTFLAGS',
         'CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','RUST_TARGET_PATH','CARGO_NET_OFFLINE')
VIEW_BINARIES=('hepta-view-call-original-oracle','view_call_sdk','view_call_router_sdk',
               'view_call_public_schema','view_call_info_sdk')
VIEW_REPLAYS=(('original','hepta-view-call-original-oracle','input.bin','fixtures'),
              ('sdk','view_call_sdk','sdk-input.jsonl',None),
              ('parameter','view_call_sdk','parameter-input.jsonl',None),
              ('wide','hepta-view-call-original-oracle','wide-input.bin','wide-fixtures'),
              ('router','view_call_router_sdk','router-input.jsonl',None),
              ('public-schema','view_call_public_schema',None,None),
              ('info','view_call_info_sdk','info-input.jsonl',None))


def module(name,path):
    spec=importlib.util.spec_from_file_location('_runtime_mcp_original_'+name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))


def relative(evidence,path):
    require(Path(path).is_relative_to(evidence.output),'shared original outside retained output owner')
    return str(Path(path).relative_to(evidence.output))


def read(evidence,folder,name,expected=None):
    raw=evidence.read(relative(evidence,folder/name))
    if expected is not None:exact(pin(raw),expected,'complete shared original artifact differs: '+name)
    return raw


def tool_path(value,name):
    require(type(value) is str and Path(value).is_absolute() and '..' not in Path(value).parts
            and Path(value).name==name and Path(value).parent.name=='bin'
            and Path(value).parent.parent.name=='1.95.0-x86_64-unknown-linux-gnu',
            'explicit original 1.95 executable required: '+name)
    return value


def view_reference(root,original,evidence):
    original=Path(original);root=Path(root)
    result=decode(read(evidence,original,'result.json'))
    require(type(result) is dict and result.get('status') in ('REFERENCE_READY','PASS'),'shared view original did not complete')
    explicit=result.get('schema') is None and 'compiler' in result
    harness=root/'tests/hia_native/view_call_oracle'
    source=module('view_sources',harness/'verify_sources.py')
    driver=module('view_driver',harness/'run.py')
    current={str(path.relative_to(harness)):pin(path.read_bytes()) for path in harness.rglob('*')
             if path.is_file() and '__pycache__' not in path.parts and path.suffix!='.pyc'}
    if explicit:
        exact(result['source_inputs']['harness'],current,'shared exact original harness identity differs')
        require(result.get('original_sources_unchanged') is True and result.get('fresh_original_builds')==1
                and result.get('actual_original_replays')==7 and result.get('compiler_version_processes')==2,
                'explicit original process/source claims differ')
        require(result.get('whole_view_handler_executed') is False and result.get('whole_runtime_complete') is False,
                'explicit original exceeded its function/fixture domain')
    else:
        exact(result.get('schema'),'hepta.runtime.view-call-original-reference.v1','shared original schema differs')
        exact(result.get('harness_inputs'),current,'shared CI original harness identity differs')
        require(result.get('harness_unchanged') is True and result.get('whole_view_migrated') is False
                and result.get('whole_runtime_replaced') is False,'shared CI original source/scope differs')
    # Re-extract current frozen original functions. This creates no Rust process
    # and compares every generated carrier byte, not a declared hash alone.
    with tempfile.TemporaryDirectory(prefix='runtime-mcp-original-source-') as temporary:
        crate=Path(temporary)/'crate';materialized=source.materialize(root,crate)
        exact(result['materialization'],materialized,'unchanged original extraction differs')
        generated={}
        for path in sorted(crate.rglob('*')):
            if not path.is_file():continue
            name=str(path.relative_to(crate));raw=read(evidence,original,'crate/'+name)
            exact(raw,path.read_bytes(),'original carrier differs from exact original bodies: '+name)
            generated[name]=pin(raw)
        if explicit:exact(result['source_inputs']['crate'],generated,'explicit materialized source inventory differs')
    original_inputs={name:pin((root/name).read_bytes()) for name in source.SOURCE_FILES}
    binary_pins={}
    for name in VIEW_BINARIES:
        raw=read(evidence,original,'target/release/'+name,result['binaries'][name])
        require(raw.startswith(b'\x7fELF'),'original binary is not ELF');binary_pins[name]=pin(raw)
    receipts=decode(read(evidence,original,'process-receipts.json'))
    exact(receipts,result['processes'],'shared original receipt copy differs')
    names=['rustc-version','cargo-version','build'] if explicit else ['rust-version','build']
    names += [row[0] for row in VIEW_REPLAYS]
    require(len(receipts)==len(names),'shared original real process count differs')
    build=receipts[2 if explicit else 1]
    command=build['command'];cargo=tool_path(command[0],'cargo')
    marker=command.index('--manifest-path');origin=Path(command[marker+1]).parent.parent
    require(origin.is_absolute() and str(origin)==str(origin.absolute()) and '..' not in origin.parts,'original execution output path differs')
    rustc=tool_path(receipts[0]['command'][0],'rustc')
    cwd=receipts[0]['cwd'] if explicit else str(origin/'crate')
    expected_build=([cargo,'build','--locked','--release','--bins','-j','2','--manifest-path',str(origin/'crate/Cargo.toml'),
                     '--target-dir',str(origin/'target')] if explicit else
                    [cargo,'build','--locked']+(['--offline'] if result.get('explicit_offline') is True else [])+['--manifest-path',str(origin/'crate/Cargo.toml'),'--release'])
    expected_commands=[[rustc,'-vV'],[cargo,'-vV'],expected_build] if explicit else [[rustc,'--version'],expected_build]
    inputs={}
    for name,binary,incoming,fixtures in VIEW_REPLAYS:
        argv=[str(origin/'target/release'/binary)]
        if fixtures:argv.append(str(origin/fixtures))
        expected_commands.append(argv)
        if incoming:inputs[incoming]=read(evidence,original,incoming)
    streams={}
    for index,(name,row,expected_command) in enumerate(zip(names,receipts,expected_commands)):
        exact(row.get('command'),expected_command,'actual original argv differs: '+name)
        exact(row.get('cwd'),cwd,'actual original cwd differs: '+name)
        require(type(row.get('exit_code')) is int and row['exit_code']==0 and row.get('timed_out') is False,
                'original process failed: '+name)
        timeout=20 if explicit and index<2 else (180 if name=='build' or not explicit else 60)
        exact(row.get('timeout_seconds'),timeout,'original real process timeout differs: '+name)
        require(finite(row.get('elapsed_seconds'),timeout),'original elapsed not finite/in budget: '+name)
        if explicit:
            exact(row.get('environment'),dict(RUSTC=rustc,cleared=list(CLEARED)),'explicit original environment differs')
            expected_sha=RUSTC_SHA if name=='rustc-version' else CARGO_SHA if name in ('cargo-version','build') else binary_pins[Path(expected_command[0]).name]['sha256']
            exact(row.get('executable_sha256'),expected_sha,'original executed binary SHA differs: '+name)
        else:
            exact(row.get('name'),name,'shared CI receipt name differs')
            require(row.get('spawn_error') is None,'shared original process start failed')
        incoming=next((filename for task,_,filename,_ in VIEW_REPLAYS if task==name),None)
        if explicit:
            exact(row.get('stdin'),pin(inputs[incoming]) if incoming else pin(b''),
                  'actual original stdin differs: '+name)
        for suffix in ('stdout','stderr'):
            filename=name+'.'+suffix;raw=read(evidence,original,filename,row[suffix]);streams[filename]=pin(raw)
            if suffix=='stderr' and name!='build':exact(raw,b'','unexpected original stderr: '+name)
    version=read(evidence,original,names[0]+'.stdout')
    require(version.startswith(RUST_VERSION),'actual original compiler version differs')
    cache=read(evidence,original,'target/.rustc_info.json',result.get('target_rustc_info'))
    require(RUST_VERSION[:-1] in cache,'actual Cargo target did not record Rust 1.95')
    if explicit:
        exact(read(evidence,original,'target-rustc-info.json'),cache,'retained target compiler cache differs')
        compiler=decode(read(evidence,original,'compiler.json'))
        exact(compiler,result['compiler'],'explicit compiler proof copy differs')
        exact(compiler['rustc_process'],receipts[0],'explicit compiler version receipt differs')
        exact(compiler['cargo_process'],receipts[1],'explicit cargo version receipt differs')
        exact(compiler['rustc_sha256'],RUSTC_SHA,'original rustc binary SHA differs')
        exact(compiler['cargo_sha256'],CARGO_SHA,'original cargo binary SHA differs')
        exact(compiler['rustc_version'].encode(),version,'full Rust version stream differs')
        exact(compiler['cargo_version'].encode(),read(evidence,original,'cargo-version.stdout'),'full Cargo version differs')
        exact(result['streams'],{**streams,**{name:pin(raw) for name,raw in inputs.items()}},'explicit complete stream inventory differs')
    else:
        exact(result['build_environment']['RUSTC'],rustc,'shared CI RUSTC differs from explicit compiler')
        exact(result['build_environment']['CARGO_TARGET_DIR'],str(origin/'target'),'shared CI target directory differs')
    exact(result['reference'],driver.reference_summary(original),'recounted full original filesystem/SDK streams differ')
    exact(result['additional_reference'],driver.additional_reference_summary(original),'recounted SDK/schema/wide streams differ')
    normalized=dict(independent_input=pin(inputs['input.bin']),original_output=streams['original.stdout'],
        additional_inputs={name:pin(inputs[name]) for name in ('parameter-input.jsonl','wide-input.bin','router-input.jsonl','info-input.jsonl')},
        additional_outputs={name:streams[name] for name in ('parameter.stdout','wide.stdout','router.stdout','public-schema.stdout','info.stdout')})
    return dict(status='REFERENCE_READY',processes=len(receipts),fresh_builds=1,replays=7,explicit_development_format=explicit,
        original_execution_root=str(origin),original_execution_cwd=cwd,rustc=rustc,cargo=cargo,
        binary_pins=binary_pins,source_inputs=original_inputs,normalized=normalized,
        original_view_handler_executed=False,actual_sdk_adapter_fixture=True)


def workdir_reference(root,original,evidence):
    helper=module('workdir_evidence',root/'scripts/hia_native_workdir_reference.py')
    admitted=helper.reference_evidence(root,original)
    for name,expected in admitted['artifact_sha256'].items():
        raw=read(evidence,original,name);exact(sha(raw),expected,'full admitted Workdir artifact differs: '+name)
    pins=decode(read(evidence,original,'source-pins.json'))
    tool_path(pins['executables']['rustc']['invocation'],'rustc')
    tool_path(pins['executables']['cargo']['invocation'],'cargo')
    exact(pins['executables']['rustc']['sha256'],RUSTC_SHA,'Workdir actual rustc SHA differs')
    exact(pins['executables']['cargo']['sha256'],CARGO_SHA,'Workdir actual cargo SHA differs')
    exact(read(evidence,original,'rust-version.stdout'),RUST_VERSION,'Workdir actual Rust version differs')
    cache=read(evidence,original,'target/.rustc_info.json')
    require(RUST_VERSION[:-1] in cache,'Workdir Cargo target compiler differs')
    return dict(status='REFERENCE_READY',processes=admitted['recorded_processes'],fresh_builds=1,replays=7,
        original_execution_root=decode(read(evidence,original,'result.json'))['execution_output_root'],
        binary_pin={k:pins['executables']['original'][k] for k in ('bytes','sha256')},
        source_inputs=admitted['source_sha256'],
        original_workdir_body_executed=True,actual_sdk_parameters_extractor=True,
        configuration_loader_executed=False,remote_io_executed=False)

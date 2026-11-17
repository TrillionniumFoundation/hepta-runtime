# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Admit completed public builds and full streams; only build launches a process."""
from pathlib import Path
import json, os, signal, stat, struct, subprocess, sys, time
from public_lifecycle_registry import (COMPILER, COMPILER_IMAGE, TESTS, encoded,
    graph, regular, require, sha, source_pins)
from hia_native_public_registry_qualification import (compile_evidence, completed,
    confined, duration, keep)


def object_at(path):
    value=json.loads(regular(path))
    require(type(value)is dict,'retained object required')
    return value


def inventory(folder):
    folder=Path(folder).resolve(strict=True);result={}
    for path in sorted(folder.rglob('*')):
        require(not path.is_symlink(),'unexpected retained symlink')
        if not path.is_dir():result[path.relative_to(folder).as_posix()]=sha(regular(path))
    return result


def build_public_lifecycle(hepta,build_root,source_root):
    root,build=Path(source_root).resolve(strict=True),Path(build_root).resolve()
    require(not build.exists(),'public lifecycle build is create-only')
    pins=source_pins(root)
    command=[sys.executable,'-I','-B',str(root/'scripts/build_public_lifecycle.py'),
        '--hepta',str(Path(hepta).resolve(strict=True)),'--build-root',str(build)]
    env={k:v for k,v in os.environ.items()if not k.startswith('HIA_')}
    begin=time.monotonic();timed=False
    process=subprocess.Popen(command,cwd=root,env=env,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,start_new_session=True)
    try:out,err=process.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        timed=True
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=process.communicate(timeout=3)
    build.mkdir(parents=True,exist_ok=True)
    row=dict(command=command,cwd=str(root),exit_code=process.returncode,timed_out=timed,
        timeout_seconds=180,cleanup_seconds=3,elapsed_seconds=time.monotonic()-begin,
        stdout_bytes=len(out),stdout_sha256=sha(out),stderr_bytes=len(err),stderr_sha256=sha(err),
        sources_before=pins,sources_after=source_pins(root),outer_parent_death_cleanup_qualified=False)
    for suffix,raw in (('stdout',out),('stderr',err),('receipt.json',encoded(row))):
        (build/('public-lifecycle-build.'+suffix)).write_bytes(raw)
    require(not timed and process.returncode==0 and not err and row['sources_after']==pins,
        'actual public lifecycle build failed')
    require(json.loads(out)==dict(build=str(build/'build.json'),images=111,packer_compiles=2,pack_invocations=4),
        'actual build summary differs')
    verify_build(root,build/'build.json')
    return build/'build.json'


def verify_build(root,manifest):
    root,manifest=Path(root).resolve(strict=True),Path(manifest).resolve(strict=True)
    build=manifest.parent;profile,pins,artifacts=graph(root),source_pins(root),{}
    report=json.loads(keep(build,artifacts,manifest))
    require(manifest.name=='build.json' and report['schema']=='hepta.public-lifecycle.build.v1'
        and report['status']=='BUILT_NOT_RUNTIME_QUALIFIED' and report['sources']==pins
        and report['compiler_commit']==COMPILER and report['compiler_sha256']==COMPILER_IMAGE
        and report['semantic_compiles']==111 and report['packer_compiles']==2
        and report['pack_invocations']==4 and report['actual_service_processes']==0
        and all(report[k]is False for k in ('production_activated','whole_runtime_replaced','full_cold_executed')),
        'selected build domain or source changed')
    require(set(report['modules'])==set(profile['image_order'])|{'packer_0','packer_1'},'compiled module domain differs')
    images={}
    selected=[(role,profile['modules'][role])for role in profile['image_order']]
    selected += [('packer_'+str(row['part']),row)for row in profile['packers']]
    for role,row in selected:
        _,images[role]=compile_evidence(root,build,row,report['modules'][role],artifacts)
    adapter=build/'adapter'
    expanded=regular(root/profile['adapter_source']).replace(
        b'.include "public_lifecycle_metadata.S"\n',regular(root/profile['metadata_source']))
    require(keep(build,artifacts,adapter/'adapter.S')==expanded
        and sha(expanded)==profile['expanded_adapter_sha256'],'assembled source changed')
    records=json.loads(keep(build,artifacts,adapter/'processes.json'))
    names=('assembler','relocations','symbols','flat')
    require([r['name']for r in records]==list(names),'assembly process domain differs')
    tails=(['--64',str(adapter/'adapter.S'),'-o',str(adapter/'adapter.o')],
        ['-r',str(adapter/'adapter.o')],['-n',str(adapter/'adapter.o')],
        ['-O','binary','--only-section=.text',str(adapter/'adapter.o'),str(adapter/'adapter.bin')])
    for row,name,tail in zip(records,names,tails,strict=True):
        require(row['command'][1:]==tail and row['cwd']==str(root)
            and row['exit_code']==0 and row['timeout_seconds']==30
            and sha(regular(Path(row['command'][0]).resolve(strict=True)))==row['tool_sha256'],
            'actual assembly command/tool differs')
        duration(row['elapsed_seconds'],30)
        for suffix in ('stdout','stderr'):
            raw=keep(build,artifacts,adapter/(name+'.'+suffix))
            require((len(raw),sha(raw))==(row[suffix+'_bytes'],row[suffix+'_sha256']),'assembly stream changed')
            if suffix=='stderr':require(raw==b'','assembler stderr differs')
    require(b'There are no relocations'in regular(adapter/'relocations.stdout'),'fixed relocation present')
    prefix=keep(build,artifacts,adapter/'prefix.bin');code=keep(build,artifacts,adapter/'adapter.bin')
    keep(build,artifacts,adapter/'adapter.o')
    require(prefix[176:]==code and (len(prefix),sha(prefix))==
        (profile['prefix_bytes'],profile['prefix_sha256']),'complete fixed prefix changed')
    order=profile['image_order'];sizes=[len(images[n])for n in order]
    parts=[]
    for packer in profile['packers']:
        part,contract=packer['part'],packer['contract']
        require(sizes==contract['complete_image_sizes'],'complete image sizes differ')
        for stage,(first,last)in enumerate(contract['ranges']):
            name=f'pack-p{part}-s{stage}'
            frame=keep(build,artifacts,build/(name+'.input'))
            expected=b'HRISEG03'+struct.pack('<QQ',part,stage)+struct.pack('<'+'Q'*len(order),*sizes)
            expected+=b''.join(images[n]for n in order[first:last])
            require(frame==expected and len(frame)==contract['input_bytes'][stage]<=8388608,
                'complete pack input differs')
            output=keep(build,artifacts,build/(name+'.output'))
            work=keep(build,artifacts,build/(name+'.workspace'))
            row=json.loads(keep(build,artifacts,build/(name+'.json')))
            derived=dict(part=part,stage=stage,artifact_prefix=name,image_range=[first,last],
                result_u64=len(output),input_bytes=len(frame),input_sha256=sha(frame),
                output_bytes=len(output),output_sha256=sha(output),workspace_bytes=len(work),workspace_sha256=sha(work))
            require(row==derived==report['pack_stages'][len(parts)]==profile['pack_stages'][len(parts)]
                and len(output)==contract['output_bytes'][stage]<=8388608
                and len(work)==packer['workspace_bytes'], 'complete actual pack reply/workspace differs')
            parts.append(output)
    expected=bytearray(prefix);total=len(prefix)+sum(sizes)
    struct.pack_into('<QQ',expected,96,total,total);offsets={};at=len(prefix)
    for name,size in zip(order,sizes,strict=True):offsets[name]=at;at+=size
    for row in profile['patches']:
        value=0x400000+offsets[row['module']]if row['kind']=='address'else len(images[row['module']])
        struct.pack_into('<Q',expected,row['offset'],value)
    expected+=b''.join(images[n]for n in order)
    binary=build/'public-lifecycle.elf';actual=keep(build,artifacts,binary)
    require(actual==expected==b''.join(parts) and stat.S_IMODE(binary.stat().st_mode)==0o500
        and report['executable']==binary.name
        and (len(actual),sha(actual))==(report['executable_bytes'],report['executable_sha256'])==
            (profile['executable_bytes'],profile['executable_sha256']),'complete native executable differs')
    return dict(schema='hepta.public-lifecycle.build-evidence.v1',sources=pins,
        manifest_sha256=sha(regular(manifest)),executable=binary.name,elf_sha256=sha(actual),
        artifact_sha256=artifacts,semantic_compiles=111,packer_compiles=2,pack_invocations=4,
        actual_service_processes=0,production_activated=False,whole_runtime_replaced=False)


def build_evidence(root,output,report):
    root,output=Path(root).resolve(strict=True),Path(output).resolve(strict=True)
    row=report['modules']['public_lifecycle']
    require(row['builder']=='public_lifecycle','aggregate builder changed')
    manifest=confined(output,row['manifest'])
    require(manifest==output/'build/public-lifecycle/build.json'
        and sha(regular(manifest))==row['sha256'],'aggregate build reference changed')
    result=verify_build(root,manifest)
    receipt=object_at(manifest.parent/'public-lifecycle-build.receipt.json')
    command=[sys.executable,'-I','-B',str(root/'scripts/build_public_lifecycle.py'),
        '--hepta',str(Path(report['compiler_checkout']).resolve(strict=True)),
        '--build-root',str(manifest.parent)]
    out,err=completed(manifest.parent,'public-lifecycle-build',receipt,command,root,180)
    require(not err and json.loads(out)==dict(build=str(manifest),images=111,packer_compiles=2,pack_invocations=4)
        and receipt['sources_before']==receipt['sources_after']==result['sources']
        and receipt['cleanup_seconds']==3 and receipt['outer_parent_death_cleanup_qualified']is False,
        'actual aggregate build completion changed')
    artifacts={'build/public-lifecycle/'+name:digest for name,digest in result['artifact_sha256'].items()}
    for suffix in ('stdout','stderr','receipt.json'):
        keep(output,artifacts,manifest.parent/('public-lifecycle-build.'+suffix))
    return {**result,'artifact_sha256':artifacts}


def test_commands(root,output,report):
    root,output=Path(root),Path(output)
    return {TESTS[0]:[sys.executable,'-I','-B',str(root/'tests/hia_native'/TESTS[0]),
            '--output',str(output/'public-lifecycle-native/bridge')],
        TESTS[1]:[sys.executable,'-I','-B',str(root/'tests/hia_native'/TESTS[1]),
            '--build',str(output/'build/public-lifecycle/build.json'),
            '--output',str(output/'public-lifecycle-native/normal')],
        TESTS[2]:[sys.executable,'-I','-B',str(root/'tests/hia_native'/TESTS[2]),
            '--build',str(output/'build/public-lifecycle/build.json'),
            '--output',str(output/'public-lifecycle-native/lifecycle')]}


def normal_evidence(root,folder,native,original=None):
    sys.path.insert(0,str(Path(root)/'tests/hia_native/public_lifecycle'))
    from normal_evidence import verify
    return verify(folder,native,original)


def lifecycle_evidence(root,folder,binary,**options):
    sys.path.insert(0,str(Path(root)/'tests/hia_native/public_lifecycle'))
    from lifecycle_suite import verify
    return verify(folder,binary,**options)


def bridge_evidence(root,folder):
    import importlib.util, re
    root,folder=Path(root),Path(folder);value=object_at(folder/'result.json')
    require(value['status']=='PASS_DIRECT_BRIDGE_UNIT_ONLY'
        and value['direct_bridge_calls']==3 and value['direct_child_error_replies']==1
        and value['subsequent_direct_success_replies']==2 and value['real_guarded_allocations']==2
        and value['real_conversion_drop_calls']==3 and value['retired_allocation_queries']==2
        and value['actual_result_intent_calls']==value['new_original_rust_processes']==0
        and all(value[k]is False for k in ('syscall_interception','fault_injection',
            'public_lifecycle_qualified','production_activated','whole_runtime_replaced')),
        'direct bridge unit scope changed')
    expected=[root/'scripts/public_lifecycle_metadata.S',root/'scripts/public_lifecycle_adapter.S',
        root/'tests/hia_native/public_lifecycle/metadata_unit.S.in',root/'tests/hia_native'/TESTS[0],
        root/'native/public_lifecycle_graph.json']
    require(value['inputs']=={str(p.resolve()):dict(bytes=len(regular(p)),sha256=sha(regular(p)))for p in expected},
        'bridge unit input provenance differs')
    spec=importlib.util.spec_from_file_location('public_bridge_unit_source',root/'tests/hia_native'/TESTS[0])
    unit=importlib.util.module_from_spec(spec);spec.loader.exec_module(unit)
    source=regular(root/'scripts/public_lifecycle_metadata.S').decode()
    adapter=regular(root/'scripts/public_lifecycle_adapter.S').decode()
    allocation=unit.block(adapter,'tk_allocate_guarded:\n','tk_read_exact:\n')
    allocation=re.sub(r'\ballocate_guarded\b','tk_allocate_guarded',allocation)
    allocation=re.sub(r'\btk_memory_fail\b','fatal',allocation)
    body=regular(root/'tests/hia_native/public_lifecycle/metadata_unit.S.in').decode()
    pieces=dict(METADATA_CALL=unit.metadata_body(source),
        CONFIG_DROP=unit.block(source,'ex_intent_config_drop:\n','# Bind the original Config'),
        ALLOCATION=allocation,CONVERSION_DROP=unit.block(adapter,'tk_intent_conversion_drop:\n','# The metadata annotator'))
    for key,piece in pieces.items():
        require(body.count('@'+key+'@')==1,'unit template marker differs')
        body=body.replace('@'+key+'@',piece)
    require(regular(folder/'unit.S')==body.encode(),'actual bridge unit source is not derived from selected input')
    require(regular(folder/'fixed.S')==b'.intel_syntax noprefix\n.text\n    mov edi, OFFSET FLAT:tk_CV_BYTES\nret\n.equ tk_CV_BYTES, 817889280\n',
        'actual immediate encoding source differs')
    names=['encoding-as','encoding-flat','unit-as','unit-link','unit-execute']
    require([r['name']for r in value['processes']]==names,'unit actual process domain differs')
    tails=[['--64',str(folder/'fixed.S'),'-o',str(folder/'fixed.o')],
        ['-O','binary','--only-section=.text',str(folder/'fixed.o'),str(folder/'fixed.bin')],
        ['--64',str(folder/'unit.S'),'-o',str(folder/'unit.o')],
        ['--build-id=none','-m','elf_x86_64','-o',str(folder/'unit.elf'),str(folder/'unit.o')],[]]
    for row,tail in zip(value['processes'],tails,strict=True):
        require(row['argv'][1:]==tail and row['cwd']==str(folder) and row['exit_code']==0
            and row['timeout_seconds']==30
            and sha(regular(Path(row['argv'][0]).resolve(strict=True)))==row['executable_sha256'],
            'unit actual command/tool differs')
        if row['name']=='unit-execute':require(row['argv'][0]==str(folder/'unit.elf'),'unit binary origin differs')
        for suffix in ('stdout','stderr'):
            raw=regular(folder/(row['name']+'.'+suffix))
            require(row[suffix]==dict(bytes=len(raw),sha256=sha(raw)),'unit stream changed')
    require(regular(folder/'fixed.bin').hex()=='bf0000c030c3'
        and regular(folder/'unit-execute.stdout')==b'METADATA_BRIDGE_UNIT_PASS\n'
        and not regular(folder/'unit-execute.stderr'),'unit result changed')
    return value


def native_evidence(root,output,report,completed_test_summary,create=False):
    root,output=Path(root).resolve(strict=True),Path(output).resolve(strict=True)
    built=build_evidence(root,output,report);commands=test_commands(root,output,report);records=[]
    artifacts=dict(built['artifact_sha256']);binary=output/'build/public-lifecycle'/built['executable']
    for name in TESTS:
        row,summary=completed_test_summary(output,report,name)
        out,err=completed(output,name,row,commands[name],root,180,aggregate=True)
        require(not err and json.loads(out)==summary,'actual native suite wrapper changed')
        records.append({k:row[k]for k in ('name','command','exit_code','timed_out','timeout_seconds','stdout_sha256','stderr_sha256')})
        for suffix in ('stdout','stderr'):keep(output,artifacts,output/(name+'.'+suffix))
    direct=bridge_evidence(root,output/'public-lifecycle-native/bridge')
    normal=normal_evidence(root,output/'public-lifecycle-native/normal',binary)
    lifecycle=lifecycle_evidence(root,output/'public-lifecycle-native/lifecycle',binary)
    require(json.loads(regular(output/(TESTS[0]+'.stdout')))=={k:direct[k]for k in
        ('status','direct_bridge_calls','real_guarded_allocations','actual_result_intent_calls','full_public_regression')},
        'direct unit summary changed')
    require(json.loads(regular(output/(TESTS[1]+'.stdout')))==dict(status='PASS',native_processes=64,
        native_requests=359,original_processes=0),'normal suite summary changed')
    require(json.loads(regular(output/(TESTS[2]+'.stdout')))==dict(status='PASS',native_processes=22,
        original_processes=0,requests_per_implementation=348,producer_starts_per_implementation=11),
        'finite lifecycle suite summary changed')
    for branch in ('bridge','normal','lifecycle'):
        for name,digest in inventory(output/'public-lifecycle-native'/branch).items():
            artifacts['public-lifecycle-native/'+branch+'/'+name]=digest
    compatibility=dict(schema='hepta.public-lifecycle.native-result.v1',status='PASS',sources=built['sources'],
        build_sha256=built['manifest_sha256'],records=records,normal=normal,lifecycle=lifecycle,direct_bridge_calls=3,
        actual_native_processes=86,actual_native_requests=707,actual_original_processes=0,
        production_activated=False,whole_runtime_replaced=False)

    path=output/'public-lifecycle-native/result.json';raw=encoded(compatibility)
    if create:
        require(not path.exists(),'native result is create-only');path.write_bytes(raw)
    else:require(regular(path)==raw,'native aggregate result changed')
    keep(output,artifacts,path)
    return dict(schema='hepta.public-lifecycle.native-evidence.v1',sources=built['sources'],
        artifact_sha256=artifacts,native_result_sha256=sha(raw),native_processes=86,native_requests=707,
        original_processes=0,direct_fixture_calls=3,new_executions_in_admission=0,
        production_activated=False,whole_runtime_replaced=False)


def verify_original(root,folder,manifest):
    import tomllib
    from public_lifecycle_crates import REMOVED,package_files
    from hia_native_public_lifecycle_reference import check
    from public_lifecycle_retained import ADMISSION, LIFECYCLE, admit, pin
    sys.path.insert(0,str(Path(root)/'tests/hia_native/public_lifecycle'))
    from normal_original import verify as retained_pair_evidence
    from lifecycle_suite import verify as retained_lifecycle_evidence
    root,folder,manifest=Path(root).resolve(strict=True),Path(folder).resolve(strict=True),Path(manifest).resolve(strict=True)
    original=object_at(folder/'result.json');built=verify_build(root,manifest)
    require(original['schema']=='hepta.public-lifecycle.original-result.v2' and original['status']=='PASS'
        and original['sources']==source_pins(root) and original['native_build_evidence']==built
        and original['build_sha256']==sha(regular(manifest)) and original['fresh_actual_cargo_build']is True
        and original['original_blocks']==315 and original['locked_registry_dependencies']==140
        and original['native_processes']==0 and original['original_processes']==86
        and original['retained_native_processes']==86 and original['retained_native_requests']==707
        and original['requests_per_implementation']==707 and original['actual_outer_call_tool_included']is True
        and original['complete_wire_and_filesystem_equality']is True
        and original['cargo_cache_retired_after_binary_and_source_verification']is True
        and original['external_host_operations']==0
        and all(original[k]is False for k in ('original_index_present_branch_qualified','syscall_interception',
            'fault_injection','production_activated','whole_runtime_replaced')),'original domain changed')
    require(check(root,folder/'project')==original['prepared'],'actual original project changed')
    require(type(original['owner']['pid'])is int and original['owner']['pid']>0
        and original['owner']['pid']==original['owner']['pgid']
        and original['owner']['outer_timeout_seconds']==180
        and original['owner']['inherited_child_process_group']is True
        and original['owner']['parent_death_cleanup_qualified']is False,'reference process ownership differs')
    env=original['environment'];offline=['--offline']if env['offline']else []
    require(env==dict(removed=list(REMOVED),removed_prefixes=['HIA_'],RUSTC=original['rustc'],
        CARGO_TARGET_DIR=str(folder/'target'),TMPDIR=str(folder/'temporary'),offline=env['offline'])
        and type(env['offline'])is bool,'reference environment differs')
    require(not (folder/'target').exists(),'disposable Cargo cache survived complete reference')
    binary=folder/'original.elf';raw=regular(binary)
    require(original['original_binary']==dict(origin=str(folder/'target/release/hia-public-async-original'),
        path=str(binary),bytes=len(raw),sha256=sha(raw)) and stat.S_IMODE(binary.stat().st_mode)==0o500,
        'retained original executable differs')
    native=manifest.parent/built['executable']
    admission=folder.parent/ADMISSION
    require(original['native_admission']==str(admission)
        and original['native_admission_sha256']==pin(admission)['sha256'],
        'current native admission identity differs')
    retained=admit(admission,original['native_admission_sha256'],original['native_invocation'],root,manifest)
    require(original['retained_native']==retained,'retained native phase differs')
    commands=[('rustc-version',[original['rustc'],'--version','--verbose'],root,10),
        ('cargo-fetch',[original['cargo'],'fetch','--locked',*offline],folder/'project',120),
        ('cargo-metadata',[original['cargo'],'metadata','--locked','--format-version','1',*offline],folder/'project',30),
        ('cargo-build',[original['cargo'],'build','--release','--locked','--bin','hia-public-async-original',*offline],folder/'project',120),
        ('normal-pairs',[sys.executable,'-I','-B',str(root/'tests/hia_native/public_lifecycle/normal_original.py'),
            '--admission',str(admission),'--admission-sha256',original['native_admission_sha256'],
            '--invocation',original['native_invocation'],'--build',str(manifest),
            '--original',str(binary),'--output',str(folder/'paired'),'--defer-final-admission'],root,120),
        ('lifecycle-pairs',[sys.executable,'-I','-B',str(root/'tests/hia_native/public_lifecycle/lifecycle_suite.py'),
            '--binary',str(binary),'--retained',str(admission.parent/LIFECYCLE),
            '--native-binary',str(native),'--output',str(folder/'lifecycle'),'--defer-final-admission'],root,120),
        ('retained-native-controls',[sys.executable,'-I','-B',str(root/'tests/hia_native/public_lifecycle/retained_controls.py'),
            '--admission',str(admission),'--admission-sha256',original['native_admission_sha256'],
            '--invocation',original['native_invocation'],'--build',str(manifest),
            '--output',str(folder/'controls')],root,30)]
    require([r['name']for r in original['processes']]==[r[0]for r in commands],'original process inventory differs')
    for row,(name,command,cwd,timeout)in zip(original['processes'],commands,strict=True):
        out,err=completed(folder,name,row,command,cwd,timeout)
        require(type(row['pid'])is int and row['pid']>0,'actual reference PID absent')
        if name=='rustc-version':require(not err and b'release: 1.95.0\n'in out,'actual Rust version changed')
        if name in ('cargo-metadata','normal-pairs','lifecycle-pairs','retained-native-controls'):require(not err,'unexpected original stdout framing')
    normal_row=next(row for row in original['processes']if row['name']=='normal-pairs')
    lifecycle_row=next(row for row in original['processes']if row['name']=='lifecycle-pairs')
    ready_path=folder/'paired/native-admission-ready.json'
    require(object_at(ready_path)==dict(schema='hepta.public-lifecycle.original-capture-ready.v1',
        pid=normal_row['pid'],process_group=original['owner']['pgid'],output=str(folder/'paired'),
        admission=pin(admission),invocation=original['native_invocation'],manifest=pin(manifest),
        original_binary=pin(binary),complete_native_admission=True,native_processes=0),
        'actual original consumer native-admission barrier differs')
    scheduling=original['capture_scheduling']
    require(type(scheduling.get('normal_live_before_lifecycle'))is bool and scheduling==dict(
        schema='hepta.public-lifecycle.independent-consumers.v1',
        admission_ready_file='paired/native-admission-ready.json',admission_ready=pin(ready_path),
        normal_pid=normal_row['pid'],lifecycle_pid=lifecycle_row['pid'],
        native_admission_completed_before_lifecycle=True,
        normal_live_before_lifecycle=scheduling['normal_live_before_lifecycle'],
        parent_verification_after_both=True,native_processes=0),
        'original consumer supervision or ownership changed')
    expected_tools={original['cargo'],original['rustc'],original['rustfmt']}
    require(set(original['tool_sha256'])==expected_tools,'original tool domain changed')
    for path,digest in original['tool_sha256'].items():
        require(sha(regular(Path(path).resolve(strict=True)))==digest,'actual original tool changed')
    lock=tomllib.loads(regular(folder/'project/Cargo.lock').decode())
    root_lock=tomllib.loads(regular(root/'Cargo.lock').decode())
    root_packages={(p['name'],p['version'],p['source']):p for p in root_lock['package']if 'checksum'in p}
    wanted={p['name']+'-'+p['version']:p for p in lock['package']if 'checksum'in p}
    before=original['registry_before']
    require(before==original['registry_after'] and set(before)==set(wanted) and len(before)==140,
        'actual registry source domain changed')
    metadata=object_at(folder/'cargo-metadata.stdout')
    selected={p['name']+'-'+p['version']:p for p in metadata['packages']if p.get('source')is not None}
    require(set(selected)==set(wanted),'actual Cargo selected package domain differs')
    require(set(inventory(folder/'registry'))=={n+'.crate'for n in wanted},'retained crate set differs')
    def edges(package,universe):
        result=set()
        for edge in package.get('dependencies',[]):
            words=edge.split();found=[(p['name'],p['version'])for p in universe['package']
                if p['name']==words[0]and(len(words)==1 or p['version']==words[1])]
            require(len(found)==1,'ambiguous locked dependency');result.add(found[0])
        return result
    for name,package in wanted.items():
        row=before[name];source=selected[name]
        key=(package['name'],package['version'],package['source']);original_package=root_packages[key]
        require(all(package[k]==original_package[k]for k in ('name','version','source','checksum'))
            and edges(package,lock)<=edges(original_package,root_lock),'original locked dependency changed')
        archive=regular(folder/'registry'/(name+'.crate'))
        require(sha(archive)==package['checksum']
            and row==dict(package=package,archive=dict(bytes=len(archive),sha256=sha(archive)),
                members=package_files(archive,name),actual_source=str(Path(source['manifest_path']).parent)),
            'complete locked crate/member evidence differs')
    paired=retained_pair_evidence(folder/'paired',binary,admission,original['native_admission_sha256'],
        original['native_invocation'],manifest,captured=True)
    require(original['paired']==paired and json.loads(regular(folder/'normal-pairs.stdout'))==dict(
        status='CAPTURED_NOT_QUALIFIED',native_processes=0,retained_native_processes=64,
        original_processes=64,requests_per_implementation=359),
        'complete actual pair evidence differs')
    finite=retained_lifecycle_evidence(folder/'lifecycle',binary,side='original',
        retained=admission.parent/LIFECYCLE,native_binary=native,captured=True)
    require(original['lifecycle']==finite and json.loads(regular(folder/'lifecycle-pairs.stdout'))==dict(
        status='CAPTURED_NOT_QUALIFIED',native_processes=0,original_processes=22,requests_per_implementation=348,
        producer_starts_per_implementation=11),'complete finite lifecycle pair evidence differs')
    controls=object_at(folder/'controls/result.json')
    names=['invocation','context-invocation','source-root','output-root','native-count','request-count',
        'new-native-count','deadline','source-pin','manifest','completed-command','completed-exit',
        'capture-inventory','extra-field','complete-native-stream','complete-lifecycle-stream']
    expected_controls=[dict(name=name,rejected=True,recomputed_admission_digest=not name.startswith('complete-'))for name in names]
    require(controls==dict(schema='hepta.public-lifecycle.retained-controls.v1',status='PASS',
        admission=pin(admission),invocation=original['native_invocation'],rejected_controls=16,
        controls=expected_controls,before=retained,after=retained,complete_restoration=True,
        native_processes=0,original_processes=0,syscall_interception=False,fault_injection=False)
        and json.loads(regular(folder/'retained-native-controls.stdout'))==dict(status='PASS',
            rejected_controls=16,complete_restoration=True,native_processes=0,original_processes=0),
        'complete data rejection controls changed')
    actual={}
    for branch in ('project','registry','paired','lifecycle','controls'):
        actual.update({branch+'/'+name:digest for name,digest in inventory(folder/branch).items()})
    for path in folder.iterdir():
        if path.is_file()and path.name!='result.json':actual[path.name]=sha(regular(path))
    require(actual==original['artifacts'],'complete immutable original artifacts changed')
    return dict(schema='hepta.public-lifecycle.original-admission.v1',status='PASS',sources=original['sources'],
        artifacts=actual,original_builds=1,locked_registry_dependencies=140,original_blocks=315,
        native_processes=0,retained_native_processes=86,original_processes=86,requests_per_implementation=707,
        new_executions_in_admission=0,production_activated=False,whole_runtime_replaced=False)


def original_command(root,output,report):
    root,output=Path(root),Path(output)
    folder=output/'public-lifecycle-original'
    original=object_at(folder/'result.json')
    command=[sys.executable,'-I','-B',str(root/'tests/hia_native/compare_public_lifecycle_original.py'),
        '--repo',str(root),'--build',str(output/'build/public-lifecycle/build.json'),'--output',str(folder),
        '--cargo',original['cargo'],'--rustc',original['rustc'],'--rustfmt',original['rustfmt'],
        '--native-admission',original['native_admission'],
        '--native-admission-sha256',original['native_admission_sha256'],
        '--native-invocation',original['native_invocation']]
    if original['environment']['offline']:command.append('--offline')
    return command


def verify_original_native_context(binding,report):
    shard='original_shard' in report
    pipeline='original_qualification_pipeline' in report
    require(not (shard and pipeline),'original native context has conflicting workflow owners')
    if shard or pipeline:
        owner=report['original_shard'] if shard else report['original_qualification_pipeline']
        if pipeline:
            require(owner['schema']=='hepta.runtime.original-pipeline.v1',
                'original aggregate workflow schema changed')
        require(binding['context']['mode']=='ci-original-pipeline'
            and binding['invocation']==owner['invocation']
            and binding['context']['invocation']==owner['invocation']
            and binding['context']['native_seal_sha256']==owner['native_sha256'],
            'original consumer used another workflow native phase')
    else:
        require(binding['context']['mode']=='owned-component-validation'
            and binding['invocation']=='aggregate:'+report['started_at']
            and binding['context']['invocation']==binding['invocation'],
            'original consumer used another owned native phase')


def original_evidence(root,output,report,completed_test_summary):
    from public_lifecycle_retained import ADMISSION, PHASE
    root,output=Path(root).resolve(strict=True),Path(output).resolve(strict=True)
    native=native_evidence(root,output,report,completed_test_summary)
    folder=output/'public-lifecycle-original';manifest=output/'build/public-lifecycle/build.json'
    result=verify_original(root,folder,manifest)
    row,summary=completed_test_summary(output,report,'public-lifecycle-rust-compare')
    out,err=completed(output,'public-lifecycle-rust-compare',row,original_command(root,output,report),root,180,aggregate=True)
    original=object_at(folder/'result.json')
    binding=object_at(output/ADMISSION)
    verify_original_native_context(binding,report)
    expected={k:original[k]for k in ('status','fresh_actual_cargo_build','native_processes',
        'retained_native_processes','original_processes','requests_per_implementation','original_blocks','locked_registry_dependencies')}
    require(not err and json.loads(out)==summary==expected,'actual original wrapper completion differs')
    artifacts=dict(native['artifact_sha256'])
    artifacts.update({'public-lifecycle-original/'+name:digest for name,digest in result.pop('artifacts').items()})
    for path in (folder/'result.json',output/'public-lifecycle-rust-compare.stdout',output/'public-lifecycle-rust-compare.stderr'):
        keep(output,artifacts,path)
    keep(output,artifacts,output/ADMISSION)
    if binding['context']['mode']=='owned-component-validation':keep(output,artifacts,output/PHASE)
    return {**result,'artifact_sha256':artifacts}

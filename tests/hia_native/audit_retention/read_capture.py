"""Read every frozen source, process stream and physical native buffer; never execute."""
from pathlib import Path
import gzip
import io
import json
import struct
import tomllib
from common import ROOT, COMPILER, encoded, envelope, files, loads, pin, read, require, sha, source
from domain import cases, domain, stdin_bytes


def commands(metadata):
    root = Path(metadata['source_root'])
    semantic = Path(metadata['producer_root'])
    rust = Path(metadata['rust_bin'])
    reference = semantic/'reference'
    python = metadata['python']
    config = ['--config', 'source.crates-io.replace-with="fixed-vendor"', '--config',
              'source.fixed-vendor.directory='+json.dumps(str(semantic/'vendor'))]
    rows = [
        ('format', [rust/'rustfmt','--check','--edition','2021','--config','hard_tabs=true,max_width=100',
                    root/'reference/oracle.rs',root/'reference/original_types.rs'], root),
        ('toolchain', [rust/'rustc','--version','--verbose'], root),
        ('cargo-version', [rust/'cargo','--version','--verbose'], root),
        ('native-build', [python,'-I','-B',root/'build_native.py','--hepta',metadata['compiler_root'],
                          '--output',semantic/'build'], root),
        ('rust-fetch', [rust/'cargo','fetch','--locked','--manifest-path',reference/'Cargo.toml'], reference),
        ('rust-vendor', [rust/'cargo','vendor','--locked','--offline','--versioned-dirs','--manifest-path',
                         reference/'Cargo.toml',semantic/'vendor'], reference),
        ('rust-build', [rust/'cargo','build','--frozen','--verbose','--target','x86_64-unknown-linux-gnu',
                        '--manifest-path',reference/'Cargo.toml',*config], reference),
        ('original', [semantic/'original'], root),
        ('native', [python,'-I','-B',root/'native_process.py','--manifest',
                    semantic/'build/modules/audit-retention/manifest.json','--output',semantic/'native'], root),
    ]
    budgets = domain()['process_budgets']
    return [dict(name=name, argv=[str(value) for value in argv], cwd=str(cwd), timeout=budgets[name])
            for name, argv, cwd in rows]


def process_custody(root, metadata, concrete):
    rows = loads(read(root/'processes/processes.json'))
    expected = commands(metadata)
    require(metadata['commands'] == expected and len(rows) == len(expected), 'complete source-owned command sequence')
    stdin = stdin_bytes(concrete)
    for actual, wanted in zip(rows, expected, strict=True):
        require(actual['name'] == wanted['name'] and actual['argv'] == wanted['argv']
                and actual['cwd'] == wanted['cwd'] and actual['timeout_seconds'] == wanted['timeout'],
                'actual command and frozen process budget')
        require(actual['exit_code'] == 0 and actual['timed_out'] is False and actual['completed'] is True
                and 0 <= actual['elapsed_seconds'] <= actual['timeout_seconds']
                and type(actual['pid']) is int and actual['pid'] > 1
                and actual['pgid'] == actual['pid'] and actual['parent_pid'] != actual['pid'],
                'actual completed and reaped process custody')
        for stream in ('stdout','stderr','stdin'):
            value = actual[stream]
            if value is None:
                require(stream == 'stdin' and actual['name'] not in ('original','native'), 'exact process input presence')
                continue
            require(value['file'] == actual['name']+'.'+stream, 'fixed complete process stream basename')
            raw = read(root/'processes'/value['file'])
            require(pin(raw) == {key:value[key] for key in ('bytes','sha256')}, 'complete retained process stream')
            if stream == 'stdin':
                require(raw == stdin, 'every original and native input equals the frozen concrete domain')
            if stream == 'stderr' and actual['name'] in ('original','native','format'):
                require(raw == b'', 'semantic and formatting process stderr is empty')
    verbose = read(root/'processes/toolchain.stdout')
    require(b'\nrelease: 1.95.0\n' in verbose and b'\nhost: x86_64-unknown-linux-gnu\n' in verbose,
            'exact original test toolchain release and target')
    require(read(root/'processes/cargo-version.stdout').startswith(b'cargo 1.95.0 '), 'exact cargo test toolchain')
    profile = tomllib.loads(read(root/'reference/Cargo.toml').decode())['profile']['dev']
    require(profile == {'opt-level':1,'debug':2,'debug-assertions':True,'overflow-checks':True,
                        'codegen-units':256,'lto':False,'panic':'unwind'}, 'exact original reference optimization profile')
    env = metadata['environment']['explicit_reference_environment']
    require(env['RUSTC'] == str(Path(metadata['rust_bin'])/'rustc')
            and env['RUSTDOC'] == str(Path(metadata['rust_bin'])/'rustdoc')
            and env['CARGO_TARGET_DIR'] == str(Path(metadata['build_temporary'])/'target')
            and env['CARGO_BUILD_TARGET'] == 'x86_64-unknown-linux-gnu'
            and all(env[name] == '' for name in ('RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER',
                'CARGO_BUILD_RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
                'CARGO_ENCODED_RUSTFLAGS','CARGO_ENCODED_RUSTDOCFLAGS','CARGO_BUILD_RUSTFLAGS')),
            'fixed nonambient reference toolchain environment')
    require(pin(read(root/'original')) == metadata['original_binary'] and read(root/'original').startswith(b'\x7fELF'),
            'actual original binary retained completely')
    return rows


def dependencies(root):
    lock = tomllib.loads(read(ROOT/'reference/Cargo.lock').decode())
    packages = [value for value in lock['package'] if 'source' in value]
    require(set(path.name for path in (root/'vendor').iterdir())
            == {item['name']+'-'+item['version'] for item in packages}, 'complete exact vendored package set')
    total_files, total_bytes = 0, 0
    for package in packages:
        name = package['name']+'-'+package['version']
        folder = root/'vendor'/name
        checksum = loads(read(folder/'.cargo-checksum.json'))
        require(checksum['package'] == package['checksum']
                and sha(read(root/'crates'/(name+'.crate'))) == package['checksum'],
                'locked original dependency archive and package identity')
        actual = files(folder, ('.cargo-checksum.json',))
        require(set(actual) == set(checksum['files']), 'complete original dependency file set')
        for path, identity in actual.items():
            require(identity['sha256'] == checksum['files'][path], 'every original dependency source byte')
            total_files += 1
            total_bytes += identity['bytes']
    require(set(path.name for path in (root/'crates').iterdir())
            == {item['name']+'-'+item['version']+'.crate' for item in packages}, 'complete exact crate archive set')
    return dict(packages=len(packages), source_files=total_files, source_bytes=total_bytes)


def compilation(root):
    fixed = loads(read(ROOT/'COMPILER_IDENTITY.json'))
    build = loads(read(root/'build/BUILD.json'))
    bootstrap = loads(read(root/'build/bootstrap/bootstrap.json'))
    require(build['compiler'] == fixed == bootstrap['dependency'], 'complete fixed compiler source identity')
    retained = files(root/'build/compiler-source')
    require(set(retained) == set(fixed['files']) and len(retained) == 1080, 'complete compiler source file set')
    for name, identity in retained.items():
        require(identity['sha256'] == fixed['files'][name], 'every fixed compiler source byte')
    for label in ('B1','B2','B3'):
        require(pin(read(root/'build/bootstrap'/(label+'.image.bin'))) == dict(bytes=673413,sha256=COMPILER),
                'actual exact fixed compiler generations')
    folder = root/'build/modules/audit-retention'
    manifest = loads(read(folder/'manifest.json'))
    composition = loads(read(ROOT/'native/audit_retention.composition.json'))
    source_raw = read(ROOT/'native/audit_retention.hepta')
    image = read(folder/'module.image.bin')
    require(read(folder/'audit-retention.hepta') == read(folder/'module.input.bin') == source_raw,
            'every compiled source byte equals the frozen generated HIA')
    require(manifest['compiler_sha256'] == COMPILER and manifest['source_sha256'] == sha(source_raw)
            and manifest['image_sha256'] == sha(image) and build['image'] == pin(image)
            and build['source'] == pin(source_raw) and build['source_manifest_sha256'] == source()
            and build['manifest'] == dict(path='modules/audit-retention/manifest.json',**pin(read(folder/'manifest.json'))),
            'complete compiled native image binding')
    require(composition['source_identity']['sha256'] == sha(source_raw)
            and composition['source_identity']['bytes'] == len(source_raw), 'frozen authored HIA source identity')
    compile_record = loads(read(folder/'module.receipt.json'))
    build_record = loads(read(folder/'build.json'))
    # build.json adds the produced image fields to the same complete invocation receipt.
    for key, value in compile_record.items():
        require(build_record['compile_receipt'][key] == value, 'actual complete compiler invocation receipt')
    full_output = read(folder/'module.output.bin')
    require(compile_record['status'] == 'returned' and compile_record['abi_status'] == 0
            and compile_record['artifact_sha256'] == COMPILER and compile_record['image_sha256'] == COMPILER
            and compile_record['source_unchanged'] is True and compile_record['input_bytes'] == len(source_raw)
            and compile_record['input_sha256'] == sha(source_raw) and compile_record['source_sha256'] == sha(source_raw)
            and compile_record['output_sha256'] == sha(full_output)
            and compile_record['result_u64'] == compile_record['core_u32'] == len(image)
            and full_output[:len(image)] == image and compile_record['forbidden_compiler_modules_loaded'] == [],
            'actual complete HIA compiler input output and result')
    require(build_record['compiler_dependency'] == fixed, 'same fixed compiler dependency at module compilation')
    return dict(image=pin(image), source=pin(source_raw), compiler_files=len(retained), shape=composition['shape'])


def parse_reply(line, case):
    from protocol import get
    prefix = case['name'].encode().hex().encode() + b':'
    require(line.startswith(prefix), 'exact ordered original scenario name')
    raw = bytes.fromhex(line[len(prefix):].decode('ascii'))
    require(line == prefix + raw.hex().encode() and len(raw) >= 40 and raw[:8] == b'HATRV001',
            'canonical complete original reply representation')
    result, error, count, trace_size = (get(raw, offset) for offset in (8,16,24,32))
    require(result in (1,2,3) and ((result==3 and error!=0) or (result!=3 and error==0)),
            'exact original typed policy result')
    records, cursor = [], 40
    for _ in range(count):
        require(cursor+8<=len(raw), 'complete original record length')
        size=get(raw,cursor);cursor+=8
        require(size>=128 and size<=len(raw)-cursor, 'complete original record projection')
        records.append(raw[cursor:cursor+size]);cursor+=size
    require(trace_size==len(raw)-cursor, 'complete original effect trace extent')
    return dict(raw=raw,result=result,error=error,records=records,trace=raw[cursor:])


def buffers(root, concrete):
    from protocol import (CAPACITY, INVALID, Fixture, START_PROBES, RESUME_PROBES,
        completed, frame_record, get, probe, put, response, text_field, workspace_frame)
    original=read(root/'processes/original.stdout')
    actual=read(root/'processes/native.stdout')
    require(actual==original, 'complete actual original and HIA process stdout equality')
    lines=original.splitlines()
    require(len(lines)==len(concrete) and original.endswith(b'\n'), 'every actual paired scenario exactly once')
    replies=[parse_reply(line,case) for line,case in zip(lines,concrete,strict=True)]
    native=loads(read(root/'native/NATIVE.json'))
    journal_raw=read(root/'native/buffers.bin.gz')
    invocation_raw=read(root/'native/INVOCATIONS.json')
    invocations=loads(invocation_raw)
    require(native['status']=='PASS' and native['cases']==native['completed_cases']==len(concrete)
        and native['native_calls']==native['completed_calls']==len(invocations)
        and native['semantic_host_fallback'] is False and native['observed_buffers_complete'] is True
        and native['journal']==pin(journal_raw) and native['invocations']==pin(invocation_raw),
        'complete actual native execution journal')
    require(native['native_image']==pin(read(root/'build/modules/audit-retention/module.image.bin')),
            'actual invoked exact HIA native image')
    require(native['schedule']==domain()['native_schedule']=='round-robin-independent-workspaces',
            'source-owned continuation interleaving schedule')
    states=[]
    for case in concrete:
        initial=bytes.fromhex(case['initial_hex'])
        count=get(initial,16)
        extent=128+8*count+len(initial)
        size=extent+case['workspace_extra']
        states.append(dict(initial=initial,wire=initial,work=b'\xa7'*size+b'\x5a'*16,
            work_size=size,extent=extent,step=0,seen=set(),fixture=Fixture(case),complete=False,
            live=list(range(count)),effect=None))
    cursor,logical_bytes,switches,previous_case,policy_calls,refusals=0,8,0,None,0,0
    refusal_names=[]
    with gzip.GzipFile(fileobj=io.BytesIO(journal_raw),mode='rb') as handle:
        require(handle.read(8)==b'HATLOG01', 'physical journal format')
        def physical(case_index,wire,out_size,work_size,work_before,name,wanted):
            nonlocal cursor,logical_bytes,switches,previous_case,policy_calls,refusals
            require(cursor<len(invocations), 'all expected physical invocations retained')
            state=states[case_index]
            row=invocations[cursor]
            expected=dict(ordinal=cursor,case=case_index,step=state['step'],probe=name,
                result=wanted,source_size=len(wire),output_size=out_size,workspace_size=work_size)
            require(row==expected, 'exact actual invocation order return and capacities')
            header=handle.read(72)
            require(len(header)==72 and header[:8]==b'HATCAL01', 'every physical invocation header')
            require(struct.unpack('<8Q',header[8:])==(cursor,case_index,state['step'],int(name!=''),
                wanted,len(wire),out_size,work_size), 'actual full native invocation header')
            expected_before=[wire+b'\xc3'*16,b'\x69'*out_size+b'\xa5'*16,work_before]
            before,after=[],[]
            for size in (len(wire)+16,out_size+16,work_size+16):
                left,right=handle.read(size),handle.read(size)
                require(len(left)==len(right)==size, 'every complete physical buffer byte')
                before.append(left);after.append(right);logical_bytes+=size*2
            logical_bytes+=72
            require(before==expected_before, 'exact initialized and continued physical buffers')
            require(after[0]==before[0], 'complete immutable borrowed input')
            require(after[1][-16:]==b'\xa5'*16, 'complete output guard tail')
            require(after[2][-16:]==b'\x5a'*16, 'complete workspace guard tail')
            if name:
                require(after[1:]==before[1:], 'protocol refusal preserves every mutable byte')
                refusals+=1;refusal_names.append(dict(case=case_index,step=state['step'],name=name,result=wanted))
            else:
                require(after[1][128:]==before[1][128:], 'complete untouched output suffix')
                require(after[2][state['extent']:]==before[2][state['extent']:], 'complete untouched high workspace suffix')
                policy_calls+=1
            cursor+=1
            if previous_case is not None and previous_case!=case_index:switches+=1
            previous_case=case_index
            return after[1][:128],after[2]

        remaining=len(states)
        while remaining:
            for case_index,(case,state) in enumerate(zip(concrete,states,strict=True)):
                if state['complete']:continue
                wire=state['wire'];names=()
                if state['step']==0 and case['start_probes']:names=START_PROBES
                elif state['step'] and case['resume_probes']:
                    kind=get(wire,24)
                    if kind not in state['seen']:
                        names=RESUME_PROBES;state['seen'].add(kind)
                for name in names:
                    altered,out_size,work_size,wanted=probe(name,wire,case['output_capacity'],state['work_size'],state['extent'])
                    before=state['work'][:work_size]+b'\x5a'*16
                    physical(case_index,altered,out_size,work_size,before,name,wanted)
                reply,work=physical(case_index,wire,case['output_capacity'],state['work_size'],state['work'],'',128)
                require(reply[:8]==b'HATRS001' and work[:8]==b'HATRW001', 'actual native response and workspace envelopes')
                if state['effect'] is not None and state['effect']['kind']==3 and get(wire,32)==0:
                    state['live'].remove(state['effect']['index'])
                live=[get(work,128+i*8) for i in range(get(work,16))]
                require(live==state['live'], 'each actual successful remove changes only its selected vector element')
                frame=workspace_frame(work[:-16])
                require(frame==state['initial'] and get(work,56)==get(frame,16)
                    and get(work,72)==128+8*get(frame,16) and get(work,64)==len(frame),
                    'complete owned immutable initialization copy')
                owner_at,owner_size=get(frame,40),get(frame,48)
                owner=frame[owner_at:owner_at+owner_size].decode('utf-8')
                owners=sum(text_field(frame_record(frame,index),1)==owner for index in live)
                require(get(work,48)==owners and get(work,104)==get(frame,16)-len(live)
                    and get(work,80)==get(frame,32) and get(work,112)==get(frame,8) and get(work,120)==0,
                    'exact remaining counts and immutable policy configuration')
                kind=get(reply,8)
                require(kind in (1,2,3,4), 'actual effect or complete response kind')
                expected_reply=bytearray(128);expected_reply[:8]=b'HATRS001'
                index=(1<<64)-1 if kind==4 else get(work,128+get(work,24)*8)
                for offset,value in ((8,kind),(16,get(work,40)),(24,index),(32,get(work,80) if kind==3 else 0),
                    (40,get(work,88)),(48,get(work,96)),(56,len(live)),(64,get(work,104)),(72,owners),
                    (80,get(work,72)),(88,get(work,56)),(96,state['extent'])):put(expected_reply,offset,value)
                require(reply==expected_reply, 'all 128 response bytes bind the actual owned state')
                if kind==4:
                    require(get(work,8)==3 and get(work,32)==0, 'terminal owned actor state')
                    full=completed(work[:-16],reply,state['fixture'].trace)
                    require(full==replies[case_index]['raw'], 'complete actual return remaining records and effect trace equal original')
                    state['complete']=True;remaining-=1
                    if case['after_completion_probe']:
                        physical(case_index,response(1,get(reply,16)),case['output_capacity'],state['work_size'],
                                 work,'after-completion',INVALID)
                else:
                    require(get(work,8) in (1,2) and get(work,32)==kind and get(work,88)==get(work,96)==0,
                            'outstanding effect belongs to a live actor')
                    record=frame_record(frame,index)
                    state['wire']=state['fixture'].consume(kind,get(reply,16),record,get(reply,32))
                    require(replies[case_index]['trace'].startswith(state['fixture'].trace),
                            'every actual ordered external effect and its result equal the original prefix')
                    require(state['fixture'].sequence<=case['max_effects'], 'source-owned effect budget')
                    state['effect']=dict(kind=kind,index=index)
                state['work']=work;state['step']+=1
        require(cursor==len(invocations) and handle.read(1)==b'', 'complete journal ends after the exact owned schedule')
    effects=sum(state['fixture'].sequence for state in states)
    require(native['logical_physical_bytes']==logical_bytes and native['policy_calls']==policy_calls
        and native['protocol_refusals']==refusals==domain()['native_protocol_controls']['expected_refusals']
        and native['effects']==effects and policy_calls==effects+len(concrete)
        and native['context_switches']==switches and native['independent_contexts']==len(concrete),
        'complete actual invocation effect and physical-byte counts')
    controls=domain()['native_protocol_controls']
    require(list(START_PROBES)==controls['start'] and list(RESUME_PROBES)==controls['resume']
            and all(state['seen']==set(controls['resume_effect_kinds']) for case,state in zip(concrete,states,strict=True)
                    if case['resume_probes']), 'complete source-owned continuation refusal domain')
    results={name:sum(reply['result']==code for reply in replies) for name,code in (('true',1),('false',2),('error',3))}
    return dict(cases=len(concrete),native_calls=cursor,policy_calls=policy_calls,effects=effects,
        protocol_refusals=refusals,protocol_refusal_cases=refusal_names,independent_contexts=len(concrete),
        context_switches=switches,results=results,logical_physical_bytes=logical_bytes,
        journal=pin(journal_raw),original_stdout=pin(original),native_stdout=pin(actual))


def semantic(root):
    root = Path(root).resolve(strict=True)
    metadata = envelope(root)
    require(metadata['schema'] == 'hepta.audit-retention.capture.v1' and metadata['status'] == 'PASS'
            and metadata['source_manifest_sha256'] == source()
            and metadata['public_handler_qualified'] is False and metadata['whole_runtime_replaced'] is False,
            'successful frozen private audit retention policy capture')
    require(files(root/'source') == files(ROOT), 'complete frozen audit retention policy source copy')
    require(files(root/'reference') == files(ROOT/'reference'), 'unchanged exact original reference source')
    original = read(ROOT/'reference/request_audit.rs.txt')
    require(sha(original) == 'b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da',
            'exact target request audit source')
    begin=original.index(b'#[cfg(unix)]\nfn archived_copy_matches')
    end=original.index(b'\n#[cfg(unix)]\nfn save(',begin)
    retained=original[begin:end].rstrip()
    oracle=read(ROOT/'reference/oracle.rs')
    require(read(ROOT/'reference/record_types.rs.txt').rstrip() in original
            and read(ROOT/'reference/record_types.rs.txt').rstrip() in oracle
            and retained in oracle and retained in read(ROOT/'reference/original_retention.rs')
            and b'const MAX_GLOBAL: usize = 512;' in original and b'const MAX_GLOBAL: usize = 512;' in oracle
            and b'const MAX_OWNER: usize = 128;' in original and b'const MAX_OWNER: usize = 128;' in oracle,
            'unchanged exact original record type retention bodies and thresholds')
    concrete = cases()
    process_custody(root, metadata, concrete)
    result = dict(schema='hepta.audit-retention.complete-read.v1', status='PASS',
        source_manifest_sha256=source(), processes=9, compiler=compilation(root),
        dependencies=dependencies(root), semantic=buffers(root,concrete),
        original_hia_equal=True, native_or_rust_executions=0, reader_writes=0,
        public_handler_qualified=False, whole_runtime_replaced=False)
    return result


def verify(output, require_controls=False):
    result = semantic(Path(output)/'semantic')
    if require_controls:
        import reader_controls
        result = dict(result, controls=reader_controls.verify(Path(output),result))
    return result

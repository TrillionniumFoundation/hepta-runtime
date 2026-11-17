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
                    semantic/'build/modules/audit-json/manifest.json','--output',semantic/'native'], root),
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
    folder = root/'build/modules/audit-json'
    manifest = loads(read(folder/'manifest.json'))
    composition = loads(read(ROOT/'native/audit_json.composition.json'))
    source_raw = read(ROOT/'native/audit_json.hepta')
    image = read(folder/'module.image.bin')
    require(read(folder/'audit-json.hepta') == read(folder/'module.input.bin') == source_raw,
            'every compiled source byte equals the frozen generated HIA')
    require(manifest['compiler_sha256'] == COMPILER and manifest['source_sha256'] == sha(source_raw)
            and manifest['image_sha256'] == sha(image) and build['image'] == pin(image)
            and build['source'] == pin(source_raw) and build['source_manifest_sha256'] == source()
            and build['manifest'] == dict(path='modules/audit-json/manifest.json',**pin(read(folder/'manifest.json'))),
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


def parse_reply(line):
    require(len(line) >= 9 and line[8:9] == b':', 'exact original reply protocol')
    code = int(line[:8],16)
    raw = bytes.fromhex(line[9:].decode('ascii'))
    require(line == f'{code:08x}:'.encode()+raw.hex().encode(), 'canonical complete reply representation')
    require((code in (0xfffffffe,0xffffffff) and not raw) or (code == len(raw) and code < 0xfffffffe),
            'original reply length or refusal')
    return code,raw


def buffers(root, concrete):
    original = read(root/'processes/original.stdout')
    actual = read(root/'processes/native.stdout')
    require(actual == original, 'complete actual original and HIA process stdout equality')
    replies = original.splitlines()
    require(len(replies) == len(concrete) and original.endswith(b'\n'), 'every actual paired reply exactly once')
    native = loads(read(root/'native/NATIVE.json'))
    raw = read(root/'native/buffers.bin.gz')
    require(native['status'] == 'PASS' and native['calls'] == native['completed_calls'] == len(concrete)
            and native['semantic_host_fallback'] is False and native['observed_buffers_complete'] is True
            and native['journal'] == pin(raw), 'complete actual native execution journal')
    require(native['native_image'] == pin(read(root/'build/modules/audit-json/module.image.bin')),
            'actual invoked exact HIA native image')
    counts = dict(success=0,invalid=0,capacity=0)
    logical_bytes = 8
    with gzip.GzipFile(fileobj=io.BytesIO(raw),mode='rb') as handle:
        require(handle.read(8) == b'HAJLOG01', 'physical journal format')
        for ordinal,(case,line) in enumerate(zip(concrete,replies,strict=True)):
            header = handle.read(48)
            require(len(header) == 48 and header[:8] == b'HAJCAL01', 'every physical invocation header')
            index,code,source_size,output_size,work_size = struct.unpack('<5Q',header[8:])
            wire = bytes.fromhex(case['wire_hex'])
            require(index == ordinal and source_size == len(wire)
                    and output_size == case['output_capacity'] and work_size == case['workspace_capacity'],
                    'every physical invocation matches its exact frozen input and capacities')
            expected_code,expected_output = parse_reply(line)
            require(code == expected_code, 'actual native return equals the original return')
            before,after = [],[]
            for size in (source_size+16,output_size+16,work_size+16):
                left,right = handle.read(size),handle.read(size)
                require(len(left) == len(right) == size, 'every complete physical buffer byte')
                before.append(left);after.append(right)
                logical_bytes += size*2
            logical_bytes += 48
            require(before[0] == wire+b'\xc3'*16 and after[0] == before[0], 'complete immutable borrowed input')
            require(before[1] == b'\x69'*output_size+b'\xa5'*16
                    and before[2] == b'\xa7'*work_size+b'\x5a'*16, 'exact initialized physical mutable buffers')
            require(after[1][-16:] == b'\xa5'*16, 'complete output guard tail')
            require(after[2][-16:] == b'\x5a'*16, 'complete workspace guard tail')
            admission = 'invalid' if code == 0xffffffff else 'capacity' if code == 0xfffffffe else 'success'
            require(admission == case['expected_admission'], 'original admission equals the source-owned contract case')
            counts[admission] += 1
            count = len(expected_output)
            require(after[1][:count] == expected_output and after[1][count:output_size] == b'\x69'*(output_size-count),
                    'exact original result and complete untouched output suffix')
            if work_size < 8192:
                require(after[2] == before[2], 'workspace capacity refused before any workspace write')
            else:
                require(after[2][1088:work_size] == before[2][1088:work_size], 'complete untouched high workspace suffix')
        require(handle.read(1) == b'', 'complete journal ends after the exact frozen invocation count')
    require(logical_bytes == native['logical_physical_bytes'], 'complete logical physical buffer byte count')
    require(counts == domain()['admissions'], 'every source-owned admission category exactly once')
    return dict(cases=len(concrete), admissions=counts, logical_physical_bytes=logical_bytes,
                journal=pin(raw), original_stdout=pin(original), native_stdout=pin(actual))


def semantic(root):
    root = Path(root).resolve(strict=True)
    metadata = envelope(root)
    require(metadata['schema'] == 'hepta.audit-json.capture.v1' and metadata['status'] == 'PASS'
            and metadata['source_manifest_sha256'] == source()
            and metadata['public_handler_qualified'] is False and metadata['whole_runtime_replaced'] is False,
            'successful frozen private audit codec capture')
    require(files(root/'source') == files(ROOT), 'complete frozen audit codec source copy')
    require(files(root/'reference') == files(ROOT/'reference'), 'unchanged exact original reference source')
    original = read(ROOT/'reference/request_audit.rs.txt')
    require(sha(original) == 'b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da',
            'exact target request audit source')
    require(read(ROOT/'reference/record_types.rs.txt').rstrip() in original
            and read(ROOT/'reference/anchor_type.rs.txt') in original
            and read(ROOT/'reference/record_types.rs.txt').rstrip() in read(ROOT/'reference/original_types.rs')
            and read(ROOT/'reference/anchor_type.rs.txt') in read(ROOT/'reference/original_types.rs'),
            'unchanged exact original generic audit types and anchor derives')
    concrete = cases()
    process_custody(root, metadata, concrete)
    result = dict(schema='hepta.audit-json.complete-read.v1', status='PASS',
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

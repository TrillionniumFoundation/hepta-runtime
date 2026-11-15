"""Execute the retained original only after complete native-first admission.

The caller supplies the exact native execution roots. Fixture roots are moved,
recreated at the same absolute pathname, replayed, then retired. None of the
readers in this package creates or restores a live filesystem fixture.
"""
from pathlib import Path
import argparse
import importlib.util
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
from capture_format import canonical, need, pin, same, sha, strict_json
import native_predecessor

TRACE = ('getpgid,openat,read,readv,pread64,write,writev,close,newfstatat,fstat,statx,'
         'readlink,readlinkat,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,'
         'chmod,fchmod,fchmodat,clone,clone3,wait4,fcntl,lseek,fsync,fdatasync')


def write(path, value):
    path = Path(path)
    with path.open('xb') as stream:
        stream.write(canonical(value))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_files(root):
    result = {}
    for path in sorted(Path(root).rglob('*')):
        info = path.lstat()
        need(not stat.S_ISLNK(info.st_mode), 'source contains a symlink')
        if stat.S_ISREG(info.st_mode):
            result[str(path.relative_to(root))] = pin(path)
        else:
            need(stat.S_ISDIR(info.st_mode), 'source contains a special file')
    need(result, 'empty original source closure')
    return result


def selected_environment(cargo, rustc, target):
    need(cargo.is_absolute() and rustc.is_absolute(), 'absolute toolchain invocation required')
    need(cargo.parent == rustc.parent, 'selected Cargo and rustc must be one toolchain')
    env = os.environ.copy()
    for name in list(env):
        if (name.startswith(('RUST', 'CARGO_', 'HEPTA_')) or name in ('LD_PRELOAD', 'LD_LIBRARY_PATH')):
            env.pop(name)
    controlled = {'PATH': str(cargo.parent) + ':/usr/bin:/bin', 'RUSTC': str(rustc),
                  'CARGO_BUILD_JOBS': '2', 'CARGO_TARGET_DIR': str(target), 'LC_ALL': 'C'}
    env.update(controlled)
    return env, controlled


class Processes:
    def __init__(self, output, env, controlled):
        self.output, self.env, self.controlled = output, env, controlled
        self.rows = []

    def run(self, name, command, cwd, *, stdin=None, umask=None):
        folder = self.output / 'processes' / name
        folder.mkdir(parents=True)
        start = time.monotonic_ns()
        process = None
        timed = False
        error = None
        code = None
        process_status = None
        try:
            with (folder / 'stdout').open('xb') as stdout, (folder / 'stderr').open('xb') as stderr:
                with (open(stdin, 'rb') if stdin is not None else open(os.devnull, 'rb')) as input_stream:
                    try:
                        process = subprocess.Popen(command, cwd=cwd, env=self.env, stdin=input_stream,
                            stdout=stdout, stderr=stderr, start_new_session=True,
                            umask=-1 if umask is None else umask)
                        if umask is not None:
                            process_status = Path('/proc/'+str(process.pid)+'/status').read_bytes()
                            (folder/'proc-status-at-start.txt').write_bytes(process_status)
                            native_predecessor.proc_identity(process_status,pid=process.pid,
                                parent=os.getpid(),umask=umask)
                        try:
                            code = process.wait(timeout=180)
                        except subprocess.TimeoutExpired:
                            timed = True
                            os.killpg(process.pid, signal.SIGKILL)
                            code = process.wait(timeout=3)
                    except OSError as exc:
                        error = {'type': type(exc).__name__, 'message': str(exc), 'errno': exc.errno}
        finally:
            finish = time.monotonic_ns()
            row = {'name': name, 'command': list(command), 'cwd': str(cwd),
                   'pid': None if process is None else process.pid,
                   'started_monotonic_ns': start, 'finished_monotonic_ns': finish,
                   'elapsed_seconds': (finish-start)/1e9, 'timeout_seconds': 180,
                   'exit_code': code, 'timed_out': timed, 'start_error': error,
                   'umask':umask,
                   'proc_status_at_start':None if process_status is None else {
                       'path':str(folder/'proc-status-at-start.txt'),
                       'bytes':len(process_status),'sha256':sha(process_status)},
                   'controlled_env': self.controlled,
                   'stdin': None if stdin is None else {'path': str(stdin), **pin(stdin)},
                   'stdout': {'path': str(folder/'stdout'), **pin(folder/'stdout')},
                   'stderr': {'path': str(folder/'stderr'), **pin(folder/'stderr')}}
            self.rows.append(row)
            write(folder/'process.json', row)
            temporary = self.output/'processes.next.json'
            temporary.write_bytes(canonical(self.rows))
            temporary.replace(self.output/'processes.json')
        need(code == 0 and not timed and error is None,
             'actual original process failed; complete partial streams retained: ' + name)
        return folder, row


def fixture_identity(path):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and not path.is_symlink(), 'owned fixture root is not a directory')
    return {'path': str(path), 'dev': info.st_dev, 'ino': info.st_ino,
            'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid}


def append_event(path, value):
    with path.open('ab') as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def original_input(source, partition, capture, destination):
    generator = load(source/'cases.py', '_batch_original_inputs')
    controls = load(source/'control_inputs.py', '_batch_original_controls')
    rows = []
    for case in generator.iter_cases():
        meta, blobs = dict(case['metadata']), list(case['blobs'])
        part = 'async' if meta['execution'] == 'async' else ('wide' if meta['large'] else 'small')
        if part != partition:
            continue
        directory = 'sequence-'+meta['sequence'] if meta['sequence'] else 'case-'+str(meta['case_id']).zfill(4)
        cwd = os.fsencode(capture/'files'/directory)
        relative = bytes.fromhex(meta['workdir_rel_hex'])
        if relative:
            cwd += b'/' + relative
        meta['fixture_cwd_hex'] = cwd.hex()
        if part == 'async':
            following = controls.cancel_followup(meta)
            meta['followup'] = following['metadata']
            meta['followup_blob_base'] = len(blobs)
            blobs.extend(following['blobs'])
        rows.append((meta, blobs))
    need(len(rows) == {'small':209, 'wide':4, 'async':2}[partition], 'complete original partition count')
    with destination.open('xb') as stream:
        stream.write(b'HBCCI002' + len(rows).to_bytes(8, 'little'))
        for metadata, blobs in rows:
            stream.write(generator.record(metadata, blobs))
    return {'case_ids':[meta['case_id'] for meta,_ in rows], **pin(destination)}


def run_original_partition(processes, binary, source, native_run, output, partition, native):
    capture = native_run/('output-'+partition)
    folder = output/partition
    folder.mkdir()
    full_input = folder/'input.bin'
    input_identity = original_input(source, partition, capture, full_input)
    admitted=next(value for value in native['captures'] if value['partition']==partition)
    masks=set(admitted['elf_umasks'].values())
    same(sorted(masks),[admitted['fixture_umask']],'fixture and ELF umask require one original process identity')
    actual_umask=admitted['fixture_umask']
    live = capture/'files'
    kept = capture/('files.before-original-'+output.name)
    retired = capture/('files.original-'+output.name)
    need(not kept.exists() and not retired.exists(), 'fixture retirement destination already exists')
    before = fixture_identity(live)
    live.rename(kept)
    same({key:fixture_identity(kept)[key] for key in ('dev','ino')},
         {key:before[key] for key in ('dev','ino')}, 'native fixture rename changed inode')
    need(not live.exists(), 'native execution root did not become absent')
    append_event(output/'fixture-renames.jsonl', {'kind':'native-fixture-retained', 'partition':partition,
        'before':before, 'after':fixture_identity(kept), 'original_path_absent':True})
    old_umask=os.umask(actual_umask)
    try:
        live.mkdir(mode=0o700)
    finally:
        os.umask(old_umask)
    append_event(output/'fixture-renames.jsonl', {'kind':'original-fixture-created', 'partition':partition,
        'identity':fixture_identity(live), 'native_fixture':fixture_identity(kept)})
    try:
        trace = folder/'strace.log'
        command = [str(processes.strace), '-f', '-qq', '-ttt', '-T', '-s', '128', '-xx', '-yy',
                   '-e', 'trace='+TRACE, '-o', str(trace), '--', str(binary), '--inner', str(live)]
        process_folder, row = processes.run('original-'+partition, command, source, stdin=full_input,
                                             umask=actual_umask)
        need((process_folder/'stderr').read_bytes() == b'', 'original replay wrote unexpected stderr')
        with (process_folder/'stdout').open('rb') as stream:
            same(stream.read(8), b'HBCCO002', 'original replay binary output magic')
        return {'partition':partition, 'input':input_identity, 'process':row,
                'trace':{'path':str(trace), **pin(trace)},
                'fixture_origin':str(live), 'native_fixture_retained':str(kept),
                'original_fixture_retired':str(retired)}
    finally:
        original = fixture_identity(live)
        live.rename(retired)
        need(not live.exists(), 'original fixture origin was not retired')
        append_event(output/'fixture-renames.jsonl', {'kind':'original-fixture-retired', 'partition':partition,
            'before':original, 'after':fixture_identity(retired), 'original_path_absent':True})


def main():
    parser = argparse.ArgumentParser()
    for name in ('source','native-source','native-run','build-source','native-manifest','output','cargo','rustc','strace'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    for name, value in vars(args).items():
        setattr(args, name, value.absolute())
    args.output.mkdir(parents=True)
    os.umask(0o077)
    start = time.monotonic_ns()
    write(args.output/'remote-process.json', {'pid':os.getpid(), 'argv':sys.argv,
        'cwd':str(Path.cwd()), 'started_monotonic_ns':start,
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'cgroup':Path('/proc/self/cgroup').read_text()})
    before = source_files(args.source)
    write(args.output/'SOURCE-FILES.json', before)
    source_path = Path(__file__).absolute()
    need(source_path == args.source/'run.py', 'executed original driver differs from selected source')
    origins = list(dict.fromkeys((str(path),str(path)) for path in (
        args.native_source,args.native_run,args.build_source,args.native_manifest.parent)))
    native_args = {'native_source':args.native_source,'native_run':args.native_run,
                   'build_source':args.build_source,'manifest':args.native_manifest,'origins':origins}
    native = native_predecessor.native_evidence(**native_args)
    write(args.output/'NATIVE-PREDECESSOR.json', native)
    admitted_at = time.monotonic_ns()
    write(args.output/'NATIVE-ADMISSION.json', {
        'schema':'hepta.runtime.batch-call-original-predecessor.v1',
        'native_source':str(args.native_source),'native_run':str(args.native_run),
        'build_source':str(args.build_source),'manifest':str(args.native_manifest),
        'native_evidence':pin(args.output/'NATIVE-PREDECESSOR.json'),
        'admitted_monotonic_ns':admitted_at,'native_artifact_sha256':native['artifact_sha256'],
        'new_native_calls':0,'original_execution_started':False})
    # There is no original compilation or business execution above this line.
    verifier = load(args.source/'oracle/verify_sources.py', '_batch_original_source_verifier')
    materialized, proof = verifier.assemble(args.source/'oracle')
    crate = args.output/'crate'
    for name, raw in materialized.items():
        path = crate/name
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
    write(args.output/'SOURCE.json',proof)
    target = args.output/'target'
    env, controlled = selected_environment(args.cargo,args.rustc,target)
    processes = Processes(args.output,env,controlled)
    processes.strace = args.strace
    (args.output/'tools').mkdir()
    toolchain = {}
    for name,path in (('cargo',args.cargo),('rustc',args.rustc),('strace',args.strace)):
        retained=args.output/'tools'/name
        shutil.copyfile(path,retained)
        same(pin(retained),pin(path),'complete selected executable copy')
        toolchain[name]={'invocation':str(path),'resolved_path':str(path.resolve()),
                         'retained':str(retained),**pin(path)}
    write(args.output/'TOOLCHAIN.json',toolchain)
    rust_folder,_ = processes.run('rustc-version',[str(args.rustc),'--version','--verbose'],args.source)
    rust_version = (rust_folder/'stdout').read_bytes()
    need(b'\nrelease: 1.95.0\n' in rust_version and
         b'\nhost: x86_64-unknown-linux-gnu\n' in rust_version,
         'reference is not the explicitly selected Rust 1.95.0 target')
    need((rust_folder/'stderr').read_bytes()==b'','rustc version stderr')
    cargo_folder,_ = processes.run('cargo-version',[str(args.cargo),'--version','--verbose'],args.source)
    need((cargo_folder/'stdout').read_bytes().startswith(b'cargo 1.95.0 '),'selected Cargo is not 1.95.0')
    need((cargo_folder/'stderr').read_bytes()==b'','Cargo version stderr')
    trace_folder,_ = processes.run('strace-version',[str(args.strace),'-V'],args.source)
    need((trace_folder/'stdout').read_bytes().startswith(b'strace -- version '),'actual selected tracer version')
    need((trace_folder/'stderr').read_bytes()==b'','strace version stderr')
    processes.run('build',[str(args.cargo),'build','--locked','--release',
                          '--manifest-path',str(crate/'Cargo.toml')],args.source)
    same((crate/'Cargo.lock').read_bytes(),materialized['Cargo.lock'],'locked original dependencies changed')
    rust_info = target/'.rustc_info.json'
    need(rust_info.is_file(),'fresh Cargo rustc identity was not retained')
    info = strict_json(rust_info.read_bytes())
    need('1.95.0' in json.dumps(info,sort_keys=True),'fresh target used a different compiler')
    shutil.copyfile(rust_info,args.output/'target.rustc_info.json')
    built = target/'release/hepta-batch-call-original'
    binary = args.output/'reference.elf'
    shutil.copyfile(built,binary)
    binary.chmod(0o500)
    same(pin(binary),pin(built),'complete original executable copy')
    write(args.output/'BUILD.json',{'binary':pin(binary),'target_binary':pin(built),
        'target_rustc_info':pin(args.output/'target.rustc_info.json'),
        'materialized_source':proof['materialized'],'native_predecessor':pin(args.output/'NATIVE-PREDECESSOR.json'),
        'fixed_rust_release':'1.95.0','fresh_target':True,'locked_build':True})
    captures=[]
    for partition in ('small','wide','async'):
        captures.append(run_original_partition(processes,binary,args.source,args.native_run,args.output,partition,native))
    same(native_predecessor.native_evidence(**native_args),native,
         'native proof changed or retained reader depends on live fixtures')
    same(source_files(args.source),before,'original source changed during execution')
    need(all(not (args.native_run/('output-'+part)/'files').exists()
             for part in ('small','wide','async')),'replay fixture origin is still live')
    result={'schema':'hepta.runtime.batch-call-original-capture.v1','status':'CAPTURED',
        'cases':215,'post_cancel_followup_calls':2,'native_predecessor':pin(args.output/'NATIVE-PREDECESSOR.json'),
        'actual_processes':len(processes.rows),'original_replay_processes':3,'fresh_locked_builds':1,
        'captures':captures,'source_unchanged':True,'source_files':before,
        'source':pin(args.output/'SOURCE.json'),'binary':pin(binary),'toolchain':toolchain,
        'trace_string_limit':128,'trace_payloads_may_be_clipped':True,
        'full_input_and_result_bytes_retained':True,'native_original_comparison_complete':False,
        'original_inner_execute_batch_edit_executed':True,'original_outer_batch_method_executed':False,
        'original_sdk_executed':False,'original_full_router_executed':False,
        'fixture_origins_retired':True,'new_native_calls':0,'public_handler_replaced':False,
        'whole_runtime_replaced':False,'started_monotonic_ns':start,
        'finished_monotonic_ns':time.monotonic_ns()}
    write(args.output/'RESULT.json',result)
    print(json.dumps({'status':'CAPTURED','cases':215,'original_replay_processes':3,
        'actual_processes':len(processes.rows),'result':pin(args.output/'RESULT.json'),
        'native_original_comparison_complete':False},sort_keys=True),flush=True)


if __name__=='__main__':
    main()

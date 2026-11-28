"""Execute the unchanged Linux module against owned real filesystem fixtures."""
from pathlib import Path
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
sys.dont_write_bytecode = True


def pin(path):
    path = Path(path)
    with path.open('rb') as stream:
        return {'bytes': path.stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def dump(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
        stream.write('\n')


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def snapshot(roots, output):
    entries = []
    objects = output/'objects'; objects.mkdir(exist_ok=True)
    def visit(path):
        row = {'path_hex': path.hex()}
        try: st = os.lstat(path)
        except OSError as error:
            row['lstat_error'] = {'errno': error.errno, 'text': str(error)}
            entries.append(row); return
        row['stat'] = {name: getattr(st, 'st_'+name) for name in
            ('dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns')}
        entries.append(row)
        if stat.S_ISLNK(st.st_mode):
            row['kind'] = 'symlink'; row['target_hex'] = os.readlink(path).hex()
        elif stat.S_ISREG(st.st_mode):
            row['kind'] = 'file'
            try:
                with open(path, 'rb') as stream: data = stream.read()
                digest = hashlib.sha256(data).hexdigest(); target = objects/(digest+'.bin')
                if not target.exists(): target.write_bytes(data)
                else: assert pin(target) == {'bytes': len(data), 'sha256': digest}
                row['content'] = {'path': str(target.relative_to(output)), 'bytes': len(data), 'sha256': digest}
            except OSError as error: row['read_error'] = {'errno': error.errno, 'text': str(error)}
        elif stat.S_ISDIR(st.st_mode):
            row['kind'] = 'directory'
            try: names = sorted(os.listdir(path))
            except OSError as error:
                row['list_error'] = {'errno': error.errno, 'text': str(error)}; return
            row['children_hex'] = [name.hex() for name in names]
            for name in names: visit(path+b'/'+name)
        elif stat.S_ISFIFO(st.st_mode): row['kind'] = 'fifo'
        else: row['kind'] = 'other'
    for root in roots: visit(root)
    return {'schema': 'hepta.runtime.filesystem-parity-state.v1',
            'roots_hex': [root.hex() for root in roots], 'entries': entries}


def setup_fixture(group):
    for root in group['roots']:
        assert not os.path.lexists(root), root
        os.makedirs(root, mode=0o700)
    for item in group['setup']:
        kind, path = item['kind'], item['path']
        if kind == 'chmod': continue
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        if kind == 'mkdir': os.makedirs(path, mode=0o700, exist_ok=True)
        elif kind == 'write':
            with open(path, 'xb') as stream: stream.write(item['data'])
        elif kind == 'symlink': os.symlink(item['target'], path)
        elif kind == 'hardlink': os.link(item['target'], path, follow_symlinks=False)
        elif kind == 'fifo': os.mkfifo(path, 0o600)
        else: raise ValueError(kind)


class OriginalProcess:
    def __init__(self, output, process_name, cases, binary, strace, regular_input):
        self.output, self.name, self.cases = output, process_name, cases
        self.folder = output/'processes'/process_name; self.folder.mkdir(parents=True)
        self.input_path = self.folder/'input.bin'
        with self.input_path.open('xb') as stream:
            stream.write(b'HFPRI001'+struct.pack('<Q', len(cases)))
            for case in cases:
                stream.write(struct.pack('<4Q', case['case_id'], case['operation'], len(case['first']), len(case['second'])))
                stream.write(case['first']); stream.write(case['second'])
        self.command = [str(strace), '-f', '-qq', '-ttt', '-s', '0', '-xx',
            '-e', 'trace=%file,%desc,getpgid',
            '-e', 'raw=read,write,readv,writev,pread64,pwrite64,preadv,pwritev,sendfile,splice,tee,vmsplice',
            '-o', str(self.folder/'trace.txt'), str(binary)]
        self.regular_input = regular_input
        self.begin = time.monotonic(); self.deadline = self.begin+180
        self.error = (self.folder/'stderr.bin').open('xb')
        self.out = (self.folder/'stdout.bin').open('xb')
        self.infile = self.input_path.open('rb') if regular_input else None
        self.proc = subprocess.Popen(self.command, cwd=output, stdin=self.infile or subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.error, start_new_session=True, bufsize=0)
        self.selector = selectors.DefaultSelector(); self.selector.register(self.proc.stdout, selectors.EVENT_READ)
        self.timed_out = False; self.input_offset = 16; self.output_offset = 64
        if not regular_input: self.send(b'HFPRI001'+struct.pack('<Q', len(cases)))
        header = self.read(64)
        assert header[:8] == b'HFPRO001'
        self.header = dict(zip(('cases', 'uid', 'euid', 'gid', 'egid', 'prior_umask', 'active_umask'), struct.unpack('<7Q', header[8:])))
        assert self.header['cases'] == len(cases) and self.header['euid'] != 0 and self.header['active_umask'] == 0o22

    def send(self, data):
        # Only the bounded ordinary cases use a pipe. Wide inputs use a regular
        # file so strace records actual input reads without pipe-fragment noise.
        view = memoryview(data)
        while view:
            if time.monotonic() >= self.deadline: raise TimeoutError('original input deadline')
            n = os.write(self.proc.stdin.fileno(), view); view = view[n:]

    def read(self, count):
        chunks = []; total = 0
        while total < count:
            left = self.deadline-time.monotonic()
            if left <= 0 or not self.selector.select(left):
                self.timed_out = True; raise TimeoutError('original output deadline')
            chunk = os.read(self.proc.stdout.fileno(), min(count-total, 1<<20))
            if not chunk: raise EOFError(('incomplete original output', count, total, self.proc.poll()))
            chunks.append(chunk); self.out.write(chunk); total += len(chunk)
        return b''.join(chunks)

    def call(self, case):
        wire = struct.pack('<4Q', case['case_id'], case['operation'], len(case['first']), len(case['second']))+case['first']+case['second']
        if not self.regular_input: self.send(wire)
        header = self.read(80); values = struct.unpack('<10Q', header)
        case_id, operation, status, created, errno_present, errno_raw, short_len, chain_len, before_count, after_count = values
        assert (case_id, operation) == (case['case_id'], case['operation'])
        assert status in (0, 1) and created in (0, 1, 2) and errno_present in (0, 1)
        short = self.read(short_len); chain = self.read(chain_len)
        fd_bytes = self.read((before_count+after_count)*40)
        fds = [list(struct.unpack_from('<5Q', fd_bytes, offset)) for offset in range(0, len(fd_bytes), 40)]
        before, after = fds[:before_count], fds[before_count:]
        assert before == after, ('actual descriptor leak', case_id, before, after)
        size = 80+short_len+chain_len+len(fd_bytes)
        row = {'case_id': case_id, 'operation': operation, 'status': status, 'created_tag': created,
            'errno_present': errno_present, 'errno': errno_raw if errno_raw < (1<<63) else errno_raw-(1<<64),
            'short': short.decode('utf-8'), 'chain': chain.decode('utf-8'),
            'before_descriptors': before, 'after_descriptors': after,
            'input_offset': self.input_offset, 'input_bytes': len(wire), 'input_sha256': hashlib.sha256(wire).hexdigest(),
            'output_offset': self.output_offset, 'output_bytes': size,
            'output_sha256': hashlib.sha256(header+short+chain+fd_bytes).hexdigest(),
            'begin_marker': -1700000000+2*case_id, 'end_marker': -1700000000+2*case_id+1}
        self.input_offset += len(wire); self.output_offset += size
        return row

    def finish(self, failure=None):
        if self.proc.stdin is not None and not self.proc.stdin.closed: self.proc.stdin.close()
        if failure is None:
            left = self.deadline-time.monotonic()
            if left <= 0: self.timed_out = True
            else:
                try: self.proc.wait(timeout=left)
                except subprocess.TimeoutExpired: self.timed_out = True
            if self.timed_out:
                os.killpg(self.proc.pid, signal.SIGKILL); self.proc.wait()
            trailing = self.proc.stdout.read()
            self.out.write(trailing)
        else:
            if self.proc.poll() is None: os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait(); trailing = self.proc.stdout.read(); self.out.write(trailing)
        self.out.close(); self.error.close(); self.selector.close(); self.proc.stdout.close()
        if self.infile: self.infile.close()
        row = {'name': self.name, 'command': self.command, 'cwd': str(self.output), 'pid': self.proc.pid,
            'exit_code': self.proc.returncode, 'timed_out': self.timed_out, 'timeout_seconds': 180,
            'elapsed_seconds': time.monotonic()-self.begin, 'input_kind': 'regular-file' if self.regular_input else 'pipe',
            'header': self.header, 'cases': [case['case_id'] for case in self.cases],
            'stdin': {'path': str(self.input_path.relative_to(self.output)), **pin(self.input_path)},
            'stdout': {'path': str((self.folder/'stdout.bin').relative_to(self.output)), **pin(self.folder/'stdout.bin')},
            'stderr': {'path': str((self.folder/'stderr.bin').relative_to(self.output)), **pin(self.folder/'stderr.bin')},
            'trace': {'path': str((self.folder/'trace.txt').relative_to(self.output)), **pin(self.folder/'trace.txt')},
            'failure': failure}
        dump(self.folder/'process.json', row)
        if failure is None:
            assert not self.timed_out and self.proc.returncode == 0 and not trailing, row
            assert row['stderr']['bytes'] == 0, row
        return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True); parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True); parser.add_argument('--cross-root', type=Path, required=True)
    args = parser.parse_args(); args.output.mkdir(mode=0o700)
    dump(args.output/'remote-process.json', {'pid': os.getpid(), 'cgroup': Path('/proc/self/cgroup').read_text(), 'argv': sys.argv})
    assert os.geteuid() != 0, 'denied-path domain requires the non-root fixture owner'
    assert not args.cross_root.exists(), 'cross-filesystem fixture must be exclusively new'
    cases_pin = pin(args.cases); driver_pin = pin(Path(__file__))
    module = load_module(args.cases, '_filesystem_parity_cases')
    result = json.loads((args.build/'RESULT.json').read_bytes())
    assert result['status'] == 'PASS' and result['fresh_locked_original_builds'] == 1
    binary = Path(result['binary']['path']); assert pin(binary) == {k: result['binary'][k] for k in ('bytes', 'sha256')}
    assert pin(args.build/'SOURCE.json') == result['source']
    assert pin(args.build/'processes.json') == result['processes']
    groups = module.groups(args.output, args.cross_root)
    ids = [case['case_id'] for group in groups.values() for case in group['cases']]
    assert ids == list(range(len(ids)))
    dump(args.output/'INPUTS.json', {'groups': {name: [module.summary(case) for case in group['cases']] for name, group in groups.items()},
        'fixture_definitions': module.fixture_json({name: {k: v for k, v in group.items() if k != 'cases'} for name, group in groups.items()})})
    source = {'schema': 'hepta.runtime.filesystem-parity-capture-source.v1', 'build_root': str(args.build),
        'build_result': pin(args.build/'RESULT.json'), 'binary': result['binary'],
        'cases_path': str(args.cases), 'cases': cases_pin, 'driver_path': str(Path(__file__)), 'driver': driver_pin,
        'strace': {'path': '/usr/bin/strace', **pin('/usr/bin/strace')},
        'fixture_home': str(args.output), 'cross_root': str(args.cross_root),
        'scope': 'unchanged Linux local_linux module; no public SDK, async wrapper, policy, cache or session execution'}
    dump(args.output/'SOURCE.json', source)
    processes, observations = [], []
    for name, group in groups.items():
        setup_fixture(group)
        folder = args.output/name; folder.mkdir(exist_ok=True)
        dump(folder/'prepared-state.json', snapshot(group['roots'], args.output))
        for item in group['setup']:
            if item['kind'] == 'chmod': os.chmod(item['path'], item['mode'], follow_symlinks=False)
        dump(folder/'armed-state.json', snapshot(group['roots'], args.output))
        if name == 'cross_device':
            devices = [os.stat(root).st_dev for root in group['roots']]
            assert devices[0] != devices[1], ('EXDEV needs actual separate filesystems', devices)
            dump(folder/'devices.json', {'roots_hex': [root.hex() for root in group['roots']], 'devices': devices})
        subsets = [[case] for case in group['cases']] if group.get('regular_file_stdin') else [group['cases']]
        for index, cases in enumerate(subsets):
            process_name = name+('-'+str(index) if len(subsets) > 1 else '')
            original = None
            try:
                # The wide process can start consuming its regular input as soon
                # as launched, so its before state is observed before Popen.
                first_before = snapshot(group['roots'], args.output)
                original = OriginalProcess(args.output, process_name, cases, binary, Path('/usr/bin/strace'), bool(group.get('regular_file_stdin')))
                for case_index, case in enumerate(cases):
                    before = first_before if case_index == 0 else snapshot(group['roots'], args.output)
                    state_name = 'case-'+str(case['case_id'])
                    before_path = folder/(state_name+'-before.json'); dump(before_path, before)
                    row = original.call(case)
                    after_path = folder/(state_name+'-after.json'); dump(after_path, snapshot(group['roots'], args.output))
                    row.update(module.summary(case)); row.update({'group': name, 'process': process_name,
                        'before_state': {'path': str(before_path.relative_to(args.output)), **pin(before_path)},
                        'after_state': {'path': str(after_path.relative_to(args.output)), **pin(after_path)}})
                    observations.append(row)
                    with (args.output/'cases.jsonl').open('a') as stream:
                        stream.write(json.dumps(row, sort_keys=True, ensure_ascii=True, allow_nan=False)+'\n')
                processes.append(original.finish()); original = None
                (args.output/'processes.json').write_text(json.dumps(processes, sort_keys=True, indent=2)+'\n')
            except BaseException as error:
                failure = {'class': type(error).__name__, 'message': str(error)}
                if original is not None:
                    try: processes.append(original.finish(failure))
                    except BaseException as cleanup_error: failure['capture_cleanup_error'] = repr(cleanup_error)
                dump(args.output/'FAILURE.json', {'group': name, 'failure': failure, 'completed_cases': len(observations), 'processes': processes})
                raise
        restore = []
        for item in group['restore_modes']:
            before = stat.S_IMODE(os.lstat(item['path']).st_mode)
            os.chmod(item['path'], item['mode'], follow_symlinks=False)
            restore.append({'path_hex': item['path'].hex(), 'before_mode': before, 'after_mode': stat.S_IMODE(os.lstat(item['path']).st_mode)})
        dump(folder/'restored-state.json', snapshot(group['roots'], args.output)); dump(folder/'observer-restorations.json', restore)
    assert len(observations) == len(ids) and {row['case_id'] for row in observations} == set(ids)
    assert pin(args.cases) == cases_pin and pin(Path(__file__)) == driver_pin
    assert pin(binary) == {k: result['binary'][k] for k in ('bytes', 'sha256')}
    exdev = [row for row in observations if row['group'] == 'cross_device']
    assert all(row['status'] == 1 and row['errno_present'] == 1 and row['errno'] == 18 for row in exdev[:4])
    for process in processes:
        for key in ('stdin', 'stdout', 'stderr', 'trace'):
            path = args.output/process[key]['path']
            with path.open('rb') as src, (path.with_name(path.name+'.gz')).open('xb') as dest:
                with gzip.GzipFile(fileobj=dest, mode='wb', mtime=0) as compressed:
                    while chunk := src.read(1<<20): compressed.write(chunk)
    observed = {'schema': 'hepta.runtime.filesystem-parity-original-capture.v1', 'status': 'PASS',
        'source': pin(args.output/'SOURCE.json'), 'inputs': pin(args.output/'INPUTS.json'),
        'processes': pin(args.output/'processes.json'), 'cases_stream': pin(args.output/'cases.jsonl'),
        'cases': len(observations), 'replay_processes': len(processes), 'fresh_builds_in_capture': 0,
        'new_native_calls': 0, 'wide_cases': len(groups['wide']['cases']),
        'body_bytes': sum(len(row['short'].encode())+len(row['chain'].encode()) for row in observations),
        'case_counts': {name: len(group['cases']) for name, group in groups.items()},
        'complete_original_outputs': True, 'strict_reference_admission_complete': False}
    dump(args.output/'ORIGINAL.json', observed); print(json.dumps(observed, sort_keys=True), flush=True)


if __name__ == '__main__': main()

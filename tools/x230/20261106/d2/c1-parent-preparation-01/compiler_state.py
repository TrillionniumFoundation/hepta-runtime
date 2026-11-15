"""Fresh bounded compiler metadata scans through directory fds; no PID cache."""
import os
from pathlib import Path
import stat
import time

COMPILER_NAMES = frozenset({'cargo', 'rustc', 'rust-lld', 'ld.lld'})
DEAD_STATES = frozenset({'Z', 'X', 'x'})
MAX_RECORDS = 256
MAX_COMM_BYTES = 256
MAX_STAT_BYTES = 8192
OPEN_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


def parse_stat(raw, expected_pid):
    opening, closing = raw.find(' ('), raw.rfind(')')
    if opening < 1 or closing <= opening + 1:
        raise ValueError('invalid proc stat delimiters')
    pid = int(raw[:opening])
    fields = raw[closing + 1:].split()
    if pid != expected_pid or len(fields) < 20 or len(fields[0]) != 1:
        raise ValueError('invalid proc stat identity or fields')
    row = {'pid': pid, 'comm': raw[opening + 2:closing], 'state': fields[0],
           'ppid': int(fields[1]), 'process_group': int(fields[2]),
           'birth_ticks': int(fields[19])}
    if row['birth_ticks'] <= 0 or row['ppid'] < 0 or row['process_group'] < 0:
        raise ValueError('invalid proc stat numeric identity')
    return row


def read_metadata(directory, name, maximum):
    fd = os.open(name, OPEN_READ, dir_fd=directory)
    try:
        # proc comm/stat are generated bounded metadata records, not regular
        # seekable files. One bounded read avoids TextIOWrapper read-to-EOF,
        # its FileIO metadata queries, and a second read solely to observe EOF.
        raw = os.read(fd, maximum)
        if len(raw) >= maximum:
            raise ValueError('proc metadata byte bound reached')
        if not raw.endswith(b'\n'):
            raise ValueError('proc metadata record was incomplete')
        return raw.decode('utf-8')
    finally:
        os.close(fd)


def compiler_snapshot(proc_root=Path('/proc'), *, maximum_process_directories=16384):
    started = time.monotonic_ns()
    root = os.open(proc_root, OPEN_READ | os.O_DIRECTORY)
    records = []
    count = 0
    try:
        names = []
        with os.scandir(root) as entries:
            for entry in entries:
                if not entry.name.isascii() or not entry.name.isdigit():
                    continue
                count += 1
                if count > maximum_process_directories:
                    raise ValueError('proc directory scan bound exceeded at ' + str(count))
                names.append(entry.name)
        for name in sorted(names, key=int):
            if len(records) >= MAX_RECORDS:
                records.append({'blocks': True, 'reason': 'compiler metadata record bound reached'})
                break
            pid = int(name)
            try:
                comm = read_metadata(root, name + '/comm', MAX_COMM_BYTES).strip()
            except (FileNotFoundError, ProcessLookupError):
                continue  # Same pre-name process-exit boundary as the original reader.
            except (OSError, ValueError) as error:
                records.append({'pid': pid, 'blocks': True, 'reason': 'comm unreadable',
                                'error_type': type(error).__name__})
                continue
            if comm not in COMPILER_NAMES:
                continue
            directory = None
            try:
                # A new PID-directory fd is opened only for a current match and
                # closed in this same scan. No identity or negative result survives
                # into the next 1 Hz scan. Reuse of the pathname cannot redirect
                # these two stat reads to a different process directory.
                directory = os.open(name, OPEN_READ | os.O_DIRECTORY, dir_fd=root)
                first = parse_stat(read_metadata(directory, 'stat', MAX_STAT_BYTES), pid)
                owner_before = os.fstat(directory)
                second = parse_stat(read_metadata(directory, 'stat', MAX_STAT_BYTES), pid)
                owner_after = os.fstat(directory)
                current_path = os.stat(name, dir_fd=root, follow_symlinks=False)
                directory_fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode')
                changed = (not stat.S_ISDIR(owner_before.st_mode)
                           or any(getattr(owner_before, key) != getattr(owner_after, key)
                                  or getattr(owner_after, key) != getattr(current_path, key)
                                  for key in directory_fields)
                           or first['birth_ticks'] != second['birth_ticks']
                           or first['comm'] != comm or second['comm'] != comm)
                if changed:
                    records.append({'pid': pid, 'comm': comm, 'blocks': True,
                                    'reason': 'compiler identity changed while reading',
                                    'before': {**first, 'uid': owner_before.st_uid},
                                    'after': {**second, 'uid': owner_after.st_uid}})
                else:
                    states = [first['state'], second['state']]
                    records.append({**second, 'uid': owner_after.st_uid, 'observed_states': states,
                                    'blocks': any(state not in DEAD_STATES for state in states)})
            except (FileNotFoundError, ProcessLookupError):
                records.append({'pid': pid, 'comm': comm, 'blocks': True,
                                'reason': 'compiler disappeared while reading'})
            except (OSError, ValueError) as error:
                records.append({'pid': pid, 'comm': comm, 'blocks': True,
                                'reason': 'compiler identity metadata unreadable',
                                'error_type': type(error).__name__})
            finally:
                if directory is not None:
                    os.close(directory)
    finally:
        os.close(root)
    blocking = [row for row in records if row['blocks']]
    return {'schema': 'hepta-compiler-state-sample/v1',
            'started_monotonic_ns': started, 'finished_monotonic_ns': time.monotonic_ns(),
            'records': records, 'blocking_records': blocking, 'quiescent': not blocking,
            'cmdline_or_environment_read': False, 'signals_sent': 0,
            'enumerated_process_directories': count}

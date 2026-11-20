"""DATA-only preservation driver; never executes a compiler or runtime image."""
from pathlib import Path
import hashlib, json, os, signal, subprocess, time, traceback

BASE = Path('/home/qian-qi/hia-binary-composition-archive-tools-20261120')
COMPLETE = Path('/home/qian-qi/hia-binary-composition-complete-package-20261120-r4')
SMALL = Path('/home/qian-qi/hia-binary-composition-build-package-20261120-r4')
READBACK = 'c2470b307aa3122559df27b13342099d0538f1538fc058c434693cdac1cda2dd'
PYTHON = ['/usr/bin/python3.12', '-I', '-S', '-B']
STAGES = []

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def pin(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def gone(pgid):
    try:
        os.killpg(pgid, 0)
        return False
    except ProcessLookupError:
        return True

def run(name, argv):
    directory = BASE / name
    directory.mkdir(mode=0o700)
    before = time.monotonic_ns()
    row = dict(name=name, argv=argv, start_unix_ns=time.time_ns(), timeout_seconds=1800,
               cleanup_seconds=5, scope='DATA_ONLY_ARCHIVE_NO_PRODUCT_OR_COMPILER')
    with (directory / 'stdout.log').open('xb') as stdout, (directory / 'stderr.log').open('xb') as stderr:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   start_new_session=True)
        row.update(pid=process.pid, pgid=os.getpgid(process.pid))
        (directory / 'START.json').write_bytes(encoded(row))
        print(json.dumps(dict(event='start', **row)), flush=True)
        row['timed_out'] = False
        try:
            row['returncode'] = process.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            row['timed_out'] = True
            os.killpg(row['pgid'], signal.SIGTERM)
            try:
                row['returncode'] = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(row['pgid'], signal.SIGKILL)
                row['returncode'] = process.wait(timeout=5)
    row.update(elapsed_seconds=(time.monotonic_ns()-before)/1e9,
               whole_group_gone=gone(row['pgid']), stdout=pin(directory/'stdout.log'),
               stderr=pin(directory/'stderr.log'))
    (directory / 'PROCESS.json').write_bytes(encoded(row))
    STAGES.append(row)
    print(json.dumps(dict(event='finish', **row)), flush=True)
    assert row['returncode'] == 0 and not row['timed_out'] and row['whole_group_gone'], row

def main():
    assert not (BASE / 'ARCHIVE_DRIVER.json').exists()
    assert not COMPLETE.exists() and not SMALL.exists()
    tools = {'package_remote.py': 'abc2f2226d8f71d37b08b7adb1cf854ce06f113717b7eee7cc693ab98b71eadd',
             'verify_archive_remote.py': '9a08d0f0ca837d18f5b184bc6373969dd5b750b427f4bcf8df6e612ba8f01516'}
    for name, expected in tools.items():
        assert pin(BASE/name)['sha256'] == expected
    began = time.monotonic_ns()
    result = dict(scope='DATA_ONLY_ARCHIVE_NO_PRODUCT_OR_COMPILER', tools=tools,
                  original_capture_and_source_immutable=True, product_executions_added=0,
                  public_binary_write_registered=False, whole_runtime_replaced=False)
    try:
        run('complete-package', PYTHON + [str(BASE/'package_remote.py'), '--mode', 'complete',
            '--readback-sha256', READBACK, '--output', str(COMPLETE)])
        run('complete-readback', PYTHON + [str(BASE/'verify_archive_remote.py'), '--evidence',
            str(COMPLETE/'EVIDENCE.json'), '--evidence-sha256', pin(COMPLETE/'EVIDENCE.json')['sha256'],
            '--output', str(BASE/'COMPLETE_ARCHIVE_READBACK.json')])
        run('small-package', PYTHON + [str(BASE/'package_remote.py'), '--mode', 'small',
            '--readback-sha256', READBACK, '--output', str(SMALL), '--complete-index',
            str(COMPLETE/'EVIDENCE.json')])
        run('small-readback', PYTHON + [str(BASE/'verify_archive_remote.py'), '--evidence',
            str(SMALL/'EVIDENCE.json'), '--evidence-sha256', pin(SMALL/'EVIDENCE.json')['sha256'],
            '--output', str(BASE/'SMALL_ARCHIVE_READBACK.json')])
        result['status'] = 'PASS_FOUR_DATA_PRESERVATION_STAGES'
        result['complete_index'] = pin(COMPLETE/'EVIDENCE.json')
        result['small_index'] = pin(SMALL/'EVIDENCE.json')
        result['complete_readback'] = pin(BASE/'COMPLETE_ARCHIVE_READBACK.json')
        result['small_readback'] = pin(BASE/'SMALL_ARCHIVE_READBACK.json')
    except BaseException:
        result['status'] = 'HOLD_DATA_PRESERVATION_FAILURE'
        result['exception'] = traceback.format_exc()
        raise
    finally:
        result.update(stages=STAGES, elapsed_seconds=(time.monotonic_ns()-began)/1e9)
        (BASE/'ARCHIVE_DRIVER.json').write_bytes(encoded(result))
        print(json.dumps(result, sort_keys=True), flush=True)

if __name__ == '__main__':
    main()

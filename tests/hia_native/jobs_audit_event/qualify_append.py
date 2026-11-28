#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Real SysV/HIA audit versus unchanged Rust, with actual syscall observations."""
from __future__ import annotations
import argparse
import ctypes
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
SHA = lambda data: hashlib.sha256(data).hexdigest()
ENC = lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def need(ok, message):
    if not ok:
        raise AssertionError(message)


def worker(args):
    sys.path.insert(0, str(ROOT / "scripts"))
    from jobs_audit_driver import Audit
    libc = ctypes.CDLL(None)
    libc.getauxval.argtypes = [ctypes.c_ulong]
    libc.getauxval.restype = ctypes.c_ulong
    before = len(os.listdir('/proc/self/fd'))
    audit = Audit(args.library, args.manifests, secure=libc.getauxval(23), test_probes=args.trace_mode=='carrier')
    from restrictive_syscall_fixture import install
    install(args.kernel_profile)
    try:
        for line in sys.stdin:
            value = json.loads(line)
            if value.get("quit"):
                audit.close()
                after = len(os.listdir('/proc/self/fd'))
                print(json.dumps({"closed":True,"descriptors_before":before,"descriptors_after":after}), flush=True)
                break
            if value.get("reset"):
                need(audit.lib.jobs_audit_destroy(audit.context)==0,'native context reset destruction')
                audit.context=audit.lib.jobs_audit_create(*(m._address for m in audit.modules),libc.getauxval(23))
                need(audit.context>0,'native context reset creation')
                print('{"reset":true}', flush=True)
                continue
            case = value["case"]
            if args.trace_mode=='carrier':
                fail=value.get('fail_sync','')
                if fail=='file':probe=(9,1,5)
                elif fail.startswith('directory:'):probe=(10,int(fail.split(':')[1])+1,5)
                else:probe=tuple(value.get('effect_probe',(0,0,5)))
                audit.configure_probe(*probe)
            os.write(2, f"JA_BEGIN {case}\n".encode())
            start = time.time_ns() // 1000000
            wire = Audit.request(value["root"], value["host"], value["subject"])
            result = audit.invoke(wire)
            finish = time.time_ns() // 1000000
            os.write(2, f"JA_END {case}\n".encode())
            frame = bytes.fromhex(result["frame_hex"])
            need(result["code"] == len(frame) and len(frame) >= 32, "native audit fault/refusal: " + str(result))
            magic, status, category, length = struct.unpack_from('<8s3Q', frame)
            need(magic == b'HRCFGM01' and status in (0,1) and category == 0 and length == len(frame)-32,
                 "complete native response frame")
            result.update(ok=status == 0, error=None if status == 0 else frame[32:].decode('utf-8'),
                          request_hex=wire.hex(), start_ms=start, finish_ms=finish)
            print(json.dumps(result,sort_keys=True), flush=True)
    finally:
        audit.close()


class Client:
    def __init__(self, argv, stderr, kernel_profile='ordinary'):
        self.log = Path(stderr).open('wb')
        from restrictive_syscall_fixture import install
        setup=(lambda:install(kernel_profile)) if kernel_profile!='ordinary' else None
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.log, start_new_session=True,preexec_fn=setup)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.rows = []

    def call(self, value):
        raw = ENC(value) + b'\n'
        self.process.stdin.write(raw)
        self.process.stdin.flush()
        need(self.selector.select(30), "owned comparison process did not respond in 30 seconds")
        answer = self.process.stdout.readline()
        need(answer, "owned comparison process ended: " + str(self.process.poll()))
        self.rows.append(dict(input_hex=raw.hex(),output_hex=answer.hex()))
        return json.loads(answer)

    def finish(self):
        self.process.stdin.close()
        code = self.process.wait(timeout=30)
        self.selector.close()
        self.log.close()
        need(code == 0, "comparison process failed: " + str(code))

    def abort(self):
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=30)
        self.selector.close()
        self.log.close()


def normalized(raw, base):
    raw = raw.replace(str(base).encode(), b'<case>')
    pieces = []
    for line in raw.splitlines(keepends=True):
        try:
            value = json.loads(line)
            if isinstance(value,dict) and value.get('action') == 'native_binary_write':
                need(isinstance(value['at_unix_ms'],int), "timestamp is not an integer")
                value['at_unix_ms'] = '<actual-clock>'
                line = ENC(value) + b'\n'
        except (ValueError, UnicodeError):
            pass
        pieces.append(line)
    return b''.join(pieces)


def snapshot(base):
    rows = {}
    def visit(path):
        info = path.lstat()
        key = path.relative_to(base).as_posix()
        row = dict(mode=info.st_mode,uid=info.st_uid,gid=info.st_gid,nlink=info.st_nlink)
        if stat.S_ISREG(info.st_mode):
            raw = path.read_bytes()
            row.update(raw_hex=raw.hex(),raw_sha256=SHA(raw),normalized_hex=normalized(raw,base).hex())
        elif stat.S_ISLNK(info.st_mode):
            row['target'] = os.readlink(path).replace(str(base),'<case>')
        rows[key] = row
        if stat.S_ISDIR(info.st_mode):
            try:
                for child in sorted(path.iterdir()):
                    visit(child)
            except PermissionError as error:
                row['list_errno'] = error.errno
    visit(base)
    return rows


def comparable(rows):
    return {name:{key:value for key,value in row.items() if key not in ('raw_hex','raw_sha256')}
            for name,row in rows.items()}


def sync_observations(path):
    result, active = {}, None
    for line in Path(path).read_text().splitlines():
        begin = re.search(r'write\(2(?:<[^>]*>)?, "JA_BEGIN (\d+)\\n"', line)
        end = re.search(r'write\(2(?:<[^>]*>)?, "JA_END (\d+)\\n"', line)
        if begin:
            need(active is None, "overlapping trace case markers")
            active = int(begin[1])
            result[active] = dict(fdatasync=[],fsync=[])
        elif end:
            need(active == int(end[1]), "trace case end differs")
            active = None
        elif active is not None:
            if re.search(r'\bfdatasync\(',line):result[active]['fdatasync'].append(line)
            if re.search(r'\bfsync\(',line):result[active]['fsync'].append(line)
    need(active is None, "unterminated trace case")
    return result


def main(args):
    if args.worker:
        return worker(args)
    output = args.output.resolve()
    output.mkdir(parents=True,exist_ok=False)
    reference = Client([str(args.reference.resolve())], output/'reference.stderr',args.kernel_profile)
    native_argv=[sys.executable,str(Path(__file__).resolve()),'--worker','--library',str(args.library.resolve()),
                 '--manifests',str(args.manifests.resolve()),'--trace-mode',args.trace_mode,
                 '--kernel-profile',args.kernel_profile]
    if args.trace_mode=='strace':
        native_argv=['strace','-f','-yy','-s','100','-e','trace=write,fdatasync,fsync',
                     '-o',str(output/'native-syscalls.log')]+native_argv
    else:
        (output/'native-syscalls.log').write_bytes(b'')
    native = Client(native_argv,output/'native.stderr')
    records, resources, unavailable = [], [], []
    passed = False
    try:
        with tempfile.TemporaryDirectory(prefix='hia-real-audit-') as folder:
            root = Path(folder)
            def reset():
                need(reference.call({'reset':True}) == {'reset':True}, 'original reset')
                need(native.call({'reset':True}) == {'reset':True}, 'native reset')
            def sites(name):
                reset()
                pair = [root/name/'reference',root/name/'native']
                for p in pair:p.mkdir(parents=True)
                return pair
            def check(name,pair,paths=None,host='host',subject='/file'):
                case=len(records)
                if paths is None:paths=[p/'state' for p in pair]
                old=[]
                for p in paths:
                    target=p/'audit/events.jsonl'
                    try:
                        old.append(target.read_bytes() if target.is_file() and not target.is_symlink() else None)
                    except OSError:old.append(None)
                wanted=reference.call(dict(root=str(paths[0]),host=host,subject=subject))
                actual=native.call(dict(case=case,root=str(paths[1]),host=host,subject=subject))
                wanted_error=(wanted.get('error') or '').replace(str(pair[0]),'<case>')
                actual_error=(actual.get('error') or '').replace(str(pair[1]),'<case>')
                need((actual['ok'],actual_error)==(wanted['ok'],wanted_error),
                     f'{name}: result differs: original={wanted_error!r}, native={actual_error!r}, native_state={actual.get("state")}')
                need(actual['state']['ready']==int(wanted['ready']),name+': readiness differs')
                if actual['ok']:
                    data=(paths[1]/'audit/events.jsonl').read_bytes()
                    before=old[1] or b''
                    need(data.startswith(before),name+': append changed the existing prefix')
                    added=data[len(before):]
                    value=json.loads(added)
                    need(actual['start_ms']<=value['at_unix_ms']<=actual['finish_ms'],name+': real clock outside invocation')
                    expected=json.loads(wanted['event'])
                    expected['at_unix_ms']=value['at_unix_ms']
                    need(added==ENC(expected)+b'\n',name+': complete native event bytes differ')
                states=[snapshot(p) for p in pair]
                need(comparable(states[0])==comparable(states[1]),name+': full filesystem effects differ')
                records.append(dict(case=case,name=name,reference=wanted,native=actual,
                                    reference_filesystem=states[0],native_filesystem=states[1]))

            pair=sites('normal')
            for subject in ('first','second','quote" backslash\\','control\x00\x01\t\n','汉字é🙂'):
                check('normal-'+str(len(records)),pair,host='host"\n🙂',subject=subject)
            for p in pair:(p/'state/audit/events.jsonl').chmod(0o644)
            check('warm-tighten-legacy-mode',pair)
            for p in pair:(p/'state/unrelated').write_bytes(b'x')
            check('state-directory-name-change-cold',pair)
            for p in pair:(p/'state/unrelated').unlink()
            check('state-directory-name-removal-cold',pair)
            for p in pair:
                audit=p/'state/audit';before=audit.stat()
                (audit/'transient').write_bytes(b'x');(audit/'transient').unlink()
                os.utime(audit,ns=(before.st_atime_ns,before.st_mtime_ns))
            check('audit-namespace-aba',pair)
            for p in pair:
                audit=p/'state/audit';audit.rename(p/'state/audit-away');(p/'state/audit-away').rename(audit)
            check('audit-directory-move-aba',pair)
            for p in pair:
                file=p/'state/audit/events.jsonl';file.unlink();file.write_bytes(b'legacy\n');file.chmod(0o600)
            check('event-inode-replacement',pair)
            check('replacement-now-warm',pair)
            for p in pair:os.link(p/'state/audit/events.jsonl',p/'extra-link')
            check('hard-link-invalidates-prior-proof',pair)
            for p in pair:(p/'extra-link').unlink()
            check('hard-link-restored-must-be-cold',pair)
            check('restored-proof-now-warm',pair)

            for kind in ('legacy-mode','audit-file-directory','audit-file-symlink','audit-file-hardlink',
                         'audit-file-fifo','audit-file-fifo-reader','audit-file-socket',
                         'audit-directory-file','audit-directory-symlink','audit-directory-broken-symlink',
                         'state-is-file','state-symlink','state-denied'):
                pair=sites(kind)
                blocked=False
                for p in pair:
                    state=p/'state';audit=state/'audit';file=audit/'events.jsonl'
                    if kind=='state-is-file':state.write_bytes(b'state');continue
                    if kind=='state-symlink':
                        (p/'real-state').mkdir();state.symlink_to(p/'real-state',target_is_directory=True)
                        continue
                    state.mkdir()
                    if kind=='state-denied':state.chmod(0o500);continue
                    if kind=='audit-directory-file':audit.write_bytes(b'audit');continue
                    if kind in ('audit-directory-symlink','audit-directory-broken-symlink'):
                        target=p/'elsewhere'
                        if kind=='audit-directory-symlink':target.mkdir()
                        audit.symlink_to(target,target_is_directory=True);continue
                    audit.mkdir()
                    if kind=='legacy-mode':file.write_bytes(b'legacy\n');file.chmod(0o644)
                    if kind=='audit-file-directory':file.mkdir()
                    if kind=='audit-file-symlink':
                        (p/'target').write_bytes(b'untouched');file.symlink_to(p/'target')
                    if kind=='audit-file-hardlink':
                        file.write_bytes(b'untouched');os.link(file,p/'extra-link')
                    if kind.startswith('audit-file-fifo'):
                        os.mkfifo(file,0o600)
                        if kind.endswith('reader'):resources.append(os.open(file,os.O_RDWR|os.O_NONBLOCK))
                    if kind=='audit-file-socket':
                        try:
                            sock=socket.socket(socket.AF_UNIX);sock.bind(str(file));resources.append(sock)
                        except PermissionError as error:
                            if not args.continue_environment_blocks or error.errno!=1:raise
                            unavailable.append(dict(case=kind,operation='socket(AF_UNIX)',errno=error.errno,
                                                    complete_case_qualified=False))
                            blocked=True
                            break
                if blocked:continue
                check(kind,pair)
                if kind=='state-denied':
                    for p in pair:(p/'state').chmod(0o700)
                    check('denied-restored-cold',pair)
            pair=sites('nested-absent')
            paths=[p/'deep'/'one'/'two'/'state' for p in pair]
            check('recursive-create-dir-all',pair,paths)
            check('recursive-created-warm',pair,paths)
            pair=sites('long-component')
            check('too-long-state-component',pair,[p/('x'*256) for p in pair])
            pair=sites('long-path')
            check('too-long-state-path',pair,[p/('/'.join(['x'*100]*42)) for p in pair])
            close=native.call({'quit':True})
            need(close['closed'] and close['descriptors_after']==close['descriptors_before'],
                 'native context/children/namespace descriptors leaked')
        reference.finish();native.finish()
        if args.trace_mode=='strace':
            observed=sync_observations(output/'native-syscalls.log')
            need(set(observed)=={r['case'] for r in records}, 'complete actual syscall case coverage')
            for row in records:
                trace=observed[row['case']]
                need(len(trace['fdatasync'])==row['reference']['file_syncs'],row['name']+': mandatory file sync count differs')
                need(len(trace['fsync'])==len(row['reference']['directories']),row['name']+': directory sync count differs')
                row['actual_syscalls']=trace
        if args.trace_mode=='carrier':
            for row in records:
                counts=row['native']['test_effect_counts']
                need(counts[8]==row['reference']['file_syncs'],row['name']+': mandatory file sync effects differ')
                need(counts[9]==len(row['reference']['directories']),row['name']+': directory sync effects differ')
        passed=True
    finally:
        for item in resources:
            os.close(item) if isinstance(item,int) else item.close()
        if not passed:
            reference.abort();native.abort()
        data=b''.join(ENC(row)+b'\n' for row in records)
        packed=gzip.compress(data,mtime=0)
        (output/'complete-comparisons.jsonl.gz').write_bytes(packed)
        for name,client in [('reference',reference),('native',native)]:
            (output/(name+'-complete-frames.jsonl.gz')).write_bytes(gzip.compress(b''.join(ENC(row)+b'\n' for row in client.rows),mtime=0))
        report=dict(schema='hepta.runtime.jobs-audit-append.actual-comparison.v1',passed=passed and not unavailable,
                    available_cases_passed=passed,unavailable_environment_cases=unavailable,
                    cases=len(records),library=dict(path=str(args.library.resolve()),sha256=SHA(args.library.read_bytes())),
                    modules= json.loads(args.manifests.read_bytes()),
                    reference=dict(path=str(args.reference.resolve()),sha256=SHA(args.reference.read_bytes())),
                    corpus=dict(bytes=len(packed),sha256=SHA(packed),raw_bytes=len(data),raw_sha256=SHA(data)),
                    syscall_trace=dict(bytes=(output/'native-syscalls.log').stat().st_size,
                                       sha256=SHA((output/'native-syscalls.log').read_bytes())),
                    observation_mode=args.trace_mode,
                    kernel_profile=args.kernel_profile,
                    kernel_fault_profile_available_cases_qualified=passed and args.kernel_profile!='ordinary',
                    syscall_trace_qualified=passed and args.trace_mode=='strace',
                    synchronization_effect_counts_qualified=passed and args.trace_mode=='carrier',
                    fault_injection_qualified=False,concurrency_qualified=False,public_route_qualified=False)
        (output/'qualification.json').write_bytes(ENC(report)+b'\n')
    print(json.dumps({k:report[k] for k in ('passed','cases','fault_injection_qualified','public_route_qualified')},sort_keys=True))
    if unavailable:
        raise SystemExit(2)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',action='store_true')
    parser.add_argument('--trace-mode',choices=('strace','carrier','none'),default='strace')
    parser.add_argument('--continue-environment-blocks',action='store_true')
    parser.add_argument('--kernel-profile',choices=('ordinary','deny-inotify','deny-fdatasync','deny-fsync','deny-audit-write'),default='ordinary')
    parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--manifests',type=Path,required=True)
    parser.add_argument('--reference',type=Path)
    parser.add_argument('--output',type=Path)
    main(parser.parse_args())

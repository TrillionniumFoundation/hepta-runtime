# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Compare both live owners on the same inodes, including complete wire bytes and held descriptors."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import select
import stat
import struct
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cache_stamp_cases import wire, records_wire, cases, fault_cases
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def read_exact(stream, count):
    value = bytearray();deadline = time.monotonic() + 15
    while len(value) < count:
        left = deadline - time.monotonic()
        assert left > 0 and select.select([stream], [], [], left)[0], 'owned response deadline'
        chunk = os.read(stream.fileno(), count-len(value));assert chunk, 'unexpected owner EOF'
        value.extend(chunk)
    return bytes(value)


def descriptors(pid, folder):
    files, events = [], []
    for entry in (Path('/proc') / str(pid) / 'fd').iterdir():
        name = os.readlink(entry)
        if any(name==str(folder/base) or name.startswith(str(folder/base)+'/') or name==str(folder/base)+' (deleted)' for base in ('fixture','held')):
            meta = entry.stat()
            info = (Path('/proc') / str(pid) / 'fdinfo' / entry.name).read_text()
            offset = int(next(s.split(':',1)[1] for s in info.splitlines() if s.startswith('pos:')))
            flags = int(next(s.split(':',1)[1] for s in info.splitlines() if s.startswith('flags:')),8)
            assert offset == 0
            files.append(dict(device=meta.st_dev,inode=meta.st_ino,mode=meta.st_mode,position=offset,flags=flags))
        elif name == 'anon_inode:inotify':
            rows = []
            for line in (Path('/proc') / str(pid) / 'fdinfo' / entry.name).read_text().splitlines():
                if line.startswith('inotify '):
                    fields = dict(part.split(':',1) for part in line.split()[1:])
                    rows.append({key:int(fields[key],16) for key in ('wd','ino','sdev','mask','ignored_mask')})
            events.append(sorted(rows,key=lambda item:ENCODE(item)))
    return dict(files=sorted(files,key=lambda item:ENCODE(item)),event_streams=sorted(events,key=lambda item:ENCODE(item)))


def snapshot(folder):
    values={}
    def visit(path):
        meta=path.lstat();name=os.fsencode(path.relative_to(folder)).hex()
        value=dict(device=meta.st_dev,inode=meta.st_ino,mode=meta.st_mode,uid=meta.st_uid,gid=meta.st_gid,
            links=meta.st_nlink,size=meta.st_size,mtime_ns=meta.st_mtime_ns,ctime_ns=meta.st_ctime_ns)
        values[name]=value
        if stat.S_ISREG(meta.st_mode):value['sha256']=SHA(path.read_bytes())
        elif stat.S_ISDIR(meta.st_mode):
            try:names=os.listdir(os.fsencode(path))
            except PermissionError as error:value['enumeration_errno']=error.errno;return
            for child in names:visit(Path(os.fsdecode(os.fsencode(path)+b'/'+child)))
    visit(folder/'fixture');return values


class Process:
    def __init__(self, executable, fixture, output, original=False, supervisor=None, files=None):
        self.output, self.original = output, original
        output.mkdir(mode=0o700)
        self.stderr=(output/'stderr.log').open('xb')
        command=[str(executable),*(str(p) for p in files)]
        self.supervised=supervisor is not None
        if self.supervised:
            (output/'kernel-config.json').write_bytes(ENCODE(supervisor))
            command=[sys.executable,'-I','-B',str(Path(__file__).with_name('cache_stamp_supervisor.py')),
                '--fixture',str(fixture),'--config',str(output/'kernel-config.json'),'--log',str(output/'kernel.json'),'--',*command]
        self.process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,env={'PATH':''},bufsize=0)
        self.stdin=bytearray();self.stdout=bytearray();self.frames=0;self.calls=0
        self.started=time.monotonic();self.command=command

    def invoke(self, raw):
        wire=struct.pack('<Q',len(raw))+raw
        self.process.stdin.write(wire);self.stdin.extend(wire);self.frames+=1
        code=read_exact(self.process.stdout,4);size=struct.unpack('<I',code)[0]
        assert 64<=size<=266432 or size in (0xffffffff,0xfffffffe,0xfffffff9),size
        body=read_exact(self.process.stdout,size) if size<=266432 else b''
        if body:
            assert body[:8]==b'HRACR001'
            diagnostic,error,missing,value,count,cache_count,initialized=struct.unpack_from('<7Q',body,8)
            assert diagnostic in (0,16,23,43) and cache_count<=16 and initialized<=1
            assert missing==(int(error==2) if diagnostic==23 else 0)
            assert not diagnostic or size==64
        self.stdout.extend(code+body)
        return code+body

    def observed_pid(self):
        return int((self.output/'kernel.pid').read_text()) if self.supervised else self.process.pid

    def finish(self):
        self.process.stdin.close();self.process.wait(timeout=15)
        assert self.process.stdout.read()==b'' and self.process.returncode==0
        self.stderr.close();stderr=(self.output/'stderr.log').read_bytes()
        calls=json.loads(stderr) if self.original else None
        if calls:
            assert calls['status']=='PASS' and calls['frames']==self.frames and sum(calls['calls'])<=self.frames
            assert calls['full_original_namespace_module'] and calls['borrowed_files_released']
        else:assert stderr==b''
        (self.output/'stdin.bin').write_bytes(self.stdin);(self.output/'stdout.bin').write_bytes(self.stdout)
        row=dict(command=self.command,frames=self.frames,valid_requests=self.calls,exit_code=self.process.returncode,
            child_reaped=True,stdin_bytes=len(self.stdin),stdin_sha256=SHA(self.stdin),stdout_bytes=len(self.stdout),stdout_sha256=SHA(self.stdout),
            stderr_bytes=len(stderr),stderr_sha256=SHA(stderr),elapsed_seconds=time.monotonic()-self.started,original=calls)
        if self.supervised:
            kernel=json.loads((self.output/'kernel.json').read_bytes())
            assert kernel['status']=='PASS' and kernel['child_reaped'] and kernel['exit_code']==0 and kernel['all_selected_faults_reached']
            row['kernel']=dict(counts=kernel['counts'],events=len(kernel['events']),sha256=SHA((self.output/'kernel.json').read_bytes()))
        (self.output/'result.json').write_bytes(ENCODE(row));return row

    def abort(self):
        if self.process.poll() is None:
            self.process.kill();self.process.wait(timeout=15)
        self.stderr.close()
        (self.output/'stdin.bin').write_bytes(self.stdin);(self.output/'stdout.bin').write_bytes(self.stdout)


def mutate(files, step):
    root=files[step['directory']-1];kind=step['mutation']
    if kind=='chmod':root.chmod(step['mode'])
    elif kind=='utime':os.utime(root,ns=(step['ns'],step['ns']))
    elif kind=='write':(root/step['name']).write_bytes(bytes.fromhex(step['data']))
    else:raise AssertionError(kind)


def pair(native, original, case, folder):
    folder.mkdir(mode=0o700);(folder/'case.json').write_bytes(ENCODE(case))
    fixture=folder/'fixture';fixture.mkdir(mode=0o700);files=[]
    for index in range(1,18):
        path=fixture/('d%03d'%index);kind=case.get('types',{}).get(str(index),'directory')
        if kind=='directory':path.mkdir(mode=0o700)
        elif kind=='file':path.write_bytes(b'owned');path.chmod(0o600)
        elif kind=='fifo':os.mkfifo(path,0o600)
        else:raise AssertionError(kind)
        files.append(fixture/('d%03d'%case.get('aliases',{}).get(str(index),index)))
    before=snapshot(folder);processes=[];observations=[];stamps={}
    try:
        if original:processes.append(Process(original,fixture,folder/'original',True,case.get('supervisor'),files))
        processes.append(Process(native,fixture,folder/'native',False,case.get('supervisor'),files))
        for index,step in enumerate(case['steps']):
            if 'mutation' in step:
                mutate(files,step);observations.append(dict(step=index,mutation=step,filesystem=snapshot(folder)));continue
            raw=wire(step,stamps);before_call=snapshot(folder)
            frames=[process.invoke(raw) for process in processes]
            assert all(value==frames[0] for value in frames),('full wire difference',case['name'],index,[v.hex() for v in frames])
            size=struct.unpack_from('<I',frames[0])[0];body=frames[0][4:]
            if 'status' in step:assert size==step['status']
            else:
                assert size>=64 and size<=266432
                assert struct.unpack_from('<2Q',body,8)==(step.get('diagnostic',0),step.get('error',0)),(case['name'],index,body.hex())
                for field,offset in (('value',32),('cache_count',48),('initialized',56)):
                    if field in step:assert struct.unpack_from('<Q',body,offset)[0]==step[field],(case['name'],index,field,body.hex())
                if step.get('save'):
                    assert size>=176 and struct.unpack_from('<Q',body,32)[0]==112
                    stamps[step['save']]=body[64:176]
                if 'expected_records' in step:
                    assert size>=176 and struct.unpack_from('<Q',body,40)[0]==len(step['expected_records'])
                    assert body[176:]==records_wire(step['expected_records']),(case['name'],index,'record vector')
                if 'inode_directory' in step:
                    meta=files[step['inode_directory']-1].stat()
                    assert struct.unpack_from('<2Q',body,72)==(meta.st_dev,meta.st_ino)
            held=[descriptors(process.observed_pid(),folder) for process in processes]
            assert all(value==held[0] for value in held),('descriptor difference',case['name'],index,held)
            assert snapshot(folder)==before_call,('cache operation changed files',case['name'],index)
            observations.append(dict(step=index,result_hex=frames[0].hex(),descriptors=held[0],filesystem_unchanged=True))
        results=[process.finish() for process in processes]
        row=dict(name=case['name'],status='PASS',requests=sum('mutation' not in s for s in case['steps']),
            exact_wire_bytes_compared=bool(original),observations=observations,processes=results,
            initial_filesystem=before,final_filesystem=snapshot(folder),original_executed=bool(original))
        (folder/'result.json').write_bytes(ENCODE(row));return row
    except BaseException as error:
        (folder/'failure.json').write_bytes(ENCODE(dict(error=repr(error),traceback=traceback.format_exc(),observations=observations)))
        for process in processes:process.abort()
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('native','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--original',type=Path);parser.add_argument('--kernel',action='store_true')
    args=parser.parse_args();out=args.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    selected=list(fault_cases() if args.kernel else cases());rows=[];started=time.monotonic()
    report=dict(schema='hepta.request-audit.actual-cache-stamp-comparison.v1',status='FAIL',cases=rows,
        native_sha256=SHA(args.native.read_bytes()),original_sha256=SHA(args.original.read_bytes()) if args.original else None,
        original_executed=bool(args.original),real_filesystem_effects=True,full_original_namespace_module=bool(args.original),child_contracts_scripted=False,cold_snapshot_admitted=False,
        kernel_controls=args.kernel,full_wire_comparison=bool(args.original),production_activated=False,whole_runtime_replaced=False)
    try:
        for index,case in enumerate(selected):rows.append(pair(args.native.resolve(strict=True),args.original.resolve(strict=True) if args.original else None,
            case,out/('case-%03d'%index)))
        report.update(status='PASS',paired_processes=len(rows) if args.original else 0,native_processes=len(rows),
            requests_per_side=sum(r['requests'] for r in rows),selected_controls_per_side=sum(len(r.get('supervisor',{}).get('faults',[])) for r in selected))
    except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc());raise
    finally:
        report['elapsed_seconds']=time.monotonic()-started;(out/'result.json').write_bytes(ENCODE(report))
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},sort_keys=True))


if __name__=='__main__':main()

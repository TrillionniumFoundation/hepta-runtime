# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reconstruct every wire and filesystem projection from completed raw captures."""
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import gzip
import json
import stat

import normal_projection as q
from normal_runner import configuration, pin


class CapturePath:
    """Read-only snapshot view; never allocates a file or performs an effect."""
    def __init__(self, rows, root, name=''):
        self.rows, self.root, self.key = rows, root, name

    def __truediv__(self, name):
        assert isinstance(name,str) and not name.startswith('/') and '..' not in name.split('/')
        return CapturePath(self.rows,self.root,'/'.join(x for x in (self.key,name) if x))

    def __lt__(self, other):
        return self.key < other.key

    @property
    def name(self):
        return self.key.rsplit('/',1)[-1]

    @property
    def parent(self):
        return CapturePath(self.rows,self.root,self.key.rpartition('/')[0])

    def relative_to(self, other):
        assert other.key==''
        return PurePosixPath(self.key)

    def exists(self):
        return self.key=='' or self.key in self.rows

    def rglob(self, pattern):
        assert self.key=='' and pattern=='*'
        return [CapturePath(self.rows,self.root,n) for n in sorted(self.rows)]

    def glob(self, pattern):
        assert pattern=='*.json'
        prefix=self.key+'/'
        return [CapturePath(self.rows,self.root,n) for n in sorted(self.rows)
                if n.startswith(prefix) and '/' not in n[len(prefix):] and n.endswith('.json')]

    def stat(self):
        row=self.root if self.key=='' else self.rows[self.key]
        assert row['kind'] in ('file','directory'), 'normal fixture must not contain special nodes'
        mode=(stat.S_IFREG if row['kind']=='file' else stat.S_IFDIR)|row['mode']
        return SimpleNamespace(st_mode=mode,**{'st_'+k:row[v] for k,v in
            [('dev','device'),('ino','inode'),('nlink','nlink'),('uid','uid'),('gid','gid')]})

    lstat=stat

    def read_bytes(self):
        row=self.rows[self.key]
        assert row['kind']=='file'
        raw=bytes.fromhex(row['hex'])
        assert len(raw)==row['bytes'] and q.H(raw)==row['sha256']
        return raw


def verify_capture(folder, case, process, binary, paired, *, retained_common=None):
    folder=Path(folder)
    common=folder.parent/'common' if retained_common is None else Path(retained_common)
    assert retained_common is None or process['side']=='original'
    assert process['cwd']==str(folder) and process['side']==folder.name
    assert process['argv']==[str(binary),'--runtime-config',str(common/'config.json')]
    assert process['status']=='PASS' and process['exit_code']==0 and process['reaped'] is True
    assert type(process['pid']) is int and process['pid']>0
    assert process['frames']==len(case['events']) and process['response_timeout_seconds']==30
    for name in ('input.bin','stdout.bin','stderr','observations.jsonl.gz','eof-filesystem.json'):
        assert pin(folder/name)==process[name]
    assert (folder/'stderr').read_bytes()==b''
    input_bytes=b''.join(bytes.fromhex(v)+b'\n' for v in case['events'])
    assert (folder/'input.bin').read_bytes()==input_bytes
    raw_config=(common/'config.json').read_bytes()
    assert raw_config==q.compact(configuration(common/'state',case))
    with gzip.open(folder/'observations.jsonl.gz','rb')as stream:
        rows=[json.loads(line)for line in stream]
    assert len(rows)==len(case['events'])
    assert b''.join(bytes.fromhex(r['input_hex'])for r in rows)==input_bytes
    assert b''.join(bytes.fromhex(r['output_hex'])for r in rows)==(folder/'stdout.bin').read_bytes()
    requests,responses,bounds={},{},{}
    provenance={'owner':None,'request_ids':{}}
    wires,logical=[],[]
    for frame,row in enumerate(rows,1):
        assert row['frame']==frame
        request=json.loads(bytes.fromhex(row['input_hex']))
        response=q.checked_json(bytes.fromhex(row['output_hex'])[:-1])
        assert response['id']==request['id']
        requests[frame],responses[frame],bounds[frame]=request,response,row['bounds']
        state=CapturePath(row['filesystem'],row['root_stat'])
        q.observe_identities(state,frame,request,response,provenance)
        recorded=row['identity_relation']
        recorded['request_ids']={int(k):v for k,v in recorded['request_ids'].items()}
        assert provenance==recorded
        parsed,wire=q.wire(bytes.fromhex(row['output_hex']),frame,provenance)
        full,projection,counts=q.snapshot(state,requests,responses,bounds,provenance)
        assert full==row['filesystem'] and projection==row['logical']
        wires.append(wire);logical.append(projection)
    final=json.loads((folder/'eof-filesystem.json').read_bytes())
    full,eof,counts=q.snapshot(CapturePath(final['full'],final['root_stat']),requests,responses,bounds,provenance)
    assert full==final['full'] and eof==final['logical'] and counts==final['counts']==process['counts']
    retired=json.loads((folder/'fixture-retirement.json').read_bytes())
    assert retired==dict(schema='hepta.public-lifecycle.fixture-retirement.v1',
        status='RETIRED_AFTER_VERIFICATION',snapshot=pin(folder/'eof-filesystem.json'),
        entries=len(full),regular_files=sum(r['kind']=='file'for r in full.values()),
        source='complete actual EOF observation after process reaping')
    assert not (folder/'final-state').exists()
    return b''.join(wires),logical,eof,counts


def verify(folder, native, original=None):
    folder=Path(folder).resolve(strict=True)
    report=json.loads((folder/'result.json').read_bytes())
    fixtures=json.loads(gzip.decompress(Path(__file__).with_name('normal.json.gz').read_bytes()))
    assert report['status']=='PASS' and report['native_processes']==64 and report['native_requests']==359
    expected_original=0 if original is None else 64
    assert report['original_processes']==expected_original and report['original_requests']==(0 if original is None else 359)
    assert report['actual_paired_filesystem_comparison'] is (original is not None)
    for field in ('entropy_source_qualification','fault_injection','syscall_interception','production_activated','whole_runtime_replaced'):
        assert report[field] is False
    assert report['fresh_rust_builds']==0 and report['external_host_operations']==0
    assert len(report['processes'])==64+expected_original and len(report['completed'])==64
    for path,want in report['sources'].items():
        assert pin(Path(path))==want
    binaries={'native':Path(native).resolve(strict=True)}
    if original is not None:binaries['original']=Path(original).resolve(strict=True)
    assert report['binaries']=={name:pin(path)for name,path in binaries.items()}
    offset=0
    for index,fixture in enumerate(fixtures):
        case=fixture['case'];directory=folder/('case-%03d'%index)
        assert json.loads((directory/'case.json').read_bytes())==case
        answers=[]
        for side,binary in binaries.items():
            row=report['processes'][offset];offset+=1
            answer=verify_capture(directory/side,case,row,binary,original is not None)
            assert answer[0].hex()==fixture['wire_hex'] and q.H(answer[0])==fixture['wire_sha256']
            answers.append(answer)
        assert len(answers)==1 or answers[0]==answers[1]
        assert report['completed'][index]==dict(name=case['name'],requests=len(case['events']),
            normalized_wire_bytes=len(answers[0][0]),normalized_wire_sha256=q.H(answers[0][0]),**answers[0][3])
    return dict(report=pin(folder/'result.json'),native_processes=64,original_processes=expected_original,
                requests_per_implementation=359,new_executions=0,full_raw_projections_reconstructed=True)

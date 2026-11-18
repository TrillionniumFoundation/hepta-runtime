"""Replay every retained native cache row through the unchanged Rust owner."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_COUNTS = {'native_image_calls':13873,'native_elf_requests':66,'original_operations':13875,
                   'lifecycle_operations':22,'poison_injections':2,'view_plan_adapters':8,
                   'frame_refusals':17,'capacity_refusals':6,'state_refusals':9,
                   'view_image_calls':13,'reference_rows':13907}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked_corpus(directory: Path, source_root: Path = ROOT, reference_root: Path | None = None):
    reference_root = source_root if reference_root is None else reference_root
    metadata_path=directory/'native-corpus.json'
    metadata=json.loads(metadata_path.read_bytes())
    if (metadata.get('schema')!='hepta.runtime.view-cache-test.v1' or metadata.get('status')!='PASS'
            or metadata.get('test_groups')!=8 or metadata.get('counts')!=EXPECTED_COUNTS):
        raise ValueError('cache native test coverage differs')
    pins={'source_sha256':'native/view_cache.hepta','test_sha256':'tests/hia_native/test_view_cache.py',
          'oracle_sha256':'tests/hia_native/oracle_view_cache.rs',
          'composition_sha256':'native/view_cache_composition.json'}
    for field,relative in pins.items():
        if metadata.get(field)!=sha((source_root/relative).read_bytes()):
            raise ValueError('cache retained source differs: '+relative)
    proof=json.loads((source_root/'native/view_cache_composition.json').read_bytes())
    for relative,pin in proof['original_sources'].items():
        raw=(reference_root/relative).read_bytes()
        if (sha(raw)!=pin['sha256'] or
                hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=pin['blob']):
            raise ValueError('cache current original owner differs: '+relative)
    original=(reference_root/'src/mcp/fs/delta.rs').read_text()
    expected=original[original.index('const MAX_CACHED_BYTES:'):original.index('/// Render a whole-file view:')]
    oracle=(source_root/'tests/hia_native/oracle_view_cache.rs').read_text()
    body=oracle.split('// BEGIN EXACT ORIGINAL CACHE OWNER\n',1)[1].split('// END EXACT ORIGINAL CACHE OWNER',1)[0]
    if body!=expected+'\n':
        raise ValueError('cache oracle changed the original method bodies')
    for item in proof['imports']:
        if sha((reference_root/item['path']).read_bytes())!=item['sha256']:
            raise ValueError('cache imported native source differs')
    if sha((reference_root/'native/view_render.hepta').read_bytes())!=proof['view_plan_source_sha256']:
        raise ValueError('cache view-plan source differs')
    names={'requests.bin.gz','native-output.bin.gz','domains.jsonl.gz'}
    if set(metadata.get('files',{}))!=names:
        raise ValueError('cache corpus file set differs')
    files={}
    for name in names:
        raw=(directory/name).read_bytes();plain=gzip.decompress(raw)
        actual={'gzip_sha256':sha(raw),'gzip_bytes':len(raw),'raw_sha256':sha(plain),'raw_bytes':len(plain)}
        if metadata['files'][name]!=actual:
            raise ValueError('cache corpus bytes differ: '+name)
        files[name]=plain
    requests=files['requests.bin.gz'];outputs=files['native-output.bin.gz']
    domains=[json.loads(line) for line in files['domains.jsonl.gz'].splitlines()]
    q=p=0
    counts={'original_operations':0,'lifecycle_operations':0,'poison_injections':0,'view_plan_adapters':0}
    executions={'native-image':0,'native-elf':0}
    sessions=set()
    for ordinal,row in enumerate(domains,1):
        if len(requests)-q<8 or len(outputs)-p<4:
            raise ValueError('cache corpus record is incomplete')
        sid,size=struct.unpack_from('<II',requests,q);q+=8
        length=struct.unpack_from('<I',outputs,p)[0];p+=4
        if size<48 or size>len(requests)-q or length<32 or length>len(outputs)-p:
            raise ValueError('cache corpus record length differs')
        wire=requests[q:q+size];answer=outputs[p:p+length]
        q+=size;p+=length
        magic,op,flags,kn,an,bn=struct.unpack_from('<8s5Q',wire)
        if magic!=b'HVCACH01' or 48+kn+an+bn!=size:
            raise ValueError('cache retained request shape differs')
        classification=('lifecycle_operations' if op in (0,10) else 'poison_injections' if op==9
                        else 'view_plan_adapters' if op==8 else 'original_operations')
        if op>10 or row!={'ordinal':ordinal,'session':sid,'operation':op,
                         'classification':classification,'execution':row.get('execution')}:
            raise ValueError('cache retained ordinal/domain differs')
        if row['execution'] not in executions:
            raise ValueError('cache execution source differs')
        if op==0:
            if sid in sessions: raise ValueError('cache session initialized twice')
            sessions.add(sid)
        else:
            if sid not in sessions: raise ValueError('cache operation outside retained lifetime')
            if op==10: sessions.remove(sid)
        prefix,present,content,reserved=struct.unpack_from('<8s3Q',answer)
        if prefix!=b'HVCAR001' or present not in (0,1) or reserved or content!=length-32:
            raise ValueError('cache retained output shape differs')
        if not present and content:
            raise ValueError('cache absent content contains bytes')
        counts[classification]+=1;executions[row['execution']]+=1
    if (sessions or q!=len(requests) or p!=len(outputs) or len(domains)!=EXPECTED_COUNTS['reference_rows']
            or any(counts[name]!=EXPECTED_COUNTS[name] for name in counts)
            or executions['native-elf']!=EXPECTED_COUNTS['native_elf_requests']
            or executions['native-image']+sum(EXPECTED_COUNTS[n] for n in
                 ['frame_refusals','capacity_refusals','state_refusals'])!=EXPECTED_COUNTS['native_image_calls']):
        raise ValueError('cache corpus domain coverage is incomplete')
    return metadata,requests,outputs,{'domains':counts,'execution_sources':executions,
                'rows':len(domains),'metadata_sha256':sha(metadata_path.read_bytes())}


def compare(directory: Path, binary: Path, *, source_root: Path = ROOT,
            reference_root: Path | None = None, timeout: int = 60):
    metadata,requests,expected,domains=checked_corpus(directory,source_root,reference_root)
    binary_raw=binary.read_bytes()
    start=time.monotonic()
    run=subprocess.run([str(binary)],input=requests,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if binary.read_bytes()!=binary_raw:
        raise ValueError('cache original binary changed during replay')
    if run.returncode or run.stderr or run.stdout!=expected:
        raise ValueError('cache original owner replay differs: '+json.dumps({
            'returncode':run.returncode,'stdout_bytes':len(run.stdout),'stdout_sha256':sha(run.stdout),
            'expected_bytes':len(expected),'expected_sha256':sha(expected),
            'stderr':run.stderr.decode(errors='replace')[:4096]}))
    checked_corpus(directory,source_root,reference_root)
    return {'schema':'hepta.runtime.view-cache-original-rust.v1','status':'PASS',
            'rust_oracle_cases':domains['rows'],'domains':domains,'elapsed_seconds':time.monotonic()-start,
            'requests_sha256':sha(requests),'native_output_sha256':sha(expected),
            'rust_output_sha256':sha(run.stdout),'output_bytes':len(run.stdout),
            'oracle_sha256':metadata['oracle_sha256'],'binary_sha256':sha(binary_raw),
            'comparison_driver_sha256':sha(Path(__file__).read_bytes()),
            'source_sha256':metadata['source_sha256'],'native_corpus_sha256':domains['metadata_sha256'],
            'precompiled_binary_supplied':True}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus',type=Path,required=True)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--source-root',type=Path,default=ROOT)
    parser.add_argument('--reference-root',type=Path)
    parser.add_argument('--result',type=Path,required=True)
    args=parser.parse_args()
    try:
        report=compare(args.corpus,args.binary,source_root=args.source_root,reference_root=args.reference_root)
    except Exception as error:
        report={'schema':'hepta.runtime.view-cache-original-rust.v1','status':'FAIL',
                'error':repr(error)}
        if isinstance(error,subprocess.TimeoutExpired):
            captured={}
            for name,value in [('stdout',error.stdout),('stderr',error.stderr)]:
                raw=(value.encode() if isinstance(value,str) else value) or b''
                path=args.result.with_name(args.result.name+'.timeout.'+name)
                path.write_bytes(raw)
                captured[name]={'file':path.name,'bytes':len(raw),'sha256':sha(raw)}
            report['timeout_capture']=captured
        args.result.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        raise
    args.result.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,sort_keys=True))

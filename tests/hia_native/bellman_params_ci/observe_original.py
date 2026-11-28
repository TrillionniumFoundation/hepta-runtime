"""CI-only complete original typed observations; never a runtime implementation."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
import tomllib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from cases import all_cases
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def write(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def check():
    for name,value in json.loads((ROOT/'package-manifest.json').read_bytes())['files'].items():
        assert pin((ROOT/name).read_bytes())==value,name
def capture(command,cwd,folder,name,timeout,input=b''):
    before=time.monotonic();timed_out=False
    try:
        result=subprocess.run(command,cwd=cwd,input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
        status=result.returncode;stdout=result.stdout;stderr=result.stderr
    except subprocess.TimeoutExpired as error:
        status=None;stdout=error.stdout or b'';stderr=error.stderr or b'';timed_out=True
    for label,raw in [('stdin',input),('stdout',stdout),('stderr',stderr)]:(folder/f'{name}.{label}').write_bytes(raw)
    report={'command':command,'cwd':str(cwd),'timeout':timeout,'wall_seconds':time.monotonic()-before,
            'returncode':status,'timed_out':timed_out,'streams':{label:pin(raw) for label,raw in [('stdin',input),('stdout',stdout),('stderr',stderr)]}}
    write(folder/f'{name}.process.json',report)
    assert status==0 and not timed_out,(name,report)
    return stdout
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    assert os.environ.get('GITHUB_ACTIONS')=='true','Rust execution is restricted to CI'
    check();output=args.output.resolve();output.mkdir();shutil.copytree(ROOT,output/'recipe-source')
    version=capture(['rustc','--version'],ROOT,output,'rust-version',15)
    assert version.startswith(b'rustc 1.95.0 ')
    reference=output/'reference-build';shutil.copytree(ROOT/'reference',reference)
    # Cargo prunes target-wide optional dependency edges for this smaller binary.
    # Resolve only the copied reference, then admit every resulting registry pin
    # against the unchanged target before any compilation. No version drift is
    # accepted, and the fully resolved lock is retained with the observations.
    capture(['cargo','metadata','--format-version','1','--manifest-path',str(reference/'Cargo.toml')],
            ROOT,output,'resolve',60)
    target_lock=tomllib.loads((ROOT/'reference/target-Cargo.lock').read_text())
    target_pins={(p['name'],p['version']):p for p in target_lock['package'] if p.get('source')}
    resolved=tomllib.loads((reference/'Cargo.lock').read_text())
    resolved_pins={(p['name'],p['version']):p for p in resolved['package'] if p.get('source')}
    for package in resolved['package']:
        if not package.get('source'):continue
        original=target_pins[(package['name'],package['version'])]
        for key in ('source','checksum'):assert package[key]==original[key],(package['name'],key)
        def identities(dependencies,pins):
            result=set()
            for dependency in dependencies:
                fields=dependency.split();options=[key for key in pins if key[0]==fields[0] and (len(fields)==1 or key[1]==fields[1])]
                assert len(options)==1,(dependency,options)
                result.add(options[0])
            return result
        assert identities(package.get('dependencies',[]),resolved_pins)<=identities(original.get('dependencies',[]),target_pins),package['name']
    write(output/'resolved-pins.json',{'status':'PASS','target_registry_pins_exact':True,
          'resolved_lock':pin((reference/'Cargo.lock').read_bytes()),'packages':resolved['package']})
    target=output/'original-build'
    capture(['cargo','build','--locked','--release','--manifest-path',str(reference/'Cargo.toml'),
             '--target-dir',str(target)],ROOT,output,'build',180)
    cases=list(all_cases(ROOT/'qualify_bellman.py'))
    assert len({(group,name) for group,name,_ in cases})==len(cases)
    wire=b''.join(struct.pack('<Q',len(raw))+raw for _,_,raw in cases)
    data=capture([str(target/'release/hia-bellman-params-reference')],ROOT,output,'original',60,wire)
    rows=[];at=0
    for group,name,raw in cases:
        size=struct.unpack_from('<Q',data,at)[0];at+=8
        row=data[at:at+size];at+=size
        assert row[:8]==b'HBPOR001' and len(row)>=64
        status,canonical_length,body_length,count,*reserved=struct.unpack_from('<7Q',row,8)
        assert status in (0,1) and reserved==[0,0,0] and len(row)==64+canonical_length+body_length
        canonical=row[64:64+canonical_length];body=row[64+canonical_length:]
        json.loads(canonical)
        if status==0:
            assert body[:8]==b'HIABELL1' and struct.unpack_from('<Q',body,8)[0]==count
            assert len(body)==(16+720*count if 1<=count<=4096 else 16)
        else:body.decode()
        rows.append({'group':group,'name':name,'raw':pin(raw),'canonical':pin(canonical),'body':pin(body),
                     'status':status,'states':count,'error':body.decode() if status and len(body)<500 else None})
    assert at==len(data);check()
    write(output/'original.json',{'status':'ORIGINAL_OBSERVED_NATIVE_REQUIRED','cases':rows,'case_count':len(rows),
          'whole_runtime_replaced':False,'native_qualified':False,'source_manifest':pin((ROOT/'package-manifest.json').read_bytes()),
          'successful_typed':sum(row['status']==0 for row in rows),'typed_errors':sum(row['status']==1 for row in rows),
          'complete_input':pin(wire),'complete_output':pin(data)})
    print(json.dumps({'status':'ORIGINAL_OBSERVED_NATIVE_REQUIRED','cases':len(rows),'input_bytes':len(wire),'output_bytes':len(data)}))
if __name__=='__main__':main()

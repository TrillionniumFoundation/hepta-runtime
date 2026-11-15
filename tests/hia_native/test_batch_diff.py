"""Capture actual native Editable → Apply → Diff, before any Rust replay."""
from pathlib import Path
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(Path(__file__).parent))
from batch_diff_harness import Chain

SOURCE_FILES=(
    'native/batch_diff.hepta','native/batch_diff_abi.md','native/batch_diff_composition.json',
    'native/batch_apply.hepta','native/editable_content.hepta','native/text_budget.hepta','native/result_publication.hepta',
    'scripts/hia_native_build.py','scripts/hia_native_loader.py','scripts/hia_native_batch_diff_build.py',
    'tests/hia_native/batch_apply_harness.py','tests/hia_native/batch_diff_harness.py',
    'tests/hia_native/test_batch_diff.py','tests/hia_native/batch_diff_oracle/cases.py',
)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def source_pins():
    return {name:sha((ROOT/name).read_bytes()) for name in SOURCE_FILES}


def header(raw):
    assert raw[:8]==b'HBDIFR02'
    row=struct.unpack_from('<7Q',raw,8);assert row[-1]==0
    return row



def main():
    parser=argparse.ArgumentParser();parser.add_argument('--bundle',type=Path,default=os.environ.get('HIA_BATCH_DIFF_BUNDLE'))
    parser.add_argument('--capture',type=Path,default=os.environ.get('HIA_BATCH_DIFF_CAPTURE_DIR'))
    args=parser.parse_args();assert args.bundle and args.capture
    args.bundle=args.bundle.resolve(strict=True);args.capture=args.capture.resolve();args.capture.mkdir(exist_ok=False)
    before=source_pins();chain=Chain(args.bundle)
    spec=importlib.util.spec_from_file_location('batch_diff_cases',ROOT/'tests/hia_native/batch_diff_oracle/cases.py')
    cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(cases)
    rows=[];failures=[];call_rows=0;diff_calls=0;case_count=0;successes=0;errors=0;total=0;over8=0;controls=0
    first_wire=None;first_needed=0;raw_call_bytes=0;input_bytes=8;output_bytes=8
    input_hash=hashlib.sha256(b'HBDIQ001');output_hash=hashlib.sha256(b'HBDIO001')
    files={name:gzip.open(args.capture/name,'wb',compresslevel=1) for name in ['calls.bin.gz','requests.bin.gz','native-output.bin.gz']}
    files['requests.bin.gz'].write(b'HBDIQ001');files['native-output.bin.gz'].write(b'HBDIO001')
    index=(args.capture/'calls.jsonl').open('w')
    case_id=0
    def capture(kind,code,wire,out,state):
        nonlocal call_rows,raw_call_bytes
        call_rows+=1
        prefix=struct.pack('<8Q',call_rows,case_id,kind,code,len(wire),len(out),len(state),0)
        files['calls.bin.gz'].write(prefix);files['calls.bin.gz'].write(wire);files['calls.bin.gz'].write(out);files['calls.bin.gz'].write(state)
        row={'call':call_rows,'case_id':case_id,'kind':kind,'return':code,'stream_offset':raw_call_bytes,
             'input_bytes':len(wire),'input_sha256':sha(wire),'output_bytes':len(out),'output_sha256':sha(out),
             'workspace_bytes':len(state),'workspace_sha256':sha(state)}
        index.write(json.dumps(row,sort_keys=True)+'\n');raw_call_bytes+=64+len(wire)+len(out)+len(state)
    def invoke(kind,wire,oc,wc):
        nonlocal diff_calls
        code,out,state=chain.diff.invoke_raw(wire,output_capacity=oc,workspace_capacity=wc,output_fill=0xa5,workspace_fill=0x7b)
        diff_calls+=1;capture(kind,code,wire,out,state)
        return code,out,state
    try:
        for case in cases.iter_cases():
            case_id=case['case_id'];assert case_id==case_count;case_count+=1
            wire=cases.encode(case);prefix=struct.pack('<Q',len(wire))
            files['requests.bin.gz'].write(prefix);files['requests.bin.gz'].write(wire);input_hash.update(prefix);input_hash.update(wire);input_bytes+=8+len(wire)
            first_call=call_rows+1
            status,parts,applied=chain.transform(wire,capture)
            old,new,rendered,plan,body,error=parts
            row={'case_id':case_id,'name':case['name'],'domain':case['domain'],'input_sha256':sha(wire),'apply':applied,'status':status}
            if status:
                assert not new and not rendered and not body and error
                errors+=1;row['error_bytes']=len(error);row['error_sha256']=sha(error)
            else:
                assert not error
                request=struct.pack('<8s7Q',b'HBDFQ002',0,len(old),len(new),len(plan),0,0,0)+old+new+plan
                code,out,state=invoke(1,request,96,0)
                assert code==64 and header(out)[0]==2 and out[64:]==b'\xa5'*32 and not state
                required=header(out)[5]
                code,out,state=invoke(2,request,64,required+17)
                values=header(out);assert code==64 and values[0] in (0,3) and values[2]==len(case['operations']) and values[5]==64+values[1]
                assert state[:required]==bytes(required) and state[required:]==b'\x7b'*17
                needed=values[5]
                code,out,state=invoke(3,request,needed+29,required+17)
                assert code==64 and header(out)==(0,values[1],values[2],values[3],values[4],values[5],0)
                body=out[64:needed];parts[4]=body
                assert out[needed:]==b'\xa5'*29
                assert state[:required]==bytes(required) and state[required:]==b'\x7b'*17
                successes+=1;total+=len(body);over8+=len(body)>8*1024*1024
                row.update({'body_bytes':len(body),'body_sha256':sha(body),'diff_request_sha256':sha(request),
                            'workspace_required':required,'old_lines':values[3],'new_lines':values[4]})
                if first_wire is None:first_wire=request;first_needed=required
            response=struct.pack('<8s8Q',b'HBDICO01',status,*(len(part) for part in parts),0)+b''.join(parts)
            prefix=struct.pack('<Q',len(response));files['native-output.bin.gz'].write(prefix);files['native-output.bin.gz'].write(response)
            output_hash.update(prefix);output_hash.update(response);output_bytes+=8+len(response)
            row.update(first_call=first_call,last_call=call_rows,output_bytes=len(response),output_sha256=sha(response));rows.append(row)
        assert first_wire is not None
        for ordinal,(name,wire,oc,wc,expected) in enumerate(cases.private_frames(first_wire)):
            case_id=100000+ordinal;code,out,state=invoke(4,wire,oc,wc)
            assert code==expected and out==b'\xa5'*oc and state==b'\x7b'*wc,(name,hex(code),hex(expected))
            controls+=1;rows.append({'case_id':case_id,'name':name,'domain':'private-framing-capacity','first_call':call_rows,'last_call':call_rows,'return':code})
        case_id=200000;code,out,state=invoke(5,first_wire,96,first_needed-1)
        assert code==64 and header(out)[0]==2 and header(out)[5]==first_needed
        assert state==b'\x7b'*(first_needed-1) and out[64:]==b'\xa5'*32
        controls+=1;rows.append({'case_id':case_id,'name':'exact-workspace-growth','domain':'private-growth','first_call':call_rows,'last_call':call_rows,'return':code})
    except BaseException as exc:
        failures.append({'case_id':case_id,'error':repr(exc)})
    finally:
        chain.close();index.close()
        for stream in files.values():stream.close()
    assert source_pins()==before
    (args.capture/'cases.jsonl').write_bytes(b''.join((json.dumps(row,sort_keys=True,ensure_ascii=False)+'\n').encode() for row in rows))
    (args.capture/'failures.json').write_text(json.dumps(failures,indent=2,ensure_ascii=False)+'\n')
    execution={'schema':'hepta.runtime.batch-diff-native-execution.v1','source_root':str(ROOT),'capture_root':str(args.capture),
               'bundle_path':str(args.bundle),'command':[sys.executable,'-I','-B',str(Path(__file__).resolve()),*sys.argv[1:]],
               'sources':before,'python':sys.executable,'cwd':str(Path.cwd()),'bundle_sha256':sha(args.bundle.read_bytes())}
    (args.capture/'execution.json').write_text(json.dumps(execution,indent=2,sort_keys=True)+'\n')
    result={'schema':'hepta.runtime.batch-diff-native-result.v1','status':'PASS' if not failures else 'FAIL','case_count':case_count,
            'native_diff_calls':diff_calls,'independent_editable_calls':chain.editable_calls,'apply_calls':chain.apply.counts,
            'captured_records':call_rows,'captured_raw_bytes':raw_call_bytes,'successful_native_diff_cases':successes,'native_apply_errors':errors,
            'complete_diff_bytes':total,'over8mib_results':over8,'private_controls':controls,'input_bytes':input_bytes,'input_sha256':input_hash.hexdigest(),
            'output_bytes':output_bytes,'output_sha256':output_hash.hexdigest(),'reference':'NOT_RUN',
            'public_batch_route_executed':False,'filesystem_effects_executed':False,'test_groups':3,'skipped':0,'errors':0,'failures':len(failures)}
    (args.capture/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,sort_keys=True))
    assert not failures,failures[:3]


if __name__=='__main__':main()

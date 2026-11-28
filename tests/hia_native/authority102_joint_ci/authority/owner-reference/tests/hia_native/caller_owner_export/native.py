"""Execute the fixed serial owner-export corpus and retain complete buffers."""
from __future__ import annotations
import argparse
import ctypes
import json
import os
from pathlib import Path
import struct
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from cases import CAPACITY, INVALID, plan
from native_support import Modules, Harness, Trace, bound, encoded, frame, projection, response, sha

def run(args):
    if args.source_pins_sha256 is not None:
        from common import source_evidence
        source_evidence(args.source_root,args.source_pins_sha256)
    args.output.mkdir(parents=True, exist_ok=False)
    fixture_dir = args.output / "owned-fixture"
    fixture_dir.mkdir(mode=0o700)
    trace = Trace(args.output)
    modules = None
    contexts = {}
    originals = {}
    rows = []
    start = time.monotonic_ns()
    reference = (args.output / "original-input.jsonl").open("xb")
    expected = (args.output / "expected-original.jsonl").open("xb")
    records = (args.output / "rows.jsonl").open("xb")
    reference_rows = 0
    try:
        modules = Modules(args.manifest,args.fixture_manifest,source_root=args.source_root,trace=trace)
        for number, item in enumerate(plan(),1):
            trace.row,trace.context = number,item["context"]
            first = trace.calls+1
            row=dict(item)
            ident,operation=item["context"],item["operation"]
            actual_code=0;actual_output=b"";state_before=None;wire=b""
            ref=None
            if operation=="start":
                if ident in contexts:raise ValueError("duplicate native context")
                h=Harness(modules,mode=item['mode'],entropy_seed=item['entropy_seed'],
                    entropy_fail=item['entropy_fail'],owner_error=item['owner_error'])
                contexts[ident]=h
                path=fixture_dir/('token-%d'%ident)
                with path.open('xb') as f:f.write(bytes.fromhex(item['token_file_hex']))
                path.chmod(item['file_mode'])
                actual_code,actual_output=h.startup(path)
                if (actual_code,actual_output)!=(0,b''):raise ValueError('native startup failed')
                originals[ident]=h.bytes(0,288,32)
                ref=dict(item,code=0,output_hex='')
                if h.mode==1:
                    ref.update(stdio_fallback_source='native-os-observation',
                        observed_stdio_fallback=h.bytes(0,320,32).hex() if h.get(0,64)==1 else None)
            elif operation in ('request','abi-control'):
                h=contexts[ident]
                state_before=bound(h)
                wire=bytes.fromhex(item['wire_hex']) if operation=='abi-control' else frame(item['request_op'],
                    [(bytes.fromhex(a),bytes.fromhex(b)) for a,b in item['headers']],bytes.fromhex(item['payload_hex']))
                capacity=item.get('capacity',256)
                actual_code,actual_output=h.request(wire,capacity)
                state_after=bound(h)
                if operation=='abi-control':
                    if actual_code!=len(actual_output) or response(actual_output)!=(INVALID,b'') or state_after!=state_before:
                        raise ValueError('malformed native ABI changed result or binding: '+item['name'])
                else:
                    semantic=item['expected_semantic_code']
                    if semantic:
                        wanted=b''
                    elif item['request_op']==3:
                        wanted=projection(state_after)
                    elif item['request_op']==1:
                        wanted=bytes((int(state_after['authenticated']),))
                    elif item['request_op']==0:
                        wanted=b''
                    else:
                        if actual_code!=len(actual_output):raise ValueError('binding response capacity')
                        got,value=response(actual_output)
                        if got!=0 or len(value)!=64:raise ValueError('legacy binding response')
                        wanted=value
                    need=8+len(wanted)*2
                    if capacity<need:
                        if actual_code!=CAPACITY or actual_output:raise ValueError('native response capacity contract')
                    elif actual_code!=need or response(actual_output)!=(semantic,wanted):
                        raise ValueError('native semantic response mismatch at row %d'%number)
                    if semantic and state_after!=state_before:raise ValueError('refusal changed existing binding')
                    if item['request_op']==0 and state_after!=state_before:raise ValueError('middleware-only request bound a session')
                    ref=dict(item,code=semantic,output_hex=wanted.hex())
            elif operation in ('replace_verified_extension','restore_verified_extension'):
                h=contexts[ident];state_before=bound(h)
                raw=contexts[item['source_context']].bytes(0,288,32) if operation=='replace_verified_extension' else originals[ident]
                ctypes.memmove(h.address(0)+288,raw,32)
                ref=dict(item,code=0,output_hex='')
            elif operation=='reconnect':
                h=contexts[ident];state_before=bound(h)
                actual_code,actual_output=h.reconnect()
                if (actual_code,actual_output)!=(0,b'') or bound(h) is not None:raise ValueError('private reconnect failed')
                ref=dict(item,code=0,output_hex='')
            elif operation=='shutdown':
                h=contexts[ident];state_before=bound(h)
                actual_code,actual_output=h.shutdown()
                if (actual_code,actual_output)!=(0,b'') or bound(h) is not None:raise ValueError('native retirement failed')
                ref=dict(item,code=0,output_hex='')
            else:raise ValueError('unknown planned operation')
            state=bound(contexts[ident])
            row.update(id=number,code=actual_code,output_hex=actual_output.hex(),wire_hex=wire.hex(),
                binding_before=state_before,binding=state,calls=list(range(first,trace.calls+1)))
            if ref is not None:
                reference_rows+=1
                reference.write(encoded(ref));reference.flush()
                wanted={'context':ident,'code':ref['code'],'output_hex':ref['output_hex'],'binding':state}
                expected.write(encoded(wanted));expected.flush()
                row['original_row']=reference_rows
            else:row['original_row']=None
            records.write(encoded(row));records.flush();rows.append(row)
        summary={'schema':'hepta.runtime.owner-export.native.v2','status':'PASS',
            'pid':os.getpid(),'ppid':os.getppid(),'pgid':os.getpgid(0),
            'rows':len(rows),'original_rows':reference_rows,'native_abi_rows':len(rows)-reference_rows,
            'native_calls':trace.calls,'complete_buffer_bytes':trace.buffer_bytes,
            'loaded':modules.loaded_artifacts,'elapsed_ns':time.monotonic_ns()-start,
            'whole_runtime_replaced':False,'current_http_listener_qualified':False,
            'concurrent_session_binding_qualified':False,'public_route_qualified':False}
        if args.source_pins_sha256 is not None:source_evidence(args.source_root,args.source_pins_sha256)
        (args.output/'summary.json').write_bytes(encoded(summary))
        print(encoded(summary).decode(),end='')
        return summary
    finally:
        for h in contexts.values():h.close()
        if modules is not None:modules.close()
        trace.close();reference.close();expected.close();records.close()
        # Retire only these explicitly created regular fixture files.
        for path in fixture_dir.iterdir():
            if not path.is_file() or path.is_symlink():raise ValueError('owned fixture kind changed')
            path.unlink()
        fixture_dir.rmdir()

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--source-root',required=True,type=Path)
    p.add_argument('--manifest',required=True,type=Path)
    p.add_argument('--fixture-manifest',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--source-pins-sha256')
    run(p.parse_args())

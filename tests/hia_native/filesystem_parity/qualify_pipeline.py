"""Refuse altered phase evidence and read both phases after two relocations."""
from pathlib import Path
import argparse
import builtins
import copy
import gzip
import importlib.util
import io
import json
import os
import shutil
import subprocess
import struct
import sys
import time
sys.dont_write_bytecode = True


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser()
    for name in ('repo', 'output', 'report', 'controls'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    for name in ('repo', 'output', 'report', 'controls'):
        setattr(args, name, getattr(args, name).absolute())
    args.controls.mkdir(mode=0o700)
    sys.path.insert(0, str(args.repo/'scripts'))
    q = load(args.repo/'scripts/hia_native_filesystem_parity_qualification.py', '_fs_pipeline_controls_reader')
    report = q.decode(args.report.read_bytes())
    started = time.monotonic(); events = []

    def completed(output, value, name):
        rows = [row for row in value['checks'] if row['name'] == name]
        q.need(len(rows) == 1, 'one recorded suite required')
        return rows[0], q.read_json(output, name+'.stdout')

    def admitted(reader, root, output, value):
        native = reader.native_evidence(root, output, value, completed)
        q.same(native, value['filesystem_parity_evidence'], 'native pipeline seal')
        retired = reader.retire_fixtures(root, output, value, completed, create=False)
        q.same(retired, value['filesystem_parity_fixture_retirement'], 'native fixture seal')
        original = reader.retained_original(root, output, value, Path(value['rust_compiler']['invocation_path']), completed)
        q.same(original, value['original_rust_comparisons']['filesystem_parity'], 'original pipeline seal')
        return {'native':native, 'retirement':retired, 'original':original}

    real_popen = subprocess.Popen
    def forbidden_process(*unused, **ignored):
        raise AssertionError('evidence admission attempted a process launch')
    subprocess.Popen = forbidden_process
    try:
        baseline = admitted(q, args.repo, args.output, report)
        source_pins = baseline['native']['source_sha256']
        output_pins = {**baseline['native']['artifact_sha256'], **baseline['retirement']['artifact_sha256'],
                       **baseline['original']['artifact_sha256']}
        def frozen(root, output):
            for name, digest in source_pins.items(): q.same(q.pin(q.owned(root,name))['sha256'], digest, 'unchanged source '+name)
            for name, digest in output_pins.items(): q.same(q.pin(q.owned(output,name))['sha256'], digest, 'unchanged artifact '+name)
        frozen(args.repo,args.output)
        moved = []
        for label in ('moved-one', 'moved-two'):
            home=args.controls/label; home.mkdir(mode=0o700)
            root, output=home/'source',home/'output'; root.mkdir(); output.mkdir()
            for source, destination, table in ((args.repo,root,source_pins),(args.output,output,output_pins)):
                for name in sorted(table):
                    target=destination/q.relative(name); target.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copyfile(q.owned(source,name),target)
            moved.append((root,output))
        blocked=[args.repo,args.output]
        origin=q.read_json(args.output/q.FOLDER/'native/captures-v1','SOURCE.json')
        original_origin=q.read_json(args.output/q.FOLDER/'original/captures-v1','SOURCE.json')
        blocked.extend(Path(value['cross_root']) for value in (origin,original_origin))
        def guard(fn):
            def call(path,*pos,**kw):
                if isinstance(path,(str,bytes,os.PathLike)):
                    current=Path(os.fsdecode(path)).absolute()
                    q.need(not any(current==home or current.is_relative_to(home) for home in blocked),
                           'relocated reader touched a producer path: '+str(current))
                return fn(path,*pos,**kw)
            return call
        for root,output in moved:
            reader=load(root/'scripts/hia_native_filesystem_parity_qualification.py','_fs_pipeline_moved_reader')
            saved=[(builtins,'open',builtins.open),(io,'open',io.open),(os,'open',os.open),
                   (os,'stat',os.stat),(os,'lstat',os.lstat)]
            for owner,name,fn in saved: setattr(owner,name,guard(fn))
            try: q.same(admitted(reader,root,output,report),baseline,'relocated complete phase evidence')
            finally:
                for owner,name,fn in saved: setattr(owner,name,fn)
            frozen(root,output)
        root,output=moved[0]
        reader=load(root/'scripts/hia_native_filesystem_parity_qualification.py','_fs_pipeline_refusal_reader')

        def refuse(name, action):
            begin=time.monotonic()
            try: action()
            except (ValueError,OSError,KeyError,TypeError,AssertionError) as error:
                events.append({'name':name,'status':'REJECTED','type':type(error).__name__,
                               'message':str(error),'elapsed_seconds':time.monotonic()-begin})
            else: raise AssertionError('corrupted pipeline admitted: '+name)

        def native(value): return reader.native_evidence(root,output,value,completed)
        def original(value): return reader.retained_original(root,output,value,Path(value['rust_compiler']['invocation_path']),completed)
        def changed_check(name,field,value):
            changed=copy.deepcopy(report)
            next(row for row in changed['checks'] if row['name']==name)[field]=value
            return changed
        refuse('native_deadline_not_180',lambda:native(changed_check(q.SUITES[2],'timeout_seconds',181)))
        refuse('native_claimed_as_original_phase',lambda:native(changed_check(q.SUITES[2],'phase','original_rust_comparison')))
        refuse('original_claimed_as_native_phase',lambda:original(changed_check(q.ORIGINAL_CHECK,'phase','native_components')))
        state=output/q.FOLDER/'state/RESULT.json'; saved=state.read_bytes()
        try:
            state.write_bytes(b'{"status":"PASS",'+saved.lstrip()[1:])
            refuse('duplicate_private_summary_field',lambda:native(copy.deepcopy(report)))
        finally:state.write_bytes(saved)

        state=output/q.FOLDER/'state'
        paths=[state/'calls.jsonl',state/'RESULT.json',output/(q.SUITES[0]+'.stdout')]
        saved={path:path.read_bytes() for path in paths}
        try:
            rows=[q.decode(line) for line in saved[paths[0]].splitlines()]
            rows[0]['expected_code']=(rows[0]['native_code']+1)&0xffffffff
            paths[0].write_bytes(b''.join(q.canonical(row)+b'\n' for row in rows))
            value=q.decode(saved[paths[1]]); value['captures']['calls.jsonl']=q.pin(paths[0])
            for path in paths[1:]:path.write_bytes(q.canonical(value)+b'\n')
            changed=copy.deepcopy(report); check=next(row for row in changed['checks'] if row['name']==q.SUITES[0])
            check.update(summary=value,stdout_bytes=paths[2].stat().st_size,stdout_sha256=q.pin(paths[2])['sha256'])
            refuse('resigned_private_return_mismatch',lambda:native(changed))
        finally:
            for path,raw in saved.items():path.write_bytes(raw)

        paths=[state/'calls.bin.gz',state/'calls.jsonl',state/'RESULT.json',output/(q.SUITES[0]+'.stdout')]
        saved={path:path.read_bytes() for path in paths}
        try:
            rows=[q.decode(line) for line in saved[paths[1]].splitlines()]
            row=next(item for item in rows if item['native_code']==0xffffffff and item['workspace_capacity']>0)
            raw=bytearray(gzip.decompress(saved[paths[0]])); at=row['stream_offset']
            for _ in range(4):
                length,=struct.unpack_from('<Q',raw,at); at+=8+length
            length,=struct.unpack_from('<Q',raw,at); at+=8
            q.need(length==row['workspace_capacity'] and length>0,'controlled refusal span')
            raw[at]^=1; row['after_sha256']=q.sha(bytes(raw[at:at+length]))
            paths[0].write_bytes(gzip.compress(bytes(raw),mtime=0))
            paths[1].write_bytes(b''.join(q.canonical(item)+b'\n' for item in rows))
            value=q.decode(saved[paths[2]])
            for name,path in (('calls.bin.gz',paths[0]),('calls.jsonl',paths[1])):value['captures'][name]=q.pin(path)
            for path in paths[2:]:path.write_bytes(q.canonical(value)+b'\n')
            changed=copy.deepcopy(report); check=next(item for item in changed['checks'] if item['name']==q.SUITES[0])
            check.update(summary=value,stdout_bytes=paths[3].stat().st_size,stdout_sha256=q.pin(paths[3])['sha256'])
            refuse('resigned_private_refusal_mutation',lambda:native(changed))
            q.need('private refusal changed buffers' in events[-1]['message'], 'wrong refusal mutation gate')
        finally:
            for path,raw in saved.items():path.write_bytes(raw)

        receipt=output/q.FOLDER/'native-fixture-retirement.json'; saved=receipt.read_bytes()
        try:
            value=q.decode(saved); value['qualification_sha256']='0'*64; receipt.write_bytes(q.canonical(value)+b'\n')
            refuse('retirement_binds_other_native_evidence',lambda:reader.retirement(root,output,
                output/q.FOLDER/'native/captures-v1',baseline['native'],'native',create=False))
        finally:receipt.write_bytes(saved)
        live=output/q.FOLDER/'native/captures-v1/validation/files'; live.mkdir()
        try:
            refuse('reintroduced_live_fixture',lambda:reader.retirement(root,output,
                output/q.FOLDER/'native/captures-v1',baseline['native'],'native',create=False))
        finally:live.rmdir()

        changed=copy.deepcopy(report)
        changed['rust_compiler']['invocation_path']='/explicit-other-compiler/rustc'
        refuse('another_declared_compiler_than_actual_build',lambda:original(changed))
        original_source=output/q.FOLDER/'original/source/original_parity_ops.rs'; saved=original_source.read_bytes()
        try:
            original_source.write_bytes(saved+b'\n')
            refuse('unchanged_original_module_changed',lambda:original(copy.deepcopy(report)))
        finally:original_source.write_bytes(saved)
        receipt=output/q.FOLDER/'original-fixture-retirement.json'; saved=receipt.read_bytes(); receipt.unlink()
        try:refuse('missing_original_retirement',lambda:original(copy.deepcopy(report)))
        finally:receipt.write_bytes(saved)
        for source,outputs in [(args.repo,args.output),*moved]:frozen(source,outputs)
        result={'schema':'hepta.runtime.filesystem-parity-pipeline-controls.v1','status':'PASS',
            'controls':len(events),'events':events,'physical_relocations':2,
            'producer_paths_blocked_during_relocation':True,'copied_live_fixtures':False,
            'new_native_calls':0,'new_rust_processes':0,'new_processes':0,
            'source_files':len(source_pins),'artifacts':len(output_pins),
            'all_source_and_artifacts_unchanged':True,
            'baseline_sha256':q.sha(q.canonical(baseline)),'elapsed_seconds':time.monotonic()-started,
            'whole_runtime_replaced':False,'public_filesystem_handlers_complete':False}
        q.write_new(args.controls/'RESULT.json',result)
        print(json.dumps(result,sort_keys=True),flush=True)
    finally:
        subprocess.Popen=real_popen


if __name__=='__main__':main()

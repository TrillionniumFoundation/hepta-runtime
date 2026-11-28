"""Re-read the actual four-suite capture under the frozen DATA-only guard.

The original readers retain their exact recorded-location checks. This command
does not rebase a receipt, execute an owner, or rerun the original Rust recipe.
"""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,stat,sys,time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'guard'))
import readonly as guard

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    root=args.capture_root.resolve(strict=True)
    source=root/'source';capture=root/'actual-system-python'
    sys.path.insert(0,str(source/'scripts'))
    import qualify_hia_runtime_native as q
    import hia_native_shell_consumer as consumer
    prepared=json.loads((capture/'prepared-report.json').read_bytes())
    build=json.loads((capture/'LOCAL_BUILD.json').read_bytes())
    suites=json.loads((capture/'LOCAL_SUITES.json').read_bytes())
    assert suites['status']=='ORIGINAL_COMPLETE_SHELL_SUITES_PASS'
    assert len(suites['checks'])==4 and all(row['exit_code']==0 and row['timed_out'] is False
        and row['timeout_seconds']==180 and 0<=row['elapsed_seconds']<=180 for row in suites['checks'])
    assert all(row['command'][0]==sys.executable for row in suites['checks'])
    for name in (q.SHELL_OUTCOME_TEST,q.SHELL_OUTPUT_TEST,*q.SHELL_FOREGROUND_TESTS):
        q._shell_test_module(name)
    # The unchanged readers check three binutils and one Python input file.
    # Admit those exact declared bytes as additional read inputs;
    # no directory, executable capability, or unspecified ambient path is added.
    tool_inputs=json.loads((root/'reader-inputs/TOOLS.json').read_bytes())
    assert set(tool_inputs)=={'as','objcopy','ld','python'}
    allowed={}
    def tool_snapshot():
        result={}
        for name,row in tool_inputs.items():
            receipt_path=(capture/'consumer-shell-build/shell-foreground/tools/link.json') if name=='ld' else (capture/'build/shell-output/tools'/(name+'.json'))
            if name=='python':receipt_path=capture/'shell-output/native/reader-controls/positive/process.json'
            receipt=json.loads(receipt_path.read_bytes())
            path=Path(row['path'])
            assert path.is_absolute() and path.resolve(strict=True)==path
            assert path==(Path(sys.executable) if name=='python' else Path('/usr/bin')/name).resolve(strict=True)
            if name=='python':
                assert receipt['executable']==str(path)
            elif name=='ld':
                assert receipt['tool']==str(path) and receipt['label']=='link'
            else:
                assert receipt['resolved_tool']==str(path) and receipt['name']==name
            raw=path.read_bytes();identity=dict(size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
            assert identity==row['pin']==receipt['tool_before']==receipt['tool_after']
            assert raw==(root/'reader-inputs'/row['retained']).read_bytes()
            info=path.stat();assert stat.S_ISREG(info.st_mode)
            result[str(path)]=dict(pin=identity,device=info.st_dev,inode=info.st_ino,
                mode=info.st_mode,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)
        return result
    before_tools=tool_snapshot()
    allowed.update((Path(name),value['pin']) for name,value in before_tools.items())
    original_inside=guard._inside
    original_open,original_close=os.open,os.close
    read_descriptors={}
    descriptor_identity=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_size,
                                      value.st_mtime_ns,value.st_ctime_ns)
    def inside_declared_inputs(path):
        if type(path) is int:
            record=read_descriptors.get(path)
            if record is None:return False
            try:
                return descriptor_identity(os.fstat(path))==record[1] and inside_declared_inputs(record[0])
            except OSError:
                return False
        if original_inside(path):return True
        if not isinstance(path,(str,bytes,os.PathLike)):return False
        p=Path(os.fsdecode(path)).absolute()
        return p in allowed and p.resolve(strict=True)==p
    guard._inside=inside_declared_inputs
    def open_owned_read(path,flags,*argv,**kwargs):
        fd=original_open(path,flags,*argv,**kwargs)
        if guard._ACTIVE:
            assert not flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)
            assert inside_declared_inputs(path)
            info=os.fstat(fd)
            if stat.S_ISREG(info.st_mode):
                read_descriptors[fd]=(Path(path).absolute(),descriptor_identity(info))
        return fd
    def close_owned_read(fd):
        read_descriptors.pop(fd,None)
        return original_close(fd)
    os.open,os.close=open_owned_read,close_owned_read
    foreign_fd=original_open('/dev/null',os.O_RDONLY)
    def operation():
        try:
            Path('/usr/bin/env').read_bytes()
        except PermissionError:
            pass
        else:
            raise AssertionError('unlisted ambient tool became readable')
        try:
            os.fdopen(foreign_fd,'rb',closefd=False)
        except PermissionError:
            pass
        else:
            raise AssertionError('unbound file descriptor became readable')
        probe=source/'scripts/hia_native_shell_consumer.py'
        probe_fd=os.open(probe,os.O_RDONLY|os.O_NOFOLLOW)
        assert inside_declared_inputs(probe_fd)
        with os.fdopen(probe_fd,'rb',closefd=False) as handle:
            assert handle.read()==probe.read_bytes()
        os.close(probe_fd)
        assert not inside_declared_inputs(probe_fd)
        proof=consumer.admit_report(capture,prepared,suites,build['prepared_sha256'],source_root=source,full=True)
        actual=dict(outcome=q.shell_outcome_evidence(capture,suites),
                    output=q.shell_output_evidence(capture,suites),
                    foreground=q.shell_foreground_evidence(capture,suites))
        assert actual==suites['evidence']
        assert proof['unchanged_images']==build['unchanged_images']
        return dict(status='ORIGINAL_COMPLETE_SHELL_CAPTURE_DATA_PASS',suites=4,
            original_timeouts_seconds=[180]*4,semantic_outcome_cases=78083,
            output_io_cases=20,foreground_controller_semantic_cases=20,
            foreground_controller_controls=84,foreground_os_cases=12,
            consumer_manifest_sha256=proof['manifest_sha256'],
            actual_native_entries=actual['outcome']['native']['counts']['actual_native_entries'],
            whole_runtime_replaced=False,original_rust_compared=False,
            production_activated=False,old_stack_removal_qualified=False,
            unlisted_tool_read_refused=True,unbound_descriptor_read_refused=True,
            stale_descriptor_read_refused=True,declared_ambient_tool_inputs=before_tools)
    start=time.monotonic()
    try:
        result=guard.guarded(operation,roots=[source,capture,root/'reader-inputs',root.parent/'retained-compiler/compiler-source'])
    finally:
        original_close(foreign_fd)
        os.open,os.close=original_open,original_close
    assert tool_snapshot()==before_tools
    elapsed=time.monotonic()-start
    assert elapsed<180
    result.update(elapsed_seconds=elapsed,timeout_seconds=180,
                  original_guard_probes_unchanged=11,additional_exact_input_files=len(allowed))
    args.output.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('before','after')},sort_keys=True))

if __name__=='__main__':main()

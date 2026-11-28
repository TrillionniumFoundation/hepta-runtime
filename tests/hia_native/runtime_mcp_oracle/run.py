"""Execute 43 supplemental unchanged Rust replays against captured public input.

This shares the already admitted View and Workdir builds. No Cargo process is
started here. Native binaries are never executed by this producer. All prior
native processes must be terminal, and the only temporary fixture mutation is
an exact hold/rebuild/restore of this native producer's own workdir subtree.
"""
from pathlib import Path
import argparse,contextlib,gzip,hashlib,io,json,os,shutil,stat,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_runtime_mcp_evidence import (Evidence,compact,decode,exact,generators,inspect_corpus,
    owned,qualification_evidence,require,sha,workdir_inputs)
from hia_native_runtime_mcp_original import (CLEARED,RUSTC_SHA,module,pin,view_reference,workdir_reference)


def dump(path,value):path.write_bytes(json.dumps(value,sort_keys=True,indent=2,allow_nan=False).encode()+b'\n')


def file_pin(path):
    digest=hashlib.sha256();size=0
    with path.open('rb') as stream:
        while raw:=stream.read(1<<20):digest.update(raw);size+=len(raw)
    return dict(bytes=size,sha256=digest.hexdigest())


def complete(output,report,name):
    rows=[row for row in report['checks'] if row.get('name')==name]
    require(len(rows)==1,'one actual native qualification process required')
    return rows[0],decode((output/(name+'.stdout')).read_bytes())


def tree(root):
    """Full bytes/raw filenames plus stable inode/permission identity; no follow."""
    if not root.exists():return None
    result=[];base=os.fsencode(root)
    def walk(path,relative):
        st=os.lstat(path);mode=st.st_mode
        row=dict(name_hex=relative.hex(),device=st.st_dev,inode=st.st_ino,mode=mode,uid=st.st_uid,gid=st.st_gid,nlink=st.st_nlink)
        row['xattrs']={os.fsencode(name).hex():os.getxattr(path,name,follow_symlinks=False).hex()
                       for name in sorted(os.listxattr(path,follow_symlinks=False),key=os.fsencode)}
        if stat.S_ISDIR(mode):
            row['kind']='directory';result.append(row)
            for name in sorted(os.listdir(path)):walk(path+b'/'+name,relative+b'/'+name if relative else name)
        elif stat.S_ISREG(mode):
            row.update(kind='file',data_hex=Path(os.fsdecode(path)).read_bytes().hex());result.append(row)
        elif stat.S_ISLNK(mode):row.update(kind='symlink',target_hex=os.readlink(path).hex());result.append(row)
        elif stat.S_ISFIFO(mode):row['kind']='fifo';result.append(row)
        else:raise ValueError('unexpected special object in owned workdir fixture')
    walk(base,b'');return result


def no_live_native(binary):
    matches=[];checked=0
    for child in Path('/proc').iterdir():
        if not child.name.isdigit():continue
        try:target=os.readlink(child/'exe')
        except (FileNotFoundError,ProcessLookupError,PermissionError):continue
        checked+=1
        if target==str(binary) or target==str(binary)+' (deleted)':matches.append(int(child.name))
    require(not matches,'a native producer process still holds this exact ELF')
    return dict(executable=str(binary),matching_pids=matches,readable_executable_links=checked,
                terminal_process_receipts=152,all_capture_processes_waited=True)


@contextlib.contextmanager
def same_origin_fixture(native_output,native,output):
    origin=Path(native['report']['execution']['corpus_root'])
    exact(str(origin),str(native_output/'runtime-mcp'),'reference must execute at this producer actual origin')
    fixture=origin/'files/workdir';parent=fixture.parent
    require(parent.is_dir() and parent.resolve()==parent.absolute(),'owned fixture parent is not a real directory')
    require(fixture.name=='workdir' and fixture.parent==native_output/'runtime-mcp/files','fixture owner differs')
    held=parent/('workdir-held-'+output.name)
    require(not held.exists() and not held.is_symlink(),'fixture hold name already exists')
    before=tree(fixture);dump(output/'fixture-before.json',before)
    journal=dict(fixture=str(fixture),held=str(held),original_present=before is not None,
                 state='PREPARED',temporary_tree_removed=False,original_tree_restored=False)
    dump(output/'fixture-journal.json',journal)
    fresh_identity=None
    try:
        if before is not None:
            os.rename(fixture,held);exact(tree(held),before,'held native fixture changed')
        fixture.mkdir();st=fixture.stat();fresh_identity=(st.st_dev,st.st_ino)
        journal.update(state='ORIGINAL_RUNNING',fresh_identity=list(fresh_identity));dump(output/'fixture-journal.json',journal)
        yield fixture
    finally:
        if fresh_identity is not None:
            st=fixture.lstat();require(stat.S_ISDIR(st.st_mode) and (st.st_dev,st.st_ino)==fresh_identity,
                                     'temporary original fixture root identity changed; retained for diagnosis')
            # shutil.rmtree uses descriptor-relative removal on supported Linux.
            require(shutil.rmtree.avoids_symlink_attacks,'descriptor-relative fixture removal unavailable')
            shutil.rmtree(fixture);journal['temporary_tree_removed']=True
        if before is not None:
            require(held.is_dir() and not fixture.exists(),'native fixture restore owner differs')
            os.rename(held,fixture)
        after=tree(fixture);dump(output/'fixture-after.json',after)
        exact(after,before,'native fixture bytes/permissions/inode identity were not restored')
        journal.update(state='RESTORED',original_tree_restored=True)
        dump(output/'fixture-journal.json',journal)


def retain_stream(folder,name,path):
    expected=file_pin(path);target=folder/(name+'.bin.gz')
    with path.open('rb') as source,target.open('xb') as raw:
        with gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as destination:shutil.copyfileobj(source,destination,1<<20)
    digest=hashlib.sha256();size=0
    with gzip.open(target,'rb') as source:
        while block:=source.read(1<<20):size+=len(block);digest.update(block)
    exact(dict(bytes=size,sha256=digest.hexdigest()),expected,'retained complete original stream differs')
    path.unlink()
    return dict(path=target.name,**expected)


def execute(output,name,command,cwd,incoming,binary_pin,rustc):
    folder=output/name;folder.mkdir();source=folder/'stdin.raw';source.write_bytes(incoming)
    exact(file_pin(Path(command[0])),binary_pin,'admitted original binary changed before execution')
    env=dict(os.environ)
    for key in CLEARED:env.pop(key,None)
    env.update(RUSTC=rustc,LC_ALL='C',TZ='UTC')
    start=time.monotonic();code=None;timed=False;error=None
    with source.open('rb') as stdin,(folder/'stdout.raw').open('xb') as stdout,(folder/'stderr.raw').open('xb') as stderr:
        try:
            process=subprocess.run(command,cwd=cwd,env=env,stdin=stdin,stdout=stdout,stderr=stderr,timeout=60)
            code=process.returncode
        except subprocess.TimeoutExpired:timed=True
        except OSError as exc:error=str(exc)
    row=dict(name=name,command=command,cwd=str(cwd),timeout_seconds=60,elapsed_seconds=time.monotonic()-start,
        exit_code=code,timed_out=timed,start_error=error,executable=binary_pin,
        environment=dict(RUSTC=rustc,LC_ALL='C',TZ='UTC',cleared=list(CLEARED)))
    for stream in ('stdin','stdout','stderr'):row[stream]=retain_stream(folder,stream,folder/(stream+'.raw'))
    dump(folder/'process.json',row)
    exact(file_pin(Path(command[0])),binary_pin,'admitted original binary changed during execution')
    require(type(code) is int and code==0 and not timed and error is None and row['stderr']['bytes']==0,
            'actual original replay failed: '+name)
    return row


def snapshot_shared(root,origin,destination,admit):
    evidence=Evidence(origin);admitted=admit(root,origin,evidence)
    if origin!=destination:
        destination.mkdir(parents=True,exist_ok=False)
        for name in evidence.artifacts:
            source=owned(origin,name);target=destination/name;target.parent.mkdir(parents=True,exist_ok=True)
            os.link(source,target)
        copied=Evidence(destination);exact(admit(root,destination,copied),admitted,'retained original snapshot changed admission')
    return admitted


def run(root,native_output,view_original,workdir_original,output):
    root=root.resolve();native_output=native_output.resolve();output=output.resolve()
    require(output.parent==native_output and output.name=='runtime-mcp-original','supplement output owner differs')
    output.mkdir(exist_ok=False);dump(output/'remote-process.json',dict(cgroup=Path('/proc/self/cgroup').read_text()))
    started=time.monotonic();records=[]
    report=decode((native_output/'result.json').read_bytes())
    admitted=qualification_evidence(root,native_output,report,complete)
    native=inspect_corpus(root,native_output/'runtime-mcp')
    binary=Path(native['report']['execution']['manifest_path']).parent/'runtime-mcp.elf'
    process_check=no_live_native(binary);dump(output/'native-process-terminal.json',process_check)
    before={name:file_pin(root/name) for name in ('scripts/hia_native_runtime_mcp_original.py',
        'tests/hia_native/runtime_mcp_oracle/run.py')}
    dump(output/'source-pins.json',before)
    vroot=native_output/'view-call-original';wroot=native_output/'workdir-original'
    view=snapshot_shared(root,view_original.resolve(),vroot,view_reference)
    workdir=snapshot_shared(root,workdir_original.resolve(),wroot,workdir_reference)
    dump(output/'shared-originals.json',dict(view=view,workdir=workdir,
        view_original_result=pin((vroot/'result.json').read_bytes()),workdir_original_result=pin((wroot/'result.json').read_bytes())))
    modules=generators(root);rustc=view['rustc'];require(file_pin(Path(rustc))['sha256']==RUSTC_SHA,'actual compiler binary changed')
    try:
        row=modules['span_inputs'].large_view_case();incoming=modules['cases'].encode_cases([row])
        exe=vroot/'target/release/hepta-view-call-original-oracle'
        records.append(execute(output,'over64',[str(exe),str(output/'over64-files')],root,incoming,
                               view['binary_pins'][exe.name],rustc))
        del incoming,row
        inputs=workdir_inputs(root,native['report']['execution']['corpus_root'])
        policies=output/'policies';policies.mkdir()
        for name,value in inputs['policies'].items():(policies/(name+'.json')).write_bytes(compact(value)+b'\n')
        with same_origin_fixture(native_output,native,output) as fixture:
            for scenario in inputs['scenarios']:
                name='workdir-'+str(scenario['scenario_id']);cwd=Path(os.fsdecode(bytes.fromhex(scenario['sessions'][0]['root_hex'])))
                require(cwd.is_relative_to(fixture) and '..' not in cwd.parts,'scenario cwd escaped owned fixture')
                cwd.mkdir(parents=True,exist_ok=True);exe=wroot/'target/release/hepta-workdir-original-oracle'
                command=[str(exe),str(fixture),str(policies/(scenario['policy_id']+'.json'))]
                records.append(execute(output,name,command,cwd,compact(scenario)+b'\n',workdir['binary_pin'],rustc))
                dump(output/'process-receipts.json',records)
        exact(before,{name:file_pin(root/name) for name in before},'supplement source changed during execution')
        result=dict(schema='hepta.runtime.mcp-original-supplement.v1',status='REFERENCE_READY',
            execution=dict(runtime_root=str(root),output_root=str(output),native_output_root=str(native_output)),
            elapsed_seconds=time.monotonic()-started,processes=records,actual_original_replays=43,
            new_rust_builds=0,new_native_calls=0,shared_view_processes=view['processes'],shared_workdir_processes=workdir['processes'],
            source_pins=before,native_evidence_sha256=sha(compact(admitted)),
            native_source_binding=native['report']['source_binding'],
            whole_view_handler_original_executed=False,whole_runtime_original_executed=False,
            original_workdir_handler_executed=True,configuration_loader_original_executed=False,
            full_native_public_comparison_executed=False)
        dump(output/'result.json',result);dump(output/'process-receipts.json',records)
        return {key:value for key,value in result.items() if key not in ('processes','native_source_binding','source_pins')}
    except BaseException as error:
        dump(output/'result.json',dict(status='FAIL',error=repr(error),processes=records,elapsed_seconds=time.monotonic()-started));raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('runtime-root','native-output','view-original','workdir-original','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();result=run(args.runtime_root,args.native_output,args.view_original,args.workdir_original,args.output)
    print(json.dumps(result,sort_keys=True),flush=True)
if __name__=='__main__':main()

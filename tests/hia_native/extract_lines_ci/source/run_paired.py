"""Actual original/native processes on identical absolute filesystem fixtures."""
from pathlib import Path
import argparse
import os
import shutil
import signal
import sys
import time
import traceback
import types
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from common import encoded, loads, pin, read, require, source
import cases
import observations
import native_observations
import run_ordinary as ordinary


def capture(definition,binary,lane,vault,decoder):
    decoded=[]
    def decode(raw,operations):
        value=decoder(raw,operations);decoded.extend(value);return value
    before=ordinary.observations
    ordinary.observations=types.SimpleNamespace(words=observations.words,decode=decode)
    try: result=ordinary.run_case(definition,binary,lane,vault)
    finally: ordinary.observations=before
    return result,decoded


def archive_work(folder,vault,row,failed=False):
    work=folder/'work';actual=ordinary.tree_snapshot(work,vault)
    if not failed:
        require(actual==row['files_after_body'][-1]['snapshot'],'complete final fixture state before retirement')
    archive=dict(schema='hepta.extract-lines.complete-filesystem.v1',snapshot=actual,
                 retired_owned_completed_fixture=True,failed_process_evidence=failed)
    raw=encoded(archive);(folder/'FILESYSTEM.json').write_bytes(raw)
    require(loads(read(folder/'FILESYSTEM.json'))==archive,'complete filesystem archive readback')
    # Every file is retained in the content-addressed vault; modes, raw names,
    # links, and symlink targets are retained in the complete snapshot above.
    for current,dirs,_ in os.walk(work,topdown=True,followlinks=False):
        os.chmod(current,0o700)
        dirs[:]=[name for name in dirs if not (Path(current)/name).is_symlink()]
    shutil.rmtree(work)
    return pin(raw)


def pair(definition,binaries,folder,vault):
    folder.mkdir();lane=folder/'lane';decoded={};rows={}
    result=dict(schema='hepta.extract-lines.pair.v1',name=definition['name'],status='RUNNING',
        actual_working_directory=str(lane/'work'),operations=len(definition['operations']),
        same_absolute_workdir=True,process_deadline_seconds=60,captures={})
    try:
        for name,decoder in [('original',observations.decode),('native',native_observations.decode)]:
            try: rows[name],decoded[name]=capture(definition,binaries[name],lane,vault,decoder)
            finally:
                if lane.exists():
                    lane.rename(folder/name)
                    result['captures'][name]=dict(folder=name,receipt=pin(read(folder/name/'result.json')))
        for name in ('operations','setup_frames','input_frames','cwd','environment','filesystem_before',
                     'responses','files_after_body'):
            require(rows['original'][name]==rows['native'][name],'complete original/native '+name)
        streams={name:{kind:read(folder/name/(kind+'.bin')) for kind in ('stdin','stdout','stderr')}
                 for name in ('original','native')}
        for kind in ('stdin','stdout'):
            require(streams['original'][kind]==streams['native'][kind],'byte-exact original/native '+kind)
        native_observations.compare(decoded['original'],decoded['native'])
        require(all(row['status']=='PASS' and row['exit_code']==0 and row['process_reaped']
                    and not row['timed_out'] and row['elapsed_seconds']<=60 for row in rows.values()),
                'both actual processes complete within original budgets')
        result['filesystem_archives']={name:archive_work(folder/name,vault,rows[name]) for name in rows}
        result.update(status='PAIRED_COMPLETE_STATE_PASS',complete_input_bytes=len(streams['original']['stdin']),
            complete_response_bytes=len(streams['original']['stdout']),
            complete_original_observer_bytes=len(streams['original']['stderr']),
            complete_native_arena_observer_bytes=len(streams['native']['stderr']),
            compared_owner_boundaries=6*len(definition['operations']),compared_hint_boundaries=len(definition['operations']))
    except BaseException as failure:
        result.update(status='FAIL',error=repr(failure),traceback=traceback.format_exc())
        result['failure_filesystem_archives']={name:archive_work(folder/name,vault,{},failed=True)
            for name in ('original','native') if (folder/name/'work').exists()}
        raise
    finally: (folder/'PAIR.json').write_bytes(encoded(result))
    return result


def run(original_build,native_build,output):
    frozen=source();domain=loads(read(ROOT/'DOMAIN.json'))
    require(os.geteuid()!=0,'actual permission cases require an unprivileged account')
    old,new=loads(read(original_build/'BUILD.json')),loads(read(native_build/'BUILD.json'))
    require(old['status']==new['status']=='PASS','complete actual build receipts')
    binaries={'original':original_build/old['executable']['path'],'native':native_build/new['executable']['path']}
    pins={name:pin(read(binary)) for name,binary in binaries.items()}
    require(pins['original']=={k:old['executable'][k] for k in ('bytes','sha256')}
        and pins['native']=={k:new['executable'][k] for k in ('bytes','sha256')},'actual build executables')
    definitions=cases.cases()
    require([x['name'] for x in definitions]==domain['ordinary_cases']
            and sum(len(x['operations']) for x in definitions)==domain['ordinary_operations'],'frozen full ordinary domain')
    output.mkdir(parents=True,exist_ok=False);vault=output/'blobs';vault.mkdir()
    result=dict(schema='hepta.extract-lines.paired.v1',status='RUNNING',source_manifest_sha256=frozen,
        producer_root=str(output),binary_paths={k:str(v) for k,v in binaries.items()},binaries=pins,
        same_absolute_workdir=True,process_deadline_seconds=60,capture_deadline_seconds=180,
        full_body_async_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False,cases=[])
    start=time.monotonic();mask=os.umask(0o022);old_signal=signal.getsignal(signal.SIGALRM)
    def timeout(*_): raise TimeoutError('complete paired extract capture exceeded 180 seconds')
    signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,180)
    try:
        for index,definition in enumerate(definitions):
            name=f'case-{index:03d}-{definition["name"]}'
            row=pair(definition,binaries,output/name,vault)
            result['cases'].append(dict(folder=name,receipt=pin(read(output/name/'PAIR.json')),**row))
            (output/'RESULT.json').write_bytes(encoded(result))
            print(encoded(dict(name=definition['name'],status=row['status'])).decode(),end='',flush=True)
        require(source()==frozen and {k:pin(read(v)) for k,v in binaries.items()}==pins,'source and executable custody unchanged')
        result.update(status='EXTRACT_LINES_ORDINARY_PAIRED_PASS',root_pairs=len(definitions),
            actual_root_processes=2*len(definitions),operations_per_side=domain['ordinary_operations'],
            complete_input_bytes=sum(x['complete_input_bytes'] for x in result['cases']),
            complete_response_bytes=sum(x['complete_response_bytes'] for x in result['cases']),
            complete_original_observer_bytes=sum(x['complete_original_observer_bytes'] for x in result['cases']),
            complete_native_arena_observer_bytes=sum(x['complete_native_arena_observer_bytes'] for x in result['cases']))
    except BaseException as failure:
        result.update(status='FAIL',error=repr(failure),traceback=traceback.format_exc());raise
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old_signal);os.umask(mask)
        result['elapsed_seconds']=time.monotonic()-start;(output/'RESULT.json').write_bytes(encoded(result))
    print(encoded({k:result[k] for k in ('status','root_pairs','operations_per_side','elapsed_seconds')}).decode(),end='')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--original-build',type=Path,required=True)
    p.add_argument('--native-build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    run(a.original_build.resolve(strict=True),a.native_build.resolve(strict=True),a.output.absolute())

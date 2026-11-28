"""Source-bound pure-reader repair for exact Cargo metadata omissions; no production changes."""
from pathlib import Path
import hashlib
import io
import json
import sys
import tarfile
import tomllib
ADAPTER=Path(__file__).resolve().parent
BASE_SOURCE_SHA='35b5d7c107e0583ac3a25cdcabf5ec9f547fbb31840079c49b5486230b8281e6'
INSTALLED=False

def check_adapter():
    raw=(ADAPTER/'RECOVERY_SOURCE.json').read_bytes()
    data=json.loads(raw)
    for name,row in data['files'].items():
        p=Path(name)
        if p.is_absolute() or '..' in p.parts:raise ValueError('adapter source path')
        body=(ADAPTER/p).read_bytes()
        if len(body)!=row['bytes'] or hashlib.sha256(body).hexdigest()!=row['sha256']:
            raise ValueError('complete adapter source pin '+name)
        if hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()!=row['git_blob']:
            raise ValueError('adapter Git source identity '+name)
    return hashlib.sha256(raw).hexdigest()

def dependencies(root):
    # Everything except the twelve exact Git metadata files is required in
    # Cargo's actual vendor directory. Every metadata byte is still read from
    # the complete locked .crate, checked here and retained in the archive.
    from common import ROOT,loads,read,require,sha,files,pin
    packages=[p for p in tomllib.loads(read(ROOT/'reference/Cargo.lock').decode())['package'] if 'source' in p]
    target=tomllib.loads(read(ROOT/'reference/target-Cargo.lock').decode())['package']
    expected={(p['name'],p['version']):p for p in target if 'source' in p}
    require(all(expected[(p['name'],p['version'])]==p for p in packages),'unchanged target locked package records')
    require(len(packages)==19,'complete original dependency package set')
    names={p['name']+'-'+p['version'] for p in packages}
    require({p.name for p in (root/'vendor').iterdir()}==names
            and {p.name for p in (root/'crates').iterdir()}=={n+'.crate' for n in names},
            'exact original registry archive and source domains')
    expected_omissions=json.loads((ADAPTER/'CARGO_METADATA_OMISSIONS.json').read_bytes())
    allowed={(v['package'],v['path']):v for v in expected_omissions}
    observed_omissions=[];count=0;total=0;archive_count=0;archive_bytes=0
    for p in packages:
        name=p['name']+'-'+p['version'];archive=read(root/'crates'/(name+'.crate'))
        require(sha(archive)==p['checksum'],'locked complete original crate archive')
        checksum=loads(read(root/'vendor'/name/'.cargo-checksum.json'))
        require(checksum['package']==p['checksum'],'original vendored package checksum')
        observed={}
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
            for member in tar:
                if member.isdir():continue
                require(member.isfile() and member.name.startswith(name+'/'),'original crate ordinary member')
                relative=member.name[len(name)+1:]
                require(relative and '..' not in Path(relative).parts and relative not in observed,
                        'exact unique original crate source path')
                with tar.extractfile(member) as stream:raw=stream.read()
                require(len(raw)==member.size,'every complete original archive member')
                archive_count+=1;archive_bytes+=len(raw)
                if (name,relative) in allowed:
                    row=dict(package=name,path=relative,**pin(raw),mode=member.mode)
                    require(row==allowed[(name,relative)]
                        and Path(relative).name in ('.gitignore','.gitattributes')
                        and relative not in checksum['files'],'exact source-bound Cargo metadata omission')
                    observed_omissions.append(row)
                    continue
                require(read(root/'vendor'/name/relative)==raw,'every compiled registry implementation byte')
                observed[relative]=dict(**pin(raw),mode=member.mode&0o777);count+=1;total+=len(raw)
        actual=files(root/'vendor'/name,('.cargo-checksum.json',))
        require(actual==observed and checksum['files']=={n:r['sha256'] for n,r in observed.items()},
                'no missing or extra compiled registry implementation files')
    require(sorted(observed_omissions,key=lambda r:(r['package'],r['path']))==expected_omissions,
            'all twelve retained metadata files exactly once')
    return dict(packages=19,source_files=count,source_bytes=total,archive_members=archive_count,
                archive_member_bytes=archive_bytes,retained_cargo_metadata_files=observed_omissions)

def install(base_source):
    global INSTALLED
    if INSTALLED:raise ValueError('reader adapter may be installed exactly once')
    identity=check_adapter()
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(base_source))
    import common
    import read_capture
    import read_build
    import read_only_guard
    import reader_controls
    if common.source()!=BASE_SOURCE_SHA:raise ValueError('exact unchanged producer package')
    original_semantic=read_capture.semantic
    original_guard=read_only_guard.guarded
    read_build.dependencies=dependencies
    def semantic(root):
        root=Path(root)
        m=common.loads(common.read(root/'CAPTURE.json'))
        build=common.loads(common.read(root/'build/BUILD.json'))
        native=common.loads(common.read(root/'native/NATIVE.json'))
        expected=[dict(manifest={k:build['modules'][n]['manifest'][k] for k in ('bytes','sha256')},
                       image=build['modules'][n]['image']) for n in ('audit-record-io','audit-json')]
        common.require(native['modules']==expected and native['root']==m['owned_fixture'],
                       'actual native calls bind both complete compiled owners and owned fixture')
        rows=common.loads(common.read(root/'processes/processes.json'))
        process=common.loads(common.read(root/'original/process.json'))
        outer=next(row for row in rows if row['name']=='original')
        common.require(process['pgid']==outer['pid']==outer['pgid']
            and type(process['parent_pid']) is int and process['parent_pid']>1
            and process['parent_pid']!=process['pid'],'actual original child remains in its owned strace process group')
        result=original_semantic(root)
        return dict(result,reader_adapter_source_sha256=identity,
                    actual_native_graph_and_original_group_binding=True)
    def guarded(operation,*,roots,foreign_path):
        admitted=[Path(p).absolute() for p in roots]
        if ADAPTER not in admitted:admitted.append(ADAPTER)
        return original_guard(operation,roots=admitted,foreign_path=foreign_path)
    read_capture.semantic=semantic
    read_only_guard.guarded=guarded
    INSTALLED=True
    return read_capture,reader_controls,read_only_guard

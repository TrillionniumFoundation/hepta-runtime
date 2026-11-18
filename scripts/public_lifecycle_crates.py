# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path,PurePosixPath
import hashlib,io,json,tarfile

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
ENCODE=lambda value:(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
REMOVED=('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC_BOOTSTRAP')

def pin(path):
    assert path.is_file() and not path.is_symlink(),path
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=SHA(raw))

def files(root):
    rows={}
    for p in sorted(root.rglob('*')):
        assert not p.is_symlink(),p
        if p.is_dir():continue
        assert p.is_file(),p
        name=p.relative_to(root).as_posix()
        if name not in ('.cargo-ok','.cargo-checksum.json'):rows[name]=pin(p)
    return rows

def package_files(raw,prefix):
    out={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        for item in archive:
            p=PurePosixPath(item.name)
            assert not p.is_absolute() and '..' not in p.parts and p.parts[0]==prefix
            if item.isdir():continue
            assert item.isfile() and len(p.parts)>1
            name=PurePosixPath(*p.parts[1:]).as_posix()
            assert item.name==prefix+'/'+name and name not in out
            data=archive.extractfile(item).read();assert len(data)==item.size
            out[name]=dict(bytes=len(data),sha256=SHA(data))
    assert out;return out

def registry(metadata,lock,original_lock,retained):
    expected={(p['name'],p['version'],p['source']):p for p in lock['package'] if 'checksum' in p}
    original={(p['name'],p['version'],p['source']):p for p in original_lock['package'] if 'checksum' in p}
    selected=[p for p in metadata['packages'] if p.get('source') is not None]
    assert {(p['name'],p['version'],p['source']) for p in selected}==set(expected)
    rows={};retained.mkdir(exist_ok=True)
    for p in selected:
        key=(p['name'],p['version'],p['source']);want=expected[key]
        assert all(want[k]==original[key][k] for k in ('name','version','source','checksum'))
        # This fixed reference enables a documented subset of the application's
        # features. Every selected edge must retain its original exact package;
        # unselected optional application edges are not claimed as executed.
        def edges(package,universe):
            out=set()
            for edge in package.get('dependencies',[]):
                parts=edge.split();found=[(q['name'],q['version']) for q in universe['package']
                    if q['name']==parts[0] and (len(parts)==1 or q['version']==parts[1])]
                assert len(found)==1,(package['name'],edge,found)
                out.add(found[0])
            return out
        assert edges(want,lock)<=edges(original[key],original_lock),(key,'locked dependency edges')
        root=Path(p['manifest_path']).parent;prefix=p['name']+'-'+p['version']
        assert root.name==prefix and root.parent.parent.name=='src'
        archive=root.parents[2]/'cache'/root.parent.name/(prefix+'.crate')
        raw=archive.read_bytes();assert SHA(raw)==want['checksum']
        members=package_files(raw,prefix);assert files(root)==members,('actual crate source',prefix)
        target=retained/(prefix+'.crate')
        if target.exists():assert target.read_bytes()==raw
        else:target.write_bytes(raw)
        rows[prefix]=dict(package=want,archive=pin(target),members=members,actual_source=str(root))
    assert len(rows)==len(expected)
    return rows


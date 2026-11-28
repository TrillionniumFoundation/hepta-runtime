"""Whole locked crate archives and vendored implementation files; pure retained reads."""
from pathlib import Path
import io,tarfile,tomllib
from common import ROOT,read,sha,loads,pin,require,files
# Exact file-level omission map from full locked archives versus actual Cargo
# 1.95 --versioned-dirs output, inspected by CI 44075510729. No implementation
# source is omitted from either archive custody or vendored-source comparison.
VENDOR_OMITTED = {
    "anyhow-1.0.104": [
        ".gitignore"
    ],
    "itoa-1.0.18": [
        ".gitignore"
    ],
    "libc-0.2.189": [
        ".gitignore"
    ],
    "memchr-2.8.3": [
        ".gitignore"
    ],
    "once_cell-1.21.4": [
        ".gitignore"
    ],
    "proc-macro2-1.0.107": [
        ".gitignore"
    ],
    "quote-1.0.47": [
        ".gitignore"
    ],
    "serde_json-1.0.151": [
        ".gitignore"
    ],
    "zmij-1.0.23": [
        ".gitignore"
    ],
    "unicode-ident-1.0.26": [
        ".gitattributes",
        ".gitignore",
        "tests/fst/.gitignore"
    ]
}

def dependencies(root):
    packages=[p for p in tomllib.loads(read(ROOT/'reference/Cargo.lock').decode())['package'] if 'source' in p]
    target=tomllib.loads(read(ROOT/'reference/target-Cargo.lock').decode())['package']
    expected={(p['name'],p['version']):p for p in target if 'source' in p}
    require(all(expected[(p['name'],p['version'])]==p for p in packages),'unchanged target locked package records')
    require(len(packages)==19,'complete original dependency package set')
    names={p['name']+'-'+p['version'] for p in packages}
    require({p.name for p in (root/'vendor').iterdir()}==names
            and {p.name for p in (root/'crates').iterdir()}=={n+'.crate' for n in names},
            'exact original registry archive and source domains')
    count=0;total=0;omitted={}
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
                require(len(raw)==member.size,'complete locked archive member')
                if relative in VENDOR_OMITTED.get(name,()):
                    omitted.setdefault(name,{})[relative]=dict(**pin(raw),mode=member.mode&0o777)
                else:
                    require(read(root/'vendor'/name/relative)==raw,
                            'every original implementation byte equals its locked archive')
                    observed[relative]=dict(**pin(raw),mode=member.mode&0o777)
                count+=1;total+=len(raw)
        actual=files(root/'vendor'/name,('.cargo-checksum.json',))
        require(actual==observed and checksum['files']=={n:r['sha256'] for n,r in observed.items()},
                'no missing or extra original registry implementation files')
    require({name:set(rows) for name,rows in omitted.items()}==
            {name:set(paths) for name,paths in VENDOR_OMITTED.items()},
            'only exactly observed Cargo Git metadata exclusions; every omitted byte remains in locked archive')
    return dict(packages=19,source_files=count,source_bytes=total,
                cargo_vendor_nonimplementation_metadata=omitted)


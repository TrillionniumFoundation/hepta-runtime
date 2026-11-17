"""Whole locked crate archives and vendored implementation files; pure retained reads."""
from pathlib import Path
import io,tarfile,tomllib
from common import ROOT,read,sha,loads,pin,require,files
# Exact file-level omission map from full locked archives versus actual Cargo
# 1.95 --versioned-dirs output, inspected by CI 44084467378. No implementation
# source is omitted from either archive custody or vendored-source comparison.
VENDOR_OMITTED = {
    "anyhow-1.0.104": [
        ".gitignore"
    ],
    "cc-1.5.1": [
        ".gitignore"
    ],
    "cfg-if-1.0.5": [
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
    "proc-macro2-1.0.107": [
        ".gitignore"
    ],
    "quote-1.0.47": [
        ".gitignore"
    ],
    "serde_json-1.0.151": [
        ".gitignore"
    ],
    "shlex-2.0.1": [
        ".gitignore"
    ],
    "unicode-ident-1.0.26": [
        ".gitattributes",
        ".gitignore",
        "tests/fst/.gitignore"
    ],
    "untrusted-0.9.0": [
        ".gitattributes",
        ".gitignore"
    ],
    "wasi-0.11.1+wasi-snapshot-preview1": [
        ".gitignore"
    ],
    "zmij-1.0.23": [
        ".gitignore"
    ]
}
OMITTED_PINS = {
    "anyhow-1.0.104": {
        ".gitignore": {
            "bytes": 21,
            "sha256": "07d64eb09a56c853b7853a47276799b38d7d6d25a4314b0c1abc10432c214e17"
        }
    },
    "cc-1.5.1": {
        ".gitignore": {
            "bytes": 31,
            "sha256": "95e941c39767e35118fb5dad9b60deadf20e0824e3acfe88020722491afca606"
        }
    },
    "cfg-if-1.0.5": {
        ".gitignore": {
            "bytes": 18,
            "sha256": "f9b1ca6ae27d1c18215265024629a8960c31379f206d9ed20f64e0b2dcf79805"
        }
    },
    "itoa-1.0.18": {
        ".gitignore": {
            "bytes": 21,
            "sha256": "07d64eb09a56c853b7853a47276799b38d7d6d25a4314b0c1abc10432c214e17"
        }
    },
    "libc-0.2.189": {
        ".gitignore": {
            "bytes": 46,
            "sha256": "2c6be680ae3173f3fa5cb35f52625547ef9ff4333b076cd236f26cdd212b6a5f"
        }
    },
    "memchr-2.8.3": {
        ".gitignore": {
            "bytes": 93,
            "sha256": "0dbac962f4ec8a8f95158677e768b3163914026973cd77a9043c30c55ef84638"
        }
    },
    "proc-macro2-1.0.107": {
        ".gitignore": {
            "bytes": 21,
            "sha256": "07d64eb09a56c853b7853a47276799b38d7d6d25a4314b0c1abc10432c214e17"
        }
    },
    "quote-1.0.47": {
        ".gitignore": {
            "bytes": 21,
            "sha256": "07d64eb09a56c853b7853a47276799b38d7d6d25a4314b0c1abc10432c214e17"
        }
    },
    "serde_json-1.0.151": {
        ".gitignore": {
            "bytes": 21,
            "sha256": "07d64eb09a56c853b7853a47276799b38d7d6d25a4314b0c1abc10432c214e17"
        }
    },
    "shlex-2.0.1": {
        ".gitignore": {
            "bytes": 72,
            "sha256": "b637a85c521cadbb11c57b3e33001db3e2c28ee416eb63d3ecd36503b466b604"
        }
    },
    "unicode-ident-1.0.26": {
        ".gitattributes": {
            "bytes": 207,
            "sha256": "ae8eb6d0bcfdf98794d1f0d4134ca8999c30ae0f6d4fe7f1a5858dcf92e30394"
        },
        ".gitignore": {
            "bytes": 36,
            "sha256": "ab4f11740636387dbd09e6f976467f0168d1d51cd888db6a736ee1f867874b40"
        },
        "tests/fst/.gitignore": {
            "bytes": 14,
            "sha256": "2cd419079c0a08bb15766520880998651dd1c72c55347a31f43357595b16ac10"
        }
    },
    "untrusted-0.9.0": {
        ".gitattributes": {
            "bytes": 156,
            "sha256": "6141065c99514dd7ea41a888c54a3ca6ddd7eba5d2026524a3e5e314b6fa3126"
        },
        ".gitignore": {
            "bytes": 322,
            "sha256": "2f58045dabc76a9b46e9117d20283b66f75fac60244967034cf4bfb8ccd013b2"
        }
    },
    "wasi-0.11.1+wasi-snapshot-preview1": {
        ".gitignore": {
            "bytes": 30,
            "sha256": "6b937008e0a58a438c32574627db6961a4d2aff4bf5c703d4e45cb56ef3b168a"
        }
    },
    "zmij-1.0.23": {
        ".gitignore": {
            "bytes": 20,
            "sha256": "c1e953ee360e77de57f7b02f1b7880bd6a3dc22d1a69e953c2ac2c52cc52d247"
        }
    }
}

RING_PIN = {"bytes":5414,"sha256":"fb8708fe62706fe7f7c7aad5f7df9f65ca19def5fabac9616375e9f1e532f4b8"}
def dependencies(root):
    packages=[p for p in tomllib.loads(read(ROOT/'reference/Cargo.lock').decode())['package'] if 'source' in p]
    target=tomllib.loads(read(ROOT/'reference/target-Cargo.lock').decode())['package']
    expected={(p['name'],p['version']):p for p in target if 'source' in p}
    require(all(expected[(p['name'],p['version'])]==p for p in packages),'unchanged target locked package records')
    require(len(packages)==31,'complete original dependency package set')
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
                    require(pin(raw)==OMITTED_PINS[name][relative],'exact retained Cargo Git metadata omission')
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
    entropy=loads(read(ROOT/"reference/ENTROPY_SOURCE.json"));actual_entropy={}
    for row in entropy["members"]:
        relative=row["path"].split("getrandom-0.2.17/",1)[1].removesuffix(".txt")
        original=read(ROOT/row["path"]);locked=read(root/"vendor/getrandom-0.2.17"/relative)
        require(original==locked,"entire authored entropy dependency equals locked target crate")
        actual_entropy[relative]=pin(locked)
    ring=read(root/"vendor/ring-0.17.14/src/rand.rs")
    require(pin(ring)==RING_PIN,"exact actual ring SystemRandom source")
    return dict(packages=31,source_files=count,source_bytes=total,
                cargo_vendor_nonimplementation_metadata=omitted,entropy_source=actual_entropy,ring=pin(ring))


"""One bounded native capture using the actual SDK observation for one case."""
from pathlib import Path
import argparse, hashlib, json, sys
sys.dont_write_bytecode = True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'build', 'original', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--case-index', required=True, type=int)
    a = p.parse_args(); source = a.source.resolve(strict=True)
    sys.path.insert(0, str(source / 'tests'))
    from native_transport import Registry
    from compare import qualify
    corpus = json.loads((source / 'tests/CORPUS.json').read_bytes())
    case = corpus[a.case_index]
    raw = (a.original / ('case-' + str(a.case_index).zfill(3)) / 'stdout.jsonl').read_bytes()
    original = json.loads(raw)
    registry = Registry(source, a.build, a.output, epoch=a.case_index + 1)
    try:
        result = qualify(case, original, registry)
        result.update(original_sha256=hashlib.sha256(raw).hexdigest(),
            native_calls=len(registry.calls), g1_projections=len(registry.projections))
    finally:
        registry.close()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()

"""Create isolated physical evidence forks and require guarded read-only rejection."""
from pathlib import Path
import argparse, hashlib, json, shutil, sys
sys.dont_write_bytecode = True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True); p.add_argument('--run', type=Path, required=True)
    a = p.parse_args(); source = a.source.resolve(strict=True); run = a.run.resolve(strict=True)
    sys.path.insert(0, str(source / 'scripts')); sys.path.insert(0, str(source / 'tests'))
    import read_only_guard as guard
    from cases import cases
    from evidence_controls import NAMES, mutation, refusal
    import reader, compare, replay
    native = run / 'native/case-003'; original = run / 'reference/case-003'
    original_raw = (original / 'stdout.jsonl').read_bytes()
    base_before = guard.snapshot([native, original, source])
    reports = run / 'control-readers'; reports.mkdir()
    result = []
    for name in NAMES:
        folder = run / 'controls' / name
        shutil.copytree(native, folder / 'native')
        (folder / 'original.json').write_bytes(original_raw)
        changed = mutation(name, native, original_raw)
        old = {path:(folder / path).read_bytes() for path in changed}
        for path, raw in changed.items():
            (folder / path).write_bytes(raw)
        report = guard.guarded(lambda:refusal(cases()[3], folder), roots=[folder, source], foreign_path='/dev/null')
        (reports / (name + '.json')).write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        result.append(dict(name=name, refusal=report['evidence'], mutations={path:dict(
            before_sha256=hashlib.sha256(old[path]).hexdigest(), after_sha256=hashlib.sha256(raw).hexdigest(),
            bytes=len(raw)) for path, raw in changed.items()}))
    base_after = guard.snapshot([native, original, source]); assert base_before == base_after
    receipt = dict(schema='hepta.sdk-request-tasks.evidence-controls.v1', names=list(NAMES),
        controls=result, base_before=base_before, base_after=base_after, native_or_rust_executions=0)
    (run / 'CONTROLS.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps(dict(status='PHYSICAL_EVIDENCE_CONTROLS8_PASS', controls=8, native_or_rust_executions=0)))


if __name__ == '__main__':
    main()

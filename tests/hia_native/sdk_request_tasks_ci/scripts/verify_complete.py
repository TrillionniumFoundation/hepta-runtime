"""Strict no-write, no-execution readback of all already captured task cases."""
from pathlib import Path
import argparse, json, sys
sys.dont_write_bytecode = True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'run'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--require-recipe-pass', action='store_true')
    a = p.parse_args(); source = a.source.resolve(strict=True); run = a.run.resolve(strict=True)
    sys.path.insert(0, str(source / 'scripts')); sys.path.insert(0, str(source / 'tests'))
    from check_source import check
    from reader import verify
    import evidence_controls
    import read_only_guard as guard
    check(source)
    def operation():
        pin = check(source)
        result = verify(source, run, require_recipe=a.require_recipe_pass)
        if a.require_recipe_pass:
            assert json.loads((run / 'RECIPE.json').read_bytes())['source_manifest'] == pin
        return result
    report = guard.guarded(operation, roots=[source, run], foreign_path='/dev/null')
    print(json.dumps(dict(status=report['evidence']['status'], evidence=report['evidence'], readonly=report), sort_keys=True))


if __name__ == '__main__':
    main()

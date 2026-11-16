"""Add a capacity hint only; the HIA Value growth/refusal protocol stays exact."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil


HINT = '''    /* A new, admitted slot10 call ends the prior output loan. Reserve an
     * input-sized output before the first parse to avoid a known full reparse
     * on ordinary canonical output. This is only a mechanical hint: it is
     * capped at64 MiB, never shrinks, and leaves all HIA-required growth and
     * refusals below/above the hint to the original exact protocol. */
    cmp ebp, 10
    jne runtime_grow_value_hint_done
    mov rdx, [rsp + 8]
    add rdx, 64
    jc runtime_grow_value_hint_done
    cmp rdx, 67108864
    ja runtime_grow_value_hint_done
    cmp rdx, [rbx + 40]
    jbe runtime_grow_value_hint_done
    mov rdi, rbx
    mov esi, 2
    call runtime_grow_resize_borrow
    test eax, eax
    jnz runtime_grow_error
runtime_grow_value_hint_done:
'''


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    old = (source / 'scripts/runtime_mcp_extra_engine.S').read_text()
    assert sha(old.encode()) in ('13a16b581ecec1f2ecbff0144af1a3f87d0d525abc92649de950bf17310316db',
                                '9aaa0910d528e8440093cb23e286784e92dc1e7ae91c7f9c01b9c978ac65fde0')
    anchor = 'runtime_grow_resume:\n'
    assert old.count(anchor) == 1
    new = old.replace(anchor, anchor + HINT, 1)
    assert new.replace(anchor + HINT, anchor, 1) == old
    shutil.copytree(source, output)
    (output / 'scripts/runtime_mcp_extra_engine.S').write_text(new)
    proof = {'schema': 'hepta.runtime.value-output-capacity-hint.v1',
             'before_sha256': sha(old.encode()), 'after_sha256': sha(new.encode()),
             'author_sha256': sha(Path(__file__).read_bytes()),
             'exact_inverse': True, 'inserted_at': anchor.strip(), 'inserted_text': HINT,
             'selected_slot': 10, 'hint': 'input loan length +64, if no overflow and <=64 MiB',
             'existing_capacity_never_reduced': True, 'unchanged_hia_sources': True,
             'all_actual_growth_and_refusal_handlers_unchanged': True,
             'old_small_capacity_leaf_tests_unchanged': True,
             'no_new_input_or_output_semantic_limit': True,
             'public_domain_qualified': False, 'fresh_ci_qualified': False}
    (output / 'native/runtime_mcp_value_capacity_hint.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    binding = json.loads((source / 'native/runtime_mcp_sources.json').read_bytes())
    binding['sources'] = {p.relative_to(output).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}
                          for p in sorted(output.rglob('*')) if p.is_file() and p != output / 'native/runtime_mcp_sources.json'}
    (output / 'native/runtime_mcp_sources.json').write_text(json.dumps(binding, sort_keys=True, indent=2) + '\n')
    assert all((source / p.relative_to(output)).read_bytes() == p.read_bytes() for p in (output / 'native').glob('*.hepta'))
    print(json.dumps({'output': str(output), 'engine_sha256': proof['after_sha256'],
                      'source_binding_sha256': sha((output / 'native/runtime_mcp_sources.json').read_bytes())}))


if __name__ == '__main__':
    main()

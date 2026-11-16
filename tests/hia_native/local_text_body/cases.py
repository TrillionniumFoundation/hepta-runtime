"""Finite ordinary Local text-body sequences with nonempty replacement needles."""
from __future__ import annotations


def edit(old, new, *, path=b'file', all=False, context=1, kind=0):
    if not isinstance(old, str) or not old or old.isspace():
        raise ValueError('ordinary replacement domain requires a nonempty text needle')
    return dict(op=2, path=path, old=old, new=new, replace_all=all, context=context, kind=kind)


def delete(*, path=b'file', context=1, kind=0):
    return dict(op=3, path=path, old='', new='', replace_all=False, context=context, kind=kind)


def undo(*, path=b'file', context=1, kind=0):
    return dict(op=4, path=path, old='', new='', replace_all=False, context=context, kind=kind)


def case(name, content=b'alpha\n', operations=(), **extra):
    value = dict(name=name, files=[(b'file', content, 0o640)] if content is not None else [],
                 directories=[], symlinks=[], hardlinks=[], directory_modes=[],
                 cache=[], history=[], cache_poison=False, history_poison=False,
                 operations=list(operations))
    value.update(extra)
    return value


def cases():
    rows = [
        case('unique_no_ending', b'alpha', [edit('alpha', 'beta')]),
        case('unique_lf', b'alpha\nomega\n', [edit('alpha', 'beta')]),
        case('unicode_exact', '猫🙂 café\nnext\n'.encode(), [edit('猫🙂', '犬🚀')]),
        case('multiline_exact', b'one\ntwo\nthree\nfour\n', [edit('two\nthree', 'second\nthird')]),
        case('crlf_normalized_old', b'one\r\ntwo\r\nthree\r\n', [edit('one\ntwo', 'first\nsecond')]),
        case('mixed_ending_preservation', b'one\r\ntwo\nthree\r\nlast', [edit('two', 'middle')]),
        case('incoming_crlf', b'one\ntwo\nthree\n', [edit('two', 'second\r\ninserted')]),
        case('escaped_newline_recovery', b'alpha\nbeta\ntail\n', [edit(r'alpha\nbeta', r'first\nsecond')]),
        case('escaped_tab_recovery', b'let\tname\n', [edit(r'let\tname', r'let\tvalue')]),
        case('escaped_all_recovery', b'x\ny\nx\ny\n', [edit(r'x\ny', r'p\nq', all=True)]),
        case('escaped_ambiguous', b'x\ny\nx\ny\n', [edit(r'x\ny', 'z', kind=1)]),
        case('literal_escape_exact_priority', b'literal \\n here\n', [edit(r'literal \n', r'actual \n')]),
        case('fuzzy_spaces', b'    alpha   beta\nend\n', [edit('alpha beta', 'first second')]),
        case('fuzzy_tabs_ascii', b'\talpha beta\nend\n', [edit('    alpha    beta', '    first second')]),
        case('fuzzy_multiline_indent', b'    first item\n    second item\nend\n',
             [edit('  first   item\n  second   item', '  changed first\n  changed second')]),
        case('unicode_whitespace_exact', 'a\u2003b\u00a0c\n'.encode(), [edit('a\u2003b', 'x\u2003y')]),
        case('ambiguous_exact', b'alpha\nalpha\n', [edit('alpha', 'beta', kind=1)]),
        case('all_nonoverlap', b'aaaaa\n', [edit('aa', 'X', all=True)]),
        case('all_multiline', b'a\nb\ntail\na\nb\n', [edit('a\nb', 'A\nB', all=True)]),
        case('all_line_growth', b'pair\nkeep\npair\nlast\n', [edit('pair', 'a\nb\nc', all=True)]),
        case('replace_fragment_with_empty', b'left alpha right\n', [edit('alpha ', '')]),
        case('identical_edit_still_history', b'alpha\n', [edit('alpha', 'alpha'), undo(), undo(kind=1)]),
        case('replace_complete_content', b'alpha\n', [edit('alpha\n', '')]),
        case('nothing_similar', b'alpha\nbeta\n', [edit('QQQQQ', 'replacement', kind=1)]),
        case('close_line_diagnostic', b'alpha beta\nother text\n', [edit('alpha zeta', 'replacement', kind=1)]),
        case('close_multiline_diagnostic', b'alpha one\nbeta two\ngamma three\ndelta four\nend\n',
             [edit('alpha one\nbeta two\ngamma tree\ndelta four', 'replacement', kind=1)]),
        case('longer_missing_needle', b'alpha\n', [edit('totally different\nsecond\nthird', 'replacement', kind=1)]),
        case('replace_missing', None, [edit('alpha', 'beta', kind=1)]),
        case('replace_directory', None, [edit('alpha', 'beta', kind=1)], directories=[b'file']),
        case('replace_invalid_utf8_file', b'alpha\xff\n', [edit('alpha', 'beta', kind=1)]),
        case('replace_existing_temp_file', b'alpha\n', [edit('alpha', 'beta')],
             files=[(b'file', b'alpha\n', 0o640), (b'.octofs_tmp_file.tmp', b'old temporary\n', 0o600)]),
        case('replace_temp_directory_failure', b'alpha\n', [edit('alpha', 'beta', kind=1), undo(kind=1)],
             directories=[b'.octofs_tmp_file.tmp']),
        case('replace_readonly_mode_preserved', b'alpha\n', [edit('alpha', 'beta')],
             files=[(b'file', b'alpha\n', 0o444)]),
        case('relative_parent_alias', b'alpha\n', [edit('alpha', 'beta', path=b'nested/../file'), undo()],
             directories=[b'nested']),
        case('non_utf8_path', None, [edit('alpha', 'beta', path=b'raw-\xff'), undo(path=b'raw-\xff')],
             files=[(b'raw-\xff', b'alpha\n', 0o640)]),
        case('replace_symlink_then_canonical_undo', b'alpha\n',
             [edit('alpha', 'beta', path=b'alias'), undo(path=b'alias', kind=1), undo()],
             symlinks=[(b'alias', b'file')]),
        case('hardlink_atomic_replacement', b'alpha\n', [edit('alpha', 'beta'), undo()],
             hardlinks=[(b'other', b'file')]),
        case('delete_then_undo', b'alpha\n', [delete(), undo(kind=1), undo(kind=1)]),
        case('delete_empty_then_undo', b'', [delete(), undo(kind=1)]),
        case('delete_missing', None, [delete(kind=1)]),
        case('delete_directory', None, [delete(kind=1)], directories=[b'file']),
        case('delete_invalid_utf8_file', b'alpha\xff\n', [delete(kind=1)]),
        case('delete_alias_then_original_undo', b'alpha\n', [delete(path=b'alias'), undo()],
             symlinks=[(b'alias', b'file')]),
        case('delete_readonly_parent', None, [delete(path=b'parent/file', kind=1)],
             files=[(b'parent/file', b'alpha\n', 0o640)], directories=[b'parent'],
             directory_modes=[(b'parent', 0o555)]),
        case('undo_without_history_existing', b'alpha\n', [undo(kind=1)]),
        case('undo_without_history_missing', None, [undo(kind=1)]),
        case('undo_seeded_history', b'current\n', [undo(), undo(), undo(kind=1)],
             history=[(b'file', 'oldest\n', 64 << 20), (b'file', 'previous\n', 64 << 20)]),
        case('undo_seeded_missing_file', None, [undo(kind=1), undo(path=b'./file')],
             history=[(b'file', 'restored\n', 64 << 20)]),
        case('undo_failure_consumes_snapshot', b'current\n', [undo(kind=1), undo(kind=1)],
             history=[(b'file', 'previous\n', 64 << 20)], directories=[b'.octofs_tmp_file.tmp']),
        case('replace_twice_undo_twice', b'alpha\n',
             [edit('alpha', 'beta'), edit('beta', 'gamma'), undo(), undo(), undo(kind=1)]),
        case('multikey_persistent_history', None,
             [edit('A0', 'A1', path=b'a'), edit('B0', 'B1', path=b'b'),
              edit('A1', 'A2', path=b'a'), undo(path=b'a'), undo(path=b'b'), undo(path=b'a')],
             files=[(b'a', b'A0\n', 0o640), (b'b', b'B0\n', 0o600)]),
        case('context_none_replacement', b'alpha\n', [edit('alpha', 'beta', context=2)],
             cache=[(b'file', 'cached old view\n')]),
        case('context_none_delete_undo', b'alpha\n', [delete(context=2), undo(context=2, kind=1)],
             cache=[(b'file', 'cached old view\n')]),
        case('cache_replacement_then_undo', b'alpha\n', [edit('alpha', 'beta'), undo()],
             cache=[(b'file', 'alpha\n')]),
        case('poisoned_cache_preserves_body', b'alpha\n', [edit('alpha', 'beta'), delete(), undo(kind=1)],
             cache_poison=True),
        case('poisoned_history_refuses_writes', b'alpha\n',
             [edit('alpha', 'beta', kind=1), delete(kind=1), undo(kind=1)], history_poison=True),
        case('all_single_match', b'before\nalpha\nafter\n', [edit('alpha', 'beta', all=True)]),
        case('nul_path_replace', None, [edit('alpha', 'beta', path=b'bad\0path', kind=1)]),
        case('nul_path_delete', None, [delete(path=b'bad\0path', kind=1)]),
        case('nul_path_undo', None, [undo(path=b'bad\0path', kind=1)]),
        case('large_single_line', b'a' * (2 << 20) + b'<marker>\n', [edit('<marker>', '<changed>')]),
        case('large_many_lines', b'unchanged\n' * 32768 + b'marker\nlast\n', [edit('marker', 'changed')]),
    ]
    rows.append(case('history_ten_level_cap', b'v0\n',
        [edit('v' + str(i), 'v' + str(i + 1)) for i in range(12)] +
        [undo() for _ in range(10)] + [undo(kind=1), undo(kind=1)]))
    rows.append(case('history_seed_budget_and_stale_queue', b'current\n', [undo(), undo(kind=1)],
        history=[(b'other', 'older\n', 8), (b'file', 'previous\n', 8)]))
    rows.extend((
        case('delete_parent_anchored_undo', b'alpha\n', [delete(), undo(path=b'./file'), undo(path=b'./file', kind=1)]),
        case('delete_empty_parent_anchored_undo', b'', [delete(), undo(path=b'./file')]),
        case('context_none_parent_anchored_undo', b'alpha\n', [delete(context=2), undo(path=b'./file', context=2)],
             cache=[(b'file', 'cached old view\n')]),
        case('poisoned_cache_parent_anchored_undo', b'alpha\n',
             [edit('alpha', 'beta'), delete(), undo(path=b'./file')], cache_poison=True),
    ))
    if len(rows) != 68 or len({row['name'] for row in rows}) != len(rows):
        raise ValueError('ordinary body case inventory differs')
    return rows

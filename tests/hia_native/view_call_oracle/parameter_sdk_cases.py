"""Additional inputs only for actual Rust Unexpected formatting and error order."""
from pathlib import Path
import importlib.util
import json

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('original_sdk_inputs', BASE / 'sdk_cases.py')
sdk = importlib.util.module_from_spec(spec); spec.loader.exec_module(sdk)


def encoded_cases():
    rows = []

    def add(name, arguments):
        row = {'case_id': 200 + len(rows), 'name': name,
               'messages': sdk.legacy([sdk.call(2, '__VIEW_TYPED_ARGUMENTS_LITERAL__')])}
        raw = json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                         allow_nan=False).replace('"__VIEW_TYPED_ARGUMENTS_LITERAL__"', arguments)
        json.loads(raw)
        rows.append(raw.encode('utf-8') + b'\n')

    values = [('float-small', '1e-7'), ('float-large', '1e16'),
              ('negative-zero-token', '-0'), ('negative-zero-decimal', '-0.0'),
              ('float-huge', '1.234e30'), ('float-one', '1.0')]
    strings = [('empty', ''), ('newline', 'a\nb'), ('nul', 'a\0b'),
               ('single-quote', "a'b"), ('double-quote', 'a"b'),
               ('backslash', 'a\\b'), ('unicode', '中🙂'),
               ('controls', '\r\t\b\f'), ('unicode-controls', '\x7f\x85\u200d'),
               ('mixed', '\'"\\\n\0中🙂')]
    values += [('string-' + name, json.dumps(text, ensure_ascii=False)) for name, text in strings]
    for field in ('context', 'full'):
        for name, literal in values:
            add(field + '-' + name, '{' + json.dumps(field) + ':' + literal + ',"path":"file"}')
    for name, arguments in [
        ('missing-path-and-bad-full', '{"full":"bad"}'),
        ('missing-path-and-bad-context', '{"context":"bad"}'),
        ('bad-content-before-bad-context', '{"content":true,"context":-1,"path":"file"}'),
        ('bad-full-before-bad-path', '{"full":1,"path":false}'),
        ('bad-context-before-bad-path', '{"context":"bad","path":false}'),
        ('unknown-before-bad-known', '{"aaa":{"anything":[1,true,null]},"full":"bad","path":"file"}'),
        ('missing-path-after-valid-null-fields', '{"content":null,"context":null,"full":null}'),
    ]:
        add(name, arguments)
    return b''.join(rows)


if __name__ == '__main__':
    Path(__file__).with_name('additional-view-params-input.jsonl').write_bytes(encoded_cases())

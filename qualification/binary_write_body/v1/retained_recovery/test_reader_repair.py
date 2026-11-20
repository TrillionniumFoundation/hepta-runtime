#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Regression controls derived from the retained FD-zero and closed-parent captures."""
from pathlib import Path
import argparse
import base64
import binascii
import copy
import json
import sys

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    source, work = args.source.resolve(strict=True), args.work.resolve(strict=True)
    here = Path(__file__).resolve().parent
    sys.path[:0] = [str(here), str(source / 'scripts')]
    from evidence_common import decode, require
    from base64_3123 import strict_decode
    from kernel_binding import duplicates_fd, fd_history
    from read_capture import read_role, Normalize
    from readonly import guarded
    runtime = decode((work / 'runtime/RUNTIME.json').read_bytes())

    def controls():
        results = []
        accepted = (("", b""), ("AA==", b"\x00"), ("/w==", b"\xff"),
                    ("/x==", b"\xff"), ("AP8=", b"\x00\xff"),
                    ("AP8Q", b"\x00\xff\x10"),
                    ("AP8Q=", b"\x00\xff\x10"),
                    ("AP8Q====", b"\x00\xff\x10"))
        for value, expected in accepted:
            require(strict_decode(value) == expected, 'exact captured CPython decoder bytes')
        length_error = ('Invalid base64-encoded string: number of data characters ({}) '
                        'cannot be 1 more than a multiple of 4')
        refused = (("=AAA", binascii.Error, 'Leading padding not allowed'),
                   ("====", binascii.Error, 'Leading padding not allowed'),
                   ("A!", binascii.Error, 'Only base64 data is allowed'),
                   ("AA==\n", binascii.Error, 'Excess data after padding'),
                   ("AA===", binascii.Error, 'Excess data after padding'),
                   ("AAA==", binascii.Error, 'Excess data after padding'),
                   ("AA=A", binascii.Error, 'Discontinuous padding not allowed'),
                   ("AP8Q=A", binascii.Error, 'Discontinuous padding not allowed'),
                   ("AP8Q=!", binascii.Error, 'Only base64 data is allowed'),
                   ("A", binascii.Error, length_error.format(1)),
                   ("AAAAA", binascii.Error, length_error.format(5)),
                   ("A===", binascii.Error, length_error.format(1)),
                   ("AA", binascii.Error, 'Incorrect padding'),
                   ("AA=", binascii.Error, 'Incorrect padding'),
                   ("AAA", binascii.Error, 'Incorrect padding'),
                   ("\u00e9", ValueError, 'string argument should contain only ASCII characters'))
        for value, kind, message in refused:
            try:
                strict_decode(value)
            except (ValueError, binascii.Error) as error:
                require(type(error) is kind and str(error) == message,
                        'exact captured decoder error class and complete message')
            else:
                raise ValueError('reader admitted invalid strict Base64 input: ' + repr(value))
        results.append(dict(frozen_base64_success_vectors=len(accepted),
                            frozen_base64_exact_error_vectors=len(refused),
                            host_decoder_is_not_the_reference=True))
        captured = {}
        for case in (53, 54, 55):
            for role in ('original', 'native'):
                value, _ = read_role(source, work / 'cases' / str(case), role, case, runtime)
                captured[case, role] = value
        for case, returned_fd in ((53, 6), (54, 7)):
            original = captured[case, 'original']
            native = captured[case, 'native']
            left = [r for r in original['_trace']['calls']
                    if duplicates_fd(r['number'], r['args']) and r['args'][0] == 0
                    and 'exit' in r and r['exit']['result'] >= 0]
            right = [r for r in native['_trace']['calls']
                     if duplicates_fd(r['number'], r['args']) and r['args'][0] == 0
                     and 'exit' in r and r['exit']['result'] >= 0]
            require(len(left) == len(right) == 1, 'one actual duplicate per real carrier')
            require(left[0]['number'] == 72 and left[0]['args'][1] == 1030
                    and right[0]['number'] == 32
                    and left[0]['exit']['result'] == right[0]['exit']['result'] == returned_fd,
                    'actual CPython fcntl and native dup returns')
            for role, call in (('original', left[0]), ('native', right[0])):
                require(set(fd_history({'calls': [call]})['live']) == {returned_fd},
                        'duplicate becomes a real live descriptor')
                failed = copy.deepcopy(call)
                failed['exit']['result'] = -9
                require(not fd_history({'calls': [failed]})['live'],
                        'failed duplicate creates no descriptor')
                results.append(dict(case=case, role=role, duplicate_and_failure_checked=True))
            wrong = copy.deepcopy(left[0])
            wrong['args'][1] = 1
            require(not duplicates_fd(wrong['number'], wrong['args'])
                    and not fd_history({'calls': [wrong]})['live'],
                    'F_GETFD does not duplicate even with a nonnegative result')
            wrong['args'][1] = 2
            require(not duplicates_fd(wrong['number'], wrong['args']),
                    'F_SETFD does not duplicate')
            wrong['args'][1] = 0
            require(duplicates_fd(wrong['number'], wrong['args']),
                    'F_DUPFD remains an actual Linux duplication operation')
            results.append(dict(case=case, fcntl_command_refusals=True, f_dupfd_admitted=True))

        original, native = captured[55, 'original'], captured[55, 'native']
        a, b = Normalize(original), Normalize(native)
        for normal, case in ((a, original), (b, native)):
            pid = case['process']['pid']
            fd = next(iter(case['actual']['chain']['parents'].values()))['fd']
            path = '/proc/' + str(pid) + '/fd/' + str(fd)
            expected = '/proc/$PROCESS/fd/' + str(fd)
            require(normal.text(path) == expected, 'only the captured parent path is normalized')
            message = '[Errno 2] No such file or directory: ' + repr(path)
            require(normal.text(message) == '[Errno 2] No such file or directory: ' + repr(expected),
                    'complete exact observer diagnostic is normalized')
            wrong_pid = '/proc/' + str(pid + 1) + '/fd/' + str(fd)
            wrong_fd = '/proc/' + str(pid) + '/fd/' + str(fd + 1)
            for value in (wrong_pid, wrong_fd, path + '0', 'prefix:' + path,
                          path + '/child', message.replace('[Errno 2]', '[Errno 9]')):
                require(normal.text(value) == value,
                        'unbound PID, FD, suffix, embedded path and error remain literal')
            corrupted = copy.deepcopy(case)
            corrupted['process']['pid'] += 1
            try:
                Normalize(corrupted)
            except ValueError:
                pass
            else:
                raise ValueError('reader admitted a process PID contradicting the kernel capture')
            results.append(dict(case=55, process_pid=case['process']['pid'], exact_observer_forms=2,
                                literal_negative_forms=6, contradictory_process_rejected=True))
        require(a.apply(original['actual']['chain']['before'])
                == b.apply(native['actual']['chain']['before']),
                'complete retained closed-parent before-state compares')
        return dict(status='RETAINED_READER_CONTROLS_PASS', rows=results,
                    control_groups=len(results), independently_admitted_real_captures=len(captured),
                    new_original_application_calls=0, new_native_application_calls=0,
                    new_compiler_calls=0)

    result = guarded(controls, roots=[here, source, work / 'runtime', work / 'cases'])
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()

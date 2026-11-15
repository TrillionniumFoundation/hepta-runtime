#!/usr/bin/env python3
"""Pure A55 15+3-event audit kernel; no actual trace or qualification is bound.

The enclosing original-byte/stderr/call/cohort audit must finish first. This
module does not replace that audit or independently establish any RPC mapping.
"""
from collections import defaultdict

ACTUAL_BINDINGS = None
TIMERS = (
    'content_walk_and_fences_us', 'content_row_lookup_us',
    'content_order_check_us', 'content_pending_selection_us',
    'content_filename_us', 'content_namespace_before_us',
    'content_stamp_before_us', 'content_open_us',
    'content_descriptor_before_us', 'content_body_read_us',
    'content_parse_and_domain_us', 'content_descriptor_after_us',
    'content_stamp_after_us', 'content_namespace_after_us',
    'content_compare_and_close_us',
)
COUNTERS = ('content_members_attempted', 'content_members_verified', 'content_scan_complete')
ORDER = TIMERS + COUNTERS
U64_MAX = (1 << 64) - 1


def need(value, message):
    if not value:
        raise ValueError(message)


def audit_aggregate_events(events, stage_pairs, successful_calls, expected_members):
    """Use only already reconciled stderr events and independently paired spans.

    successful_calls comes from the enclosing fixed-schedule reconciliation,
    not from this helper. expected_members is archive count, not hot+archive.
    """
    need(type(expected_members) is int and expected_members > 0, 'positive archive population required')
    need(type(successful_calls) is set and all(type(n) is int and n > 0 for n in successful_calls),
         'explicit already-reconciled successful local calls required')
    calls = defaultdict(list)
    for event in events:
        need(type(event['call']) is int and event['call'] > 0, 'local call identity differs')
        if event['phase'].startswith('content_'):
            need(event['phase'] in ORDER, 'unknown content aggregate phase')
        calls[event['call']].append(event)
    need(successful_calls <= set(calls), 'successful call is absent')
    scans, absent = [], []
    for call, rows in calls.items():
        need(all(a['sequence'] < b['sequence'] for a, b in zip(rows, rows[1:])),
             'per-call event sequence must already be ordered')
        spans = stage_pairs.get(call, {}).get('complete_original_verification', [])
        groups, index = [], 0
        while index < len(rows):
            if rows[index]['phase'] not in ORDER:
                index += 1
                continue
            group = rows[index:index + len(ORDER)]
            need(len(group) == len(ORDER) and tuple(v['phase'] for v in group) == ORDER,
                 'one exact ordered eighteen-event group required')
            need(all(v['kind'] == 'event' and v['cohort'] == 0
                     and type(v['value']) is int and 0 <= v['value'] <= U64_MAX
                     and v['tool'] == 'request_archive' for v in group),
                 'serial page aggregate shape differs')
            parents = [span for span in spans
                       if span['begin']['sequence'] < group[0]['sequence']
                       and group[-1]['sequence'] < span['end']['sequence']]
            need(len(parents) == 1, 'aggregate must be inside exactly one outer verification span')
            span = parents[0]
            need(all(span['begin']['at_us'] <= v['at_us'] <= span['end']['at_us'] for v in group),
                 'aggregate event timestamp lies outside its outer span')
            attempted, verified, complete = (v['value'] for v in group[-3:])
            need(complete in (0, 1) and verified <= expected_members
                 and verified <= attempted <= verified + 1,
                 'serial attempted/verified/complete relationship differs')
            if complete:
                need(attempted == verified == expected_members,
                     'complete serial scan must cover the full archive population')
            else:
                need(call not in successful_calls, 'incomplete serial verification cannot serve success')
            values = {v['phase']: v['value'] for v in group[:len(TIMERS)]}
            measured = sum(values.values())
            need(0 <= measured <= span['elapsed_us'], 'phase clock sum exceeds enclosing elapsed span')
            groups.append(span['begin']['sequence'])
            scans.append({'call': call, 'begin_sequence': span['begin']['sequence'],
                'end_sequence': span['end']['sequence'], 'phase_us': values,
                'sum_phase_us': measured, 'outer_verification_us': span['elapsed_us'],
                'outer_minus_phase_us': span['elapsed_us'] - measured,
                'attempted_members': attempted, 'verified_members': verified,
                'serial_kernel_complete': bool(complete),
                'caller_successful': call in successful_calls,
                'aggregate_events': group,
                'interpretation': 'Per-scan wall-time categories, including their named bookkeeping; not CPU time or per-record samples.'})
            index += len(ORDER)
        need(len(groups) == len(set(groups)), 'duplicate aggregate group in one serial invocation')
        for span in spans:
            if span['begin']['sequence'] in groups:
                continue
            tool = span['begin']['tool']
            if tool == 'request_archive':
                need(call not in successful_calls, 'successful serial page span lacks its eighteen events')
                absent.append({'call': call, 'begin_sequence': span['begin']['sequence'],
                    'scope': 'Failed before a serial observer was established, or otherwise outside an observed serial scan; no phase duration or member count is fabricated.'})
            else:
                need(tool == 'usage_stats', 'unexpected verification tool')
                absent.append({'call': call, 'begin_sequence': span['begin']['sequence'],
                    'scope': 'Large usage verifier uses the existing parallel kernel; the serial aggregate is not emitted there.'})
    return {'aggregate_scan_count': len(scans), 'aggregate_events': len(scans) * len(ORDER),
        'expected_archive_members': expected_members, 'scans': scans,
        'outer_spans_without_serial_aggregate': absent,
        'scope': [
            'Requires the separate whole-original transport, stderr reparse, sequence/drop, span, fixed call and cohort audits.',
            'No actual input is bound in this pending module.',
            'complete=1 means the serial kernel finished its full walk, coverage and deadline check; projection/final fences/caller deadline can still fail.',
            'Fifteen independently accumulated nanosecond categories round only once to microseconds; total fractional loss is less than fifteen microseconds when unsaturated.',
            'Outer-minus-phase includes preflight, emission and surrounding destruction; it is not attributed to a guessed phase.',
            'Attempted counts begin after the visitor deadline check; verified increments only after full Entry comparison. Partial failure can occur between members or in final fences.',
        ]}


def main():
    need(ACTUAL_BINDINGS is not None, 'A55 actual originals/qualification/source binding is absent')
    raise ValueError('Only the pure aggregate kernel is prepared; the full actual enclosing audit must be frozen separately')


if __name__ == '__main__':
    main()

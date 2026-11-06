"""Independently validate retained monitor ledgers; never inspect processes."""
from fractions import Fraction
import json
import math


def validate(ledger, expected_limits, parent_start_ns, parent_end_ns):
    errors = []
    def need(value, reason):
        if not value: errors.append(reason)
    try:
        need(ledger['schema'] == 'hepta-bounded-compiler-monitor/v1', 'ledger schema differs')
        need(ledger['limits'] == expected_limits, 'frozen monitor limits differ')
        need(ledger['passed'] is True and ledger['thread_joined'] is True, 'monitor did not pass and completely join')
        need(not ledger['errors'] and ledger['errors_dropped'] == 0 and ledger['missed_scheduled_slots'] == 0, 'monitor error/missed ledger is not empty')
        need(ledger['hot_loop_file_writes'] == 0 and ledger['signals_sent'] == 0 and ledger['argv_or_environment_read'] is False, 'monitor read-only scope differs')
        need(isinstance(ledger['native_thread_id'], int) and ledger['native_thread_id'] > 0, 'monitor thread identity absent')
        need((ledger['parent_started_monotonic_ns'], ledger['parent_finished_monotonic_ns']) == (parent_start_ns, parent_end_ns), 'parent interval binding differs')
        start, finish = ledger['monitor_started_monotonic_ns'], ledger['monitor_finished_monotonic_ns']
        need(start <= parent_start_ns <= parent_end_ns <= finish, 'monitor did not contain the original parent interval')
        wall, cpu = finish - start, ledger['thread_cpu_ns']
        need(0 < wall <= expected_limits['maximum_duration_ns'] and ledger['wall_ns'] == wall and cpu >= 0, 'monitor wall/CPU duration invalid')
        fraction = Fraction(str(expected_limits['maximum_cpu_seconds_per_wall_second']))
        need(cpu * fraction.denominator <= wall * fraction.numerator, 'independent monitor CPU cost bound failed')
        ratio = ledger['thread_cpu_seconds_per_wall_second']
        need(isinstance(ratio, (int, float)) and math.isfinite(ratio) and ratio == cpu / wall, 'reported CPU ratio differs from raw counters')
        samples = ledger['samples']
        need(2 <= len(samples) == ledger['sample_count'] <= expected_limits['maximum_samples'], 'sample count differs or is incomplete')
        need(samples[0]['kind'] == 'periodic' and samples[0]['slot'] == 0 and samples[-1]['kind'] == 'final', 'initial/final sample kinds differ')
        need(samples[0]['finished_monotonic_ns'] <= parent_start_ns and samples[-1]['started_monotonic_ns'] >= parent_end_ns, 'ready/final sample ACK order misses parent endpoints')
        observed_slots, sample_cpu, records, serialized = [], 0, 0, 0
        previous_start, previous_end = None, None
        for index, row in enumerate(samples):
            a, b = row['started_monotonic_ns'], row['finished_monotonic_ns']
            need(start <= a <= b <= finish and b - a <= expected_limits['maximum_scan_ns'], 'sample clock/scan bound differs')
            if previous_start is not None:
                need(a >= previous_end and a - previous_start <= expected_limits['maximum_start_gap_ns'], 'sample ordering or maximum gap failed')
            previous_start, previous_end = a, b
            need(row['error'] is None and row['thread_cpu_ns'] >= 0, 'sample exception or negative CPU')
            sample_cpu += row['thread_cpu_ns']
            if row['slot'] is not None:
                scheduled = start + row['slot'] * expected_limits['period_ns']
                need(row['slot'] >= 0 and row['scheduled_monotonic_ns'] == scheduled and 0 <= a - scheduled <= expected_limits['maximum_lateness_ns'], 'scheduled sample slot/lateness differs')
                if scheduled <= parent_end_ns: observed_slots.append(row['slot'])
            else:
                need(index == len(samples) - 1 and row['kind'] == 'final' and row['scheduled_monotonic_ns'] is None, 'unassigned non-final schedule slot')
            if index < len(samples) - 1: need(row['kind'] == 'periodic', 'premature final sample')
            snapshot = row['snapshot']
            need(snapshot['schema'] == 'hepta-compiler-state-sample/v1' and
                 1 <= snapshot['enumerated_process_directories'] <= expected_limits['maximum_process_directories_per_scan'], 'sample inventory absent or beyond bound')
            need(a <= snapshot['started_monotonic_ns'] <= snapshot['finished_monotonic_ns'] <= b, 'metadata clock is outside sample')
            need(snapshot['quiescent'] is True and snapshot['blocking_records'] == [] and snapshot['signals_sent'] == 0 and snapshot['cmdline_or_environment_read'] is False, 'metadata observed activity/failure or scope differs')
            records += len(snapshot['records'])
            for record in snapshot['records']:
                states = record.get('observed_states')
                need(record.get('reason') is None and record['blocks'] is False and record['state'] in ('Z', 'X', 'x')
                     and isinstance(states, list) and len(states) == 2 and states[-1] == record['state']
                     and all(state in ('Z', 'X', 'x') for state in states), 'live or unproved compiler record present')
                need(record['pid'] > 0 and record['birth_ticks'] > 0 and record['uid'] >= 0 and record['comm'] in ('cargo', 'rustc', 'rust-lld', 'ld.lld'), 'compiler record identity incomplete')
            serialized += len(json.dumps(row, separators=(',', ':'), allow_nan=False).encode())
        required = (parent_end_ns - start) // expected_limits['period_ns'] + 1
        need(required <= expected_limits['maximum_samples'], 'required slot count exceeded bound')
        if required <= expected_limits['maximum_samples']:
            need(observed_slots == list(range(required)), 'required slots through parent end missing/duplicate/reordered')
        need(ledger['required_slots_through_parent_end'] == required and ledger['observed_required_slots'] == observed_slots, 'reported scheduled-slot coverage differs')
        need(sample_cpu <= cpu, 'sample CPU exceeds whole monitor thread CPU')
        need(serialized == ledger['serialized_sample_bytes'] <= expected_limits['maximum_serialized_sample_bytes'], 'serialized ledger byte budget differs')
        need(records == ledger['compiler_records'] <= expected_limits['maximum_compiler_records'], 'compiler record count/budget differs')
        need(ledger['covers_parent_lifecycle'] is True, 'monitor coverage flag is false')
    except (KeyError, TypeError, ValueError, ZeroDivisionError, OverflowError, IndexError, AttributeError) as error:
        errors.append('malformed monitor ledger: ' + type(error).__name__ + ': ' + str(error)[:200])
    samples_for_count = ledger.get('samples', []) if isinstance(ledger, dict) else []
    return {'schema': 'hepta-compiler-monitor-independent-validation/v1', 'passed': not errors,
            'errors': errors, 'validated_sample_count': len(samples_for_count) if isinstance(samples_for_count, list) else None,
            'scope': '1 Hz sampled observations, with bounded schedule and cost; unsampled activity is not ruled out'}

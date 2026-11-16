"""Compare HIA decisions with retained observations of the unchanged SDK loop."""
import json, struct


def same_id(first, second):
    return type(first) is type(second) and first == second


def checked(registry, operation, generation=0, arg0=0, arg1=0, payload=b''):
    reply = registry.invoke(operation, generation, arg0, arg1, payload)
    assert len(reply) == 20 and reply[18:] == (0, 0)
    raw = registry.last_workspace
    header = struct.unpack_from('<19Q', raw)
    assert raw[:8] == b'HRTKST01' and header[1] == registry.epoch
    assert not any(raw[112:128]) and not any(raw[152:256])
    rows = registry.rows()
    assert len({row['generation'] for row in rows}) == len(rows)
    assert header[5] == sum(row['live'] for row in rows)
    assert header[6] == sum(not row['done'] for row in rows)
    assert header[7] == sum(row['send_pending'] for row in rows)
    assert header[8] == len(rows) and not any(raw[header[9]:])
    assert reply[2] == registry.epoch and reply[7:17] == (
        header[3], header[5], header[6], header[7], header[8], header[9],
        header[13], header[12], header[4], header[10])
    assert reply[17] == header[11]
    chosen = next((row for row in rows if row['generation'] == reply[3]), None)
    if chosen:
        flags = sum(int(chosen[key]) << i for i, key in enumerate(
            ('live', 'cancelled', 'done', 'response_seen', 'send_pending', 'cancel_delivery_pending')))
        assert reply[4:7] == (chosen['tag'], chosen['job'], flags)
    else:
        assert reply[4:7] == (0, 0, 0)
    return reply


def qualify(case, original, registry):
    assert original['schema'] == 'hepta.sdk-request-tasks.actual-original.v1'
    assert original['label'] == case['label'] and len(original['events']) == len(case['events'])
    assert original['actual_serve_directly_with_ct'] and original['actual_request_context_ct']
    assert original['custom_in_process_transport'] and not original['async_rw_transport_qualified']
    generations, send_indices, acknowledged = {}, {}, set()
    decisions, boundaries = [], []
    phase = 0

    def admit(label, wire, caller=False):
        projection = registry.project(wire)
        reply = checked(registry, 1, payload=projection)
        assert reply[1] == 1 and reply[3] > 0 and label not in generations
        gen = reply[3]
        generations[label] = gen
        if caller:
            # This is an explicit private ABI binding fixture, not a real worker.
            tag = 1000 + gen
            result = checked(registry, 9, gen, tag, 0)
            assert result[4:6] == (tag, 0)
            result = checked(registry, 9, gen, tag, 10000 + gen)
            assert result[4:6] == (tag, 10000 + gen)
        return gen

    def complete(label, before, after):
        gen = generations[label]
        task = next(t for t in after['tasks'] if t['label'] == label)
        new_sends = [s for s in after['sends'][len(before['sends']):]
                     if same_id(s['id'], task['id'])]
        assert len(new_sends) <= 1
        reply = checked(registry, 3, gen)
        expected = 4 if new_sends else 5
        assert reply[1] == expected, (case['label'], label, reply[1], expected)
        if new_sends:
            send_indices[gen] = new_sends[0]['index']
        decisions.append(dict(label=label, generation=gen, disposition=reply[1],
            actual_send_indices=[s['index'] for s in new_sends]))

    def acknowledge_sends(snapshot):
        for gen, index in send_indices.items():
            status = snapshot['sends'][index]['status']
            if status != 'started' and gen not in acknowledged:
                assert status in ('done', 'failed', 'aborted')
                assert checked(registry, 4, gen, int(status == 'done'))[1] == 0
                acknowledged.add(gen)

    def acknowledge_cancellation(snapshot):
        while True:
            reply = checked(registry, 10)
            if reply[1] == 9:
                break
            assert reply[1] == 10
            label = next(name for name, gen in generations.items() if gen == reply[3])
            actual = next(t for t in snapshot['tasks'] if t['label'] == label)
            assert actual['cancelled'] and not actual['done']
            assert reply[4:6] == (1000 + reply[3], 10000 + reply[3])
            assert checked(registry, 11, reply[3])[1] == 0

    def compare_snapshot(snapshot):
        rows = {row['generation']: row for row in registry.rows()}
        assert len(rows) == len(snapshot['tasks']) == len(generations)
        for actual in snapshot['tasks']:
            gen = generations[actual['label']]
            row = rows[gen]
            assert same_id(row['id'], actual['id']), (case['label'], actual['label'], 'typed ID')
            assert row['id_kind'] == (2 if isinstance(actual['id'], str) else 1)
            assert row['cancelled'] == actual['cancelled'], (case['label'], actual['label'], 'context token')
            assert row['done'] == actual['done'], (case['label'], actual['label'], 'handler completion')
            assert actual['peer_info'] is None
            assert not row['cancel_delivery_pending']
            if gen in send_indices:
                assert row['send_pending'] == (snapshot['sends'][send_indices[gen]]['status'] == 'started')
            else:
                assert not row['send_pending']
        reply = checked(registry, 12)
        assert reply[9] == sum(not t['done'] for t in snapshot['tasks'])
        assert reply[10] == sum(s['status'] == 'started' for s in snapshot['sends'])
        assert bool(reply[16]) == snapshot['outer_cancelled']
        assert (reply[7] == 2) == snapshot['closed']
        boundaries.append(dict(tasks=len(rows), live=reply[8], handlers=reply[9],
            pending_sends=reply[10], phase=reply[7], cancelled=sum(r['cancelled'] for r in rows.values()),
            actual_time_ns=snapshot['time_ns']))

    for index, (action, observed) in enumerate(zip(case['events'], original['events'], strict=True)):
        assert observed['action'] == action
        before, after, extra = observed['before'], observed['after'], observed['extra']
        assert before['time_ns'] <= after['time_ns']
        op = action['op']
        if op == 'request':
            admit(action['label'], action['wire'], caller=True)
        elif op == 'notify':
            reply = checked(registry, 2, payload=registry.project(action['wire']))
            assert reply[1] in (2, 3, 11)
            changed = [t['label'] for t in after['tasks'] if t['cancelled'] and
                not next(b for b in before['tasks'] if b['label'] == t['label'])['cancelled']]
            assert changed == ([next(label for label, gen in generations.items() if gen == reply[3])]
                               if reply[1] == 2 else [])
            assert after['notifications'] == before['notifications'] + 1
            decisions.append(dict(notification=index, disposition=reply[1], selected_generation=reply[3]))
        elif op in ('finish', 'finish_drain', 'finish_closed'):
            complete(action['label'], before, after)
            if op == 'finish':
                wire = extra['barrier_wire']
                label = json.loads(wire)['id']
                admit(label, wire)
                complete(label, before, after)
        elif op == 'release_send':
            pass  # Only the actual transport completion below permits SEND_ACK.
        elif op == 'begin_drain':
            reason = 1 if action['reason'] == 'eof' else 2
            reply = checked(registry, 6, arg0=reason, arg1=extra['begin_ns'])
            assert reply[1] == 6 and reply[13] == reason
            assert reply[14] == extra['begin_ns'] + (5_000_000_000 if reason == 1 else 2_000_000_000)
            phase = 1
        elif op != 'await_close':
            raise AssertionError(op)
        # Closing can abort an actual pending send. Preserve the registry's send
        # ownership until that recorded abort/done event acknowledges the future.
        if phase == 1 and after['closed']:
            if any(s['status'] == 'aborted' for s in after['sends']):
                reply = checked(registry, 7, arg0=after['time_ns'])
                assert reply[1] == 7
                phase = 2
        acknowledge_sends(after)
        if phase == 1:
            reply = checked(registry, 7, arg0=after['time_ns'])
            assert reply[1] == (7 if after['closed'] else 6)
            phase = 2 if reply[1] == 7 else 1
        acknowledge_cancellation(after)
        compare_snapshot(after)
    assert original['final'] == original['events'][-1]['after'] or (
        {k:v for k,v in original['final'].items() if k != 'time_ns'} ==
        {k:v for k,v in original['events'][-1]['after'].items() if k != 'time_ns'})
    assert original['final']['closed'] and original['outer_after_running_service_drop']
    assert phase == 2 and not any(row['live'] or row['send_pending'] for row in registry.rows())
    for gen in list(generations.values())[::2] + list(generations.values())[1::2]:
        assert checked(registry, 8, gen)[1] == 8
    terminal = checked(registry, 12)
    assert terminal[8:13] == (0, 0, 0, 0, 256)
    return dict(label=case['label'], status='PASS', actions=len(case['events']),
        admitted_tasks=len(generations), decisions=decisions, boundaries=boundaries,
        actual_send_attempts=len(original['final']['sends']),
        actual_send_done=sum(s['status'] == 'done' for s in original['final']['sends']),
        actual_send_failed=sum(s['status'] == 'failed' for s in original['final']['sends']),
        actual_send_aborted=sum(s['status'] == 'aborted' for s in original['final']['sends']),
        private_binding_fixture=True, real_worker_executed=False, public_graph_executed=False)

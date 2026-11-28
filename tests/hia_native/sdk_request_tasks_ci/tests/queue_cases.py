"""Retain the 110 frozen cases and add normal EOF response-queue ordering."""
from cases import cases as retained_cases, request, finish, cancelled


def cases():
    result = retained_cases()
    assert len(result) == 110
    for reason in ('eof', 'service_cancel'):
        for variant in ('fifo', 'queued-send-failure', 'old-send-failure', 'cancelled-queued'):
            events = [request('alpha', '1'), request('beta', '2'), request('gamma', '3')]
            if variant == 'cancelled-queued':
                events.append(cancelled('2'))
            events.append(finish('alpha', hold_send=True, fail_send=variant == 'old-send-failure'))
            events.extend([
                dict(op='begin_drain', reason=reason),
                dict(op='finish_queued', label='beta', hold_send=variant == 'fifo',
                     fail_send=variant == 'queued-send-failure'),
                dict(op='finish_queued', label='gamma'),
            ])
            if variant == 'fifo':
                events.extend([dict(op='release_send', label='alpha', await_send_label='beta'),
                               dict(op='release_send', label='beta', await_closed=True)])
            else:
                events.append(dict(op='release_send', label='alpha', await_closed=True))
            events.append(dict(op='await_close'))
            result.append(dict(label='queue-' + reason + '-' + variant, events=events))
    assert len(result) == 118 and len({x['label'] for x in result}) == 118
    return result

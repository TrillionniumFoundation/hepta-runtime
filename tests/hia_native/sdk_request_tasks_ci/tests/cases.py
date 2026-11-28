"""Normal, owned in-process SDK task and cancellation conversations."""
import json

ENCODE = lambda value: json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def request(label, identifier):
    wire = '{"jsonrpc":"2.0","id":' + identifier + ',"method":"tools/call","params":' + \
        ENCODE(dict(name=label, arguments={})) + '}'
    return dict(op='request', label=label, wire=wire)


def cancelled(identifier=None, *, absent=False, metadata=False):
    params = '{}' if absent else '{"requestId":' + (identifier or 'null') + '}'
    if metadata:
        value = json.loads(params)
        value.update(reason='ordinary request no longer needed',
                     _meta={'protocolVersion': '2026-07-28'})
        params = ENCODE(value)
    return dict(op='notify', wire='{"jsonrpc":"2.0","method":"notifications/cancelled","params":' + params + '}')


def finish(label='alpha', **kwargs):
    return dict(op='finish', label=label, **kwargs)


def closed(label, events):
    return dict(label=label, events=events + [dict(op='begin_drain', reason='eof'), dict(op='await_close')])


def cases():
    values = [('integer', '17'), ('integer_float', '17.0'), ('negative', '-29'),
        ('zero', '0'), ('numeric_string', '"17"'), ('empty_string', '""'),
        ('unicode', ENCODE('普通请求☀️')), ('escaped', ENCODE('quote"slash\\line\n')),
        ('long_string', ENCODE('request-' + 'ab' * 2048))]
    result = []
    for name, identifier in values:
        prefix = request('alpha', identifier)
        for outcome in ('success', 'tool_error', 'protocol_error'):
            result.append(closed(name + '-' + outcome, [prefix, finish(outcome=outcome)]))
        for variant, notice in [('cancel', cancelled(identifier)),
                ('cancel_metadata', cancelled(identifier, metadata=True)),
                ('unknown_cancel', cancelled(ENCODE('unrelated-request'))),
                ('no_target', cancelled()), ('absent_target', cancelled(absent=True))]:
            result.append(closed(name + '-' + variant, [prefix, notice, finish()]))
        result.append(closed(name + '-late_cancel', [prefix, finish(), cancelled(identifier)]))
        result.append(closed(name + '-other_notification', [prefix, dict(op='notify',
            wire='{"jsonrpc":"2.0","method":"notifications/initialized"}'), finish()]))
    result.extend([
        closed('typed-numeric-and-string', [request('alpha', '17'), request('beta', '"17"'),
            cancelled('17.0'), finish('beta'), finish('alpha')]),
        closed('typed-string-and-numeric', [request('alpha', '17'), request('beta', '"17"'),
            cancelled('"17"'), finish('alpha'), finish('beta')]),
        closed('three-reverse-completions', [request('alpha', '1'), request('beta', '2'),
            request('gamma', '3'), finish('gamma'), finish('beta'), finish('alpha')]),
        closed('three-one-cancelled', [request('alpha', '1'), request('beta', '2'),
            request('gamma', '3'), cancelled('2'), finish('gamma'), finish('beta'), finish('alpha')]),
        closed('sequential-id-reuse', [request('alpha', '17'), finish('alpha'),
            request('beta', '17.0'), cancelled('17'), finish('beta')]),
        closed('sequential-string-reuse', [request('alpha', '"shared"'), finish('alpha'),
            request('beta', '"shared"'), finish('beta')]),
        closed('held-send-late-cancel', [request('alpha', '1'), finish(hold_send=True),
            cancelled('1'), dict(op='release_send', label='alpha')]),
        closed('held-send-concurrent-request', [request('alpha', '1'), finish(hold_send=True),
            request('beta', '2'), finish('beta'), dict(op='release_send', label='alpha')]),
        closed('ordinary-send-failure', [request('alpha', '1'), finish(fail_send=True), cancelled('1')]),
        closed('held-send-other-cancel', [request('alpha', '1'), request('beta', '2'),
            finish(hold_send=True), cancelled('2'), finish('beta'), dict(op='release_send', label='alpha')]),
    ])
    for reason in ('eof', 'service_cancel'):
        for cancel in (False, True):
            events = [request('alpha', '7')]
            if cancel:
                events.append(cancelled('7'))
            events += [dict(op='begin_drain', reason=reason), dict(op='finish_drain', label='alpha'),
                       dict(op='await_close')]
            result.append(dict(label=reason + ('-cancelled-early' if cancel else '-early'), events=events))
        result.append(dict(label=reason + '-handler-deadline', events=[request('alpha', '7'),
            dict(op='begin_drain', reason=reason), dict(op='await_close'),
            dict(op='finish_closed', label='alpha')]))
        result.append(dict(label=reason + '-send-release', events=[request('alpha', '7'),
            finish(hold_send=True), dict(op='begin_drain', reason=reason),
            dict(op='release_send', label='alpha'), dict(op='await_close')]))
        result.append(dict(label=reason + '-send-deadline', events=[request('alpha', '7'),
            finish(hold_send=True), dict(op='begin_drain', reason=reason), dict(op='await_close')]))
    assert len(result) == 110 and len({x['label'] for x in result}) == len(result)
    return result


if __name__ == '__main__':
    print(json.dumps(cases(), ensure_ascii=False, sort_keys=True, indent=2))

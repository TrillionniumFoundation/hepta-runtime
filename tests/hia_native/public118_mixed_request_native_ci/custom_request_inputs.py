"""Inputs only for typed CustomRequest and adjacent protocol classifications.

No response, error code, response count, or filesystem outcome is authored.
"""
from pathlib import Path
import copy
import extract_public_inputs as peer
def scenarios(fixture,*,modern=False):
    assert type(modern) is bool
    trials=[]
    def add(name,method,params=peer.ABSENT,identifier=b'41000'):
        assert type(identifier) is bytes
        raw=peer.raw_request(identifier,peer.encode(method),params)
        trials.append((name,raw))
    ordinary=peer.encode({'_meta':peer.inline_meta()} if modern else {})
    for method in ('tools/call','tools/list','ping','initialize','resources/read'):
        for name,params in (('absent',peer.ABSENT),('null',b'null'),('empty-object',ordinary)):
            add('known-'+method.replace('/','-')+'-'+name,method,params)
    methods=[('control-'+str(i),'custom'+chr(i)+'method') for i in range(32)]
    methods += [('empty',''),('ordinary','unknown.method'),('quote','quoted"method'),('backslash','slash'+chr(92)+'method'),
                ('unicode','λ😀/method'),('long','custom-'+'q'*4096),('slash','slash/method')]
    for name,method in methods:add('method-'+name,method,ordinary)
    identifiers=[('zero',b'0'),('positive',b'17'),('negative',b'-17'),('max',b'9223372036854775807'),('min',b'-9223372036854775808'),
        ('integral-float',b'17.0'),('negative-zero',b'-0.0'),('empty-string',b'""'),
        ('escaped-string',peer.encode('"'+chr(92)+chr(9)+chr(10)+chr(0)+'λ')),('long-string',peer.encode('custom-id-'+'i'*4096))]
    for name,identifier in identifiers:add('identifier-'+name,'custom.identifier',ordinary,identifier)
    for name,params in (('absent',peer.ABSENT),('null',b'null'),('false',b'false'),('number',b'7'),('array',b'[]'),('string',b'"plain"'),('object',ordinary)):
        add('custom-params-'+name,'custom.params',params)
    assert len(trials)==71 and len({n for n,_ in trials})==71
    result=[];setup=peer.fixture_actions(Path(fixture))
    for index,(name,wire) in enumerate(trials):
        barrier='custom-barrier-'+str(index);recovery=50000+index
        result.append({'name':('modern-' if modern else 'legacy-')+name,'category':'typed-custom-and-adjacent-shapes',
            'session_count':1,'requires_real_stdio':True,'actions':copy.deepcopy(setup),
            'initial':peer.initialization_inputs(modern=modern,sessions=(0,)),
            'anchor':{'wire':peer.ping_wire(40000,modern=modern),'input_id':40000,'collect':'through-input-id-or-eof'},
            'trial':{'wire':wire,'collect':'defer-to-barrier'},
            'recovery':{'wire':peer.ping_wire(recovery,modern=modern),'input_id':recovery,'collect':'all-actual-lines-through-input-id-or-eof'},
            'barrier':{'wire':peer.ping_wire(barrier,modern=modern),'input_id':barrier,'collect':'all-actual-lines-through-input-id-or-eof'},
            'finish':{'action':'close-stdin-after-barrier-or-observed-eof','collect':'all-remaining-lines-and-process-exit'},
            'per_exchange_deadline_seconds':60,'outer_lane_deadline_seconds':180,'response_count':None})
    return result

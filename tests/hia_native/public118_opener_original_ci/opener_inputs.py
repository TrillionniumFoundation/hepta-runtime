"""Frozen additional inputs for the actual pre-service receive loop and EOF.

Only input bytes and mechanical sequencing are declared. No reply, status,
response count, or filesystem outcome is precomputed.
"""
from pathlib import Path
import copy
import extract_public_inputs as peer
def scenarios(fixture):
    def request(name,method,params,identifier):
        return {'name':name,'wire':peer.raw_request(peer.encode(identifier),peer.encode(method),params)}
    def custom(name,identifier,version=None,missing=False):
        params={} if missing else {'_meta':peer.inline_meta()}
        if version is not None:params['_meta']['io.modelcontextprotocol/protocolVersion']=version
        return request(name,'custom.opener',peer.encode(params),identifier)
    def ping(name,identifier,modern=False):
        return {'name':name,'wire':peer.ping_wire(identifier,modern=modern)}
    def init(name,identifier):
        return {'name':name,'wire':peer.encode(peer.initialize(identifier))+b'\n'}
    definitions=[
      ('single-pre-init-ping',[ping('ping',61001)],None),
      ('virgin-empty',[],None),
      ('virgin-blank-lines',[],b'\n\r\n\n'),
      ('mixed-pre-init-pings',[ping('ping-a',61002),ping('ping-b',61003,True),ping('ping-c',61004)],None),
      ('missing-meta-then-ping',[custom('missing',61005,missing=True),ping('recovery',61006,True)],None),
      ('missing-meta-then-inline',[custom('missing',61007,missing=True),custom('inline',61008),ping('barrier',61009,True)],None),
      ('missing-meta-then-initialize',[custom('missing',61010,missing=True),init('initialize',61011),ping('barrier',61012)],None),
      ('unsupported-then-ping',[custom('unsupported',61013,'2999-01-01'),ping('recovery',61014,True)],None),
      ('unsupported-then-inline',[custom('unsupported',61015,'2999-01-01'),custom('inline',61016),ping('barrier',61017,True)],None),
      ('unsupported-then-initialize',[custom('unsupported',61018,'2999-01-01'),init('initialize',61019),ping('barrier',61020)],None),
      ('two-unsupported-then-missing-then-inline',[custom('unsupported-a',61021,'2999-01-01'),custom('unsupported-b',61022,'1900-01-01'),custom('missing',61023,missing=True),custom('inline',61024),ping('barrier',61025,True)],None),
      ('initialize-without-notification',[init('initialize',61026)],None),
      ('initialize-without-notification-then-list',[init('initialize',61027),request('list','tools/list',b'{}',61028),ping('barrier',61029)],None),
      ('inline-then-missing-then-valid',[custom('inline',61030),custom('missing',61031,missing=True),custom('valid',61032),ping('barrier',61033,True)],None),
      ('inline-then-unsupported-then-valid',[custom('inline',61034),custom('unsupported',61035,'2999-01-01'),custom('valid',61036),ping('barrier',61037,True)],None),
    ]
    assert len(definitions)==15 and len({n for n,_,_ in definitions})==15
    result=[]
    for name,rows,tail in definitions:
        item={'name':'opener-'+name,'category':'additional-pre-service-state-and-eof',
          'session_count':1,'requires_real_stdio':True,'actions':copy.deepcopy(peer.fixture_actions(Path(fixture))),
          'rows':rows,'finish':{'action':'close-stdin-after-planned-input-or-observed-eof','collect':'all-remaining-lines-stderr-and-process-exit'},
          'per_exchange_deadline_seconds':60,'outer_lane_deadline_seconds':180,'response_count':None}
        if tail is not None:item['tail']={'wire':tail}
        result.append(item)
    return result

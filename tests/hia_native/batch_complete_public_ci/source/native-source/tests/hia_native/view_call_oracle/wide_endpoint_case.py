"""One additional input-only domain: small JSON expands to a large endpoint.

The million scalars are encoded as the original JSON token 1e15. No expected
canonical serialization, Rust diagnostic or native output is constructed here.
This case is separate from the frozen ordinary-file 58-case corpus.
"""
from __future__ import annotations
import json,struct

CASE_ID=1000
COUNT=1000000
MARKER='__VIEW_WIDE_ENDPOINT_LITERAL__'

def scalar_array():
    return b'['+b'1e15,'*(COUNT-1)+b'1e15]'

def case():
    metadata=dict(case_id=CASE_ID,name='wide-noninteger-endpoint-display',session=2000,
        path_hex=b'file'.hex(),params={'start':MARKER},reset_cache=True,context=True,
        raw_path=False,cancel_after_render=False,
        setup=[dict(kind='write',path_hex=b'file'.hex(),blob=0)],hooks=[],cache_probes=[b'file'.hex()])
    return dict(metadata=metadata,blobs=[b'a\n'])

def arguments():
    return b'{"path":"file","start":'+scalar_array()+b'}'

def original_input():
    row=case();metadata=json.dumps(row['metadata'],sort_keys=True,ensure_ascii=False,
        separators=(',',':'),allow_nan=False).encode()
    token=json.dumps(MARKER).encode();assert metadata.count(token)==1
    metadata=metadata.replace(token,scalar_array())
    return b'HVCOI001'+struct.pack('<3Q',1,len(metadata),1)+metadata+struct.pack('<Q',2)+b'a\n'

"""Read the frozen concrete inputs without producing any semantic output."""
import gzip
import base64
from common import ROOT, loads, pin, read, require, sha


def domain():
    value = loads(read(ROOT / 'DOMAIN.json'))
    require(value['schema'] == 'hepta.audit-retention.domain.v1', 'exact codec domain schema')
    return value


def cases():
    specification = domain()['cases']
    raw = base64.b64decode(read(ROOT / specification['file']),validate=True)
    require(len(raw) == specification['compressed_bytes'] and sha(raw) == specification['compressed_sha256'],
            'complete compressed input domain')
    plain = gzip.decompress(raw)
    require(pin(plain) == {key: specification[key] for key in ('bytes', 'sha256')}, 'complete uncompressed input domain')
    rows = [loads(line) for line in plain.splitlines()]
    require(len(rows) == specification['count'] and len({row['name'] for row in rows}) == len(rows),
            'each frozen concrete input exactly once')
    return rows


def stdin_bytes(rows):
    import json
    return b''.join((json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
                    for row in rows)

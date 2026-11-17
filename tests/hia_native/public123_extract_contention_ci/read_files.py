from pathlib import Path
import stat,hashlib
from wait_observations import need
def pin(raw):return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def read_snapshot(case,snapshot,fixture,used):
    raw=snapshot['complete_metadata'];need(len(raw)==1 and raw[0]['root_hex']==str(fixture).encode().hex(),'absolute unchanged fixture root')
    nodes={n['relative_hex']:n for n in raw[0]['nodes']};need(len(nodes)==len(raw[0]['nodes']) and '' in nodes,'complete unique metadata tree')
    relative={k:v for k,v in nodes.items() if k};view=snapshot['filesystem'];need({n['path_hex'] for n in view['nodes']}==set(relative),'same complete filesystem paths')
    links={}
    for row in view['nodes']:
        path=bytes.fromhex(row['path_hex']);need(path and not path.startswith(b'/') and b'..' not in path.split(b'/'),'owned observed path')
        meta=relative[row['path_hex']]
        need(row['mode']==stat.S_IMODE(meta['mode']) and all(row[k]==meta[k] for k in ('uid','gid','links')),'complete filesystem metadata')
        if row['kind']=='file':
            need(stat.S_ISREG(meta['mode']),'file kind');blob=row['content'];need(blob['path']==blob['sha256']+'.bin','content-addressed bytes')
            value=(case/'blobs'/blob['path']).read_bytes();need(pin(value)=={k:blob[k] for k in ('bytes','sha256')} and value.hex()==meta['content_hex'] and len(value)==meta['size'],'complete original filesystem bytes')
            used.add(blob['path']);links.setdefault((meta['device'],meta['inode']),[]).append(row['path_hex'])
        elif row['kind']=='directory':need(stat.S_ISDIR(meta['mode']),'directory kind')
        elif row['kind']=='symlink':need(stat.S_ISLNK(meta['mode']) and row['target_hex']==meta['target_hex'],'full symlink target')
        else:raise ValueError('unexpected observed filesystem object')
    need(view['hardlink_groups']==sorted(sorted(x) for x in links.values() if len(x)>1),'complete hardlink relationships')
    return view

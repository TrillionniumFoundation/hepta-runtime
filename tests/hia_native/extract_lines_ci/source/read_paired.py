"""Strict complete retained transport, filesystem and persistent-owner parity."""
from pathlib import Path
import os
import struct
from common import ROOT, encoded, loads, pin, read, require, sha, source
import cases
import observations
import native_observations
import run_ordinary as ordinary


def framed(raw):
    out=[];at=0
    while at<len(raw):
        require(len(raw)-at>=8,'complete transport length')
        n,=struct.unpack_from('<Q',raw,at);at+=8
        require(8<=n<=134217728 and n<=len(raw)-at,'complete transport extent')
        out.append(raw[at:at+n]);at+=n
    return out


def compact(value,vault):
    if isinstance(value,bytes):
        name=sha(value)+'.bin';require(read(vault/name)==value,'complete owner state blob')
        return dict(path=name,**pin(value))
    if isinstance(value,list):return [compact(x,vault) for x in value]
    if isinstance(value,dict):return {(k.hex() if isinstance(k,bytes) else k):compact(v,vault) for k,v in value.items()}
    return value


def snapshot(value,vault):
    nodes=value['nodes'];names=[];mapping={}
    for node in nodes:
        name=bytes.fromhex(node['path_hex'])
        require(name and not name.startswith(b'/') and b'\0' not in name
                and all(p not in (b'',b'.',b'..') for p in name.split(b'/')),'complete raw filesystem path')
        require(name not in mapping,'unique retained filesystem entry');names.append(name);mapping[name]=node
        require(all(type(node[k]) is int and node[k]>=0 for k in ('mode','uid','gid','links'))
                and node['mode']<=0o7777 and node['links']>0,'filesystem metadata')
        if b'/' in name: require(mapping[name.rsplit(b'/',1)[0]]['kind']=='directory','retained parent directory')
        if node['kind']=='file':
            row=node['content'];raw=read(vault/row['path'])
            require(row==dict(path=sha(raw)+'.bin',**pin(raw)),'complete filesystem bytes')
        elif node['kind']=='symlink':require(b'\0' not in bytes.fromhex(node['target_hex']),'actual symlink target')
        else:require(node['kind']=='directory','ordinary retained filesystem kind')
    require(names==sorted(names),'complete filesystem name order')
    seen=set()
    for group in value['hardlink_groups']:
        require(len(group)>1 and group==sorted(group) and len(set(group))==len(group),'hardlink group')
        entries=[mapping[bytes.fromhex(n)] for n in group]
        require(all(n not in seen for n in group),'hardlink groups are disjoint');seen.update(group)
        first={k:v for k,v in entries[0].items() if k!='path_hex'}
        require(first['kind']=='file' and first['links']==len(group)
                and all({k:v for k,v in e.items() if k!='path_hex'}==first for e in entries),'complete hardlink identity')
    require(all(n['links']==1 or n['path_hex'] in seen for n in nodes if n['kind']=='file'),'all hardlinks retained')
    return value


def initial_snapshot(value,definition,vault):
    nodes={bytes.fromhex(row['path_hex']):row for row in value['nodes']}
    expected={}
    def parents(name):
        parts=name.split(b'/')
        for n in range(1,len(parts)):expected.setdefault(b'/'.join(parts[:n]),('directory',None,0o750))
    for name in definition['directories']:
        parents(name);expected[name]=('directory',None,0o750)
    for name,raw,mode in definition['files']:
        parents(name);expected[name]=('file',raw,mode)
    for name,original in definition['hardlinks']:expected[name]=expected[original]
    for name,target in definition['symlinks']:expected[name]=('symlink',target,0o777)
    for name,mode in definition['directory_modes']:
        require(expected[name][0]=='directory','declared fixture directory mode')
        expected[name]=('directory',None,mode)
    require(set(nodes)==set(expected),'complete source-declared initial filesystem set')
    for name,(kind,data,mode) in expected.items():
        node=nodes[name];require(node['kind']==kind and node['mode']==mode,'source-declared initial filesystem kind and mode')
        if kind=='file':require(read(vault/node['content']['path'])==data,'source-declared initial file bytes')
        if kind=='symlink':require(bytes.fromhex(node['target_hex'])==data,'source-declared initial symlink target')


def verify(root,old_binary,new_binary):
    root=Path(root);report=loads(read(root/'RESULT.json'));domain=loads(read(ROOT/'DOMAIN.json'))
    definitions=cases.cases();require([r['name'] for r in definitions]==domain['ordinary_cases'],'fixed ordinary source cases')
    require(report['schema']=='hepta.extract-lines.paired.v1' and report['status']=='EXTRACT_LINES_ORDINARY_PAIRED_PASS'
            and report['source_manifest_sha256']==source() and report['root_pairs']==len(definitions)==153
            and report['actual_root_processes']==306 and report['operations_per_side']==175
            and report['process_deadline_seconds']==60 and report['capture_deadline_seconds']==180
            and 0<report['elapsed_seconds']<=180 and report['same_absolute_workdir'] is True
            and not any(report[k] for k in ('full_body_async_qualified','public_handler_qualified','whole_runtime_replaced')),
            'complete ordinary source domain and original budgets')
    require(report['binaries']=={'original':old_binary,'native':new_binary},'actual paired executable identities')
    require(len(report['cases'])==len(definitions),'every ordinary case exactly once')
    vault=root/'blobs';pids=set();totals={k:0 for k in ('complete_input_bytes','complete_response_bytes',
        'complete_original_observer_bytes','complete_native_arena_observer_bytes')}
    for index,(definition,summary) in enumerate(zip(definitions,report['cases'],strict=True)):
        name=f'case-{index:03d}-{definition["name"]}';folder=root/name
        pair_raw=read(folder/'PAIR.json');pair=loads(pair_raw)
        require(summary==dict(folder=name,receipt=pin(pair_raw),**pair)
                and pair['schema']=='hepta.extract-lines.pair.v1' and pair['name']==definition['name']
                and pair['status']=='PAIRED_COMPLETE_STATE_PASS' and pair['same_absolute_workdir'] is True
                and pair['process_deadline_seconds']==60 and pair['operations']==len(definition['operations']),
                'complete ordinary case binding')
        cwd=Path(pair['actual_working_directory'])
        require(cwd==Path(report['producer_root'])/name/'lane/work','exact shared original/native path')
        previous=ordinary.canonical
        def seed_key(work,path):
            require(path and b'/' not in path and b'\0' not in path and path not in (b'.',b'..'),'fixed seed key')
            return os.fsencode(work)+b'/'+path
        ordinary.canonical=seed_key
        try: requests,setup_count=ordinary.requests(definition,cwd)
        finally:ordinary.canonical=previous
        wire=b''.join(ordinary.q(len(x))+x for x in requests);rows={};streams={};states={}
        for lane,decoder in [('original',observations.decode),('native',native_observations.decode)]:
            capture=folder/lane;raw=read(capture/'result.json');row=loads(raw)
            require(pair['captures'][lane]==dict(folder=lane,receipt=pin(raw)),'retained process receipt')
            require(row['schema']=='hepta.extract-lines.ordinary-case.v1' and row['name']==definition['name']
                    and row['status']=='PASS' and row['cwd']==str(cwd) and row['command']==[report['binary_paths'][lane]]
                    and row['environment']==ordinary.ENVIRONMENT and row['process_deadline_seconds']==60
                    and row['timed_out'] is False and row['process_reaped'] is True and row['exit_code']==0
                    and 0<row['elapsed_seconds']<=60 and row['input_frames']==len(requests)
                    and row['setup_frames']==setup_count and type(row['pid']) is int and row['pid']>1 and row['pid'] not in pids,
                    'successful isolated actual pair process')
            pids.add(row['pid']);current={k:read(capture/(k+'.bin')) for k in ('stdin','stdout','stderr')}
            require(row['streams']=={k:pin(v) for k,v in current.items()} and current['stdin']==wire,'complete source request and streams')
            output=framed(current['stdout']);require(len(output)==len(requests),'one exact response for every input')
            parsed=[ordinary.response(request,response,definition['operations'][n-setup_count] if n>=setup_count else None)
                    for n,(request,response) in enumerate(zip(requests,output,strict=True))]
            require(row['responses']==parsed,'complete actual response frames')
            decoded=decoder(current['stderr'],definition['operations'])
            require(row['observations']==[dict(x,state=compact(x['state'],vault)) for x in decoded],'complete physical owner observations')
            require(row['operations']==[dict(x,generation=n+1) for n,x in enumerate(definition['operations'])],
                    'all actual operations are the frozen source domain')
            require(len(row['files_after_body'])==len(definition['operations'])
                    and [x['generation'] for x in row['files_after_body']]==list(range(1,len(definition['operations'])+1)),
                    'complete filesystem boundary sequence')
            for state in [row['filesystem_before'],*[x['snapshot'] for x in row['files_after_body']]]:snapshot(state,vault)
            initial_snapshot(row['filesystem_before'],definition,vault)
            final_raw=read(capture/'FILESYSTEM.json');archive=loads(final_raw)
            require(pair['filesystem_archives'][lane]==pin(final_raw)
                    and archive['schema']=='hepta.extract-lines.complete-filesystem.v1'
                    and archive['retired_owned_completed_fixture'] is True
                    and archive['failed_process_evidence'] is False
                    and archive['snapshot']==row['files_after_body'][-1]['snapshot'],'complete retired filesystem archive')
            require(not (capture/'work').exists(),'retired fixture remains retired')
            rows[lane],streams[lane],states[lane]=row,current,decoded
        for kind in ('stdin','stdout'):
            require(streams['original'][kind]==streams['native'][kind],'byte-exact original/native '+kind)
        for field in ('operations','setup_frames','input_frames','cwd','environment','filesystem_before','responses','files_after_body'):
            require(rows['original'][field]==rows['native'][field],'complete original/native '+field)
        native_observations.compare(states['original'],states['native'])
        counts=dict(complete_input_bytes=len(wire),complete_response_bytes=len(streams['original']['stdout']),
                    complete_original_observer_bytes=len(streams['original']['stderr']),
                    complete_native_arena_observer_bytes=len(streams['native']['stderr']))
        require(all(pair[k]==v for k,v in counts.items()) and pair['compared_owner_boundaries']==6*len(definition['operations'])
                and pair['compared_hint_boundaries']==len(definition['operations']),'full ordinary boundary accounting')
        for key,value in counts.items():totals[key]+=value
    require(len(pids)==306 and all(report[k]==v for k,v in totals.items()),'complete ordinary aggregate')
    return dict(status='PASS',root_pairs=153,actual_processes=306,operations_per_side=175,**totals)

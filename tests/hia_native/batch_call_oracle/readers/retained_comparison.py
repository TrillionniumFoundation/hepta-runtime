"""Complete-value Batch differential reader; no generated expected results."""
from pathlib import Path
import gzip
import stat
import struct
from capture_format import blob, canonical, need, same, fields, uint, sha, strict_json
import trace_evidence as trace_reader


def value_equal(a,b):
    if type(a) is not type(b):return False
    if type(a) is dict:return set(a)==set(b) and all(value_equal(a[k],b[k]) for k in a)
    if type(a) in (list,tuple):return len(a)==len(b) and all(value_equal(x,y) for x,y in zip(a,b))
    return a==b


class Comparison:
    def __init__(self,files,capture):
        self.files,self.capture=files,Path(capture)
        self.checks=0
        self.body_bytes=0
        self.snapshot_bytes=0
        self.atomic_receipts=0
        self.operation_boundaries=0
    def same(self,a,b,message):
        self.checks+=1
        need(value_equal(a,b),'complete Batch comparison: '+message)
    def native_blob(self,value):
        fields(value,('artifact','bytes','sha256'),'complete native blob descriptor')
        raw=gzip.decompress(self.files.raw(str(self.capture/value['artifact'])))
        same({'bytes':len(raw),'sha256':sha(raw)},{k:value[k] for k in ('bytes','sha256')},
             'complete native body identity')
        return raw
    def history_native(self,state):
        v=state['history']['decoded']
        return {'poisoned':v['poisoned'],'total_bytes':v['total_bytes'],
            'order':[bytes.fromhex(k) for k in v['order_hex']],
            'entries':[{'key':bytes.fromhex(e['key_hex']),
                        'values':[self.native_blob(b) for b in e['values']]} for e in v['entries']]}
    @staticmethod
    def history_original(get,state):
        v=state['history']
        fields(v,('poisoned','total_bytes','order','entries'),'complete original History observation')
        need(type(v['poisoned']) is bool,'typed original history poison')
        uint(v['total_bytes'],'original history bytes')
        entries=[]
        for e in v['entries']:
            fields(e,('key_blob','values'),'complete original history item')
            entries.append({'key':get(e['key_blob']),'values':[get(i) for i in e['values']]})
        need(sum(len(x) for e in entries for x in e['values'])==v['total_bytes'],
             'original history byte count differs from complete values')
        return {'poisoned':v['poisoned'],'total_bytes':v['total_bytes'],
                'order':[k.encode() for k in v['order']],'entries':entries}
    def cache_native(self,state):
        return [{'session':c['session'],'poisoned':c['poisoned'],
            'entries':[{'key':bytes.fromhex(e['key_hex']),'value':self.native_blob(e['value'])}
                       for e in c['entries']]} for c in state['caches']]
    @staticmethod
    def cache_original(get,state):
        result=[]
        for c in state['caches']:
            fields(c,('session','poisoned','entries'),'complete original per-Session cache')
            uint(c['session'],'original Session identity')
            need(type(c['poisoned']) is bool,'typed original cache poison')
            entries=[]
            for e in c['entries']:
                fields(e,('key_blob','value_blob'),'complete original cache item')
                entries.append({'key':get(e['key_blob']),'value':get(e['value_blob'])})
            need([x['key'] for x in entries]==sorted(set(x['key'] for x in entries)),
                 'cache keys not sorted/unique')
            result.append({'session':c['session'],'poisoned':c['poisoned'],'entries':entries})
        need([x['session'] for x in result]==sorted(set(x['session'] for x in result)),
             'original cache Session identities not unique')
        return result
    @staticmethod
    def tree(value,get,original,identities):
        nodes=[]
        paths=[]
        for node in value['nodes']:
            info=node['metadata']
            for name in ('dev','ino','mode','nlink','uid','gid','size'):uint(info[name],'actual file metadata '+name)
            if original:
                same(info['is_file'],stat.S_ISREG(info['mode']),'original metadata file type')
                same(info['is_dir'],stat.S_ISDIR(info['mode']),'original metadata directory type')
                same(info['is_symlink'],stat.S_ISLNK(info['mode']),'original metadata symlink type')
                for name in ('mtime','ctime'):
                    need(type(info[name]) is list and len(info[name])==2 and
                         all(type(x) is int for x in info[name]) and 0<=info[name][1]<1000000000,
                         'complete original inode timestamp')
            identity=info['dev'],info['ino']
            if identity not in identities:identities[identity]=len(identities)
            relative=bytes.fromhex(node['relative_hex'])
            need(not relative.startswith(b'/') and b'..' not in relative.split(b'/'),'fixture tree escapes root')
            paths.append(relative)
            result={'relative':relative,'mode':info['mode'],'nlink':info['nlink'],
                    'uid':info['uid'],'gid':info['gid'],'inode_class':identities[identity]}
            # Directory storage size and ctime/mtime/inode numbers are physical
            # observations, never assumed equal across two real fixture runs.
            if not stat.S_ISDIR(info['mode']):result['size']=info['size']
            if 'target_hex' in node:result['target']=bytes.fromhex(node['target_hex'])
            if 'content' in node:
                content=node['content'];need(type(content['ok']) is bool,'typed full file read result')
                body={'ok':content['ok']}
                if content['ok']:
                    body['bytes']=get(content['blob'])
                    same(len(body['bytes']),info['size'],'full actual file content extent')
                    if 'fixture_retained_fd' in content:
                        need(content['fixture_retained_fd'] is True,'fixture retained fd type')
                        uint(content['pathname_errno'],'actual pathname denial')
                        body.update(fixture_retained_fd=True,pathname_errno=content['pathname_errno'])
                else:body['errno']=content['errno']
                result['content']=body
            if 'readdir_error' in node:result['readdir_error']=node['readdir_error']
            nodes.append(result)
        need(paths and paths[0]==b'' and len(paths)==len(set(paths)),'complete unique fixture tree')
        return {'root':get(value['root_blob']) if original else bytes.fromhex(value['root_hex']),
                'nodes':nodes}
    def states(self,native,original,get,label,ni,oi):
        fields(original,('history','caches','file_locks','tree','descriptors'),'full original state fields')
        self.same(self.history_native(native),self.history_original(get,original),label+'.history')
        self.same(self.cache_native(native),self.cache_original(get,original),label+'.all_session_caches')
        self.same(self.tree(native['tree'],self.native_blob,False,ni),
                  self.tree(original['tree'],get,True,oi),label+'.complete_tree_and_inode_relationships')
        trace_reader.descriptors(native,native=True,origin=str(self.capture/'files').encode())
        trace_reader.descriptors(original,native=False,origin=str(self.capture/'files').encode())

    def native_stages(self,events,*,atomic):
        result=[]
        effects=[]
        for event in events:
            if event['kind']=='child':
                slot,phase=event['slot'],event['phase']
                if slot==1 and phase in (4,15):
                    body=self.native_blob(event['body'])
                    need(len(body)==80 and body[:8]==b'HVRDR001','actual exists response')
                    q=struct.unpack_from('<9Q',body,8)
                    need(q[1]==1 and q[2] in (0,1,2),'actual exists owner domain')
                    result.append(('exists',{'ok':True,'value':q[2]==0}))
                elif slot in (2,3) and phase in (10,16):
                    body=self.native_blob(event['body'])
                    need(len(body)>=80 and body[:8]==b'HVRDR001','actual strict read response')
                    q=struct.unpack_from('<9Q',body,8)
                    need(q[1]==2 and q[2] in (0,1,2,3),'actual read owner domain')
                    if q[2]==0:
                        same(len(body)-80,q[7],'complete actual strict read snapshot')
                        result.append(('read',{'ok':True,'body':body[80:]}))
                        self.snapshot_bytes+=len(body)-80
                    else:
                        need(len(body)==80,'failed read published data')
                        result.append(('read',{'ok':False,'errno':q[3] if q[2]==1 else None}))
                elif slot==8 and phase==23:result.append(('note_write',{}))
            elif event['kind']=='atomic-effect':
                raw=self.native_blob(event['effect'])
                need(len(raw)==96 and raw[:8]==b'HIAATFX1','complete native atomic effect')
                q=struct.unpack_from('<11Q',raw,8)
                seq,action,a,b,c,reserved,count,err,value,acked,zero=q
                need(seq==len(effects)+1 and 1<=action<=11 and reserved==zero==0 and acked==1,
                     'native atomic actual effect sequence/ACK')
                same(event['header'][2:4],[seq,action],'outer atomic effect identity')
                effects.append(q)
                self.atomic_receipts+=1
            elif event['kind']=='atomic-await':
                need(atomic,'sync-only atomic observer appeared in asynchronous transport')
                stage=event['header'][2]
                raw=self.native_blob(event['effect'])
                need(effects and raw==b'HIAATFX1'+struct.pack('<11Q',*effects[-1]),
                     'atomic barrier is not the exact last completed effect')
                same(event['header'][3],effects[-1][0],'atomic barrier last ACK sequence')
                action=effects[-1][1];err=effects[-1][7]
                names={1:'atomic_metadata',2:'atomic_write',3:'atomic_permissions',
                       4:'atomic_rename',5:'atomic_cleanup'}
                need(stage in names,'unknown native atomic await stage')
                if stage==1:
                    need(action in (1,2,3,10,11),'metadata barrier effect')
                    value={'ok':err==0}
                    if err:value['errno']=err
                    else:value['mode']=effects[-1][8]
                elif stage==2:
                    relevant=[q for q in effects if q[1] in (4,5)]
                    need(relevant,'write closure barrier lacks actual open/write')
                    errors=[q[7] for q in relevant if q[7]]
                    value={'ok':not errors}
                    if errors:value['errno']=errors[0]
                    else:value['bytes']=sum(q[6] for q in relevant if q[1]==5)
                else:
                    same(action,{3:7,4:8,5:9}[stage],'atomic await stage effect')
                    value={'ok':err==0}
                    if err:value['errno']=err
                result.append((names[stage],value))
        return result

    def lock_order(self,native,*,cancelled):
        events=[e for e in native['events'] if e['kind']=='child']
        lock_events=[e for e in events if e['slot']==18]
        completed=[]
        for event in lock_events:
            raw=self.native_blob(event['body'])
            need(len(raw)==64 and raw[:8]==b'HRFLKR01','complete actual lock response')
            op,status,lease,node,count,strong,woken=struct.unpack_from('<7Q',raw,8)
            same(op,{6:1,7:3,30:5,31:6}.get(event['phase']),'actual fixed lock operation/phase')
            need(status in (0,1,2),'actual lock status')
            if status==0:completed.append((event['phase'],lease,event['wire']['offset']))
        phases=[x[0] for x in completed]
        if completed:
            same(phases,[6,7,30,31],'acquire/poll/unlock/drop each actually completed once')
            need(completed[0][1]>0 and len(set(x[1] for x in completed))==1,
                 'actual lock lease changed within request')
            same([x[2] for x in completed],sorted(x[2] for x in completed),'actual lock response order')
            reads=[e for e in events if e['slot']==2 and e['phase']==10]
            if reads:
                need(len(reads)==1 and completed[1][2]<reads[0]['wire']['offset']<completed[2][2],
                     'first actual read was not protected by successful poll')
            uses=[e for e in events if (e['slot'],e['phase']) in ((3,16),(19,19),(8,23),(16,24))]
            need(all(completed[1][2]<e['wire']['offset']<completed[2][2] for e in uses),
                 'history/atomic/cache/diff escaped the held lease')
            need(completed[3][2]<native['result']['wire']['offset'],'terminal result preceded lock drop')
        else:
            need(not any(e['slot'] in (2,3,19) or (e['slot'],e['phase']) in ((8,23),(16,24))
                         for e in events),'actual read/write path has no completed canonical lock')
        scope_close=[e for e in events if e['slot']==6 and e['phase']==33]
        need(len(scope_close)==1 and scope_close[0]['wire']['offset']<native['result']['wire']['offset'],
             'actual terminal result lacks scope close/cancel')
        if completed:need(completed[-1][2]<scope_close[0]['wire']['offset'],'scope ended before lease retirement')
        drains=[e for e in events if e['slot']==6 and e['phase']==32]
        if native['result']['status']==0:
            need(len(drains)==1 and drains[0]['wire']['offset']<scope_close[0]['wire']['offset'],
                 'successful result lacks actual hint drain')
            if completed:need(completed[-1][2]<drains[0]['wire']['offset'],'hints drained before lock drop')
        else:need(not drains,'error/cancel unexpectedly drained hints')
        if cancelled:
            cancel=native['cancel']
            need(native['result']['wire']['offset']<cancel['late']['wire']['offset'],
                 'late worker retired before cancellation was observed')
            late_scope=[e for e in events if e['slot']==6 and e['phase']==91]
            need(len(late_scope)==1 and native['result']['wire']['offset']<
                 late_scope[0]['wire']['offset']<cancel['late']['wire']['offset'],
                 'late borrow lacks actual tombstone continuation retirement')
        self.checks+=1

    def stage_comparison(self,native_events,original_events,get,*,atomic):
        native=self.native_stages(native_events,atomic=atomic)
        original=[]
        current_write=None
        for kind,event in trace_reader.stage_observations(original_events):
            if kind=='history':continue
            if kind.startswith('atomic_') and not atomic:continue
            data=event['data']
            if kind=='exists':
                value={'ok':data['ok'],'value':data['value']}
            elif kind=='read':
                entered=[x for x in original_events if x['kind']=='read_enter' and x['marker']<event['marker']]
                need(entered,'original read wrapper has no actual entry')
                children=[x for x in original_events if x['kind']=='tokio_read_exit' and
                          entered[-1]['marker']<x['marker']<event['marker']]
                need(len(children)==1,'original local read lacks one complete actual Tokio result')
                child=children[0]['data']
                same(data['ok'],child['ok'],'read wrapper/actual Tokio success identity')
                value={'ok':data['ok']}
                if data['ok']:
                    same(get(data['body_blob']),get(child['body_blob']),'complete read wrapper/Tokio bytes')
                    value['body']=get(data['body_blob'])
                else:
                    # The unchanged PathSource wrapper formats an anyhow error,
                    # so its downcast errno is None. Preserve that record and
                    # compare the native errno with the actual nested OS result.
                    need(data['errno'] is None,'original formatted read error unexpectedly retained errno')
                    value['errno']=child['errno']
            elif kind=='atomic_metadata':
                value={'ok':data['ok']}
                value.update(mode=data['metadata']['mode']) if data['ok'] else value.update(errno=data['errno'])
            elif kind=='atomic_write':
                value={'ok':data['ok']}
                if data['ok']:
                    entered=[x for x in original_events if x['kind']=='tokio_write_enter' and x['marker']<event['marker']]
                    need(entered,'original write exit without full input')
                    value['bytes']=len(get(entered[-1]['data']['body_blob']))
                else:value['errno']=data['errno']
            elif kind.startswith('atomic_'):
                value={'ok':data['ok']}
                if not data['ok']:value['errno']=data['errno']
            elif kind=='note_write':value={}
            else:raise ValueError('unknown actual logical stage '+kind)
            original.append((kind,value))
        self.same(native,original,'actual ordered exists/read/atomic/cache boundaries')
        self.operation_boundaries+=len(original)

    def mutation_actions(self,row,meta,get):
        events=row['events']
        used=[i for i,value in enumerate(row['hook_used']) if value]
        need(all(type(v) is bool for v in row['hook_used']),'typed original hook markers')
        same(used,list(range(len(meta['hooks']))),'all declared original mutations executed')
        expected=[]
        for action in meta['initial']:expected.append(action)
        for event in events:
            if event['kind']=='mutation_begin':
                index=uint(event['data']['hook'],'actual mutation hook')
                need(index<len(meta['hooks']),'unbound mutation index')
                same(event['data']['event'],meta['hooks'][index]['event'],'original mutation boundary')
                expected.extend(meta['hooks'][index]['actions'])
        if meta['execution']=='async':
            base=meta['followup_blob_base']
            for action in meta['followup']['initial']:
                action=dict(action)
                if 'blob' in action:action['blob']+=base
                expected.append(action)
        enters=[e for e in events if e['kind']=='fixture_action_enter']
        exits=[e for e in events if e['kind']=='fixture_action_exit']
        same([e['data']['action'] for e in enters],expected,'complete executed fixture actions')
        same([e['data'] for e in enters],[e['data'] for e in exits],'every fixture action actually completed')
        cwd=bytes.fromhex(meta['fixture_cwd_hex'])
        for event in enters:
            action=event['data']['action']
            self.same(get(event['data']['path_blob']),cwd+b'/'+action['path'].encode(),
                      'exact actual fixture action pathname')
        begins=[e['data'] for e in events if e['kind']=='mutation_begin']
        ends=[e['data'] for e in events if e['kind']=='mutation_end']
        same(begins,ends,'complete actual mutation brackets')


def compare_partition(files,capture,native_rows,original_raw,original_records,input_rows,trace):
    reader=Comparison(files,capture)
    same(len(native_rows),len(original_records),'complete native/original row counts')
    same(len(original_records),len(input_rows),'complete input/output counts')
    evidence=[]
    all_markers=[]
    followups=0
    for native,record,input_record in zip(native_rows,original_records,input_rows):
        original=record['metadata'];meta=input_record['metadata'];case=meta['case_id']
        get=lambda index:blob(original_raw,record,index)
        fields(original,('kind','case_id','name','domain','sequence','session','canonical_parameters_blob',
            'result','before','after','request_context_present_after','original_sdk_executed',
            'original_outer_batch_method_executed','original_inner_execute_batch_edit_executed',
            'events','hook_used'),'complete original case fields')
        for name in ('case_id','name','domain','sequence','session'):
            same(original[name],meta[name],'original case input '+name)
            same(native[name],meta[name],'native case input '+name)
        need(original['kind']=='case' and original['original_inner_execute_batch_edit_executed'] is True and
             original['original_sdk_executed'] is False and original['original_outer_batch_method_executed'] is False,
             'original inner result scope changed')
        typed=reader.native_blob(native['typed'])
        need(len(typed)>=64 and typed[:8]==b'HBPRR002','actual typed input response')
        q=struct.unpack_from('<7Q',typed,8);status,path_len,json_len=q[:3]
        need(status==0 and path_len+json_len==len(typed)-64,'complete typed response layout')
        reader.same(typed[64+path_len:],get(original['canonical_parameters_blob']),
                    'actual complete typed projection')
        if meta['execution']=='sync':reader.lock_order(native,cancelled=False)
        else:
            same(native['events'],[],'asynchronous fixture does not emit per-child trace')
            same(native['io_counts'],{},'asynchronous fixture must not invent per-child counts')
        first,following=trace_reader.lifecycle(original,meta,get,trace)
        operations=trace_reader.operation_trace(trace,original['events'],get)
        reader.mutation_actions(original,meta,get)
        ni={};oi={}
        reader.states(native['before'],original['before'],get,'before',ni,oi)
        if meta['execution']=='sync':
            fields(original['result'],('ok','body_blob'),'complete original String result')
            reader.same(native['result']['status']==0,original['result']['ok'],'String success')
            body=reader.native_blob(native['result']['body'])
            reader.same(body,get(original['result']['body_blob']),'complete String body')
            reader.body_bytes+=len(body)
            reader.states(native['after'],original['after'],get,'after',ni,oi)
            reader.stage_comparison(native['events'],first,get,atomic=True)
        else:
            result=original['result'];cancel=native['cancel']
            fields(result,('after_cancel','after_late','barrier','cancelled','followup','late',
                           'normal_original_result_received'),'complete original cancel result')
            need(cancel is not None and result['cancelled'] is True and
                 result['normal_original_result_received'] is False,'actual cancelled result scope')
            reader.same(reader.native_blob(cancel['transfer']),get(result['late']['body_blob']),
                        'complete actual late worker transfer')
            reader.same(result['late']['bytes'],len(get(result['late']['body_blob'])),'actual late byte count')
            reader.states(native['after'],result['after_late'],get,'after_late',ni,oi)
            follow=cancel['followup'];other=result['followup']
            same(follow['events'],[],'async followup does not emit per-child trace')
            same(follow['io_counts'],{},'async followup must not invent per-child counts')
            fields(other,('canonical_parameters_blob','result'),'complete subordinate followup')
            ftyped=reader.native_blob(follow['typed']);fp=struct.unpack_from('<Q',ftyped,16)[0]
            reader.same(ftyped[64+fp:],get(other['canonical_parameters_blob']),'complete followup typed input')
            reader.same(follow['result']['status']==0,other['result']['ok'],'followup success')
            body=reader.native_blob(follow['result']['body'])
            reader.same(body,get(other['result']['body_blob']),'complete followup String body')
            reader.body_bytes+=len(body)
            reader.states(follow['after'],original['after'],get,'after_followup',ni,oi)
            need(native['result']['wire']['offset']<cancel['late']['wire']['offset']<
                 follow['result']['wire']['offset'],'actual cancel/late/followup transport order')
            followups+=1
        reader.same(native['hook_used'],[i for i,value in enumerate(original['hook_used']) if value],
                    'actual mutation execution order')
        markers=[event['marker'] for event in original['events']]
        need(markers==sorted(set(markers)),'unique original case event order')
        all_markers.extend(markers)
        evidence.append({'case_id':case,'original_record':record['record'],'original_events':len(markers),
            'actual_operations':operations,'complete_original_blobs':record['blobs'],
            'native_result':native['result']['body'],'cancelled':meta['execution']=='async',
            'native_per_child_lifetime_trace':meta['execution']=='sync'})
    same(all_markers,list(trace['markers']),'every actual marker belongs to one original case')
    lifetimes=trace_reader.descriptor_lifetimes(trace)
    return {'cases':len(evidence),'case_ids':[x['case_id'] for x in evidence],
        'post_cancel_followups':followups,'complete_comparisons':reader.checks,'full_body_bytes':reader.body_bytes,
        'complete_read_snapshot_bytes':reader.snapshot_bytes,'atomic_receipts':reader.atomic_receipts,
        'completed_operation_boundaries':reader.operation_boundaries,'case_evidence':evidence,
        'trace':{'bytes':trace['bytes'],'sha256':trace['sha256'],'lines':trace['line_count'],
                 'syscalls':len(trace['records']),'markers':len(trace['markers']),
                 'syscall_counts':dict(sorted(__import__('collections').Counter(x['name'] for x in trace['records']).items())),
                 'descriptor_lifetimes':lifetimes,'string_limit':128,'payloads_may_be_clipped':True}}

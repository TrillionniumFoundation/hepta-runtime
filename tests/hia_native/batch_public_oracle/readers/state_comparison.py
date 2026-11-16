"""Full retained Session/cache/History/locks and Unix-file projections."""
import stat,struct
from capture_format import need,same,fields,uint,sha,canonical
def word(raw,at):
 need(type(raw)is bytes and 0<=at<=len(raw)-8,'private state u64 boundary');return struct.unpack_from('<Q',raw,at)[0]
def native_history(raw):
 if not raw:return {'poisoned':False,'total_bytes':0,'order':[],'entries':{}}
 need(len(raw)>=64 and raw[:8]==b'HHISTA01'and word(raw,8)==1,'actual History header')
 used,count,queue,total,poison,end=struct.unpack_from('<6Q',raw,16)
 need(64<=end<=used<=len(raw)and poison in(0,1),'actual History extent/state')
 need(raw[used:]==bytes(len(raw)-used),'retired History storage')
 at=64;entries={};records=0;bytes_total=0
 while at<end:
  need(at+16<=end,'complete History record');kn,vn=struct.unpack_from('<2Q',raw,at);at+=16
  need(kn+vn<=end-at,'History record spans');key=raw[at:at+kn].decode();at+=kn;value=raw[at:at+vn];value.decode();at+=vn
  entries.setdefault(key,[]).append(value.hex());records+=1;bytes_total+=vn
  need(len(entries[key])<=10,'original per-key History limit')
 same(records,count,'actual History snapshot count');same(bytes_total,total,'actual History byte total')
 order=[]
 for _ in range(queue):
  n=word(raw,at);at+=8;need(n<=used-at,'actual History queue span');order.append(raw[at:at+n].decode());at+=n
 same(at,used,'complete History queue bytes')
 return {'poisoned':bool(poison),'total_bytes':total,'order':order,'entries':entries}
def original_history(value,get):
 fields(value,('poisoned','total_bytes','order','entries'),'complete original History')
 need(type(value['poisoned'])is bool and type(value['order'])is list,'actual original History types')
 entries={}
 for e in value['entries']:
  fields(e,('key_blob','values'),'original History entry');key=get(e['key_blob']).decode();need(key not in entries,'duplicate History key')
  entries[key]=[get(x).hex()for x in e['values']]
 same(sum(len(bytes.fromhex(x))for values in entries.values()for x in values),uint(value['total_bytes'],'actual History total'),'full original History body total')
 return {'poisoned':value['poisoned'],'total_bytes':value['total_bytes'],'order':value['order'],'entries':entries}
def native_locks(raw):
 if not raw:return {'initialized':False,'poisoned':False,'entries':{}}
 need(len(raw)>=256 and raw[:8]==b'HFLSTATE'and word(raw,8)==1,'actual lock arena header')
 used=word(raw,16);need(256<=used<=len(raw)and used%16==0,'actual lock used extent')
 need(word(raw,64)==word(raw,72)==0,'completed request retained lock lease')
 at=word(raw,32);count=word(raw,40);entries={};seen=set();identities=set()
 while at:
  need(at not in seen and at%16==0 and 272<=at<=used-80,'actual lock map node')
  seen.add(at);need(raw[at:at+8]==b'HFLNODE1','actual lock node magic')
  identity=word(raw,at+8);need(identity>0 and identity not in identities,'unique actual node identity');identities.add(identity)
  refs=word(raw,at+24);n=word(raw,at+32)
  need(n<=used-at-80,'complete actual lock key');key=raw[at+80:at+80+n].decode()
  need(key not in entries,'duplicate actual lock key')
  need(refs==0 and word(raw,at+48)==word(raw,at+56)==word(raw,at+64)==0,'actual lock remained held/queued at completion')
  entries[key]={'available':True,'strong_count':1};at=word(raw,at+16)
 same(len(entries),count,'actual retained lock map count')
 need(raw[used:]==bytes(len(raw)-used),'lock arena trailing storage')
 return {'initialized':True,'poisoned':False,'entries':entries}
def session(value,get):
 fields(value,('root_blob','current_blob','effective_blob','poisoned','latched'),'complete original Session')
 need(type(value['poisoned'])is bool and type(value['latched'])is bool,'typed original Session state')
 return {'root_hex':get(value['root_blob']).hex(),'current_hex':None if value['current_blob']is None else get(value['current_blob']).hex(),'effective_hex':get(value['effective_blob']).hex(),'poisoned':value['poisoned'],'session_applied':value['latched']}
def original_trees(values,get):
 out=[]
 for value in values:
  fields(value,('root_blob','nodes'),'complete original file tree');rows=[]
  for n in value['nodes']:
   path=bytes.fromhex(n['relative_hex']);need(b'\0'not in path,'actual relative Unix path');r={'relative_hex':n['relative_hex']}
   if 'error'in n:r['errno']=n['error']['errno']
   else:
    m=n['metadata'];r.update(device=m['dev'],inode=m['ino'],mode=m['mode'],uid=m['uid'],gid=m['gid'],links=m['nlink'],size=m['size'],mtime=m['mtime'],ctime=m['ctime'])
    if 'target_hex'in n:r['target_hex']=n['target_hex']
    if 'content'in n:
     if n['content']['ok']:r['content_hex']=get(n['content']['blob']).hex()
     else:r['read_errno']=n['content']['errno']
    if 'readdir_error'in n:r['readdir_errno']=n['readdir_error']['errno']
   rows.append(r)
  out.append({'root_hex':get(value['root_blob']).hex(),'nodes':rows})
 return out
def incarnation_snapshots(sequence):
 """Retain aliases/moves; inode reuse after complete absence starts a new object."""
 previous={};next_id=0;out=[];reused=[];seen={}
 for ordinal,trees in enumerate(sequence):
  current={};result=[]
  for tree in trees:
   root=bytes.fromhex(tree['root_hex']);need(root.startswith(b'/'),'actual absolute fixture root');nodes=[];paths=[]
   for node in tree['nodes']:
    value=dict(node);path=bytes.fromhex(value['relative_hex']);paths.append(path)
    if 'inode'in value:
     for k in('device','inode','mode','uid','gid','links','size'):uint(value[k],'actual Unix metadata '+k)
     key=(value.pop('device'),value.pop('inode'),stat.S_IFMT(value['mode']))
     if key not in current:
      if key in previous:current[key]=previous[key]
      else:
       current[key]=next_id;next_id+=1
       if key in seen:reused.append({'observation':ordinal,'device':key[0],'inode':key[1],'kind':key[2],'previous_identity':seen[key],'new_identity':current[key]})
      seen[key]=current[key]
     value['identity']=current[key];value.pop('mtime');value.pop('ctime')
     if stat.S_ISDIR(value['mode']):value.pop('size')
     if 'content_hex'in value:same(len(bytes.fromhex(value['content_hex'])),value['size'],'complete file content size')
    nodes.append(value)
   need(len(paths)==len(set(paths)),'duplicate relative fixture path')
   result.append({'root_hex':tree['root_hex'],'nodes':nodes})
  previous=current;out.append(result)
 return out,reused
def terminal_native_state(state,read_blob):
 b=state['batch'];v=b['fields'];raw={k:read_blob(x)for k,x in b['sections'].items()}
 for k,x in v.items():uint(x,'actual Batch observer '+k)
 need(v['worker_pid']==v['session_borrowers']==v['pending_target']==v['caller_phase']==v['retired']==0,'terminal Batch worker/borrow/pending lifecycle')
 if v['flags']&2:
  same(v['flags'],15,'actual bound cache/lease aliases');same(v['binding_phase'],4,'actual bound terminal phase')
  same((len(raw['context']),len(raw['scope']),len(raw['lease'])),(64,256,256),'actual Batch lifecycle prefix extents')
  same(raw['context'],bytes(64),'task-local context escaped completed public request')
  need(raw['scope'][:8]==b'HRSCST01'and word(raw['scope'],8)==1 and word(raw['scope'],24)==0 and word(raw['scope'],64)==0,'actual Batch scope remained active')
  need(raw['lease'][:8]==b'HRCLST01'and word(raw['lease'],8)==1 and word(raw['lease'],24)==1,'actual shared cache lease owner lifetime')
  same(raw['lease'],read_blob(state['view']['sections']['lease']),'actual same View/Batch lease arena bytes')
  need(raw['caller'][:8]==b'HBCWS002'and word(raw['caller'],8)==0 and word(raw['caller'],112)==word(raw['caller'],120)==0,'terminal caller retained lock/phase')
  same(word(raw['caller'],48),v['caller_used'],'caller actual used bytes')
 else:
  need(v['flags']in(0,1)and v['binding_phase']==0,'uncreated Batch owner was invoked by observation')
  need(not raw['caller']and not raw['context']and not raw['scope']and not raw['lease'],'uncreated binding retained private request state')
 return native_history(raw['history']),native_locks(raw['locks'])

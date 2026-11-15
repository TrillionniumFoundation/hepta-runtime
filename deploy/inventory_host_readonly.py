# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bounded read-only archive inspector. Terminal receipt != complete archived output.

No file content from stdout/stderr, credentials, arbitrary process argv or env is
returned. Missing/corrupt metadata is never converted to success or empty inventory.
"""
import os,stat,json,pathlib,time,hashlib,re,collections
CAP=1024*1024
SCHEMA="hepta-readonly-inventory-host-v1"
class Refusal(Exception):pass

def strict_json(raw):
 def pairs(xs):
  d={}
  for k,v in xs:
   if k in d:raise Refusal('duplicate_json_key')
   d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Refusal('invalid_json_constant')))
def version(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_uid,s.st_mode,s.st_nlink)
def open_directory(path, observe_group_writable=False):
 p=pathlib.PurePosixPath(path)
 if not p.is_absolute() or '..' in p.parts:raise Refusal('invalid_absolute_root')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for name in p.parts[1:]:
   n=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=n
  s=os.fstat(fd)
  if s.st_uid!=os.getuid() or s.st_mode&0o002 or (s.st_mode&0o020 and not observe_group_writable):raise Refusal('root_owner_or_write_mode')
  return fd
 except BaseException:os.close(fd);raise

def read_record(dfd,name,budget):
 if '/' in name or name in ('.','..'):raise Refusal('invalid_leaf')
 fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=dfd)
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_uid!=os.getuid() or a.st_mode&0o077 or a.st_nlink!=1 or a.st_size>CAP:raise Refusal('metadata_shape_or_mode')
  budget[0]+=a.st_size
  if budget[0]>64*1024*1024:raise Refusal('metadata_total_byte_limit')
  buf=bytearray()
  while len(buf)<a.st_size:
   b=os.read(fd,min(65536,a.st_size-len(buf)))
   if not b:break
   buf.extend(b)
  if len(buf)!=a.st_size or version(a)!=version(os.fstat(fd)) or version(a)!=version(os.stat(name,dir_fd=dfd,follow_symlinks=False)):raise Refusal('metadata_changed')
  v=strict_json(buf)
  if not isinstance(v,dict):raise Refusal('metadata_not_object')
  return v,hashlib.sha256(buf).hexdigest()
 finally:os.close(fd)
def optional(dfd,name,budget):
 try:return read_record(dfd,name,budget)
 except FileNotFoundError:return None,None

def integer(x):return type(x) is int and -2147483648<=x<=2147483647

def terminal_receipt(kind,req,final,log_sizes):
 if not isinstance(final,dict) or not integer(final.get('exit_code')):raise Refusal('invalid_exit_code')
 if kind=='jobs':
  if type(final.get('cancelled')) is not bool or type(final.get('timed_out')) is not bool:raise Refusal('invalid_exit_flags')
  state='cancelled' if final['cancelled'] else 'timed_out' if final['timed_out'] else 'succeeded' if final['exit_code']==0 else 'failed'
  complete=final.get('output_complete') is True
  maps=[final.get(k,{}) for k in ('log_bytes','log_truncated','log_errors')]
  if not all(isinstance(v,dict) for v in maps):raise Refusal('invalid_output_maps')
  for label in ['stdout','stderr']:
   counts=maps[0].get(label,{})
   if not isinstance(counts,dict):raise Refusal('invalid_output_counts')
   if (type(counts.get('seen')) is not int or type(counts.get('stored')) is not int or
       counts.get('seen')!=counts.get('stored') or counts.get('stored')!=log_sizes.get(label) or
       final.get('log_truncated',{}).get(label) is not False or final.get('log_errors',{}).get(label,'missing') is not None):complete=False
 else:
  if final.get('state')!='exited':raise Refusal('invalid_terminal_state')
  state='exited'
  complete=(final.get('output_complete') is True and final.get('capture_error','missing') is None and
            type(final.get('bytes_stored')) is int and type(final.get('bytes_seen')) is int and
            final['bytes_stored']==final['bytes_seen']==log_sizes.get('output'))
 return {'state':state,'exit_code':final['exit_code'],'output_verified_by_size_and_receipt':complete,'content_hash_verified':False}

def bounded_names(fd,limit=16384):
 names=[]
 with os.scandir(fd) as entries:
  for entry in entries:
   if len(names)>=limit:raise Refusal('directory_entry_limit')
   names.append(entry.name)
 return sorted(names)
def log_stat(fd,name):
 try:
  s=os.stat(name,dir_fd=fd,follow_symlinks=False)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_nlink!=1 or s.st_mode&0o022:raise Refusal('unsafe_log_metadata')
  return s.st_size
 except FileNotFoundError:return None

def observe_host(q):
 rows=q['rows'];assert len(rows)<=16384 and q['platform'] in ('linux','macos')
 root=q['root'];fd=open_directory(root,observe_group_writable=True);root_mode=os.fstat(fd).st_mode&0o7777;start=time.monotonic();budget=[0];results=[];members={};names_before={};issues=[]
 try:
  for kind in ['jobs','terminals']:
   try:
    d=os.open(kind,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
    try:names_before[kind]=bounded_names(d)
    finally:os.close(d)
   except FileNotFoundError:names_before[kind]=[]
  for r in rows:
   out={'id':r['id'],'kind':r['kind']};results.append(out)
   try:
    if time.monotonic()-start>85:raise Refusal('host_budget_exhausted')
    kind=r['kind'];rid=r['id'];pattern=r'[0-9a-f]+-[0-9a-f]+-[0-9a-f]+' if kind=='jobs' else r'dpty-[A-Za-z0-9-]{1,91}'
    if kind not in ('jobs','terminals') or re.fullmatch(pattern,rid) is None:raise Refusal('invalid_identity')
    kfd=os.open(kind,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
    try:jfd=os.open(rid,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=kfd)
    finally:os.close(kfd)
    try:
     ds=os.fstat(jfd)
     if ds.st_uid!=os.getuid() or ds.st_mode&0o077:raise Refusal('job_directory_not_private')
     req,rsha=read_record(jfd,'request.json',budget)
     if req.get('job_id' if kind=='jobs' else 'session_id')!=rid:raise Refusal('request_identity_mismatch')
     if kind=='jobs' and (type(req.get('request_fingerprint')) is not str or req['request_fingerprint']!=r['fingerprint']):raise Refusal('request_binding_mismatch')
     final,fsha=optional(jfd,'exit.json',budget)
     started,ssha=optional(jfd,'started.json',budget)
     out['request_bound']=True;out['receipt_sha256']=fsha
     if final is not None:
      logs={x:log_stat(jfd,x+'.log') for x in (['stdout','stderr'] if kind=='jobs' else ['output'])}
      out.update(terminal_receipt(kind,req,final,logs))
     else:
      out.update(state='nonterminal_or_missing_receipt',output_verified_by_size_and_receipt=False)
      if isinstance(started,dict):
       pid=started.get('supervisor_pid' if kind=='jobs' else 'owner_pid')
       if type(pid) is int and 1<pid<2147483647:out['recorded_owner_pid']=pid
     # No all-file-atomic claim: each metadata read must remain the same at final reread.
     _,r2=read_record(jfd,'request.json',budget);f2,h2=optional(jfd,'exit.json',budget)
     if r2!=rsha or h2!=fsha:raise Refusal('request_or_exit_changed')
     leaf=os.stat(root+'/'+kind+'/'+rid,follow_symlinks=False)
     if (leaf.st_dev,leaf.st_ino)!=(ds.st_dev,ds.st_ino):raise Refusal('job_directory_replaced')
    finally:os.close(jfd)
   except (OSError,ValueError,Refusal,KeyError,TypeError) as ex:
    out.clear();out.update(id=r['id'],kind=r['kind'],state='unknown',reason=str(ex) if isinstance(ex,Refusal) else type(ex).__name__,output_verified_by_size_and_receipt=False)
  for kind in ['jobs','terminals']:
   try:
    d=os.open(kind,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
    try:names_after=bounded_names(d)
    finally:os.close(d)
   except FileNotFoundError:names_after=[]
   wanted={r['id'] for r in rows if r['kind']==kind}
   members[kind]={'before_count':len(names_before[kind]),'after_count':len(names_after),'names_stable':names_before[kind]==names_after,
                  'referenced_missing':sorted(wanted-set(names_after)),'unreferenced_present':sorted(set(names_after)-wanted)}
  z=os.stat(root,follow_symlinks=False);a=os.fstat(fd)
  if (a.st_dev,a.st_ino)!=(z.st_dev,z.st_ino):raise Refusal('host_root_replaced')
 finally:os.close(fd)
 return {'schema':SCHEMA,'host':q['host'],'root_mode':oct(root_mode),'root_group_writable':bool(root_mode&0o020),'source_root_integrity_qualified':False,'observation_only_not_authorization':True,'rows':results,'members':members,'metadata_bytes_read':budget[0],'elapsed_seconds':round(time.monotonic()-start,3),'live_process_state_qualified':False,'atomic_snapshot':False,'job_log_contents_read':False,'metadata_scan_finished':len(results)==len(rows) and not any(v.get('reason') in ('host_budget_exhausted','metadata_total_byte_limit') for v in results),'all_records_resolved':all(v['state'] not in ('unknown','nonterminal_or_missing_receipt') for v in results)}
if __name__=='__main__':
 import sys
 request=sys.stdin.buffer.read(8*1024*1024+1)
 if len(request)>8*1024*1024:raise Refusal('input_limit')
 result=observe_host(strict_json(request));raw=json.dumps(result,separators=(',',':')).encode()
 if len(raw)>8*1024*1024:raise Refusal('response_limit')
 sys.stdout.buffer.write(raw)

import errno,fcntl,json,os,tempfile
checks=[]
def run_case(explicit_unlock):
 with tempfile.TemporaryDirectory(prefix='hepta-v9-lock-inheritance-independent-') as root:
  os.chmod(root,0o700)
  path=root+'/metadata.lock'
  held=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
  fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
  ready_r,ready_w=os.pipe()
  release_r,release_w=os.pipe()
  child=os.fork()
  if child==0:
   os.close(ready_r);os.close(release_w)
   os.write(ready_w,b'R')
   os.read(release_r,1)
   os._exit(0)
  os.close(ready_w);os.close(release_r)
  try:
   assert os.read(ready_r,1)==b'R'
   if explicit_unlock: fcntl.flock(held,fcntl.LOCK_UN)
   os.close(held);held=None
   candidate=os.open(path,os.O_RDWR|os.O_CLOEXEC)
   inode_same=os.fstat(candidate).st_ino==os.stat(path).st_ino
   try:
    fcntl.flock(candidate,fcntl.LOCK_EX|fcntl.LOCK_NB)
    acquired=True;err=None
   except OSError as exc:
    acquired=False;err=exc.errno
   assert acquired==explicit_unlock, (explicit_unlock,acquired,err)
   if not explicit_unlock: assert err in (errno.EAGAIN,errno.EWOULDBLOCK)
   assert inode_same
   os.close(candidate)
   checks.append({'explicit_unlock_before_parent_close':explicit_unlock,'child_still_holds_inherited_open_file_description':True,'same_lock_inode':inode_same,'new_descriptor_acquired_before_child_release':acquired,'errno':err})
  finally:
   if held is not None: os.close(held)
   os.write(release_w,b'X');os.close(release_w);os.close(ready_r)
   pid,status=os.waitpid(child,0)
   assert pid==child and status==0
 print('',end='')
run_case(False)
run_case(True)
print(json.dumps({'schema':'hepta-v9-independent-lock-inheritance-proof-v1','checks':checks,'owned_children_reaped':True,'owned_temp_directories_removed':True,'source_modified':False,'production_services_changed':False},sort_keys=True))

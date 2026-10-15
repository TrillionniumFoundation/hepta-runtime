import pathlib,hashlib,os,stat,sys,types
p=pathlib.Path('/home/qian-qi/hepta-runtime-operation-v10-20261013/tests/dc_functional_v10_operation_umask_causal_tests_r2.py')
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
try:
 a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=1048576
 raw=b''
 while len(raw)<=a.st_size:
  b=os.read(fd,a.st_size+1-len(raw))
  if not b:break
  raw+=b
 fields=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 assert len(raw)==a.st_size and fields(a)==fields(os.fstat(fd))==fields(p.lstat()) and hashlib.sha256(raw).hexdigest()=='a03f3f94f867e0ec8df8ab5024ac7a50415bfa10f1c6ea0f08f717326ae1264d'
finally:os.close(fd)
m=types.ModuleType('__main__');m.__file__=str(p);sys.modules['__main__']=m
sys.argv=[str(p),'--repo-root','/home/qian-qi/hepta-runtime-v10-code-frozen-37e56f8-20261014','--binary','/home/qian-qi/hepta-runtime-v10-root-pinned-native-757ef1-20261014-r1/hepta-runtime-debug','--expected-binary-sha256','757ef140732744e4c29d50e615375d3bb300b6288c520d741bd6a3ed8f0813bd','--expected-source-fingerprint','498cca6da8c442c70534b0a35807c94d7b5f7fbef4b2b4d8f15fa9c22484e33c','--expected-head','37e56f8d24b7aec8519c46b8ec19911c17ea07f7','--new-harness','/home/qian-qi/hepta-runtime-operation-v10-20261013/tests/dc_functional_v10_operation_explicit_state_acceptance.py','--expected-new-harness-sha256','22837c70f1fa9deb093eda82233c22c496a20617c1baeca545a96e7a235cf6e5','--out','/home/qian-qi/hepta-runtime-operation-v10-20261013/docs/qualification/dc-functional-v10-operation-candidate-20261013/ci-private-state-umask-r3-native-causal']
exec(compile(raw,str(p),'exec'),m.__dict__)

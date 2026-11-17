"""Fixed descriptor duplication immediately followed by the actual target exec."""
import fcntl,os,sys
original=[int(x) for x in sys.argv[1:4]]
copies=[fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,100) for fd in original]
for target,source in zip((3,4,5),copies,strict=True):os.dup2(source,target,inheritable=True)
for fd in set(original+copies):
    if fd not in (3,4,5):os.close(fd)
binary=sys.argv[4]
os.execve(binary,sys.argv[4:],{"PATH":"","LC_ALL":"C"})

"""Real descriptor layout and RLIMIT, matching the independent original observer."""
import errno,fcntl,os,resource
from common import require
ROOT_FIRST=512
def absent(fd):
    try:fcntl.fcntl(fd,fcntl.F_GETFD)
    except OSError as e:require(e.errno==errno.EBADF,"actual absent descriptor");return True
    return False
def reserve():
    require(all(absent(fd)for fd in list(range(32,320))+list(range(512,772))),"owned pool/root slots are absent")
    base=os.open("/dev/null",os.O_RDONLY|os.O_CLOEXEC)
    require(3<=base<32,"reservation outside kernel descriptor pool")
    for fd in range(3,32):
        if absent(fd):os.dup2(base,fd,inheritable=False)
    return dict(pool_first=32,pool_end=320,root_first=512,root_end=772)
def open_root(path,index):
    require(type(index)is int and 0<=index<260,"fixed owned root index")
    to=ROOT_FIRST+index;require(absent(to),"no replacement of live root descriptor")
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC)
    try:
        require(32<=fd<320,"actual transient root within free pool")
        os.dup2(fd,to,inheritable=False)
    finally:os.close(fd)
    return to
def clear():require(all(absent(fd)for fd in list(range(32,320))+list(range(512,772))),"all actual case-owned descriptors closed")
def limit():return resource.getrlimit(resource.RLIMIT_NOFILE)
def set_limit(soft,hard):resource.setrlimit(resource.RLIMIT_NOFILE,(soft,hard))

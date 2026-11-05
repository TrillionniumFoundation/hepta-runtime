import json, os, stat
parent = "/Users/qianqi/work"
names = ("hepta-runtime-r29-mac-companion-tools-01", "hepta-runtime-r29-mac-companion-inputs-01")
uid = os.geteuid()
if os.path.realpath(parent) != parent:
    raise RuntimeError("fixed parent must be direct")
p = os.lstat(parent)
if not stat.S_ISDIR(p.st_mode) or p.st_uid != uid:
    raise RuntimeError("fixed parent must be an owned directory")
fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
created = []
try:
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino, opened.st_uid) != (p.st_dev, p.st_ino, uid):
        raise RuntimeError("fixed parent identity changed")
    for name in names:
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("both fixed directories must be absent")
    for name in names:
        os.mkdir(name, 0o700, dir_fd=fd)
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            s = os.fstat(child)
            linked = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(s.st_mode) or s.st_uid != uid or stat.S_IMODE(s.st_mode) != 0o700 or (s.st_dev, s.st_ino) != (linked.st_dev, linked.st_ino):
                raise RuntimeError("new fixed directory failed ownership, mode or identity check")
            created.append({"path": parent + "/" + name, "uid": s.st_uid, "mode": stat.S_IMODE(s.st_mode), "device": s.st_dev, "inode": s.st_ino})
        finally:
            os.close(child)
    after = os.lstat(parent)
    if (after.st_dev, after.st_ino, after.st_uid) != (p.st_dev, p.st_ino, uid):
        raise RuntimeError("fixed parent changed during creation")
finally:
    os.close(fd)
print(json.dumps({"schema": "hepta-r29-mac-companion-staging-directories/v1", "created": created, "collector_executed": False, "services_modified": False}, sort_keys=True), flush=True)

"""Pure fixed native transport layout; definitions never load or execute code."""
import struct
from common import require

CONTEXT_BYTES = 98304
OFFSETS = dict(caps=256, table=640, owner_work=1024, owner_out=33824,
               json_work=42048, json_out=50272, ack=54400, owner_in=58784,
               scratch=63168, json_in=87776, observation=92224)
FUNCTIONS = ("__errno_location", "openat", "fstat", "geteuid", "read", "write",
             "fsync", "close", "linkat", "unlinkat", "renameat", "fcntl",
             "fdopendir", "readdir", "closedir", "fstatat", "pread", "syscall", "open", "poll")

def capabilities(raw):
    require(len(raw) == 384, "complete native capability table")
    values = {}
    actual = {}
    for at in range(0, len(raw), 24):
        token, kind, descriptor = struct.unpack_from("<3Q", raw, at)
        if not token:
            require(kind == descriptor == 0, "empty capability slot is wholly empty")
            continue
        require(token not in values and kind in (1, 2), "unique actual capability token")
        require((kind == 1 and descriptor <= 0x7fffffff) or
                (kind == 2 and descriptor > 0), "actual native descriptor kind")
        values[str(token)] = "file" if kind == 1 else "directory"
        actual[str(token)] = dict(slot=at // 24, kind=kind, actual=descriptor)
    require(values.get("1") == "file" and actual["1"]["slot"] == 0, "borrowed root slot")
    return values, actual


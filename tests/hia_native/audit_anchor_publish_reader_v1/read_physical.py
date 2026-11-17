"""Exact physical journals, including every unused byte, guard, and final footer."""
import gzip
import struct
from common import loads, pin, read, require
from callable_contract import CONTEXT_BYTES


class Physical:
    def __init__(self, path, marker):
        self.raw = path.open("rb")
        self.file = gzip.GzipFile(fileobj=self.raw, mode="rb")
        self.count = 0
        self.logical_bytes = 0
        require(self.exact(8) == marker, "complete physical journal header")

    def exact(self, size):
        require(type(size) is int and 0 <= size <= 1 << 24, "bounded complete physical record")
        raw = self.file.read(size)
        require(len(raw) == size, "complete physical journal extent")
        self.logical_bytes += size
        return raw

    def end(self, marker):
        require(self.exact(8) == marker and struct.unpack("<Q", self.exact(8))[0] == self.count and
                not self.file.read(1), "all physical records and complete gzip/footer")
        self.close()
        return dict(records=self.count, logical_bytes=self.logical_bytes)

    def close(self):
        try:
            self.file.close()
        finally:
            self.raw.close()


class Outer(Physical):
    def __init__(self, folder):
        self.rows = loads(read(folder / "OUTER.json"))
        require(type(self.rows) is list, "actual complete outer call receipts")
        super().__init__(folder / "outer.bin.gz", b"AIOTOP01")

    def call(self, case, step, kind):
        require(self.count < len(self.rows) and self.exact(8) == b"AIOENT01", "every actual outer invocation")
        index, ci, si, typ, returned, ni, no, nw, nt, gi, go, gw = struct.unpack("<12Q", self.exact(96))
        require((index, ci, si, typ, nw, nt, gi, go, gw) ==
                (self.count, case, step, kind, CONTEXT_BYTES, 168, 16 if kind == 1 else 0,
                 16 if kind == 1 else 0, 16) and
                ((kind == 1 and 128 <= ni <= 4352 and no == 8192) or
                 (kind in (0, 2) and ni == no == 0)), "fixed complete callable spans")
        sizes = (ni + gi, no + go, nw + gw, nt)
        before = [self.exact(n) for n in sizes]
        after = [self.exact(n) for n in sizes]
        row = self.rows[index]
        require(row == dict(index=index, case=ci, step=si, kind=typ, returned=returned,
                input_bytes=ni, output_capacity=no, context_capacity=nw, table_bytes=nt,
                guards=[gi, go, gw], elapsed_ns=row["elapsed_ns"], args=row["args"],
                before=[pin(x) for x in before], after=[pin(x) for x in after]) and
                type(row["elapsed_ns"]) is int and row["elapsed_ns"] >= 0,
                "complete outer buffers and exact actual receipt")
        require(before[2][nw:] == after[2][nw:] == b"\x5a" * 16 and before[3] == after[3],
                "whole immutable libc table and context guard")
        self.count += 1
        return row, before, after

    def finish(self, expected):
        require(self.count == len(self.rows) == expected, "all actual init/run/dispose calls")
        return self.end(b"AIOTEND1")


class Boundaries(Physical):
    def __init__(self, folder):
        self.rows = loads(read(folder / "BOUNDARIES.json"))
        require(type(self.rows) is list, "all actual native boundary receipts")
        super().__init__(folder / "boundaries.bin.gz", b"AIOFXLOG")

    def call(self, case, step):
        require(self.count < len(self.rows) and self.exact(8) == b"AIOFX001", "every actual filesystem boundary")
        raw_header = self.exact(96)
        index, ci, si, category, ni, no, nw, gi, go, gw, nd0, nd1 = struct.unpack("<12Q", raw_header)
        require((index,ci,si)==(self.count,case,step), "exact ordered boundary identity")
        if category==3:
            require((no,nw,gi,go,gw)==(4352,384,16,16,0) and 128<=ni<=8192 and nd0 in (0,8,144) and nd1 in (0,8,144),
                    "complete ordinary anchor filesystem boundary")
        else:
            require(category==4 and (ni,no,nw,gi,go,gw,nd0,nd1)==(24,0,384,0,0,0,0,0),
                    "complete native dispose boundary")
        before_record = self.exact(128)
        after_record = self.exact(128)
        sizes = (ni + gi, no + go, nw + gw)
        before = [self.exact(n) for n in sizes]
        after = [self.exact(n) for n in sizes]
        detail_before, detail_after = self.exact(nd0), self.exact(nd1)
        complete = (before_record + after_record + b"".join(before + after) +
                    detail_before + detail_after)
        row = self.rows[index]
        require(row == dict(index=index, case=ci, step=si, category=category,
                input_bytes=ni, output_capacity=no, workspace_capacity=nw, guards=[gi, go, gw],
                before_record=pin(before_record), after_record=pin(after_record),
                before=[pin(x) for x in before], after=[pin(x) for x in after],
                detail_before=pin(detail_before), detail_after=pin(detail_after),
                elapsed_ns=row["elapsed_ns"], complete_record=pin(raw_header + complete)) and
                type(row["elapsed_ns"]) is int and row["elapsed_ns"] >= 0,
                "every raw native boundary record and byte is bound")
        require((category==4 or before[0]==after[0]) and (category==4 or before[1][4352:]==after[1][4352:]==b"\x5a"*16), "complete boundary input and guard")
        self.count += 1
        return dict(before_record=before_record, after_record=after_record, before=before, after=after,
                    detail_before=detail_before, detail_after=detail_after)

    def finish(self):
        require(self.count == len(self.rows), "no omitted or extra actual filesystem boundaries")
        return self.end(b"AIOFXEND")

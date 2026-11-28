"""Complete acquisition-order index around the unchanged physical buffer store."""
from evidence_common import encoded
from buffer_store import Writer
class CaptureStore:
    def __init__(self,root):
        self.writer=Writer(root);self.index=(root.parent/"buffer-index.jsonl").open("xb")
    @property
    def images(self):return self.writer.images
    @property
    def logical_bytes(self):return self.writer.logical_bytes
    @property
    def known(self):return self.writer.known
    def put(self,raw):
        row=self.writer.put(raw);self.index.write(encoded(row));self.index.flush();return row
    def close(self):
        if not self.index.closed:self.index.close()

"""Only the native process's final EOF witness is permitted in direct-leaf trials."""
import struct
from evidence_common import require
class EOFHooks:
    def __init__(self,carrier,store):
        self.carrier=carrier;self.store=store;self.rows=[]
    def consume(self,raw):
        require(len(raw)==64 and raw[:8]==b"HMRDEOF1" and raw[8:]==bytes(56),
            "direct leaf emitted a body effect, live orphan, or invalid EOF")
        require(not self.rows,"duplicate native EOF witness")
        observed=self.carrier.observed_process()
        ack=bytes(8)
        self.rows.append(dict(raw=self.store.put(raw),ack=self.store.put(ack),observed=observed))
        return ack

"""Pure exact-byte native callable composition; no dynamic execution."""
import struct
from common import pin, require


def inputs(owner, codec, composition):
    require(pin(owner) == composition["owner"] and pin(codec) == composition["json"],
            "both qualified semantic HIA images")
    adapter = bytes.fromhex(composition["adapter_hex"])
    require(pin(adapter) == composition["adapter"], "complete mechanical adapter bytes")
    offsets = composition["offsets"]
    require(offsets["entry"] == 0 and offsets["owner"] == len(adapter) and
            offsets["json"] == len(adapter) + len(owner) and
            offsets["end"] == composition["image_bytes"] == len(adapter) + len(owner) + len(codec) and
            0 < offsets["initialize"] < offsets["dispose"] < offsets["owner"],
            "all native export and semantic-image offsets")
    request = b"HAIOPK01" + struct.pack("<3Q", 1, len(owner), len(codec)) + owner + codec
    return request, adapter + owner + codec


def cases(wire, size):
    return [
        ("valid", wire, size + 64, size),
        ("empty", b"", size + 64, 0xffffffff),
        ("short", wire[:-1], size + 64, 0xffffffff),
        ("long", wire + b"\0", size + 64, 0xffffffff),
        ("magic", b"X" + wire[1:], size + 64, 0xffffffff),
        ("version", wire[:8] + struct.pack("<Q", 2) + wire[16:], size + 64, 0xffffffff),
        ("owner-size", wire[:16] + struct.pack("<Q", 295102) + wire[24:], size + 64, 0xffffffff),
        ("json-size", wire[:24] + struct.pack("<Q", 161259) + wire[32:], size + 64, 0xffffffff),
        ("capacity", wire, size - 1, 0xfffffffe),
    ]

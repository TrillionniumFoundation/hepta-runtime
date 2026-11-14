"""Verify the complete static authority ELF against its pinned HIA pack input.

This verifier executes no native code. It checks the bytes reached through the
actual metadata pointer, rather than accepting descriptor hashes on trust.
"""
from __future__ import annotations

import hashlib
import struct

SCHEMA = "hepta.runtime.authority-embedded-layout.v1"
WORK_START = 16982016
MEMBER_COUNT = 9


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require(condition, reason):
    if not condition:
        raise ValueError("authority ELF layout: " + reason)


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _words(raw, at, count):
    _require(_integer(at, 0, len(raw)) and count * 8 <= len(raw) - at,
             "truncated word record")
    return struct.unpack_from("<" + str(count) + "Q", raw, at)


def validate_authority_layout(executable: bytes, frame: bytes,
                              profile: dict, provenance: dict) -> dict:
    _require(type(executable) is bytes and type(frame) in (bytes, bytearray),
             "input must be immutable executable bytes and a bounded frame")
    _require(176 <= len(executable) <= 8 << 20 and 32 <= len(frame) <= 8 << 20,
             "executable or frame length is outside the native packer domain")
    _require(executable[:16] == b"\x7fELF\x02\x01\x01" + bytes(9), "ELF identity differs")
    header = struct.unpack_from("<HHI3QI6H", executable, 16)
    _require(header == (2, 62, 1, 0x4000B0, 64, 0, 0, 64, 56, 2, 0, 0, 0),
             "static x86-64 executable header differs")
    _require(struct.unpack_from("<2I6Q", executable, 64) ==
             (1, 5, 0, 0x400000, 0x400000, len(executable), len(executable), 4096),
             "the sole executable mapping differs")
    _require(struct.unpack_from("<2I6Q", executable, 120) ==
             (0x6474E551, 6, 0, 0, 0, 0, 0, 16),
             "nonexecutable stack or program-header count differs")

    at = provenance.get("metadata_offset")
    pointer = provenance.get("metadata_hole")
    _require(_integer(at, 176, len(executable) - 64) and at % 16 == 0,
             "metadata offset is invalid")
    _require(_integer(pointer, 179, at - 4), "metadata pointer location is invalid")
    _require(executable[pointer - 3:pointer] == b"\x4c\x8d\x2d",
             "metadata pointer instruction differs")
    displacement = struct.unpack_from("<i", executable, pointer)[0]
    _require(pointer + 4 + displacement == at, "metadata pointer does not reach the checked table")
    prefix = bytearray(executable[:at])
    prefix[96:112] = bytes(16)
    _require(_sha(prefix) == provenance.get("elf_prefix_normalized_sha256"),
             "source-owned native adapter bytes differ")
    _require(frame[:8] == b"HIABND01" and _words(frame, 8, 3) == (MEMBER_COUNT, 0, 0),
             "packing frame header differs")
    members = profile.get("members")
    _require(type(members) is list and len(members) == MEMBER_COUNT,
             "fixed profile member count differs")

    code = at + 64 + MEMBER_COUNT * 128
    memory = WORK_START
    cursor = 32
    layouts = []
    for index, member in enumerate(members):
        _require(type(member) is dict and member.get("id") == index,
                 "profile order differs")
        required = ("image_bytes", "input_capacity", "output_capacity",
                    "workspace_capacity", "flags", "call_mask")
        _require(all(_integer(member.get(key), 0, 1 << 30) for key in required),
                 "profile integer fields differ")
        size = member["image_bytes"]
        _require(0 < size <= 1 << 20 and size <= len(executable) - code,
                 "embedded image extent is invalid")
        _require(cursor <= len(frame) - 128 and size <= len(frame) - cursor - 128,
                 "packing frame member extent is invalid")
        expected_frame = (size, member["input_capacity"], member["output_capacity"],
                          member["workspace_capacity"], member["flags"], member["call_mask"], 0, 0)
        _require(_words(frame, cursor, 8) == expected_frame, "packing frame capability differs")
        try:
            tags = bytes.fromhex(member["source_sha256"] + member["image_sha256"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("authority ELF layout: profile hash spelling differs") from error
        _require(len(tags) == 64 and frame[cursor + 64:cursor + 128] == tags,
                 "packing frame source/image identities differ")
        image = bytes(frame[cursor + 128:cursor + 128 + size])
        _require(_sha(image) == member["image_sha256"], "packing frame actual image differs")
        descriptor = at + 64 + index * 128
        expected_descriptor = (code, size, member["input_capacity"], member["output_capacity"],
                               memory, member["workspace_capacity"], member["flags"], member["call_mask"])
        _require(_words(executable, descriptor, 8) == expected_descriptor,
                 "embedded image descriptor or workspace authority differs")
        _require(executable[descriptor + 64:descriptor + 128] == tags,
                 "embedded source/image tags differ")
        _require(executable[code:code + size] == image,
                 "actual embedded image bytes differ from the checked native member")
        end = code + size
        aligned = (end + 15) & -16
        _require(aligned <= len(executable) and executable[end:aligned] == bytes(aligned - end),
                 "embedded image alignment bytes differ")
        layouts.append({"id": index, "image_offset": code, "image_bytes": size,
                        "workspace_offset": memory, "workspace_bytes": member["workspace_capacity"],
                        "source_sha256": member["source_sha256"], "image_sha256": member["image_sha256"]})
        code = aligned
        memory += ((member["workspace_capacity"] + 4095) & -4096) + 4096
        _require(memory <= 1 << 30, "private workspace mapping exceeds its bound")
        cursor += 128 + size

    _require(cursor == len(frame), "packing frame has trailing bytes")
    _require(code == len(executable), "executable has trailing or missing image bytes")
    _require(_words(executable, at, 8) ==
             (int.from_bytes(b"HIAMOD01", "little"), MEMBER_COUNT, 0, memory, 128, WORK_START, 0, 0),
             "metadata header or total mapping bound differs")
    return {"schema": SCHEMA, "metadata_offset": at, "metadata_pointer": pointer,
            "mapping_bytes": memory, "member_count": MEMBER_COUNT,
            "normalized_prefix_sha256": _sha(prefix), "frame_sha256": _sha(frame),
            "executable_sha256": _sha(executable), "members": layouts,
            "all_actual_embedded_images_match": True, "dynamic_interpreter": False,
            "writable_executable_mapping": False}


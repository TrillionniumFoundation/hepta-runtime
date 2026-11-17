"""Decode complete public-carrier observations without running a component."""
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "capture"))
sys.path.insert(0, str(ROOT / "corpus/state_reference"))
import capture_fixture as fixture
import native_observations as native
import observations as original

need = fixture.common.need


def serial(value):
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, dict):
        if any(isinstance(key, bytes) for key in value):
            return [[key.hex(), serial(item)] for key, item in sorted(value.items())]
        return {key: serial(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [serial(item) for item in value]
    return value


def state(value):
    return serial({key: item for key, item in value.items() if key not in ("phase", "generation")})


def native_state(session_bodies, shared):
    need(len(session_bodies) == 2, "both native session observations")
    sessions, caches = [], []
    for raw in session_bodies:
        sections, _ = fixture.observer_spans(raw)
        projection = fixture.state_projection(raw)
        sessions.append({key: projection[key] for key in
            ("root_hex", "current_hex", "effective_hex", "poisoned", "session_applied")})
        caches.append(state(native.cache(sections["cache"], 1, 1)))
        context = sections["context"]
        if any(context):
            need(context[:8] == b"HRCXST01", "request context magic")
            version, arena, used, top, depth, z0, z1 = struct.unpack_from("<7Q", context, 8)
            need(version == 1 and arena >= 64 and used == 64 and not (top or depth or z0 or z1),
                "returned public request retained a context scope")
        scope = sections["scope"]
        need((not any(scope) and not any(context)) or
            (scope[:8] == b"HRSCST01" and struct.unpack_from("<Q", scope, 8)[0] == 1
            and struct.unpack_from("<Q", scope, 24)[0] == 0
            and struct.unpack_from("<Q", scope, 64)[0] == 0),
            "returned public request retained an active scope or scope lease")
        lease = sections["lease"]
        need(lease[:8] == b"HRCLST01" and struct.unpack_from("<Q", lease, 8)[0] == 1,
            "complete current lease-owner observation")
    need(len(shared) >= 32 and shared[:8] == b"HLTBSH01", "shared text/Batch observer magic")
    lock_size, history_size, statx = struct.unpack_from("<3Q", shared, 8)
    need(lock_size >= 4096 and history_size >= 4096 and lock_size % 4096 == history_size % 4096 == 0
        and len(shared) == 32 + lock_size + history_size and statx in (0, 1),
        "complete shared lock/history/statx state")
    locks = native.locks(shared[32:32 + lock_size], 1, 1)
    history = native.history(shared[32 + lock_size:], 1, 1)
    return {"sessions": sessions, "caches": caches, "history": state(history),
        "locks": state(locks), "scope_unbound_after_exchange": True}


def original_state(row, command, *, session_count=2):
    need(type(session_count) is int and session_count in (1, 2), "explicit original session domain")
    need(set(row) == {"id", "session", "kind", "output_hex", "cache_snapshots_hex", "sessions",
        "scope_unbound_after_exchange", "closed_sessions", "history_snapshot_hex", "lock_snapshot_hex"},
        "complete original observer fields")
    need((row["id"], row["session"], row["kind"]) == (command["id"], command["session"], command["kind"])
        and type(command["session"]) is int and 0 <= command["session"] < session_count
        and row["scope_unbound_after_exchange"] is True and row["closed_sessions"] == [False, session_count == 1],
        "original command identity or current scope/session lifetime")
    need(len(row["sessions"]) == len(row["cache_snapshots_hex"]) == 2, "both original server-state slots")
    sessions, caches = [], []
    for session, encoded in zip(row["sessions"], row["cache_snapshots_hex"], strict=True):
        need(set(session) == {"root", "current", "effective", "poisoned", "session_applied"}
            and type(session["poisoned"]) is bool and type(session["session_applied"]) is bool,
            "original session fields")
        sessions.append({"root_hex": session["root"].encode().hex(),
            "current_hex": None if session["current"] is None else session["current"].encode().hex(),
            "effective_hex": session["effective"].encode().hex(), "poisoned": session["poisoned"],
            "session_applied": session["session_applied"]})
        raw = bytes.fromhex(encoded)
        need(raw[:8] == b"HLCSCS01", "original cache magic")
        parsed = original.cache(raw)
        need(parsed["phase"] == 1, "original complete post-command cache observation")
        caches.append(state(parsed))
    parsed = {}
    for name, magic, parse in (("history", b"HLTBHS01", original.history),
            ("locks", b"HLTBLK01", original.locks)):
        raw = bytes.fromhex(row[("lock" if name == "locks" else name) + "_snapshot_hex"])
        need(raw[:8] == magic, "original state observer magic")
        value = parse(raw)
        need(value["phase"] == 1 and value["generation"] == command["id"] + 1,
            "original observer phase/actual outer command sequence")
        if name == "locks":
            need(all(count == 1 for count in value["entries"].values()), "original returned a retained lock lease")
        parsed[name] = state(value)
    return {"sessions": sessions, "caches": caches, **parsed, "scope_unbound_after_exchange": True}


def trace_frames(raw):
    """Partition every complete source-owned private receipt, including tails."""
    sizes = {b"HRGTR002": 224, b"HRCNAK02": 128, b"HWDIOAK2": 160,
        b"HFSPCL02": 80, b"HFSPAK02": 192, b"HVRDACK1": 128, b"HFLKEYFX": 128}
    at, counts = 0, {}
    while at < len(raw):
        magic = raw[at:at + 8]
        size = sizes.get(magic)
        need(size is not None and size <= len(raw) - at, "unrecognized or incomplete actual private receipt")
        if magic == b"HRGTR002":
            seq, slot, event, result, workspace, output = struct.unpack_from("<6Q", raw, at + 8)
            need(seq > 0 and slot < 56 and event in (1, 2, 3, 4, 5, 6) and workspace >= 4096
                and output >= 4096 and (result <= output or result >= 0xffffff00),
                "actual growth-engine receipt fields")
        counts[magic.decode()] = counts.get(magic.decode(), 0) + 1
        at += size
    return counts

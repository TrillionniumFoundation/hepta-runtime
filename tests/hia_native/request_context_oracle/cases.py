"""Deterministic public-domain traces for the unchanged Rust request context."""
from __future__ import annotations
import json
import random


def cases():
    rows = [{"op": "scenarios"}]

    def trace(name, events):
        rows.append({"op": "trace", "id": name,
            "events": [{"op": "init"}, *events, {"op": "destroy"}]})

    def push(text):
        return {"op": "push", "hint": text}

    trace("outside", [push("lost"), {"op": "peek"}, {"op": "drain"}, {"op": "cache"}])
    trace("empty-scope", [{"op": "enter", "cache": 1}, {"op": "peek"}, {"op": "drain"},
        {"op": "cache"}, {"op": "exit"}])
    trace("dedup-order", [{"op": "enter", "cache": 1},
        *[push(x) for x in ["b", "a", "b", "", "a", "c", "", "b"]],
        {"op": "peek"}, {"op": "drain"}, {"op": "peek"}, {"op": "drain"},
        push("b"), {"op": "drain"}, {"op": "exit"}])
    trace("unicode-distinct", [{"op": "enter", "cache": 0},
        *[push(x) for x in ["é", "e\u0301", "\0", "a\0b", "\r\n", "\n", "⚠️ ", "中文", "𝄞", "é"]],
        {"op": "peek"}, {"op": "drain"}, {"op": "exit"}])
    for name, alias in [("nested-same-cache", 23), ("nested-different-cache", 24)]:
        trace(name, [{"op": "enter", "cache": 23}, push("outer"),
            {"op": "enter", "cache": alias}, push("inner"), {"op": "cache"},
            {"op": "drain"}, {"op": "exit"}, {"op": "peek"}, {"op": "cache"},
            {"op": "drain"}, {"op": "exit"}])
    trace("large-alias", [{"op": "enter", "cache": (1 << 64) - 1}, push("max"),
        {"op": "cache"}, {"op": "drain"}, {"op": "exit"}])
    rows.append({"op": "trace", "id": "destroy-active-reinit", "events": [
        {"op": "init"}, {"op": "enter", "cache": 2}, push("discarded-outer"),
        {"op": "enter", "cache": 3}, push("discarded-inner"), {"op": "destroy"},
        {"op": "init"}, {"op": "drain"}, {"op": "enter", "cache": 2},
        {"op": "drain"}, push("fresh"), {"op": "drain"}, {"op": "exit"}, {"op": "destroy"}]})
    trace("deep-scopes", [*[ {"op": "enter", "cache": i // 2} for i in range(40)],
        push("leaf"), {"op": "drain"}, *[{"op": "exit"} for _ in range(40)]])
    trace("many-same", [{"op": "enter", "cache": 9}, *[push("same") for _ in range(4096)],
        {"op": "peek"}, {"op": "drain"}, {"op": "exit"}])
    trace("many-distinct", [{"op": "enter", "cache": 9},
        *[push("hint-%05d" % i) for i in range(1025)], {"op": "drain"}, {"op": "exit"}])
    for length in [31, 32, 63, 64, 255, 256, 1024, 4096, 65536]:
        trace("length-" + str(length), [{"op": "enter", "cache": 7},
            push("x" * length), push("x" * length), push("x" * (length - 1) + "y"),
            {"op": "peek"}, {"op": "drain"}, {"op": "exit"}])
    rng = random.Random(712110)
    pool = ["", "a", "ab", "a\0b", "\r\n", "same", "⚠️ ", "中", "é", "e\u0301"]
    for number in range(48):
        events, depth = [], 0
        for _ in range(40):
            choice = rng.randrange(8)
            if choice == 0 and depth < 5:
                events.append({"op": "enter", "cache": rng.randrange(4)}); depth += 1
            elif choice == 1 and depth:
                events.append({"op": "exit"}); depth -= 1
            elif choice in [2, 3, 4]:
                events.append(push(rng.choice(pool)))
            elif choice == 5:
                events.append({"op": "drain"})
            elif choice == 6:
                events.append({"op": "peek"})
            else:
                events.append({"op": "cache"})
        events.extend({"op": "exit"} for _ in range(depth))
        trace("generated-%02d" % number, events)
    for index, (base, hints) in enumerate([
        ("", []), ("", [""]), ("base", ["x", "x"]),
        ("a\r\n\0尾", ["\n", "é", "e\u0301", "⚠️ "]), ("already\n", [""])
    ]):
        rows.append({"op": "append_only", "id": "append-%02d" % index, "base": base, "hints": hints})
    return rows


if __name__ == "__main__":
    for row in cases():
        print(json.dumps(row, ensure_ascii=True, separators=(",", ":")))

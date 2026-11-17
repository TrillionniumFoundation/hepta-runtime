# Literal exception extension

HBRDS001 kind 3 adds wire classes 15 Error (binascii.Error), 16 NotImplementedError, and 17 RuntimeError. Errno32 and filename-kind48 must be zero. Literal length40 and total payload length56 must both equal input length minus64. Sequence16 remains opaque. The complete literal must be valid UTF-8. Output is the exact class name followed by colon-space and the literal bytes, with no newline and no repr transformation.

All accepted previous HBRDS001, HMDSR001 and HOSER001 inputs preserve their existing contracts. All 32 qualified path-error functions remain exact IR, relocating only the old f0 to f32. A new f0 dispatches these additional literal cases to f33. The unchanged immutable platform pool remains 10152 bytes and workspace requirement remains12288 bytes. The new wire class numbers do not alter internal rendered OS exception-class indexes. All other envelopes still reject these new literal classes.

Returns are exact produced byte length, INVALID0xffffffff or CAPACITY0xfffffffe. Invalid frames and short workspace leave complete arenas unchanged. Short output may install only the same frozen platform pool; output and all unused tails remain unchanged. No path or descriptor authority is carried and no OS call is performed.

This is a source-authoring package only: no native compilation, HIA application execution or CPython comparison occurs here. Native qualification and full original comparisons must follow before production integration.

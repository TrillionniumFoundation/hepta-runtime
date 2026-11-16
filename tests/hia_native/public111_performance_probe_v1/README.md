# Actual default111 timing observation

This isolated engineering source is based on production 08406d5 and CI package
635838e7. It does not change any HIA source, any packed worker or port bytes, or
the production entry. It reuses all 103 direct members and the exact eight-member
port from the already completed fresh build in run 43961663648.

The fixed private FD4 carrier adds entry/exit monotonic timestamps at existing
engine calls. All registers and flags survive the hook. A complete inverse
transformation recovers the original engine source. A newly packed diagnostic
ELF is explicitly different from the production or FD3 ELF.

Three requests are copied byte-for-byte from completed exchanges 38, 275, and
276 of the retained failure artifact. Each gets the original initialize and
initialized frames first. All response bytes are compared with the already
recorded native response; the original frozen comparator normalizes only the
solver's wall-time field. Independent review of the original 278-response
prefix against current Rust is preserved by the referenced Git blob.

Each diagnostic process keeps the existing 60-second cap. This small diagnostic
domain does not replace the complete 1394-record gate or its 180-second process
cap. It does not qualify asynchronous ownership, cancellation, the complete
router, or production rollout. The failed 180-second run is retained unchanged.

The workflow performs compilation/packing only in CI, downloads an exact
existing build ZIP, verifies every archive member and the complete old build,
and preserves complete input, output, FD3 journal, FD4 trace, and process records.

## Observer revision

The first CI diagnostic preserved an actual reader failure: communicate() closed
stdin immediately, so the wide request entered EOF draining before its reply.
That source and full failure artifact remain immutable. This revision borrows
the original complete stdio exchange/read/reap implementation, adds only fixed
FD4 custody, and narrows its diagnostic process cap to 60 seconds. Its inverse
recovers the exact original source; all eight other NativeStdio method ASTs are
unchanged. EOF is sent after the three complete exchanges. Production sources,
all HIA images, the full 1394 domain and its 180/60 limits remain unchanged.

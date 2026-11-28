# Native bounded multi-file body

Fixed SysV exports are multi_read_body_create(callback, callback_context, shared_pool),
multi_read_body_invoke(context, HMRDQ001_packet, byte_length), release(context), destroy(context).
Constructor validates the exact c811 HPORP001 pool, page size and creator PID. All contexts
in one process borrow the same pool; none duplicates, closes or destroys it.

The five production body images are multi_read_body, parent_directory, binary_codec,
stat_version and utf8_decode_diagnostic. One unchanged structured_error image is also
packed for private diagnostic observation; it is not another public tool. The build uses
eight fresh B3 compiles including the linker and image packer, and executes zero application
requests. There is no libc, Python runtime or arbitrary-address plugin entry in the ELF.

The 4,096-byte opaque native context retains the established arena/generation/journal layout.
Body/stat/codec/UTF8 code entries are at 16/24/32/152, fixed at construction. Native state at
56 is 0 idle, 1 executing, 2 output borrowed, 3 infrastructure failure. Output span is 168;
generation 192; eight operable owned file slots 256..319; shared orphan pool 376; source
and confirmation parent contexts 384 and 392; orphan transfer count 400. Each parent
context is the unchanged qualified parent_directory implementation. They are distinct
instances of one immutable image. A held directory FD is never duplicated or returned to
the operable file ledger.

Only HIA selects an open, fstat, raw read, orphan, close, parent acquire/close or fixed child.
Open verifies the actual still-held parent context and its complete basename loan. Returned
file FDs, including zero, are enrolled in an available owned slot. Fstat/read/close/orphan
accept only a current owned token. ORPHAN_OWNED appends to the shared process pool before
retiring that token and never calls close/dup. Raw reads return all actual bytes and errno.

HIA owns normal error ordering and all four nested cleanup positions. Final output is
admitted only after both file ledgers and both parent contexts are idle. Private observer
or allocation failure is state 3, with remaining owned descriptors retained for explicit
teardown; destructor closes operable file tokens and asks held parents to close through
their own HIA. Persistent teardown/observer/allocation failures are not application parity
claims. Orphans are excluded from this teardown and live until process exit.

The private HMRDFQ01 carrier has length-prefix framing and two context slots. Commands:
1 invoke; 2 release; 3 destroy; 4 complete context; 5 complete workspace; 6 complete output
arena; 7 complete input arena; 8 observed create; 9 observer-off create; 11 complete pool;
13 diagnostic observation; 15 both complete parent contexts; 17 move only stdin control
away from FD 0; 18 arm a real kernel fstat-EIO filter with a 16-byte phase/regular-role
payload; 19 unowned orphan refusal; 20 distinct-PID pool refusal; 21 direct UTF8 leaf.
Commands 10/12/14/16 are absent: no fixture-held target-parent capability is substituted.

Each journal event preserves a complete actually passed span. HMRDJR01 is the body;
HPD0JR01 and HPD1JR01 identify the distinct source and confirmation parents. Corresponding
HMRDHK01/HPD0HK01/HPD1HK01 barriers delay the real operation for an independently specified
filesystem actor; their ACK cannot replace a result. The actual seccomp filter is installed
only at the frozen HIA fstat phase/role and returns kernel EIO. EOF releases terminal
outputs and destroys contexts, then emits HMRDEOF1 before process exit. The observer
checks actual /proc FD survival there, acknowledges, and observes actual exit.

Command 21 is private leaf qualification, not application behavior. Its payload is
out-capacity, work-capacity, out-seed-byte, work-seed-byte, then HUTFQ001. Both capacities
are at most 4,096. The returned 16,416-byte capture contains capacities, native return,
input length, then both full 4,096-byte arenas before and after the HIA call. This retains
physical tails outside the declared spans. The fixture performs no decode or expected-result
calculation. Command 13 uses the unchanged HIA error formatter for HBRDS001, or exposes the
already complete HUTFD001 diagnostic payload without a second formatting call.

The HRCODEC1 SHA child packet has operation 2 and reserved u64 word at byte 16 equal
to zero. Its complete packet length carries the raw data extent after the 24-byte header.
The fixed native edge validates this exact reserved-zero contract before the HIA child.

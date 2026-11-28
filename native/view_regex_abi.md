# Private native regular-file regex search

This owner supplies the raw regex operation used by the local regular-file
`view(regex=true, content=...)` route. The existing configuration controller
continues to apply its own anchoring rules. It is a separate caller; its
wrapped pattern is never substituted for a view search pattern.

## Trusted routing and order

The public frontend first performs the existing SDK metadata, typed
`ViewParams`, session/workdir and installed-policy admission. Only the trusted
`view_gateway.f9` constructs `HVCRQ001`. An empty or whitespace-only content
argument still follows ordinary view. The private frame has the same layout
as `HVCSQ001`: magic, flags, raw-path length, resolved-path length, pattern
length, admitted u64 context, zero, zero, then the three complete byte spans.
Only flag 4 is admitted and search ignores it. Start/end endpoints are not
resolved for the content-search branch.

The caller retains the original outer exists/is-directory and inner
exists/is-file/metadata order, the metadata 5 MiB check, and raw operation 5
reads through EOF. A subsequent growth creates no new total-read quota.
The read completes before lossy UTF-8 conversion. A read error precedes regex
compilation. Empty Rust `str::lines` input returns the original empty-file
message without compiling even an invalid pattern. A nonempty file compiles
the exact untrimmed pattern once, then matches each original logical line.
Context expansion, range merging, scalar hashes and rendering are the same
HIA search functions used by literal search. Search never mutates the view
cache. The original 8 MiB gate applies only to a successful complete base;
regex error text is retained in full within the declared resource profile.
Cancellation retires its request scope and does not roll back prior effects.

## Owner wire

All integers are little-endian u64. `f0` has the ordinary borrowed-byte HIA
ABI and returns a zero-extended u32 status or output length.

| Offset | Request field |
| ---: | --- |
| 0 | Eight bytes `HVRGX001` |
| 8 | Operation 1: compile; 2: is_match |
| 16 | Pattern byte length |
| 24 | Haystack byte length; zero for compile |
| 32 | Pattern bytes, immediately followed by haystack bytes |

The successful response starts with `HVRGR001`, status, capture count
(including group zero) and boolean matched, four u64 words. Status zero is a
compiled/matched result. Status 1 is an AST/HIR regex error and status 2 is the
original compiled-size error; these append the complete UTF-8 text after the
32-byte response. The text begins with the original
`Invalid regex pattern: ` prefix. Status 3 reports the finite native
compilation/resource profile and is propagated as a private resource failure;
it is not relabelled as an original tool capacity error.

The private state retains only the current compiled pattern and NFA. A byte
identical pattern may reuse that native compilation. Both forward and reverse
NFA budget checks run before a compiled pattern becomes reusable. A pattern
containing none of `.^$?*+{}[]()|\\` may use native KMP after complete regex
admission. Its exact UTF-8 byte substring semantics equal literal regex
matching; if the prefix table does not fit, the existing matcher remains the
path. There is no Python or Rust semantic implementation in the service.

## Fixed private graph

The view engine has 19 source-owned slots. It reuses the syntax, Unicode, HIR,
NFA and matcher images already present in the public configuration composition.

| Actual view slot | Owner | Permitted children |
| ---: | --- | --- |
| 12 | Raw view regex | 13, 14, 15, 16, 18 |
| 13 | Syntax, raw mode 2 with diagnostics | 17 |
| 14 | HIR with diagnostic spans | 17 |
| 15 | NFA | None |
| 16 | Matcher | 17 |
| 17 | Unicode data | None |
| 18 | Regex error formatter | None |

The raw owner's logical selectors 10, 12, 13, 14 and 16 map to actual view
slots 13, 14, 15, 16 and 18. Logical Unicode selector 11 maps to actual 17.
These are fixed internal addresses, not request-selectable capabilities.
The bridge validates the complete HIACAL footer, monotonic sequence, exact
borrowed output capacity, bounded non-overlapping spans, child workspace and
call graph. It restores a child's prior output borrow after return. A resource
failure is never acknowledged as a successful child call. Descriptors retain
only offsets/pointers belonging to the current private engine, never a public
JSON-RPC ID.

Formatting first obtains an exact extent in HIA. If the root's independent
output window is too short, phase 7 preserves that completed error and the
bridge grows the result allocation before retrying delivery. It does not
repeat file I/O, regex parsing or cache effects. Allocation failure preserves
the old allocation. The completed caller result is copied into the existing
independently owned publisher before the engine can be reused.

## Resource and qualification boundary

The current raw-owner profile has a 128 MiB input carrier, 64 MiB individual
pattern/haystack spans and a 256 MiB workspace. Its output starts at 1 MiB and
can grow to 128 MiB. The syntax diagnostic stack has 400 private frames and
preserves the original parser nest limit of 250. The native error formatter
also has a finite borrowed output extent. These are explicit native profile
limits, not a claim to cover every Rust-successful input length. The original
file read has no added application cumulative limit. LP64 representation,
allocation and I/O remain real resource constraints.

The standalone caller has 17 images and 19 slots; it is a deterministic
component fixture. The public service has 39 images and routes actual MCP
requests through typed admission, session/policy, the same caller, and native
publication. Their execution counts and retained streams are distinct.

Reproducible acceptance uses `test_view_regex_search.py` (271 independent
actual-I/O inputs), `test_view_regex_search_native_evidence.py`,
`test_view_regex_search_public.py`, and
`test_view_regex_search_public_evidence.py`. The immutable eight-file
`view_regex_search_oracle` builds the original Rust bodies with a locked
dependency set and supplies complete outputs. Its original evidence controls
execute no HIA or Rust. Public comparison uses 510 complete original bodies;
eight public resolved-path controls have a different resolution context and
are counted separately. Every actual test keeps the 180-second deadline.

Directory, alternative-path, remote/background routes, unrestricted
concurrency, the complete SDK surface, and the full 125-tool runtime are
outside this qualification. No whole-view or whole-runtime replacement flag
is raised by this owner.

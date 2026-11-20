# Install the qualified binary-root owner in the current product graph

The existing private binary-root qualification implemented operation 9, but the
current public graph still compiled its 52-function predecessor and its slot 11
bridge rejected operation 9. This change installs the exact qualified 60-function
source and admits this read-only query through the existing installed owner.

The public graph remains 116 direct HIA members, eight packed worker members,
117 physical images and 69 engine slots. It still has 13 wired public handlers.
`binary_write` remains an unknown public tool. The currently configured catalog
advertises 11 tools; the absent-configuration catalog advertises eight. These
catalog counts and the existing completion/activation flags are unchanged.

## Exact source change

- Base: `328953dc96d26ceb5ab02a172172deb7916873c7` (PR #126).
- Qualified owner source: commit `36d89dd2656077248c7e5e5a387cddb3a9268e83`,
  `qualification/binary_root/v1/source/native/config_directory_owner_span.hepta`.
- Qualified root handoff: `19d586be0db6a13d18a6f7e1356ce6c8dc55abce`.
- Imported bytes: 319,711; SHA256
  `cb22aa72a33b4a429356fdb7d70dd33828492676de1a89c11837d9d8f68a55b5`.
- Fifty original functions are unchanged. Original `f8` is retained exactly as
  `f52`; `f8` dispatches operation 9 to the new owner. The only original entry
  change admits operation 9 beside operation 8 in one block.
- The mechanical bridge admits exactly operation 9 and retries its read-only
  short-output result. Existing opcode validation and operation 8 behavior remain
  intact. The source checker proves the complete bridge inverse.

`native/runtime_mcp_binary_root_integration.json` records the exact old/new pins
and bridge replacements. The source binding changes only the owner, bridge and
new integration record; all 533 other bound files are byte-identical.

## Product ABI

Slot 11 accepts `HRCFGQ01`, followed by operation 9 and an exact payload length
(u64 little endian). The 40-byte payload prefix is explicit-user=0,
explicit-port=0, write=0/1, host byte length and path byte length. UTF-8 host and
path bytes follow. This is the existing operation 8 layout, with no new NUL
filter. The bridge borrows the installed configuration owner and sets footer
kind 1; neither JSON clients nor public tool arguments receive a selector.

The completed result is `HRCFGM01`, status (0 root / 1 original error), reserved
zero, payload byte length, then the UTF-8 root or error. The returned u32 is the
complete extent. Invalid frames return `0xffffffff`; owner capacity and
`HGRWS002` growth retain their qualified meanings.

Policy order remains: installed configuration, exact configured host name,
operator mode, unchanged alias/path policy, then the longest raw UTF-8 prefix
from the originally named host. Equal lengths keep the last match. Root bytes
are returned unchanged, including trailing slashes.

## Actual verification

`RESULTS.json` and `evidence.tar.xz` retain the observed results, full build
outputs, complete process streams and the first unsuccessful comparison.

1. The exact compiler dependency check passed for all 1,080 source files at
   Hepta commit `d3e2c90173cf733e42b299d0c4274df4b593a12f`; B3 SHA256 is
   `bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
2. The changed owner was actually compiled. The unchanged product builder
   verified 115 reused direct members and the packed worker. HIA linking and
   packing actually ran for the product and both private fixture graphs.
3. Eight actual public processes compared 116 response pairs across configured
   and absent policy, legacy and modern metadata, all 13 wired handlers, typed
   errors, real read/refusal bodies, a successful Bellman worker calculation,
   the complete advertised catalog and the still-unrouted binary writer.
   Workspace contents, inode identities and modification/change times remained
   unchanged.
4. All response bytes match except the one declared elapsed-duration token in
   each successful Bellman request (id 34). Both original values and complete
   wires are retained; each duration must be finite, nonnegative and below the
   existing 60-second request deadline. No other timing, PID or numeric field
   is normalized. The original exact comparison failure is preserved.
5. The actual product fixture passed 68 queries in seven configuration groups:
   24 old-operation response pairs, 17 malformed ABI controls, exact host versus
   SSH alias behavior, operator and write restrictions, error ordering, raw
   prefix/UTF-8/NUL behavior, and an 18,001-byte root that forces real output
   growth. Both fixed sessions use the same installed owner. A separate old
   product fixture run proves that the original bridge rejected operation 9.

No Rust application, Python remote helper or SSH process was run for this local
integration regression. Python is the explicit test/build driver; emitted
runtime behavior is executed by the real HIA images and mechanical syscall
bridge. This is a product-integration regression with a pinned HIA baseline,
not a new full Rust/public equivalence qualification. Normal repository CI is
independent of these local observations.

## Reproduce

Use separate baseline and candidate checkouts, the pinned Hepta checkout, and
a normal baseline `hia_native_runtime_mcp_build.py` output. The retained baseline
used here is run 44174634731, artifact 14370041088 (`public124-default-entry-`
`328953dc96d26ceb5ab02a172172deb7916873c7-1`). Its ZIP has 95,120,157 bytes and
SHA256 `48d6ed3307bb03c4c8eab30a212c1746b3b75511055340488a39691122062b66`;
all 4,277 extracted files (449,883,409 bytes) were verified. After extraction,
the build directory is `capture/default-build` and source is `capture/source`.

```bash
python -I -S -B tests/hia_native/binary_root_product/build.py \
  --base-source /absolute/baseline-source \
  --source /absolute/candidate-source \
  --hepta /absolute/pinned-Hepta \
  --baseline-build /absolute/baseline-default-build \
  --output /absolute/fresh-integration-build

python -I -S -B tests/hia_native/binary_root_product/verify_runtime.py \
  --baseline /absolute/baseline-default-build/build/public-task-batch-extract/manifest.json \
  --candidate /absolute/fresh-integration-build/product/product/manifest.json \
  --baseline-fixture /absolute/fresh-integration-build/baseline-fixture/baseline-fixture/manifest.json \
  --candidate-fixture /absolute/fresh-integration-build/fixture/fixture/manifest.json \
  --output /absolute/fresh-runtime-regression
```

The ordinary default builder remains unchanged and can compile the complete
candidate from source without reusing earlier member images. No CI workflow,
deadline or completion flag is relaxed here.

## Remaining binary_write product work

The 101-input qualified writer domain recovered in PR #133 is a private body
with `HBWTQ001` input and a borrowed parent directory FD. Its create operation
also requires process-owned orphan-pool and entropy contexts. It does not
implement the complete public host-based API by itself. PR #133 is unchanged.

- `native/runtime_mcp.hepta` needs a public typed dispatch path preserving the
  original `BinaryWriteParams` errors. The already-qualified parameter owner
  at `0666613d8c3cad74f6eb192c287069988e813827` is not in `MEMBERS` or the slot
  table. Its raw-map-to-typed `HBPRQ001/HBPRR001` ABI must be connected, including
  the original 1,398,104-byte Base64-input cap and exact error ordering.
- The qualified binary call planner (`binary_call_plan.hepta`, SHA256
  `fc8624cc760735a0fdaea46fb5c7434c09cc1fe96d8b218d510a3858fe3305bc`) is not
  installed in the public graph. This change supplies its genuine installed
  root-policy dependency. Its audit and RPC qualification boundaries were
  recorded stubs and do not establish actual remote execution.
- The original `src/mcp/runtime/binary.rs` targets a configured operator host
  through `run_python_json` with a 30-second budget. A HIA remote helper must
  preserve configured SSH identity, remote root/parent opening, payload
  transport, errors and timeout behavior. Remote-helper leaf work at
  `819ed071a9ddd37643d52ef442cf54fd92de2945` built projection/bootstrap leaves;
  it does not provide the complete installed remote writer. A controller FD
  cannot stand in for a remote parent directory FD.
- Actual effect-owner admission, `native_binary_write` audit, shared process
  entropy/orphan-pool creation and retirement, pending-request cancellation,
  result publication and remote cleanup need product ownership. The public
  source binding still explicitly reports audit/full-runtime gaps.
- The public call needs actual original/native comparison over the qualified
  101-body input domain plus the missing host, typed-parameter, SSH, audit,
  lifecycle and full public error domains before route qualification or old
  stack removal is justified.

This change does not set `public_binary_write_registered`, `full_136_route_qualified`,
`production_activated` or `old_path_removed` to true.

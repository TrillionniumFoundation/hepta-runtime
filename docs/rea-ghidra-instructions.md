# Bounded Ghidra instruction windows

## Implementation status

This source change adds native operation `instructions`, an explicit adapter for REA 6.8.0 `read_function_instructions`. Its baseline is commit `6c224e4d913dd596e44fb936e22b447531f8962b`, tree `5d75e3bfdcaa20b43b4f170288b4221ceb9040ad`. Source preparation and synthetic contract checks do not qualify a built candidate or a real engine run.

| Native operation | Code before this change | Actual recorded qualification |
| --- | --- | --- |
| `inventory` revision 2 | Implemented | Candidate A (`c25e4cef`) exercised it in its 11-check Ghidra profile. |
| `functions`, `function`, `decompile`, `xrefs` | Implemented | Candidate A exercised these operations, original-job restart readback, cancellation, worker crash and owner timeout. |
| `instructions` | Added by this change | No actual Ghidra qualification is inherited from A or the separate B2 matrix. |

The historical A receipt is `provider-gates-r1/01-ghidra/workspace/qualification.json`, SHA-256 `aa0cb4dac6146bd66a3627ab9d32fc8891314393a7287022ae3c1553298bb3d2`; A runtime SHA-256 was `9cde66234030515651177e3d8ab113b2b6f674ee76196283c71874348a0b6c90`. Those are historical evidence identities, not a qualification of this source.

## Request and admission

Use the existing `rea_static_start` / observe / cancel job interface with `operation: "instructions"`. The administrator must explicitly include that operation in the selected Ghidra profile's `allowed_operations`, select `bridge_revision: 2`, and bind the runtime, Ghidra 12.2 installation manifest, JDK and input bytes. The caller supplies one canonical lowercase hexadecimal `function_address` identifying an exact internal function entry. A name, interior address, range, expression, caller script or missing selector is refused.

This uses the existing captured input, private scratch owner, Java process group, durable original-job identity and report-validation path. It introduces no controller registry, secondary session owner or ambient project state. Legacy import-only bridge bytes remain unchanged. GNU and JADX profiles do not admit this operation.

## Returned observation

`instruction_window` has the original strict value shape:

- `procedure`: exact address and full bounded name, native symbol metadata, actual FunctionManager external/thunk classification, and the complete observed inclusive function-body AddressSet.
- `instructions`: ordered Listing lines, rendered as canonical address, mnemonic and default operand representations.
- `limitations`: the adapter's explicit scope restrictions.

The body preserves disjoint ranges instead of substituting its enclosing span. The validator recomputes byte totals, span (null for multiple spaces), non-contiguity and entry membership. Every returned instruction's entire byte range must lie inside one body range; rows cannot overlap or run backwards. The native observation adds corresponding initialized-memory bytes, row count, complete/omitted flags, and a SHA-256 of UTF-8 instruction lines joined by a single newline with no final newline.

The Java producer escapes only UTF-8 address-space bytes outside the unreserved ASCII set and emits uppercase percent escapes. The Rust consumer validates that original observed-address spelling grammar without decoding or merging names: redundant uppercase escapes such as `%41` are accepted by this syntax check. It does not claim to have established a stronger canonical identity for named spaces. Request entry addresses remain strict lowercase hexadecimal coordinates in the default ELF address space.

The Rust consumer checked-adds every UTF-8 line and its intervening newline before retaining the line or joining the text, refusing any total above 65,536 bytes. After joining the bounded set, it still verifies the actual length and SHA-256. It cross-checks the procedure against the selected function row and source-bound report. Resealing the outer JSON report cannot make a corrupt inner body, different address, incorrect count or incomplete window valid.

## Fixed bounds and scope

The existing restricted analyzer profile remains `hepta.ghidra.elf-functions.v1`: Disassemble Entry Points, Function Start Search, Stack and Subroutine References. This operation does not invoke the decompiler or scan whole-program names and strings. It is limited to 4,096 body ranges, 4,096 instruction rows, 65,536 bytes of joined text, 4,096 UTF-8 bytes per line, a 1,024-byte full procedure name, and a 10-second cooperative instruction monitor, bounded by the existing total owner deadline. The existing total worker, output, memory and scratch budgets still apply. A limit violation fails the complete observation; the implementation never truncates an instruction list and labels it complete.

“Complete” means every instruction presently in the selected function's Listing after the fixed restricted analysis. It does not establish that Ghidra discovered every machine-code instruction or selected the original source function boundary. A complete empty Listing remains an uncertain observation. Byte rows represent Ghidra's initialized instruction memory, including loader adjustments; they are not file offsets or proof of raw-file byte identity.

The original provider's terminal-call and Borland SEH boundary heuristics are not implemented here. This adapter also does not reproduce the original provider's persistent document lifecycle, whole analysis profile or full Evidence envelope. Its report retains `rea_evidence_compatible: false`, partial coverage and `upstream_contract_equivalent: false`.

## Original contract provenance

These files were read from the fixed REA 6.8.0 installation:

| Original file | SHA-256 | Contract used |
| --- | --- | --- |
| `dist/ghidra/GhidraFunctionValues.js` | `a34c606f6cc4989d5b01b4171e4dc830939d2cbbdbcd365b74157f8325e8566c` | Exact operation, input and strict observation envelope/value. |
| `dist/ghidra/GhidraInventoryValues.js` | `d29538770a0558582bbb8050fc0bfadc4dee41fc446e4b1f82447dcca03230b3` | Native procedure identity and body provenance. |
| `dist/domain/hopperValues.js` | `bfe7de495a3f4489ccb27541435ee353bf65e59e62520c42622a522834ec0f5b` | Complete inclusive body and instruction-window value. |
| `bridge/ghidra/ReaGhidraBridge.java` | `60cfdb22b436107c2139b5dbf5c48c6a6fa89b8b704ac88b0a7370a9ffc91fc1` | Actual Listing iterator/rendering, symbol/body extraction and boundary limitations. |

The supplemental address and symbol schemas are pinned in `tests/rea_ghidra_instructions_contract.mjs`. Official Ghidra [AddressSetView](https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressSetView.html), [Listing](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html) and [Instruction](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html) API documentation supports the intended calls; documentation review is not an installed-engine compilation or execution.

## Bounded validation plan

1. Format only this change's Rust files; parse the Node oracle. Run synthetic Rust contract tests covering exact row/text bounds, UTF-8 byte accounting, disjoint bodies, named spaces, corruption, missing fields and resealed outer reports. Run them only in the subsequently scheduled combined candidate qualification. This preparation does not create a Cargo target or compile against the active B2 candidate.
2. Run `tests/rea_ghidra_instructions_contract.mjs` with explicit `--rea-root`, `--fixture` and new `--output` absolute paths. It invokes only the pinned original schema functions: one accepted synthetic window and 14 rejected malformed observations. It does not start Ghidra or native runtime. Its direct-module pins do not attest all transitive Node dependencies.
3. After the fixed B2 installation checks finish, bind a newly built candidate and run a separate private real-Ghidra profile. Generate an owned ELF with known function entries/instruction bytes; compare complete observed ranges/rows against independent GNU output while accounting for formatting and loader semantics. Include disjoint-body and exact-boundary fixtures only where the real producer can establish their actual bodies.
4. Run the same owned input through the fixed, unmodified REA 6.8.0 Ghidra function-instruction implementation in its own private document/session. Retain actual bridge input/output and analysis settings, then compare mnemonic/default-operand rendering, address spelling, symbol metadata, complete body ranges and limitations. Record separate observed/passed/different/unobserved denominators for each category. Keep terminal-call and Borland SEH boundary heuristics in that comparison: a fixture that does not trigger either contributes an explicit unobserved result, not a pass. Preserve the original default-analysis versus native restricted-profile difference instead of modifying the original to match. Schema acceptance alone cannot establish this semantic comparison or full `read_function_instructions` parity.
5. Require successful original job readback after controller restart, invalid/interior selector refusal, over-budget complete-window refusal, original-owner cancellation/timeout, complete logs and verified private scratch/process cleanup. Preserve failures and use a new revision for diagnosed fixes. Do not count synthetic cancellation as actual instruction semantics.

No real instruction-window qualification or performance benefit is claimed by this document.

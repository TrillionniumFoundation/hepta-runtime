// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
// Pure-data R36 seal. Caller supplies verified exact text; no filesystem,
// host, compiler, auditor, child-process or runtime operation exists here.
// The reviewed preparer and actual owner identities remain unchanged. The
// completed closure hash is filled only after the original owner documents arrive.
const EXPECTED_CLOSURE_SHA256 = "7371da4735a72020d8a73eb820b0bd6ce7d4090f14326b6b4127f80d4de0f45f";
function sealR36Qualification(h, unsealedInputText, unsealedClosureText) {
  function ordered(x) {
    if (Array.isArray(x)) return x.map(ordered);
    if (x !== null && typeof x === "object")
      return Object.fromEntries(Object.keys(x).sort().map(k => [k, ordered(x[k])]));
    return x;
  }
  function encode(value) { return JSON.stringify(ordered(value), null, 2) + "\n"; }
  function need(test, why) { if (!test) throw new Error(why); }
  need(h.sha256(h.utf8(unsealedInputText)) === "2d824f1378210b14914ce0e63722a57bb3646a38da30489fbbf10a8b9ccb0220", "unsealed input identity");
  need(typeof EXPECTED_CLOSURE_SHA256 === "string" && /^[0-9a-f]{64}$/.test(EXPECTED_CLOSURE_SHA256), "actual owner closure not pinned");
  need(h.sha256(h.utf8(unsealedClosureText)) === EXPECTED_CLOSURE_SHA256, "unsealed closure identity");
  const input = JSON.parse(unsealedInputText), closure = JSON.parse(unsealedClosureText);
  need(input.sealed === false && closure.sealed === false, "only original unsealed data");
  need(input.preparation_tool.bytes === 40482 && input.preparation_tool.sha256 === "a090e7ce69f7bb31db2676fecbce7f546401deaa382a383b9dba8e759c5ecb7a", "reviewed preparer");
  need(Object.keys(closure.inputs).length === 28, "owner evidence count");
  need(closure.required_missing_bindings.length === 0 && closure.qualification_or_measurement_still_running === false, "listed owner facts incomplete");
  need(typeof closure.c1_recovery_diagnostic_evidence_passed === "boolean", "actual recovery diagnostic verdict missing");
  for (const pin of Object.values(closure.inputs))
    need(typeof pin.path === "string" && Number.isInteger(pin.bytes) && pin.bytes > 0 && /^[0-9a-f]{64}$/.test(pin.sha256), "missing original owner identity");
  need(input.actual_r36_qualification === null && input.actual_r36_formatted_map === null &&
       input.actual_r36_test_counts === null && input.actual_r36_release_programs === null, "no future results");
  closure.sealed = true; closure.required_missing_bindings = [];
  const closureText = encode(closure);
  input.sealed = true; input.required_missing_bindings = [];
  input.owner_closure_input_sha256 = h.sha256(h.utf8(closureText));
  return { input: encode(input), closure: closureText };
}
sealR36Qualification;

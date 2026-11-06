// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
// Pure-data recovery seal. Caller supplies verified exact text; no filesystem,
// host, compiler, auditor, child-process or runtime operation exists here.
// Python draft/static JSON checks ran before local executor loss. Its two
// unsealed payloads must match those recorded identities before sealing.
function sealRecoveredD2(h, unsealedInputText, unsealedClosureText) {
  function ordered(x) {
    if (Array.isArray(x)) return x.map(ordered);
    if (x !== null && typeof x === "object")
      return Object.fromEntries(Object.keys(x).sort().map(k => [k, ordered(x[k])]));
    return x;
  }
  function encode(value) { return JSON.stringify(ordered(value), null, 2) + "\n"; }
  function need(test, why) { if (!test) throw new Error(why); }
  need(h.sha256(h.utf8(unsealedInputText)) === "cf6ef8cc48678cbc1fe6acba57a6f0a7041ba50fd181ffff56e4d39cc62c0290", "unsealed input identity");
  need(h.sha256(h.utf8(unsealedClosureText)) === "dbe2414fa078b00e0d7868d0dede908fd840ad47afa2fafa8e1cc2e7dc29820d", "unsealed closure identity");
  const input = JSON.parse(unsealedInputText), closure = JSON.parse(unsealedClosureText);
  need(input.sealed === false && closure.sealed === false, "only original unsealed data");
  need(input.preparation_tool.bytes === 39590 && input.preparation_tool.sha256 === "2e36a1f29f4edd7439c32bc6f6443873dca03d2998381931db67f7034db404fb", "reviewed preparer");
  need(Object.keys(closure.inputs).length === 27, "owner evidence count");
  need(input.actual_d2_qualification === null && input.actual_d2_formatted_map === null &&
       input.actual_d2_test_counts === null && input.actual_d2_release_programs === null, "no future results");
  closure.sealed = true; closure.required_missing_bindings = [];
  const closureText = encode(closure);
  input.sealed = true; input.required_missing_bindings = [];
  input.owner_closure_input_sha256 = h.sha256(h.utf8(closureText));
  return { input: encode(input), closure: closureText };
}
sealRecoveredD2;

/** Reviewed controller for the official Hepta binary-write API.
 * No call is made by loading this file. Caller must retain the entire result.
 * Scope: switch one fixed account entry, or restore its exact original bytes.
 * No provider, account configuration, ledger, lock or bootstrap is modified.
 */
async function switchOriginalMasteryEntry(tools, mode, authorization) {
  const scope = "ndu-repair-mastery-20261120-aa42a9-v1";
  if (!authorization || authorization.scope !== scope || !/^[0-9a-f]{40}$/.test(authorization.frozen_commit || "")) {
    throw new Error("FROZEN_SCOPE_AUTHORIZATION_REQUIRED");
  }
  if (!["activate", "rollback"].includes(mode)) throw new Error("INVALID_SWITCH_MODE");
  const host = "rog";
  const entry = "/home/qian-qi/.local/bin/hepta-kaggle-account";
  const task = "/home/qian-qi/ndu-work/ndu-runtime-close-20261120-c2c548b7";
  const oldRelease = "/home/qian-qi/.local/share/hepta-kaggle/releases/batch-0.1.12-gpuimage-4920";
  const newRelease = "/home/qian-qi/.local/share/hepta-kaggle/releases/batch-0.1.13-cache-import-c2c548b7";
  const oldHashes = {
    "kaggle_jobs.py": "44405daa976f741639ca9596ced1e131263e17e90b71b81010b4947c60a4a337",
    "kaggle_create_only.py": "c655c00729b5b1db3b1e8832599d9088c848c098e7ad1641200c97cca12459da",
    "kaggle_transport.py": "99e44c8054eab22534399de3eef9088fcbb98406f64726ab99241d6b5054566c",
    "hepta_kaggle.py": "5579284b9655da80269a9dd9c0de535ff13ce5827d9cfcd467d9f99ea9567853",
    "tool_contract.py": "34cc0fe783cb813919964163e0fbe69efc816b3fb23bb027ea692b7c8434ae95"
  };
  const newHashes = {
    "kaggle_jobs.py": "7a4f8ea009f3761a63e7fdffc80ecc8759df68aeb6bb11e692f659d483c4ca1b",
    "kaggle_create_only.py": "9bc161048319d14e0cf855f6d4aa937478486842237b1ca6675b5b68e60e0648",
    "kaggle_transport.py": "99e44c8054eab22534399de3eef9088fcbb98406f64726ab99241d6b5054566c",
    "hepta_kaggle.py": "5cbc8455d4482f3d6223cb51f981c302780779f4a1f51325076dea4583a2f864",
    "tool_contract.py": "fd5e91d791831d6eca57594ea925e78ff3d9426d08c69c3b326f2a24d6bb89da"
  };
  const oldSha = "83cb827b69028c6312ea1560c92d9cbb6c5fd6eb0dbb5597623f98b12a76b5de";
  const newSha = "c60bc1bacac20aec5dce2e3acc18bcc30ee03cd96a686d489bafe6dc0ce16653";
  const expectedCurrent = mode === "activate" ? oldSha : newSha;
  const replacementSha = mode === "activate" ? newSha : oldSha;
  const replacement = task + (mode === "activate" ? "/proposed_account_entry.bin" : "/original_account_entry.bin");
  const journal = {schema: "ndu-fixed-entry-switch-v1", scope, mode, authorization, inspections: [], mutation_attempted: false};
  function parse(result) {
    if (result.isError) throw new Error("HEPTA_API_ERROR");
    const value = result.structuredContent || JSON.parse(result.content.find(x => x.type === "text").text);
    if (value.error) throw new Error("HEPTA_API_ERROR");
    return value;
  }
  function guard(info, path, digest) {
    if (info.path !== path || info.sha256 !== digest || typeof info.version !== "string" ||
        info.metadata?.uid !== 1000 || info.metadata?.link_count !== 1 || (info.mode & 0o022)) {
      throw new Error("EXACT_DEPLOYMENT_IDENTITY_CHANGED: " + path);
    }
  }
  async function inspect(path, digest) {
    const info = parse(await tools.mcp__codex_apps__h_file_info({host, path}));
    guard(info, path, digest);
    journal.inspections.push(info);
    return info;
  }
  try {
    const pins = Object.entries(oldHashes).map(([name, digest]) => [oldRelease + "/" + name, digest]);
    pins.push(["/home/qian-qi/.local/share/hepta-kaggle/multiaccount-v7-gpuimage-4920/account_launcher.py", "12cbbd077338b7d034531f7ba188f41d1525c96ace5a55e18c7124eacbd2affe"]);
    pins.push(["/home/qian-qi/.local/bin/hepta-compute", "ca8c564d76d49ba4475f9237d3614b8df4db5b5202e38084033fbce8224b22d6"]);
    pins.push(["/home/qian-qi/.hepta-kaggle-adoption-releases/v5-batch-4920/bootstrap_fixed.py", "673e1303d455642a7b477553cc93a6bfc3b62667f3de65a970ed2b012a6fffe0"]);
    pins.push(["/home/qian-qi/.hepta-kaggle-adoption-releases/v5-batch-4920/hepta_compute_base.py", "5b55efba3496b74a00b525b656e41617cc8157b287a69e21ea7896b1236fcb8d"]);
    if (mode === "activate") {
      pins.push(...Object.entries(newHashes).map(([name, digest]) => [newRelease + "/" + name, digest]));
      pins.push(["/home/qian-qi/.local/share/hepta-kaggle/multiaccount-cache-import-c2c548b7/account_launcher.py", "3fc7dbf0456f4dd0b300732a66508301813fdadfab16a93ddad2776ace4097e4"]);
    }
    // All checks finish before a write is considered; parallel failures are inspected.
    const outcomes = await Promise.allSettled(pins.map(([path, digest]) => inspect(path, digest)));
    const failures = outcomes.filter(x => x.status === "rejected");
    if (failures.length) throw new Error("DEPLOYMENT_PREFLIGHT_FAILED: " + failures.map(x => x.reason.message).join("; "));
    const retained = await inspect(replacement, replacementSha);
    const bytes = parse(await tools.mcp__codex_apps__h_binary_read({host, path: replacement, expected_version: retained.version, offset: 0, limit: 65536}));
    if (bytes.path !== replacement || bytes.version !== retained.version || bytes.offset !== 0 || bytes.eof !== true ||
        bytes.next_offset !== retained.size || bytes.chunk_sha256 !== replacementSha) throw new Error("RETAINED_SWITCH_BYTES_CHANGED");
    const before = await inspect(entry, expectedCurrent);
    if (before.mode !== 0o700 || before.size !== (mode === "activate" ? 295 : 300)) throw new Error("ENTRY_METADATA_CHANGED");
    journal.entry_before = before;
    journal.replacement = {path: replacement, sha256: replacementSha, bytes: retained.size};
    journal.mutation_attempted = true;
    // Native atomic compare-and-publish preserves descriptor-bound metadata and
    // rejects a concurrent version change. Never retry with a different version.
    journal.write_result = parse(await tools.mcp__codex_apps__h_binary_write({host, path: entry, expected_version: before.version, data_base64: bytes.data_base64}));
    const after = await inspect(entry, replacementSha);
    journal.entry_after = after;
    if (after.mode !== before.mode || after.metadata.uid !== before.metadata.uid || after.metadata.gid !== before.metadata.gid ||
        after.metadata.acl_sha256 !== before.metadata.acl_sha256 ||
        JSON.stringify(after.metadata.xattr_names) !== JSON.stringify(before.metadata.xattr_names) ||
        JSON.stringify(after.metadata.xattr_sha256) !== JSON.stringify(before.metadata.xattr_sha256)) {
      throw new Error("ENTRY_METADATA_VERIFICATION_FAILED");
    }
    journal.ok = true;
    journal.state = mode === "activate" ? "ENTRY_ACTIVATED_ONLY" : "ORIGINAL_ENTRY_RESTORED_ONLY";
  } catch (error) {
    journal.ok = false;
    journal.state = journal.mutation_attempted ? "RECONCILE_EXACT_ENTRY_DO_NOT_RETRY" : "NO_MUTATION";
    journal.error = String(error.message);
  }
  journal.provider_calls = 0;
  journal.ledger_or_lock_writes = 0;
  journal.rollback_limit = "Restoring the old entry does not undo official imported evidence; the old adapter cannot independently validate the new cache provenance. Never rewrite a receipt or remove payloads/locks to make rollback appear complete.";
  return journal;
}

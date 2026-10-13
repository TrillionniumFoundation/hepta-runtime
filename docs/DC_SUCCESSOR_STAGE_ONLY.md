# Successor stage-only bundle

The installed Runtime/Full Operator app remains v4. deploy/stage_dc_successor.py creates a separate reviewable successor bundle without starting a controller, tunnel or service; changing a live file; reading an authentication token; refreshing ChatGPT tools; or stopping Desktop Commander. Successful staging means the pinned files were copied correctly. It does not qualify their compilation, native execution, actual workflows, activation or DC replacement.

## Inputs and validation

The command takes a full committed source HEAD and the complete compile-input fingerprint sealed by the build, separately pinned native/facade/contract-helper/candidate-contract files, a pinned previous contract, pinned external qualification receipts, and a credential-free installed baseline pin file. All paths are absolute. The destination must be absent and its parent must already exist.

The source fingerprint is SHA256 of the canonical sorted map of every src/**/*.rs, src/**/*.py, Cargo.toml and Cargo.lock file to its byte count and SHA256. The source must match the supplied HEAD, contain no modified/untracked compile inputs, and reproduce the supplied fingerprint twice before staging. Generated lock sidecars are not compile inputs. The helper does not rebuild or execute the candidate; the caller must retain genuine build and qualification receipts. Receipt names do not imply particular tests passed.

All input snapshots use descriptor-relative no-follow traversal, trusted-owner ordinary single-link files, explicit SHA256, bounded reads and stable inode/size/timestamp observations. Symlink components, hard links, group/other-writable inputs, unexpected owners and digest mismatches are refused. Every validation completes before the first directory creation. Existing destinations are never reused or overwritten. A failed publication removes only files created within this call's new directory.

The bundled original v4 contract is fixed to SHA256 d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1. Every original 50 tool definition must remain exactly identical in the previous, candidate and installed-baseline contracts. The manifest lists added, removed and changed definitions against both the supplied previous contract and original v4. Retained tool annotation changes are refused. A changed description/schema in a post-v4 tool is an explicit delta and remains subject to review; the stage does not activate it or replace the model's scanned definition.

## Baseline pin file

Use independently observed pins from the actual installed baseline. The file must have exactly the following fields. The four artifact entries are snapshotted for rollback; the live file entries, state directory and token are references only. The helper never opens those live files. Do not put raw profiles, tokens, HTTP headers or credential values in this file.

~~~json
{
  "schema": "hepta-installed-baseline-pins-v1",
  "native": {"path": "/absolute/installed-native", "sha256": "<actual 64-hex digest>"},
  "facade": {"path": "/absolute/installed-facade.py", "sha256": "<actual 64-hex digest>"},
  "helper": {"path": "/absolute/installed-mcp_tool_contract.py", "sha256": "<actual 64-hex digest>"},
  "contract": {"path": "/absolute/installed-contract.json", "sha256": "<actual 64-hex digest>"},
  "live_files": {
    "profile": {"path": "/absolute/live-tunnel-profile", "sha256": "<actual 64-hex digest>"},
    "installed_manifest": {"path": "/absolute/live-installed-manifest", "sha256": "<actual 64-hex digest>"},
    "runtime_config": {"path": "/absolute/live-runtime-config", "sha256": "<actual 64-hex digest>"},
    "unit_dropin": {"path": "/absolute/existing-native-unit-dir/60-parity-v4.conf", "sha256": "<actual 64-hex digest>"}
  },
  "state_directory": "/absolute/existing-runtime-state",
  "auth_token_file": "/absolute/existing-private-token"
}
~~~

The token and runtime-config references must equal the corresponding CLI arguments. The existing user unit directory supplies the exact planned successor drop-in location, 70-parity-successor.conf; staging does not create that live drop-in. It preserves the previous v4 and document-worker drop-ins.

## Command

All SHA variables below must come from the actual frozen candidate/build/baseline receipts. This command does not discover, rotate or copy credentials.

~~~bash
python3 deploy/stage_dc_successor.py \
  --source-root "$SOURCE_ROOT" --source-head "$COMMITTED_HEAD" \
  --compiled-source-fingerprint "$BUILD_SOURCE_FINGERPRINT" \
  --native "$CANDIDATE_NATIVE" --native-sha256 "$NATIVE_SHA" \
  --facade "$CANDIDATE_FACADE" --facade-sha256 "$FACADE_SHA" \
  --helper "$CONTRACT_HELPER" --helper-sha256 "$HELPER_SHA" \
  --contract "$CANDIDATE_CONTRACT" --contract-sha256 "$CONTRACT_SHA" \
  --previous-contract "$PREVIOUS_CONTRACT" --previous-contract-sha256 "$PREVIOUS_SHA" \
  --baseline-pins "$BASELINE_PINS" --baseline-pins-sha256 "$BASELINE_SHA" \
  --receipt build "$BUILD_RECEIPT" "$BUILD_RECEIPT_SHA" \
  --receipt six-host "$SIX_HOST_RECEIPT" "$SIX_HOST_RECEIPT_SHA" \
  --destination "$ABSENT_PRIVATE_DESTINATION" \
  --token-file "$EXISTING_TOKEN_FILE" --runtime-config "$EXISTING_RUNTIME_CONFIG" \
  --controller-workspace "$EXISTING_CONTROLLER_WORKSPACE" \
  --upstream http://127.0.0.1:8790/mcp
~~~

The result prints only the stage destination, manifest path/hash and activated=false. Failures print only an exception type, avoiding raw inputs and credential-related diagnostics.

## Bundle and plans

The new directory is 0700. Native candidate and rollback executables are 0700; facade/helper/contracts, manifest, commands, native drop-in content and plans are 0600. Each non-manifest artifact's byte count, SHA256 and exact output mode are in manifest.json; the returned manifest SHA covers that map. Inputs remain untouched.

candidate-commands.json contains the exact planned argv. candidate-profile-template.json contains only the replacement MCP command and an exact live-profile reference, with is_runnable_tunnel_profile=false. It does not copy tunnel identity, health settings or credentials. The existing full profile must later be merged and backed up privately with all other fields preserved.

activation-plan.json and rollback-plan.json remain HOLD. They bind the staged candidate, the real baseline copies, exact existing live-file pins, preserved state/token/config references and the future successor drop-in location. Before service changes they require fresh complete dynamic six-host job/PTY/stream and dispatch inventories, old/new identity preservation, private exact-byte backups and a compatible rollback. Historical inventory counts and old 46-tool rollback qualification are not used.

Metadata/history/search credential ownership and process/PTY operator-account authority are separate. An old job missing a trusted cancel nonce/supervisor binding must not be automatically canceled or relabeled authoritative; same-ID archive access alone does not grant cancellation authority. Unknown effects are never replayed. Active nonpersistent controller-owned PTYs cannot be represented as restart-preserved.

The native and facade contracts must be a consistent exact pair; the helper adds no catalog projection. After a qualified private server change, an authorized administrator must refresh the existing ChatGPT connection, verify the changed metadata, and run genuine affected model-origin tests in a new conversation. Staging does not perform or infer that refresh. DC-off, merge/release and public publication remain separate decisions.

## Offline verification

~~~bash
python3 -m py_compile deploy/stage_dc_successor.py tests/dc_successor_stage_tests.py
python3 tests/dc_successor_stage_tests.py
~~~

These tests use disposable local Git/source/artifact fixtures. They do not run the candidate executables or contact SSH targets, services, a tunnel, authentication files or ChatGPT administration.

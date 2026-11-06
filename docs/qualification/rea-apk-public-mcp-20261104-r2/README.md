# APK signature worker: independent public MCP lifecycle qualification

These receipts qualify the public MCP route and the owned worker lifecycle for
the exact frozen binaries below; the latest corrected candidate is primary. Cryptographic fixture parity is a separate gate
owned by the APK implementation. The complete REA and Android contracts remain
unqualified.

## Frozen inputs and result

- Runtime SHA-256: `01ff4fc0127dda50f3a18a1901f77e43f900076a1cbcc32c888e76d7e0645157`.
- Runtime size: 440,160,320 bytes; optimized dev build with debug information.
- Signed reference fixture: `custom-0103-rsa.apk`, 2,688 bytes,
  SHA-256 `2319675743cca6f540fb2fe04385ddf25209d65a5f342613f4ddba0f8010aa7d`.
- Test script SHA-256: `633dd05e70696b5082f6d5f092e02a56f50ed5d43d7faf8b4ba64ff4105b1bbf`.

All six gates passed on Linux:

| Gate | Observed result |
| --- | --- |
| Public `tools/list` and `rea_inspect_apk_signature` | The tool was registered; the genuine signed fixture verified with exact captured source identity and bounded claims. |
| File and identity admission | Outside-root, symlink, directory, wrong hash and malformed hash all refused. |
| Worker parse failure | A truncated APK was rejected; the same controller successfully processed the next valid request. |
| Ordinary MCP cancellation | A pidfd-identified, deliberately stopped worker was killed and reaped by its original controller in 0.0216085 seconds, inside the unchanged 5-second budget. |
| Fixed worker deadline | With no cancellation notification, the stopped worker was killed and reaped at 30.072239 seconds after observed stop; the response named the production 30-second deadline and the next request succeeded. |
| Cold controller restart | Reinspection preserved full captured identity and source-bound signer IDs. |

Both controllers exited normally after stdin EOF. No manual worker cleanup,
controller termination or controller kill was needed. Both selected input hashes
were rechecked after the run. `post-exponent-fix-mcp.json` is the complete
machine-readable receipt. The earlier complete passing lifecycle run is retained
in `pre-exponent-fix-mcp.json` with its original binary fingerprint.

The large lifecycle input is an owned, valid classic ZIP containing a copied
test manifest and 64 MiB of stored padding. Its 67,112,482 bytes are inside the
production 128 MiB admission limit. It gives the observer time to stop the
actual parser during input transfer. It is unsigned and is not a positive
cryptographic fixture.

## Ownership and observation

The test uses no production runtime configuration, SSH host, service port or
credential. It creates an isolated controller policy with a deny-all host entry
and an explicit owned workspace. It never installs an APK or executes its
payload. The large ZIP copies only the bounded manifest from the owned test
fixture; no user package is unpacked.

Before stopping a child, the observer checks membership in the controller's
thread children lists, parent PID, worker command and the frozen executable's
device/inode identity, then sends SIGSTOP through a Linux pidfd. A passing gate
requires the stopped process to disappear from `/proc` and every parent task's
child list while the controller stays alive. A normal follow-up MCP request
must succeed. This distinguishes original-owner reaping from terminating the
controller or manually killing an abandoned child.

The cancellation stopwatch uses a fixed 5-second observation budget. The
deadline test waits for the production 30-second timeout with a fixed 35-second
observation budget. These budgets are constants in the committed test and are
not extended after observing a failure. Failure teardown is recorded separately
and cannot produce a passing receipt.

## Revision boundary and the confirmed classification regression

The previous frozen binary was
`7b5f0cd117ba37b5ab2c34f961375b647a5bf3ed6e1c0f5ba53dd369038382dc`.
Its lifecycle gates also passed, but the independent cryptographic audit found a
distinct RSA support-boundary defect.

The owned public APK uses a valid RSA 2048-bit key with exponent
`8589934609` (34 bits), and RSA PKCS#1 v1.5/SHA-256. Android `apksigner verify`
accepted it. Its exact full-file SHA-256 is
`008a67e253527e1f181d5d713fd90956c52ef7305a22fa36188c1476401ba041`
(2,714 bytes). The APK implementation owner copied that public input unchanged
as `tests/fixtures/rea_apk_signature/custom-0103-rsa34audit.apk`.

| Same exact public fixture | Before the fix | After the fix |
| --- | --- | --- |
| APK content digest | match | match |
| Leaf-certificate SPKI binding | match | match |
| Signature status | invalid | unsupported |
| Native record-set status | invalid | partial |

The [ring 0.17.14 signature documentation](https://docs.rs/ring/0.17.14/ring/signature/index.html)
limits RSA public exponents to odd integers of 2–33 bits. The old classifier
checked modulus size only and mistook this library support limit for a bad
signature. The production owner added explicit exponent validation and a
partial/unsupported classification for larger valid exponents, alongside a
separate independent 34-bit fixture and a supported 33-bit upper-bound fixture.

`rsa-exponent-before.json` retains the actual Android and old native results.
`rsa-exponent-after.json` proves that the **same original auditor input**
receives the corrected partial/unsupported result from the new frozen binary.
The six public MCP gates were then repeated with the unchanged script and
budgets; those results are the primary table above.

These are independently qualified **APK development candidates**, not the
combined release containing the Evidence and other native changes. A later
merged release must run the same script against its own frozen fingerprint.
Neither the classification fix nor the lifecycle gates establish full Android
or REA compatibility.

## Reproduce against the final release

From the repository root, select a frozen binary and the genuine supported
reference fixture. Use a fresh output directory:

```sh
python3 tests/rea_apk_signature_mcp.py \
  --binary "$REA_QUALIFIED_BINARY" \
  --binary-sha256 "$REA_QUALIFIED_BINARY_SHA256" \
  --fixture tests/fixtures/rea_apk_signature/custom-0103-rsa.apk \
  --fixture-sha256 2319675743cca6f540fb2fe04385ddf25209d65a5f342613f4ddba0f8010aa7d \
  --output "$REA_APK_MCP_OUTPUT"
```

Linux pidfd support is required; the script refuses a weaker process-identity
fallback. Allow 300 seconds for the complete command on a loaded host. It saves
incremental gate results and all MCP requests/responses in its new output
directory. The final receipt must report `status: pass`, six passing gates,
unchanged fingerprints, empty `manual_worker_cleanup`, and two normal
controller exits. Keep that final receipt attached to its exact tested release.

The repository stores only compact receipts and source/input/transcript hashes.
The frozen binary, large padding archive and full protocol logs remain outside
git.

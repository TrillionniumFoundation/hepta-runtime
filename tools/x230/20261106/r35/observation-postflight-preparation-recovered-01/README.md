# R35 observation postflight recovery and actual seal

This package preserves the exact reviewed postflight source and its real completed-observation bindings after the local workspace was lost. The recovered revision is byte-identical to the source reviewed before the outage: 15,998 bytes, SHA256 6db941beabb85baa7e6b25cf193a46cba5bb27620c392579ef5bfad2ed75c1e0. The earlier 15,919-byte draft is retained as historical preparation and must not be used.

## Current source and real outcome

The actual sealed source is postflight_r35_observation_sealed.py: 33,131 bytes, SHA256 6a7f50b8b9a6921bec9196a933889e3b03825b2d802d75dbf8e44850da3ba2c4. Local Python AST comparison verified that only ACTUAL and PAYLOAD changed from the recovered template; all seven function bodies are byte-identical.

The coordinator ran this postflight once as job 1a1afaffd3b-fc05-6ad4. The original report is included unchanged as observation-postflight-01.json, 6,370 bytes, SHA256 9a95bf8e9b8de880c15f9fa979f0f4f03dfc0ca1fb50e2270836420f5a97b977. The report records the completed original observation holder 1a1af9bb312-fc05-6a14, passing observation/performance gates, 2,304 measured calls plus 288 warmup and 72 preflight/restart calls, and 301 monitor samples.

The report also records the 220 current compiler inputs matching the qualified map. It preserves 16 original-file identities. These are source/report and holder-custody checks, not a whole-machine idle claim or a final candidate-adoption verdict.

## First snapshot before normal lifecycle

The original observation completed before normal lifecycle materialization or execution. At that capture, the coordinator explicitly declared nonlaunch and the tool checked five absent namespace paths. The report retains not_started_at_capture, the actual declaration source, and a null final lifecycle outcome. A passing observation gate sets the disposition to awaiting_normal_lifecycle. It does not predict the later lifecycle result.

The template supports a complete ordinary observation workflow with either real performance outcome. The original correctness/evidence and full seven-stage closure conditions remain. Revision 02 records the real RSS boolean instead of assuming a future RSS pass. Partial workflows, missing summaries or incomplete holder custody cannot be made to satisfy this snapshot with synthetic data.

## Original data and code boundaries

The unchanged read/create/native helpers require bounded regular singly linked files, NOFOLLOW, stable metadata, exclusive writes and full native stored/seen stream closure. The monitor ledger must match both the parent and independent audit identity; sample_count must equal its retained samples, the audit count and the actual seal.

The three embedded holder documents retain their original UTF-8 bytes via base64. Parent and other original JSON bodies were not reconstructed or round-tripped through JavaScript numbers. Only small byte lengths, counts, booleans and string identities were selected into the actual binding. Full raw originals are identified by their Git object and SHA256 in the catalog.

The tool creates only three holder original files and observation-postflight-01.json under the fixed R35 root. Existing files are never overwritten. Partial write failures would remain for inspection, with no automatic cleanup or retry. Reads and each embedded body are bounded to 8 MiB. No source, ELF, auditor, workload, cache operation or remote command is executed by the postflight.

The coordinator has already executed the actual snapshot. Do not invoke it again. If the source is inspected elsewhere, the entry point is Python 3 with no arguments; its fixed root is /home/qian/hepta-runtime-optimization-20261106-r35.

## Recovery provenance

Both pre-outage source hashes were matched before the recovered originals were published. The sealed source was separately parsed in the new local environment. recovery-record-01.json records these checks and the scope of the coordinator's execution report.

The earlier peer review's 4,392-byte body was lost before it was copied to Git. Its reported identity and verdict are recorded transparently; the body is not claimed to have been recovered, and no replacement is represented as the old b6d21e89 hash. The source to which that review referred was recovered exactly.

No x230 or Mac call, runtime execution, benchmark retry, auditor rerun or Git ref change was made by the recovery author. The actual archive and normal lifecycle remain separate workflows under the coordinator.

The peer subsequently issued peer-exact-source-confirmation.json (1,450 bytes, SHA256 618f937545d9368bfb83660a52e943c8a260903c2852913c16d895a9d1d75538), confirming the recovered original source identity. This new confirmation is included separately and does not replace the lost original review body.

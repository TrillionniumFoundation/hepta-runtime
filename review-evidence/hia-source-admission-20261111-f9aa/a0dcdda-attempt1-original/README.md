# Original archive-retention candidate failure

This directory preserves original pull-request run 43022234643, attempt 1, job 130527996979, artifact 13855932062 for Runtime a0dcdda1991ec536d5e2d252c006a778993fa566 and Hepta 7c20b6cfc792f0147b5418968f94734b8890fcca.

The ZIP is exactly 58,784,411 bytes. SHA256: 12a73eea08bde925f801050530817b66ee67c5624d81ee2dd332f68e327b07c1. Its 6,209 entries have valid CRCs. All 637 declared Hepta source files, including the four .github workflow files omitted by the older archives, are present and match the fixed Git support contract. No source supplement is used.

## Original outcome remains HOLD

| Stage | Original result |
| --- | --- |
| Source admission | 20 controls passed |
| Cold | FAIL; 6 of 11 checks; QUALIFICATION_TIMEOUT |
| Language | 1,242 checks passed |
| Native helper integration | HOLD; no checks completed |

The cold owner exceeded the unchanged 180-second qualification deadline. The cold report records 180.187798546 seconds, return code -9, and exit_observed_before_deadline=false. Owned-child cleanup completed in 0.084347305 seconds within the unchanged 3-second cleanup budget. The nested final qualification report and generation arrays were not produced. The native entry correctly refused to consume incomplete cold evidence.

The language stage ran independently and passed. The archive retention change is therefore verified as 637/637 source coverage; this does not turn the candidate joint qualification into PASS. The two successful original Runtime 7924 attempts remain separate in the parent evidence directory and in commit 82e7ce895373eef9dc313ca0c366156593584ce9.

## Custody and scope

The archive was downloaded and checked in the cloud workspace, then transferred unchanged to the operator host for durable Git preservation. Both locations independently checked the complete ZIP digest, CRCs, original source bytes, and failed reports. cloud-archive-verification.json, transfer-receipt.json, and custody.json retain those identities. reports/ contains byte-identical member copies, linked by member-copies.json; original-job.log retains the original job output.

Only member paths were used for the private-path review: no .git component, private worker sibling, SSH client_key/host_key, or agent.sock was included. The two .hia-new-stage-owner markers are expected local ownership evidence. No credential contents were displayed.

The evidence branch remains based on Runtime 7924 code and adds these a0dcdda results as data. It is not an execution of a0dcdda from the evidence branch. Original source candidates and ZIP bytes are unchanged. whole_worker_native=false and production_deployed=false remain in force.

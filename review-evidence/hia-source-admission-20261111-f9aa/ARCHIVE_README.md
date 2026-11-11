# Original HIA source admission joint evidence

This evidence-only branch retains the two original successful GitHub Actions attempts for Runtime 7924a0c3545125f7a1c3c888adc63f6515668063 and Hepta 7c20b6cfc792f0147b5418968f94734b8890fcca. Its parent is the unchanged Runtime code candidate.

| Event | Original run / attempt | Artifact ID | ZIP bytes | SHA256 |
| --- | --- | --- | ---: | --- |
| push | [43016837973](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43016837973) / 1 | 13854030779 | 64640752 | 152676ded50e6fa9c6d0380f107ef88bd9f70135344b4a3f6b9afa1c3aba9721 |
| pr | [43016939924](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43016939924) / 1 | 13853837009 | 64675363 | d56dbb51331bbab23883c586aea29cdfa014d4676e429e1de82c27d29cac9645 |

Both original jobs passed 20 source admission controls, 11 cold checks, 1,242 language checks, and 10 native helper integration checks. Each retained joint report contains 39 calls and four transport sessions. The original cold limits remain 180 seconds plus 3 seconds for cleanup.

| Event | Cold wall time in seconds | Original archive source coverage |
| --- | ---: | --- |
| push | 121.620193704 | 633 present / 4 absent |
| pr | 170.448923344 | 633 present / 4 absent |

## Original archive coverage and separate source supplements

The first independent verifier rejected the assumption that every source-manifest entry was stored inside the original ZIP. That failed verification process, its stderr, and its original STARTED custody record are retained here. It did not change either original GitHub Actions result.

Each original archive contains 633 of the 637 exact Hepta source-manifest entries. The four absent entries are .github/workflows/hia-candidate-bindings.yml, hia-compiler-extension.yml, hia-core.yml, and hia-ndu-feedback.yml. The workflow artifact upload omitted these hidden-directory files.

source-coverage-push.json and source-coverage-pr.json enumerate every manifest path as archive_present or archive_absent. Only the four actually absent paths were fetched from the fixed Hepta commit. source-supplement/manifest.json records their exact Git blob identities, SHA256 values, and sizes. The supplemental files remain outside the untouched original ZIPs.

## What was independently checked

The downloaded ZIP sizes and complete SHA256 values match GitHub artifact metadata; all member CRCs pass. Original reports agree on the exact Runtime and Hepta commits and trees. Cold and language source manifests match the selected support contract; all 637 source hashes are checked through the 633 archived sources and four pinned Git supplements. Cold compiler generations, native image bytes, helper bundle, client source digest, installation pins, compile receipt, original operation observation, replay, unknown outcome, rollback and lease assertions remain consistent.

reports/ contains exact byte copies of the original joint, cold, qualification, language, stage, and native build JSON members. member-copies.json binds each copy to its original archive and member hash. The runtime_binary_sha256 field is retained from the original report; this custody check does not independently reconstruct the Runtime executable.

custody.json records both successful archive checks separately from the earlier failed archive-completeness check. verification/ retains the commands as executed. The original workflow run and artifact metadata and original job logs are included beside the ZIPs.

## Scope

The reports retain whole_worker_native=false and production_deployed=false. They qualify the selected native helper path with the hosted worker and JSON/journal path. No production activation, new qualification run, or change to the tested code candidate was performed. Full native worker qualification remains outside this evidence.

The PR artifact name uses GitHub synthetic merge SHA 5190e1e789d5314aaed92b538ec37c27ea891961; both the checkout log and retained source identities bind the actually tested Runtime source to 7924a0c3545125f7a1c3c888adc63f6515668063.

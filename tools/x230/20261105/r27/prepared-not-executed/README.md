# Prepared R27 work that was not executed

These archives preserve the qualification and six-host campaign preparations
made before the component result was known. R27 was not promoted to either stage.
They are planning snapshots, not successful qualification or performance evidence.

- `qualification-plan-01.tar.gz` contains the launcher, fixed input, source maps,
  patch, request and preparation notes. The full source is reconstructible from
  accepted R24 plus the published two-file candidate patch; it is not duplicated
  in this archive.
- `campaign-tools-01.tar.gz` is the final prepared eleven-file campaign bundle.
- `campaign-plan-01.tar.gz` retains the campaign preparation notes, frozen inputs,
  derivation tools, local checks and independent review, excluding superseded
  bundles. It does not contain an actual campaign result.
- `qualification-file-manifest.json` records every qualification-plan archive member.
- `campaign-plan-file-manifest.json` records every campaign-plan archive member.
- `campaign-prepared-complete.json` records the final local campaign identities.

**Do not execute the qualification request unchanged.** It still names R25
`target-build-02` as a third-party cache source. Later native inventory found that
the cache/release directories existed, but the requested product fingerprint and
rlibs for the four inspected dependency names were absent. The successful component used current R26
third-party dependencies instead, with an exact fingerprint pin. Any full future
run must update and verify the qualification cache source, launcher hash and
corresponding campaign bindings together, while keeping the R24 source baseline,
two-file candidate runtime-source delta and frozen performance gates intact.

Actual qualification job/terminal/report, formatted source and candidate binary
identities remain unavailable. Expected test counts in these plans are not results.

# Root review of borrowed-directory binary HIA

The exact 67-function HIA source and fixed native bridge were frozen before any
application invocation. All 63 prior function IRs are preserved; the prior entry
is relocated from f0 to f63. The build-only stale digest failure remains FAIL.
Correcting that digest did not change any HIA, native bridge or fixture source.

The actual 59-pair domain passed on its first execution. It includes 52 borrowed
parent calls, 21 real mutation pairs and two actual one-free-FD limits. The
caller retained the same directory inode after result publication, release and
selected context destruction. The bridge does not duplicate the parent or add
it to its owned-file ledger. Eight refusals preserve every context byte.

The complete 68,863,901-byte upload was fetched independently. All 55,684 files,
1,201 directories, 2,777,462,902 logical bytes and all retained cases/controls
were re-admitted under 11 fresh read-only guards in 44.739 seconds of the
unchanged 180-second budget. No HIA or Rust application was replayed. Every
journal span and every logical buffer is retained, including unused tails and
growth attempts; observed HIA calls total 766 and journal span bytes total
2,923,196,921. Observer-off internal calls are not counted in observed journals.

This closes the private borrowed-directory primitive and the explicit actual
mutation domain. Public formatting, metadata, async/remote dispatch and full
runtime replacement remain separate. Main 5a5a35b3 is unchanged.

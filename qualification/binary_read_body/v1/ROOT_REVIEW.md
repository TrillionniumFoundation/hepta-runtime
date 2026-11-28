# Root review of the native binary read component

The actual 114 paired filesystem inputs, 15 observer-off calls and 30 private
lifecycle controls passed in run 44062962274. Source 7f497c9a was completely
frozen and all 50 source/workflow files read back before execution. The existing
368,640-byte native syscall callable was reused without rebuilding or changing
application bytes.

Independent run 44063940188 read the full uploaded ZIP, TAR, all 44,629 logical
files and 1,237 directories, every complete comparison and all physical controls.
Its actual full pure reader took 77.263 seconds of the unchanged 180-second
budget. Eleven new guard probes and 49,178 unchanged entries passed. No HIA or
Rust execution occurred during independent admission.

The observed native journal contains 2,495 body calls, 219 child calls and
2,086 raw OS effects. All 18,043 journal entries retain their complete spans,
9,803,009,450 uncompressed buffer bytes. These counts exclude the internal calls
of the 15 observer-disabled cases; their full results, arenas and filesystem
snapshots are retained. Four additional private borrow/error invocations belong
to the 30 lifecycle controls and are included in the observed journal counts.

This closes the declared immutable private Linux read/fingerprint/private-read
domain. It does not assert mutation-race equivalence, a borrowed-parent entry,
OS diagnostic formatting, metadata/publishing, SSH, public registration or async
cancellation. Those remain distinct integration work. Main remains 111 components
and nine advertised tools. No old production implementation was deleted.

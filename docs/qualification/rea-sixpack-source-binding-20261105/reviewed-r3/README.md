# Source descriptor acquisition review

Independent review reproduced two actual filesystem failures in the earlier
source reader: an already hard-linked source file could be changed through an
external alias and restored without a directory event, and opening a FIFO could
block before the regular-file validation ran. These are counterexamples for the
reader, not evidence that the selected production checkout contained such files.

The reader now opens with `O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC`, refuses nonregular
and multiply linked files, and includes the link count in its within-read identity
comparison. The same eleven-test suite is retained for the earlier and corrected
readers. The earlier reader fails the hard-link assertion and the FIFO timeout;
the corrected reader passes eleven tests. The FIFO observer is an owned child;
the regression uses subprocess timeout handling that kills and reaps it.

The observed source hashes, commands, return codes and exact output hashes are
in `red.json` and `green.json`. These controls do not remove the documented trust
in the local operator or claim protection against arbitrary malicious same-UID
rewrites of source and receipts.

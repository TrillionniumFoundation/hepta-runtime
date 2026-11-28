# Audit record callable reader recovery

The frozen f7273eb producer completed the native build, all 219 cases / 459 operations with the observer enabled, the same full domain with the observer disabled, and 45 admission/refusal/recovery controls. Its qualification remains FAIL: the newly written pure control reader expected one missing-file lookup. The unchanged original read_record performs the pending-file lookup and then the permanent-file lookup. All 45 saved contexts contain three owner calls, zero codec calls, two filesystem effects, and final sequence two.

The independent dc541116 inspection read every byte and mode in all 44,786 original files, then all physical control and ordinary outer buffers. It confirmed the exact same request and two complete ENOENT effects. This package changes only the pure control reader, in a separate explicitly bound namespace. Original source, evidence, process receipts, failure proofs, and HIA/GAS/packer bytes remain unchanged.

Each pure phase retains its 180-second limit. All 13 physical refusals, two complete independently relocated copies, and twelve unchanged-byte guard probes per read are retained. No native image or Rust reference is executed during recovery. Archive/HOT_CACHE, begin/finish callers, public handlers, and whole runtime qualification remain false.

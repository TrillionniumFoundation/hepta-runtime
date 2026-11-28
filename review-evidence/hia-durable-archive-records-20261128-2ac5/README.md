# Original audit archive record types

The new HIA owner parses the original raw JSON bytes for ArchiveAnchor, ShardAnchor, and InitIntent. The original derives run in the complete fixed abc9ecb95ee9538518ec3f36c47b881974107021 Rust dependency graph, with unchanged Cargo lock, default features, and release profile. The ancestor 7815 checkpoint retains the complete graph provenance; this checkpoint rechecks all 360 original crate archives and all 309 registry packages used by this specific original build.

The actual gate compared 3,024 raw inputs byte for byte and ran 45 additional frame, capacity, and output-boundary controls. All passed. The original full build took 168.340821 seconds; the native module compile took 2.320117 seconds and the comparison took 2.820541 seconds. Complete inputs, stdout/stderr, original executable, compiled HIA artifacts, physical source snapshots, and transport readbacks are retained in the archive.

The typed owner preserves raw file limits of 2,048 and 65,536 bytes and the original Option/sequence behavior. It intentionally applies no 256-shard policy to the Vec type: that belongs to the separate v12 filesystem and topology admission. Unknown fields, duplicates, malformed input, integer overflow, and capacity failures retain their declared rejection domains.

This checkpoint does not qualify retained filesystem anchors, archive initialization/recovery, the redb index, or the ten public Durable Requests handlers. Those remain ongoing work. The native owner and its compiler source are HIA; the Rust executable is an independent fixed oracle, and Python scripts are qualification/authoring tools.

complete-originals.tar.gz is content-addressed. Its manifest.json maps every logical original path to exact bytes, SHA-256, mode, and captured physical identity; the archive contains every referenced complete object. Every member was reread and compared before this commit.

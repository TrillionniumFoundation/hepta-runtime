// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
mod audit {
use super::*;
#[derive(Clone, Copy, PartialEq, Eq)]
struct ArchiveStamp {
	device: u64,
	inode: u64,
	modified: (i64, i64),
	changed: (i64, i64),
	namespace: super::namespace_version::Version,
}
fn private_directory_metadata(directory: &File) -> Result<std::fs::Metadata> {
	use std::os::unix::fs::MetadataExt;
	let metadata = directory.metadata()?;
	if !metadata.is_dir()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o700
	{
		bail!("private request audit directory refused");
	}
	Ok(metadata)
}
fn archive_stamp(directory: &File) -> Result<ArchiveStamp> {
	use std::os::unix::fs::MetadataExt;
	let metadata = private_directory_metadata(directory)?;
	Ok(ArchiveStamp {
		device: metadata.dev(),
		inode: metadata.ino(),
		modified: (metadata.mtime(), metadata.mtime_nsec()),
		changed: (metadata.ctime(), metadata.ctime_nsec()),
		namespace: super::namespace_version::version(directory)?,
	})
}

pub(super) fn observed_stamp(directory: &File) -> Result<Vec<u8>> {
    let stamp = archive_stamp(directory)?;
    let mut raw = vec![0;112];
    raw[..8].copy_from_slice(b"HRAST001");
    for (index,value) in [stamp.device,stamp.inode,stamp.modified.0 as u64,stamp.modified.1 as u64,
        stamp.changed.0 as u64,stamp.changed.1 as u64].into_iter().enumerate() {
        put(&mut raw,8+index*8,value);
    }
    match stamp.namespace {
        namespace_version::Version::Watch(first,second) => {
            put(&mut raw,56,1);put(&mut raw,64,first);put(&mut raw,72,second);
        }
        namespace_version::Version::Fingerprint(digest) => {
            put(&mut raw,56,2);raw[80..].copy_from_slice(&digest);
        }
    }
    Ok(raw)
}
}

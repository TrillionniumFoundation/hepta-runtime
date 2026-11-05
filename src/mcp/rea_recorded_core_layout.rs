// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Recorded ABI layouts and labels from the frozen reference dependencies.
//!
//! Verified against pwntools 4.15.0 `pwnlib/elf/datatypes.py` SHA-256
//! 474fd89de246251ce145f6b5a46cedc8dd1cec4221fbbaea4ce76a5f5a7cb233
//! and pyelftools 0.33 `elftools/elf/enums.py` SHA-256
//! 4d975df4e75de4433cc673dfc7524a9a302792b1d2ec087a649dd24f120dad88.
//! These are byte layouts and names, not a claim that those libraries execute here.

use super::{u16_at, CoreFailure};
use serde_json::{json, Value};

#[path = "rea_recorded_core_sections.rs"]
mod sections;

pub(super) const MAX_SECTION_CONSTRUCTORS: usize = sections::MAX_SECTION_CONSTRUCTORS;

// The selected pwntools ctypes is a 32-byte prefix, not Linux's usual entire
// 128-byte siginfo_t. Additional recorded bytes remain in the original descriptor.
pub(super) const SIGINFO_SIZE: usize = 32;

const AMD64_REGISTERS: [&str; 27] = [
	"r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
	"rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs",
	"gs",
];
const AARCH64_REGISTERS: [&str; 34] = [
	"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
	"x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
	"x28", "x29", "x30", "sp", "pc", "pstate",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Architecture {
	X86_64,
	Aarch64,
}

impl Architecture {
	pub(super) fn name(self) -> &'static str {
		match self {
			Self::X86_64 => "x86_64-little-endian",
			Self::Aarch64 => "aarch64-little-endian",
		}
	}

	pub(super) fn label(self) -> &'static str {
		match self {
			Self::X86_64 => "x86-64",
			Self::Aarch64 => "AArch64",
		}
	}

	pub(super) fn prstatus_size(self) -> usize {
		match self {
			Self::X86_64 => 336,
			Self::Aarch64 => 392,
		}
	}

	pub(super) fn registers(self) -> &'static [&'static str] {
		match self {
			Self::X86_64 => &AMD64_REGISTERS,
			Self::Aarch64 => &AARCH64_REGISTERS,
		}
	}
}

pub(super) fn core_note_type(value: u32) -> Value {
	let label = match value {
		1 => "NT_PRSTATUS",
		2 => "NT_FPREGSET",
		3 => "NT_PRPSINFO",
		4 => "NT_TASKSTRUCT",
		6 => "NT_AUXV",
		0x5349_4749 => "NT_SIGINFO",
		0x4649_4c45 => "NT_FILE",
		_ => return json!(value),
	};
	json!(label)
}

pub(super) fn program_type(value: u32, architecture: Architecture) -> Value {
	let label = match value {
		0 => "PT_NULL",
		1 => "PT_LOAD",
		2 => "PT_DYNAMIC",
		3 => "PT_INTERP",
		4 => "PT_NOTE",
		5 => "PT_SHLIB",
		6 => "PT_PHDR",
		7 => "PT_TLS",
		0x6000_0000 => "PT_LOOS",
		0x6fff_ffff => "PT_HIOS",
		0x6474_e550 => "PT_GNU_EH_FRAME",
		0x6474_e551 => "PT_GNU_STACK",
		0x6474_e552 => "PT_GNU_RELRO",
		0x6474_e553 => "PT_GNU_PROPERTY",
		0x7000_0000 if architecture == Architecture::Aarch64 => "PT_AARCH64_ARCHEXT",
		0x7000_0001 if architecture == Architecture::Aarch64 => "PT_AARCH64_UNWIND",
		_ => return json!(value),
	};
	json!(label)
}

pub(super) fn program_count(
	content: &[u8],
	work_remaining: &mut usize,
) -> Result<u64, CoreFailure> {
	let count = u16_at(content, 56)?;
	if count != 0xffff {
		return Ok(u64::from(count));
	}
	sections::extended_program_count(content, work_remaining)
}

pub(super) fn validate_dynamic_segment(
	content: &[u8],
	segment_offset: u64,
	work_remaining: &mut usize,
) -> Result<(), CoreFailure> {
	sections::validate_dynamic_segment(content, segment_offset, work_remaining)
}

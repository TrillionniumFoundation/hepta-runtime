// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Borrow fully validated command text until a lookup or inventory selects its fields.
use serde::de::{Deserializer, Visitor};
use serde::Deserialize;
use std::borrow::Cow;
use std::fmt;

// Unlike IgnoredAny this rejects numbers, arrays, objects, booleans and null.
// Plain JSON strings borrow the input. Escaped strings retain their decoded
// data so selected originals can be materialized without a second parse.
pub(super) struct BorrowedJobString<'a>(Cow<'a, str>);

impl BorrowedJobString<'_> {
	pub(super) fn into_owned(self) -> String {
		self.0.into_owned()
	}

	#[cfg(test)]
	pub(super) fn is_borrowed(&self) -> bool {
		matches!(self.0, Cow::Borrowed(_))
	}
}

impl<'de> Deserialize<'de> for BorrowedJobString<'de> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct StringVisitor;

		impl<'de> Visitor<'de> for StringVisitor {
			type Value = BorrowedJobString<'de>;

			fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
				formatter.write_str("a string")
			}

			fn visit_borrowed_str<E: serde::de::Error>(
				self,
				value: &'de str,
			) -> Result<Self::Value, E> {
				Ok(BorrowedJobString(Cow::Borrowed(value)))
			}

			fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
				Ok(BorrowedJobString(Cow::Owned(value.to_owned())))
			}

			fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
				Ok(BorrowedJobString(Cow::Owned(value)))
			}
		}

		deserializer.deserialize_str(StringVisitor)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ValidatedJobString;

impl<'de> Deserialize<'de> for ValidatedJobString {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct StringVisitor;
		impl<'de> Visitor<'de> for StringVisitor {
			type Value = ValidatedJobString;
			fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
				formatter.write_str("a string")
			}
			fn visit_str<E: serde::de::Error>(self, _value: &str) -> Result<Self::Value, E> {
				Ok(ValidatedJobString)
			}
			fn visit_borrowed_str<E: serde::de::Error>(
				self,
				_value: &'de str,
			) -> Result<Self::Value, E> {
				Ok(ValidatedJobString)
			}
			fn visit_string<E: serde::de::Error>(self, _value: String) -> Result<Self::Value, E> {
				Ok(ValidatedJobString)
			}
		}
		// serde_json still checks escapes and Unicode. Only the second, retained
		// copy is avoided; IgnoredAny would incorrectly accept non-string fields.
		deserializer.deserialize_str(StringVisitor)
	}
}

impl serde::Serialize for ValidatedJobString {
	fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
		Err(serde::ser::Error::custom(
			"validated discarded job text cannot be serialized",
		))
	}
}

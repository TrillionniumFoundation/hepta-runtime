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
// Appended only inside the complete original caller_scope module for qualification.
// These helpers read private observation fields; they do not implement resolution.
pub(crate) fn fixture_authenticated(scope: &OwnerScope) -> bool {
	scope.authenticated
}

pub(crate) fn fixture_bound(binding: &SessionOwnerBinding) -> Option<(String, bool)> {
	binding
		.0
		.lock()
		.unwrap()
		.as_ref()
		.map(|scope| (scope.owner.clone(), scope.authenticated))
}

pub(crate) fn fixture_owner(scope: &AuthenticatedOperatorScope) -> &str {
	&scope.owner
}

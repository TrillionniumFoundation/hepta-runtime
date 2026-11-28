// Copyright 2026 Muvon Un Limited
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

// Fixture-owned metadata supply and explicit installed projection; all policy is original.
const INSTALLED_TOOLS: &[&str] = &["directory_create", "directory_move", "effective_config", "execution_shadow_admit", "extract_lines", "file_move", "host_list", "text_editor", "text_file_write", "view", "workdir"];
struct FixtureToolRouter;
impl FixtureToolRouter {
    fn list_all(&self) -> Vec<Tool> {
        let tools: Vec<Tool> = serde_json::from_str(include_str!("../raw-catalog-input.json")).expect("retained original Tool array");
        assert_eq!(tools.len(), 136);
        tools
    }
}
impl OctofsServer { fn tool_router() -> FixtureToolRouter { FixtureToolRouter } }

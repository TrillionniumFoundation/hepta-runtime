// Fixture-owned metadata supply and explicit installed projection; all policy is original.
const INSTALLED_TOOLS: &[&str] = &["directory_create", "directory_move", "effective_config", "execution_shadow_admit", "extract_lines", "file_move", "host_list", "text_editor", "view", "workdir"];
struct FixtureToolRouter;
impl FixtureToolRouter {
    fn list_all(&self) -> Vec<Tool> {
        let tools: Vec<Tool> = serde_json::from_str(include_str!("../raw-catalog-input.json")).expect("retained original Tool array");
        assert_eq!(tools.len(), 136);
        tools
    }
}
impl OctofsServer { fn tool_router() -> FixtureToolRouter { FixtureToolRouter } }

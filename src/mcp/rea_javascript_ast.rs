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

//! Oxc AST and lexical-symbol inspection. Matches are structural observations;
//! no branch, module loader, Electron process or function body is executed.

use anyhow::{bail, Result};
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{walk, Visit};
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::{Scoping, SemanticBuilder, SymbolId};
use oxc_span::{SourceType, Span};
use oxc_syntax::module_record::{ExportExportName, ExportImportName, ExportLocalName};
use serde_json::{json, Value};
use std::collections::{hash_map::Entry, HashMap, VecDeque};

use super::{AdmittedSource, JavascriptModuleKind, JavascriptSyntax, MAX_ROWS};

const MAX_AST_NODES: usize = 200_000;
const MAX_TEXT_BYTES: usize = 8192;

#[derive(Default)]
pub(super) struct ModuleAnalysis {
	pub imports: Vec<Value>,
	pub exports: Vec<Value>,
	pub electron_calls: Vec<Value>,
	pub unknowns: Vec<Value>,
	pub node_count: usize,
	pub scope_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ElectronValue {
	Namespace,
	IpcMain,
	IpcRenderer,
	ContextBridge,
	BrowserWindowConstructor,
	BrowserWindow,
	WebContents,
}

fn electron_component(name: &str) -> Option<ElectronValue> {
	match name {
		"ipcMain" => Some(ElectronValue::IpcMain),
		"ipcRenderer" => Some(ElectronValue::IpcRenderer),
		"contextBridge" => Some(ElectronValue::ContextBridge),
		"BrowserWindow" => Some(ElectronValue::BrowserWindowConstructor),
		_ => None,
	}
}

fn literal<'a>(expression: &'a Expression<'_>) -> Option<&'a str> {
	match expression.get_inner_expression() {
		Expression::StringLiteral(value) if !value.lone_surrogates => Some(value.value.as_str()),
		Expression::TemplateLiteral(value)
			if value.expressions.is_empty()
				&& value.quasis.len() == 1
				&& !value.quasis[0].lone_surrogates =>
		{
			value.quasis[0].value.cooked.map(|value| value.as_str())
		}
		_ => None,
	}
}

fn argument_literal<'a>(argument: Option<&'a Argument<'_>>) -> Option<&'a str> {
	argument.and_then(Argument::as_expression).and_then(literal)
}

fn unbound_identifier(expression: &Expression<'_>, name: &str, scoping: &Scoping) -> bool {
	let Expression::Identifier(identifier) = expression.get_inner_expression() else {
		return false;
	};
	identifier.name == name
		&& identifier
			.reference_id
			.get()
			.is_some_and(|id| scoping.get_reference(id).symbol_id().is_none())
}

fn unbound_require<'a, 'b>(
	expression: &'b Expression<'a>,
	scoping: &Scoping,
) -> Option<&'b CallExpression<'a>> {
	match expression.get_inner_expression() {
		Expression::CallExpression(call)
			if !call.optional && unbound_identifier(&call.callee, "require", scoping) =>
		{
			Some(call)
		}
		_ => None,
	}
}

fn resolved_electron(
	expression: &Expression<'_>,
	scoping: &Scoping,
	bindings: &HashMap<SymbolId, ElectronValue>,
	depth: usize,
) -> Option<ElectronValue> {
	if depth > 16 {
		return None;
	}
	if let Expression::Identifier(identifier) = expression.get_inner_expression() {
		let reference = identifier.reference_id.get()?;
		let symbol = scoping.get_reference(reference).symbol_id()?;
		return bindings.get(&symbol).copied();
	}
	if let Some(call) = unbound_require(expression, scoping) {
		return (call.arguments.len() == 1
			&& argument_literal(call.arguments.first()) == Some("electron"))
		.then_some(ElectronValue::Namespace);
	}
	if let Expression::NewExpression(constructor) = expression.get_inner_expression() {
		return (resolved_electron(&constructor.callee, scoping, bindings, depth + 1)
			== Some(ElectronValue::BrowserWindowConstructor))
		.then_some(ElectronValue::BrowserWindow);
	}
	let member = expression.get_member_expr()?;
	let object = resolved_electron(member.object(), scoping, bindings, depth + 1)?;
	let property = member.static_property_name()?;
	match object {
		ElectronValue::Namespace => electron_component(property),
		ElectronValue::BrowserWindow if property == "webContents" => {
			Some(ElectronValue::WebContents)
		}
		_ => None,
	}
}

#[derive(Clone)]
struct DeferredValue {
	source: SymbolId,
	components: Vec<ElectronValue>,
}

// A lexical module alias has at most one source symbol. Retain that symbol
// and bounded namespace component selections, without retaining AST references
// or recursively following aliases. Constructed objects are not new alias roots.
fn deferred_electron(
	expression: &Expression<'_>,
	scoping: &Scoping,
	depth: usize,
) -> Option<DeferredValue> {
	if depth > 16 {
		return None;
	}
	if let Expression::Identifier(identifier) = expression.get_inner_expression() {
		let reference = identifier.reference_id.get()?;
		return Some(DeferredValue {
			source: scoping.get_reference(reference).symbol_id()?,
			components: Vec::new(),
		});
	}
	let member = expression.get_member_expr()?;
	let component = electron_component(member.static_property_name()?)?;
	let mut value = deferred_electron(member.object(), scoping, depth + 1)?;
	value.components.push(component);
	Some(value)
}

struct DeferredBinding {
	target: SymbolId,
	value: DeferredValue,
}

struct Bindings<'s> {
	scoping: &'s Scoping,
	values: HashMap<SymbolId, ElectronValue>,
	definition_counts: HashMap<SymbolId, usize>,
	deferred: Vec<DeferredBinding>,
	imports_only: bool,
}

impl Bindings<'_> {
	fn insert(&mut self, identifier: &BindingIdentifier<'_>, value: ElectronValue) {
		if let Some(symbol) = identifier.symbol_id.get() {
			// An assignment makes the initial Electron binding an unsafe receiver
			// inference. Property mutation remains an explicit graph limitation.
			if !self.scoping.symbol_is_mutated(symbol) {
				self.values.insert(symbol, value);
			}
		}
	}

	fn bind_pattern(&mut self, pattern: &BindingPattern<'_>, value: ElectronValue) {
		match pattern {
			BindingPattern::BindingIdentifier(identifier) => self.insert(identifier, value),
			BindingPattern::ObjectPattern(pattern) if value == ElectronValue::Namespace => {
				for property in &pattern.properties {
					if let (Some(name), BindingPattern::BindingIdentifier(identifier)) =
						(property.key.static_name(), &property.value)
					{
						if let Some(component) = electron_component(name.as_ref()) {
							self.insert(identifier, component);
						}
					}
				}
			}
			_ => {}
		}
	}

	fn defer(&mut self, identifier: &BindingIdentifier<'_>, value: DeferredValue) {
		if let Some(target) = identifier.symbol_id.get() {
			if !self.scoping.symbol_is_mutated(target)
				&& !self.scoping.symbol_is_mutated(value.source)
			{
				self.deferred.push(DeferredBinding { target, value });
			}
		}
	}

	fn defer_pattern(&mut self, pattern: &BindingPattern<'_>, value: DeferredValue) {
		match pattern {
			BindingPattern::BindingIdentifier(identifier) => self.defer(identifier, value),
			BindingPattern::ObjectPattern(pattern) => {
				for property in &pattern.properties {
					if let (Some(name), BindingPattern::BindingIdentifier(identifier)) =
						(property.key.static_name(), &property.value)
					{
						if let Some(component) = electron_component(name.as_ref()) {
							let mut selected = value.clone();
							selected.components.push(component);
							self.defer(identifier, selected);
						}
					}
				}
			}
			_ => {}
		}
	}

	fn resolve_deferred(&mut self) {
		let mut dependents: HashMap<SymbolId, Vec<DeferredBinding>> = HashMap::new();
		for binding in std::mem::take(&mut self.deferred) {
			// Preserve every value already learned by the existing passes. Only
			// unique declarations can add new facts; redeclarations stay unknown.
			if !self.values.contains_key(&binding.target)
				&& self.definition_counts.get(&binding.target) == Some(&1)
				&& self
					.definition_counts
					.get(&binding.value.source)
					.copied()
					.unwrap_or(0) <= 1
			{
				dependents
					.entry(binding.value.source)
					.or_default()
					.push(binding);
			}
		}
		let mut ready: VecDeque<_> = self.values.keys().copied().collect();
		while let Some(source) = ready.pop_front() {
			let value = self.values[&source];
			// The fixed npm control recognizes the constructor alias, but not
			// its constructed-object/WebContents alias chain. Preserve that
			// boundary while leaving pre-existing instance observations intact.
			if matches!(
				value,
				ElectronValue::BrowserWindow | ElectronValue::WebContents
			) {
				continue;
			}
			if let Some(bindings) = dependents.remove(&source) {
				for binding in bindings {
					if let Entry::Vacant(entry) = self.values.entry(binding.target) {
						if let Some(value) = binding.value.components.into_iter().try_fold(
							value,
							|value, component| {
								(value == ElectronValue::Namespace).then_some(component)
							},
						) {
							entry.insert(value);
							ready.push_back(binding.target);
						}
					}
				}
			}
		}
		// Each admitted declaration/edge is processed at most once. Cycles
		// without a proven Electron seed never enter the queue. The existing
		// AST-node cap bounds storage; initializer steps retain the depth cap.
	}
}

impl<'a> Visit<'a> for Bindings<'_> {
	fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
		if !self.imports_only {
			if let Some(symbol) = identifier.symbol_id.get() {
				*self.definition_counts.entry(symbol).or_default() += 1;
			}
		}
	}

	fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'a>) {
		if declaration.source.value == "electron"
			&& !matches!(declaration.import_kind, ImportOrExportKind::Type)
		{
			if let Some(specifiers) = &declaration.specifiers {
				for specifier in specifiers {
					match specifier {
						ImportDeclarationSpecifier::ImportSpecifier(specifier)
							if !matches!(specifier.import_kind, ImportOrExportKind::Type) =>
						{
							if let Some(component) =
								electron_component(specifier.imported.name().as_ref())
							{
								self.insert(&specifier.local, component);
							}
						}
						ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => {
							self.insert(&specifier.local, ElectronValue::Namespace);
						}
						ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => {
							self.insert(&specifier.local, ElectronValue::Namespace);
						}
						_ => {}
					}
				}
			}
		}
	}

	fn visit_variable_declarator(&mut self, declaration: &VariableDeclarator<'a>) {
		if !self.imports_only {
			if let Some(expression) = &declaration.init {
				if let Some(value) = resolved_electron(expression, self.scoping, &self.values, 0) {
					self.bind_pattern(&declaration.id, value);
				} else if let Some(value) = deferred_electron(expression, self.scoping, 0) {
					self.defer_pattern(&declaration.id, value);
				}
			}
		}
		walk::walk_variable_declarator(self, declaration);
	}
}

enum Collection {
	Imports,
	Exports,
	Electron,
	Unknowns,
}

struct Observations<'s> {
	source_id: &'s str,
	scoping: &'s Scoping,
	bindings: &'s HashMap<SymbolId, ElectronValue>,
	result: ModuleAnalysis,
	error: Option<String>,
}

impl Observations<'_> {
	fn add(&mut self, collection: Collection, span: Span, mut value: Value) {
		if self.error.is_some() {
			return;
		}
		let count = self.result.imports.len()
			+ self.result.exports.len()
			+ self.result.electron_calls.len()
			+ self.result.unknowns.len();
		if count >= MAX_ROWS {
			self.error = Some("JavaScript AST inventory exceeds 10000 rows".into());
			return;
		}
		if value.to_string().len() > 32 * 1024 {
			self.error = Some("JavaScript AST observation exceeds 32 KiB".into());
			return;
		}
		value["source_id"] = json!(self.source_id);
		value["span"] = json!({"start":span.start,"end":span.end,"unit":"utf8_bytes"});
		match collection {
			Collection::Imports => self.result.imports.push(value),
			Collection::Exports => self.result.exports.push(value),
			Collection::Electron => self.result.electron_calls.push(value),
			Collection::Unknowns => self.result.unknowns.push(value),
		}
	}

	fn dependency(
		&mut self,
		span: Span,
		kind: &str,
		specifier: Option<&str>,
		type_only: bool,
		declaration_type_only: bool,
	) {
		if specifier.is_some_and(|value| value.len() > MAX_TEXT_BYTES) {
			self.error = Some("JavaScript module specifier exceeds 8192 bytes".into());
			return;
		}
		self.add(
			Collection::Imports,
			span,
			json!({
				"kind":kind,"specifier":specifier,"type_only":type_only,
				// Inline type specifiers can leave an empty runtime import/export.
				// Keep their syntax distinct from whole-declaration type erasure.
				"type_only_scope":if declaration_type_only {"declaration"}
					else if type_only {"named_specifiers"} else {"none"},
				"bindings":[]
			}),
		);
		if specifier.is_none() {
			self.unknown(span, "dynamic_module_specifier", kind);
		}
	}

	fn unknown(&mut self, span: Span, kind: &str, detail: &str) {
		self.add(
			Collection::Unknowns,
			span,
			json!({"kind":kind,"detail":detail}),
		);
	}

	fn electron_call(&mut self, call: &CallExpression<'_>) {
		let Some(member) = call.callee.get_member_expr() else {
			return;
		};
		let Some(receiver) = resolved_electron(member.object(), self.scoping, self.bindings, 0)
		else {
			return;
		};
		let Some(method) = member.static_property_name() else {
			self.unknown(
				call.span,
				"dynamic_electron_method",
				"method is not a static property name",
			);
			return;
		};
		let (api, role, channel_argument) = match (receiver, method) {
			(ElectronValue::IpcMain, "handle" | "handleOnce") => ("ipcMain", "invoke_handler", 0),
			(ElectronValue::IpcMain, "on" | "once" | "addListener") => {
				("ipcMain", "message_handler", 0)
			}
			(ElectronValue::IpcRenderer, "invoke") => ("ipcRenderer", "invoke_sender", 0),
			(ElectronValue::IpcRenderer, "send" | "sendSync" | "postMessage") => {
				("ipcRenderer", "message_sender", 0)
			}
			(ElectronValue::IpcRenderer, "on" | "once" | "addListener") => {
				("ipcRenderer", "renderer_handler", 0)
			}
			(ElectronValue::WebContents, "send" | "postMessage") => {
				("webContents", "renderer_sender", 0)
			}
			(ElectronValue::ContextBridge, "exposeInMainWorld") => {
				("contextBridge", "bridge_exposure", 0)
			}
			(ElectronValue::ContextBridge, "exposeInIsolatedWorld") => {
				("contextBridge", "bridge_exposure", 1)
			}
			_ => return,
		};
		let channel = argument_literal(call.arguments.get(channel_argument));
		if channel.is_some_and(|value| value.len() > MAX_TEXT_BYTES) {
			self.error = Some("Electron channel or exposure key exceeds 8192 bytes".into());
			return;
		}
		self.add(
			Collection::Electron,
			call.span,
			json!({
				"api":api,"method":method,"role":role,
				"channel":(role != "bridge_exposure").then_some(channel).flatten(),
				"exposure_key":(role == "bridge_exposure").then_some(channel).flatten(),
				"argument_count":call.arguments.len(),
				"optional":call.optional || member.optional(),
				"binding_basis":"lexical_symbol_from_electron_import_or_unbound_require",
				"runtime_observed":false
			}),
		);
		if channel.is_none() {
			self.unknown(
				call.span,
				"dynamic_electron_channel_or_key",
				"non-literal or missing argument",
			);
		}
	}

	fn commonjs_target(&self, expression: &AssignmentTarget<'_>) -> Option<Option<String>> {
		let member = expression
			.as_simple_assignment_target()?
			.as_member_expression()?;
		let property = member.static_property_name();
		if unbound_identifier(member.object(), "exports", self.scoping) {
			return Some(property.map(str::to_owned));
		}
		if property == Some("exports")
			&& unbound_identifier(member.object(), "module", self.scoping)
		{
			return Some(Some("*".into()));
		}
		let object = member.object().get_member_expr()?;
		if object.static_property_name() == Some("exports")
			&& unbound_identifier(object.object(), "module", self.scoping)
		{
			return Some(property.map(str::to_owned));
		}
		None
	}
}

impl<'a> Visit<'a> for Observations<'_> {
	fn visit_string_literal(&mut self, value: &StringLiteral<'a>) {
		if value.lone_surrogates {
			self.error =
				Some("JavaScript graph does not normalize lone-surrogate string values".into());
		}
	}

	fn visit_template_element(&mut self, value: &TemplateElement<'a>) {
		if value.lone_surrogates {
			self.error =
				Some("JavaScript graph does not normalize lone-surrogate template values".into());
		}
	}

	fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'a>) {
		self.dependency(
			declaration.span,
			"esm_import",
			Some(declaration.source.value.as_str()),
			matches!(declaration.import_kind, ImportOrExportKind::Type)
				|| declaration.specifiers.as_ref().is_some_and(|specifiers| {
					!specifiers.is_empty()
						&& specifiers.iter().all(|specifier| {
							matches!(
								specifier,
								ImportDeclarationSpecifier::ImportSpecifier(specifier)
								if matches!(specifier.import_kind, ImportOrExportKind::Type)
							)
						})
				}),
			matches!(declaration.import_kind, ImportOrExportKind::Type),
		);
		if self.error.is_none() {
			let bindings: Vec<_> = declaration
				.specifiers
				.iter()
				.flatten()
				.map(|specifier| {
					let (kind, imported, local, span, type_only) = match specifier {
						ImportDeclarationSpecifier::ImportSpecifier(specifier) => (
							"named",
							specifier.imported.name().to_string(),
							specifier.local.name.as_str(),
							specifier.span,
							matches!(specifier.import_kind, ImportOrExportKind::Type),
						),
						ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => (
							"default",
							"default".to_owned(),
							specifier.local.name.as_str(),
							specifier.span,
							false,
						),
						ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => (
							"namespace",
							"*".to_owned(),
							specifier.local.name.as_str(),
							specifier.span,
							false,
						),
					};
					json!({"kind":kind,"imported_name":imported,"local_name":local,
					"type_only":type_only || matches!(declaration.import_kind, ImportOrExportKind::Type),
					"span":{"start":span.start,"end":span.end,"unit":"utf8_bytes"}})
				})
				.collect();
			let bindings = json!(bindings);
			if bindings.to_string().len() > 32 * 1024 {
				self.error = Some("JavaScript import bindings exceed 32 KiB".into());
			} else if let Some(row) = self.result.imports.last_mut() {
				row["bindings"] = bindings;
			}
		}
		walk::walk_import_declaration(self, declaration);
	}

	fn visit_export_from_declaration(&mut self, declaration: &ExportFromDeclaration<'a>) {
		self.dependency(
			declaration.span,
			"esm_reexport",
			Some(declaration.source.value.as_str()),
			matches!(declaration.export_kind, ImportOrExportKind::Type)
				|| (!declaration.specifiers.is_empty()
					&& declaration.specifiers.iter().all(|specifier| {
						matches!(specifier.export_kind, ImportOrExportKind::Type)
					})),
			matches!(declaration.export_kind, ImportOrExportKind::Type),
		);
		walk::walk_export_from_declaration(self, declaration);
	}

	fn visit_export_all_declaration(&mut self, declaration: &ExportAllDeclaration<'a>) {
		self.dependency(
			declaration.span,
			"esm_reexport_all",
			Some(declaration.source.value.as_str()),
			matches!(declaration.export_kind, ImportOrExportKind::Type),
			matches!(declaration.export_kind, ImportOrExportKind::Type),
		);
		walk::walk_export_all_declaration(self, declaration);
	}

	fn visit_import_expression(&mut self, expression: &ImportExpression<'a>) {
		self.dependency(
			expression.span,
			"dynamic_import",
			literal(&expression.source),
			false,
			false,
		);
		walk::walk_import_expression(self, expression);
	}

	fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
		if !call.optional && unbound_identifier(&call.callee, "require", self.scoping) {
			self.dependency(
				call.span,
				"commonjs_require",
				argument_literal(call.arguments.first()),
				false,
				false,
			);
		}
		self.electron_call(call);
		walk::walk_call_expression(self, call);
	}

	fn visit_assignment_expression(&mut self, expression: &AssignmentExpression<'a>) {
		if let Some(name) = self.commonjs_target(&expression.left) {
			self.add(
				Collection::Exports,
				expression.span,
				json!({
					"kind":"commonjs_assignment","exported_name":name,"type_only":false,
					"runtime_observed":false
				}),
			);
			if name.is_none() {
				self.unknown(
					expression.span,
					"dynamic_commonjs_export",
					"computed export property",
				);
			}
		}
		walk::walk_assignment_expression(self, expression);
	}

	fn visit_new_expression(&mut self, expression: &NewExpression<'a>) {
		if resolved_electron(&expression.callee, self.scoping, self.bindings, 0)
			== Some(ElectronValue::BrowserWindowConstructor)
		{
			let mut preload = None;
			let mut preload_present = false;
			if let Some(Expression::ObjectExpression(options)) = expression
				.arguments
				.first()
				.and_then(Argument::as_expression)
				.map(Expression::get_inner_expression)
			{
				for property in &options.properties {
					if let ObjectPropertyKind::ObjectProperty(property) = property {
						if property.key.static_name().as_deref() == Some("webPreferences") {
							if let Expression::ObjectExpression(preferences) =
								property.value.get_inner_expression()
							{
								for preference in &preferences.properties {
									if let ObjectPropertyKind::ObjectProperty(preference) =
										preference
									{
										if preference.key.static_name().as_deref()
											== Some("preload")
										{
											preload_present = true;
											preload = literal(&preference.value);
										}
									}
								}
							}
						}
					}
				}
			}
			self.add(
				Collection::Electron,
				expression.span,
				json!({
					"api":"BrowserWindow","method":"new","role":"window_constructor",
					"preload_declaration_present":preload_present,"literal_preload":preload,
					"runtime_observed":false
				}),
			);
			if preload_present && preload.is_none() {
				self.unknown(
					expression.span,
					"dynamic_preload_path",
					"preload expression is not evaluated",
				);
			}
		}
		walk::walk_new_expression(self, expression);
	}
}

pub(super) fn inspect(source: &AdmittedSource) -> Result<ModuleAnalysis> {
	let source_type = match source.syntax {
		JavascriptSyntax::Javascript => SourceType::mjs(),
		JavascriptSyntax::Typescript => SourceType::ts(),
		JavascriptSyntax::Jsx => SourceType::jsx(),
		JavascriptSyntax::Tsx => SourceType::tsx(),
	}
	.with_commonjs(matches!(source.module_kind, JavascriptModuleKind::Commonjs));
	let allocator = Allocator::default();
	let parsed = Parser::new(&allocator, &source.text, source_type)
		.with_options(ParseOptions {
			parse_regular_expression: true,
			..ParseOptions::default()
		})
		.parse();
	if parsed.panicked || !parsed.diagnostics.is_empty() || parsed.is_flow_language {
		bail!(
			"JavaScript source {} is not a valid supported AST ({} parser diagnostics)",
			source.id,
			parsed.diagnostics.len()
		);
	}
	// Oxc 0.144 leaves Semantic::nodes empty by default. Materialize the
	// node store so the inventory and node budget reflect the actual AST.
	let built = SemanticBuilder::new()
		.with_build_nodes(true)
		.with_check_syntax_error(true)
		.build(&parsed.program);
	if !built.diagnostics.is_empty() {
		bail!(
			"JavaScript source {} failed semantic syntax checks ({} diagnostics)",
			source.id,
			built.diagnostics.len()
		);
	}
	let semantic = built.semantic;
	if semantic.nodes().len() > MAX_AST_NODES {
		bail!("JavaScript source {} exceeds 200000 AST nodes", source.id);
	}
	let mut bindings = Bindings {
		scoping: semantic.scoping(),
		values: HashMap::new(),
		definition_counts: HashMap::new(),
		deferred: Vec::new(),
		imports_only: true,
	};
	bindings.visit_program(&parsed.program);
	bindings.imports_only = false;
	// Preserve the existing import and direct initializer observations, then
	// resolve their pending lexical aliases independently of declaration order.
	// This does not infer execution order or general interprocedural dataflow.
	bindings.visit_program(&parsed.program);
	bindings.resolve_deferred();
	let mut observations = Observations {
		source_id: &source.id,
		scoping: semantic.scoping(),
		bindings: &bindings.values,
		result: ModuleAnalysis::default(),
		error: None,
	};
	observations.visit_program(&parsed.program);
	for (kind, exports) in [
		("esm_local", &parsed.module_record.local_export_entries),
		(
			"esm_indirect",
			&parsed.module_record.indirect_export_entries,
		),
		("esm_star", &parsed.module_record.star_export_entries),
	] {
		for entry in exports {
			let exported = match &entry.export_name {
				ExportExportName::Name(name) => Some(name.name.as_str()),
				ExportExportName::Default(_) => Some("default"),
				ExportExportName::Null => None,
			};
			let imported = match &entry.import_name {
				ExportImportName::Name(name) => Some(name.name.as_str()),
				ExportImportName::All => Some("*"),
				ExportImportName::AllButDefault => Some("* except default"),
				ExportImportName::Null => None,
			};
			let local = match &entry.local_name {
				ExportLocalName::Name(name) | ExportLocalName::Default(name) => {
					Some(name.name.as_str())
				}
				ExportLocalName::Null => None,
			};
			observations.add(
				Collection::Exports,
				entry.span,
				json!({
					"kind":kind,"exported_name":exported,"imported_name":imported,
					"local_name":local,"specifier":entry.module_request.as_ref().map(|name|name.name.as_str()),
					"type_only":entry.is_type
				}),
			);
		}
	}
	if let Some(error) = observations.error {
		bail!("{}: {error}", source.id);
	}
	observations.result.node_count = semantic.nodes().len();
	observations.result.scope_count = semantic.scoping().scopes_len();
	Ok(observations.result)
}

#[cfg(test)]
#[path = "rea_javascript_alias_tests.rs"]
mod alias_tests;

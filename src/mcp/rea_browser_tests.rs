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

use super::{cdp, input, BrowserCaptureArgs};
use serde_json::json;

fn fixture() -> (tempfile::TempDir, BrowserCaptureArgs, serde_json::Value) {
	let dir = tempfile::tempdir().unwrap();
	std::fs::write(dir.path().join("body.txt"), b"hello").unwrap();
	let manifest = json!({"schema":input::SCHEMA,"resources":[{"url_path":"/body.txt","mime_type":"text/plain","before":{"file":"body.txt","sha256":input::sha256(b"hello")}}],"requests":["/body.txt","/body.txt"]});
	let bytes = serde_json::to_vec(&manifest).unwrap();
	std::fs::write(dir.path().join("manifest.json"), &bytes).unwrap();
	let args = BrowserCaptureArgs {
		manifest: dir.path().join("manifest.json").to_str().unwrap().into(),
		expected_sha256: input::sha256(&bytes),
		output_directory: dir.path().join("out").to_str().unwrap().into(),
	};
	(dir, args, manifest)
}

#[test]
fn capture_admission_keeps_repeated_requests_and_immutable_source_bytes() {
	let (dir, args, _) = fixture();
	let admitted = input::admit(&args).unwrap();
	std::fs::write(dir.path().join("body.txt"), b"changed").unwrap();
	assert_eq!(admitted.manifest.requests.len(), 2);
	assert_eq!(&*admitted.snapshots[0].before, b"hello");
	assert_eq!(&*admitted.snapshots[0].after, b"hello");
}

#[test]
fn capture_admission_rejects_hash_symlink_traversal_and_duplicate_fields() {
	let (dir, mut args, mut manifest) = fixture();
	let original = args.expected_sha256.clone();
	args.expected_sha256 = "0".repeat(64);
	assert!(input::admit(&args).is_err());
	args.expected_sha256 = original;
	std::fs::remove_file(dir.path().join("body.txt")).unwrap();
	std::os::unix::fs::symlink("manifest.json", dir.path().join("body.txt")).unwrap();
	assert!(input::admit(&args).is_err());
	manifest["resources"][0]["before"]["file"] = json!("../secret");
	let bytes = serde_json::to_vec(&manifest).unwrap();
	std::fs::write(&args.manifest, &bytes).unwrap();
	args.expected_sha256 = input::sha256(&bytes);
	assert!(input::admit(&args).is_err());
	let duplicate = br#"{"schema":"hepta.rea.local-browser-capture.v1","schema":"hepta.rea.local-browser-capture.v1","resources":[],"requests":[]}"#;
	std::fs::write(&args.manifest, duplicate).unwrap();
	args.expected_sha256 = input::sha256(duplicate);
	assert!(input::admit(&args).is_err());
	assert!(!dir.path().join("out").exists());
}

#[test]
fn capture_admission_refuses_reserved_urls_unselected_requests_and_excess_budget() {
	for (pointer, value) in [
		("/resources/0/url_path", json!("/__hepta_fixture__")),
		("/requests/0", json!("/not-declared")),
		("/resources/0/delay_ms", json!(2001)),
		("/timeout_seconds", json!(61)),
	] {
		let (_dir, mut args, mut manifest) = fixture();
		if pointer == "/timeout_seconds" {
			manifest["timeout_seconds"] = value;
		} else if pointer == "/resources/0/delay_ms" {
			manifest["resources"][0]["delay_ms"] = value;
		} else {
			*manifest.pointer_mut(pointer).unwrap() = value;
		}
		let bytes = serde_json::to_vec(&manifest).unwrap();
		std::fs::write(&args.manifest, &bytes).unwrap();
		args.expected_sha256 = input::sha256(&bytes);
		assert!(input::admit(&args).is_err(), "{pointer}");
	}
}

#[test]
fn capture_publication_never_overwrites_existing_files_or_symlinks() {
	let (dir, args, _) = fixture();
	let admitted = input::admit(&args).unwrap();
	let output = admitted.parent.create_child("out").unwrap();
	output.publish("before.har", b"first", 64).unwrap();
	assert!(output.publish("before.har", b"replacement", 64).is_err());
	assert_eq!(
		std::fs::read(dir.path().join("out/before.har")).unwrap(),
		b"first"
	);
	std::os::unix::fs::symlink("../body.txt", dir.path().join("out/after.har")).unwrap();
	assert!(output.publish("after.har", b"replacement", 64).is_err());
	assert_eq!(
		std::fs::read(dir.path().join("body.txt")).unwrap(),
		b"hello"
	);
	assert!(admitted.parent.create_child("out").is_err());
	assert_eq!(
		std::fs::read_dir(dir.path().join("out")).unwrap().count(),
		2
	);
}

#[test]
fn capture_decodes_binary_and_empty_bodies_without_accepting_malformed_base64() {
	assert_eq!(cdp::decode_base64("AP9/gA==").unwrap(), [0, 255, 127, 128]);
	assert!(cdp::decode_base64("").unwrap().is_empty());
	for malformed in [
		"=AAA", "A===", "AB==", "AAF=", "AAAA=", "AA==AAAA", "AA\n=", "AA--",
	] {
		assert!(cdp::decode_base64(malformed).is_err(), "{malformed}");
	}
}

#[test]
fn capture_publication_refuses_output_directory_renamed_after_admission() {
	let temp = tempfile::tempdir().unwrap();
	let parent = input::Directory::open_absolute(temp.path().to_str().unwrap()).unwrap();
	let output = parent.create_child("output").unwrap();
	std::fs::rename(temp.path().join("output"), temp.path().join("moved-output")).unwrap();
	std::fs::create_dir(temp.path().join("output")).unwrap();
	assert!(output
		.publish("before.har", b"must not be published", 64)
		.is_err());
	assert!(!temp.path().join("output/before.har").exists());
	assert!(!temp.path().join("moved-output/before.har").exists());
}

#[test]
fn capture_admission_refuses_replaced_ancestor_before_child_creation() {
	let temp = tempfile::tempdir().unwrap();
	std::fs::create_dir(temp.path().join("admitted")).unwrap();
	let admitted =
		input::Directory::open_absolute(temp.path().join("admitted").to_str().unwrap()).unwrap();
	std::fs::rename(
		temp.path().join("admitted"),
		temp.path().join("moved-parent"),
	)
	.unwrap();
	std::fs::create_dir(temp.path().join("admitted")).unwrap();
	assert!(admitted.create_child("private").is_err());
	assert!(!temp.path().join("admitted/private").exists());
	assert!(!temp.path().join("moved-parent/private").exists());
}

fn settle_peer_send(stream: &mut std::os::unix::net::UnixStream, value: serde_json::Value) {
	use std::io::Write;
	let mut bytes = serde_json::to_vec(&value).unwrap();
	bytes.push(0);
	stream.write_all(&bytes).unwrap();
}

fn settle_peer_read(stream: &mut std::os::unix::net::UnixStream) -> serde_json::Value {
	use std::io::Read;
	let mut bytes = Vec::new();
	loop {
		let mut byte = [0];
		stream.read_exact(&mut byte).unwrap();
		if byte[0] == 0 {
			return serde_json::from_slice(&bytes).unwrap();
		}
		bytes.push(byte[0]);
		assert!(bytes.len() <= 4096);
	}
}

fn settle_event(method: &str, params: serde_json::Value) -> serde_json::Value {
	json!({"sessionId":"fixture-session","method":method,"params":params})
}

fn settle_request(id: &str, url: &str) -> serde_json::Value {
	settle_event(
		"Network.requestWillBeSent",
		json!({
			"requestId":id,"request":{"url":url,"method":"GET","headers":{}},
			"timestamp":1.0,"wallTime":1700000000.0
		}),
	)
}

#[test]
fn capture_settle_waits_for_late_terminals_and_repeated_url_occurrences() {
	use std::collections::BTreeSet;
	use std::os::unix::net::UnixStream;
	use std::time::{Duration, Instant};
	let (stream, mut peer) = UnixStream::pair().unwrap();
	stream.set_nonblocking(true).unwrap();
	peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
	peer.set_write_timeout(Some(Duration::from_secs(2)))
		.unwrap();
	let entry = "http://127.0.0.1:12345/__hepta_fixture__";
	let resource = "http://127.0.0.1:12345/repeated";
	let probe = "http://127.0.0.1:23456/__hepta_blocked__";
	let (release, late) = std::sync::mpsc::channel();
	let thread = std::thread::spawn(move || {
		let evaluate = settle_peer_read(&mut peer);
		assert_eq!(evaluate["method"], "Runtime.evaluate");
		for (id, url) in [
			("entry", entry),
			("first", resource),
			("second", resource),
			("probe", probe),
		] {
			settle_peer_send(&mut peer, settle_request(id, url));
		}
		for id in ["entry", "first", "second"] {
			settle_peer_send(
				&mut peer,
				settle_event(
					"Network.responseReceived",
					json!({
						"requestId":id,"response":{"status":200,"statusText":"OK","mimeType":"text/plain","headers":{},"protocol":"http/1.1"}
					}),
				),
			);
		}
		for id in ["entry", "first"] {
			settle_peer_send(
				&mut peer,
				settle_event(
					"Network.loadingFinished",
					json!({"requestId":id,"timestamp":2.0}),
				),
			);
		}
		settle_peer_send(
			&mut peer,
			settle_event(
				"Fetch.requestPaused",
				json!({
					"requestId":"gate-probe","request":{"url":probe,"method":"GET"}
				}),
			),
		);
		settle_peer_send(
			&mut peer,
			json!({"id":evaluate["id"],"result":{"result":{"value":true}}}),
		);
		let gate = settle_peer_read(&mut peer);
		assert_eq!(gate["method"], "Fetch.failRequest");
		late.recv_timeout(Duration::from_secs(2)).unwrap();
		settle_peer_send(
			&mut peer,
			settle_event(
				"Network.loadingFinished",
				json!({"requestId":"second","timestamp":2.0}),
			),
		);
		settle_peer_send(
			&mut peer,
			settle_event(
				"Network.loadingFailed",
				json!({"requestId":"probe","timestamp":2.0,"errorText":"AccessDenied"}),
			),
		);
		settle_peer_send(&mut peer, json!({"id":gate["id"],"result":{}}));
		for _ in 0..3 {
			let body = settle_peer_read(&mut peer);
			assert_eq!(body["method"], "Network.getResponseBody");
			let text = if body["params"]["requestId"] == "first" {
				""
			} else {
				"owned"
			};
			settle_peer_send(
				&mut peer,
				json!({"id":body["id"],"result":{"body":text,"base64Encoded":false}}),
			);
		}
	});
	let mut client = cdp::Cdp::new(
		stream,
		Instant::now() + Duration::from_secs(2),
		BTreeSet::from([entry.into(), resource.into()]),
	);
	client.session = Some("fixture-session".into());
	client.begin_phase("before").unwrap();
	client.call("Runtime.evaluate", json!({})).unwrap();
	assert!(client.har().unwrap_err().to_string().contains("unsettled"));
	release.send(()).unwrap();
	client
		.settle_requests(&[entry.into(), resource.into(), resource.into(), probe.into()])
		.unwrap();
	let (har, coverage) = client.har().unwrap();
	assert_eq!(coverage["entry_count"], 4);
	assert_eq!(coverage["body_states"]["complete"], 2);
	assert_eq!(coverage["body_states"]["empty"], 1);
	assert_eq!(coverage["body_states"]["missing"], 1);
	let empty = &har["log"]["entries"][1]["response"]["content"];
	assert_eq!(empty["text"], "");
	assert_eq!(empty["size"], 0);
	let missing = &har["log"]["entries"][3]["response"]["content"];
	assert!(missing.get("text").is_none());
	assert!(missing.get("size").is_none());
	assert_eq!(missing["mimeType"], "");
	assert_eq!(
		har["log"]["entries"][2]["_hepta"]["network_loading_complete"],
		true
	);
	assert_eq!(
		har["log"]["entries"][2]["response"]["content"]["text"],
		"owned"
	);
	client.require_settled().unwrap();
	thread.join().unwrap();
}

#[test]
fn capture_settle_propagates_late_request_gate_error_before_browser_close() {
	use std::collections::BTreeSet;
	use std::os::unix::net::UnixStream;
	use std::time::{Duration, Instant};
	let (stream, mut peer) = UnixStream::pair().unwrap();
	stream.set_nonblocking(true).unwrap();
	peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
	peer.set_write_timeout(Some(Duration::from_secs(2)))
		.unwrap();
	let probe = "http://127.0.0.1:23456/__hepta_blocked__";
	let (release, late) = std::sync::mpsc::channel();
	let thread = std::thread::spawn(move || {
		let evaluate = settle_peer_read(&mut peer);
		settle_peer_send(&mut peer, settle_request("probe", probe));
		settle_peer_send(
			&mut peer,
			settle_event(
				"Fetch.requestPaused",
				json!({
					"requestId":"gate-probe","request":{"url":probe,"method":"GET"}
				}),
			),
		);
		settle_peer_send(
			&mut peer,
			settle_event(
				"Network.loadingFailed",
				json!({"requestId":"probe","timestamp":2.0,"errorText":"AccessDenied"}),
			),
		);
		settle_peer_send(&mut peer, json!({"id":evaluate["id"],"result":{}}));
		let gate = settle_peer_read(&mut peer);
		assert_eq!(gate["method"], "Fetch.failRequest");
		late.recv_timeout(Duration::from_secs(2)).unwrap();
		settle_peer_send(
			&mut peer,
			json!({"id":gate["id"],"error":{"message":"late gate failure"}}),
		);
	});
	let mut client = cdp::Cdp::new(
		stream,
		Instant::now() + Duration::from_secs(2),
		BTreeSet::new(),
	);
	client.session = Some("fixture-session".into());
	client.begin_phase("before").unwrap();
	client.call("Runtime.evaluate", json!({})).unwrap();
	assert!(client.require_settled().is_err());
	release.send(()).unwrap();
	let error = client.settle_requests(&[probe.into()]).unwrap_err();
	assert!(format!("{error:#}").contains("request gate acknowledgement failed: late gate failure"));
	assert!(client.har().is_err());
	thread.join().unwrap();
}

#[test]
fn capture_settle_refuses_a_missing_repeated_occurrence() {
	use std::collections::BTreeSet;
	use std::os::unix::net::UnixStream;
	use std::time::{Duration, Instant};
	let (stream, mut peer) = UnixStream::pair().unwrap();
	stream.set_nonblocking(true).unwrap();
	let url = "http://127.0.0.1:12345/repeated";
	settle_peer_send(&mut peer, settle_request("only-one", url));
	settle_peer_send(
		&mut peer,
		settle_event(
			"Network.loadingFinished",
			json!({"requestId":"only-one","timestamp":2.0}),
		),
	);
	drop(peer);
	let mut client = cdp::Cdp::new(
		stream,
		Instant::now() + Duration::from_secs(1),
		BTreeSet::new(),
	);
	client.session = Some("fixture-session".into());
	client.begin_phase("before").unwrap();
	assert!(client.settle_requests(&[url.into(), url.into()]).is_err());
	assert!(client.require_settled().is_err());
}

fn close_pair(timeout: std::time::Duration) -> (cdp::Cdp, std::os::unix::net::UnixStream) {
	use std::collections::BTreeSet;
	use std::os::unix::net::UnixStream;
	use std::time::{Duration, Instant};
	let (stream, mut peer) = UnixStream::pair().unwrap();
	stream.set_nonblocking(true).unwrap();
	peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
	peer.set_write_timeout(Some(Duration::from_secs(2)))
		.unwrap();
	let url = "http://127.0.0.1:12345/settled";
	settle_peer_send(&mut peer, settle_request("settled", url));
	settle_peer_send(
		&mut peer,
		settle_event(
			"Network.loadingFinished",
			json!({"requestId":"settled","timestamp":2.0}),
		),
	);
	let mut client = cdp::Cdp::new(
		stream,
		Instant::now() + timeout,
		BTreeSet::from([url.into()]),
	);
	client.session = Some("fixture-session".into());
	client.begin_phase("after").unwrap();
	client.settle_requests(&[url.into()]).unwrap();
	(client, peer)
}

#[test]
fn capture_close_allows_only_clean_pipe_end_after_sent_browser_command() {
	for acknowledge in [false, true] {
		let (mut client, mut peer) = close_pair(std::time::Duration::from_secs(2));
		let thread = std::thread::spawn(move || {
			let command = settle_peer_read(&mut peer);
			assert_eq!(command["method"], "Browser.close");
			assert!(command.get("sessionId").is_none());
			if acknowledge {
				settle_peer_send(&mut peer, json!({"id":command["id"],"result":{}}));
			}
		});
		assert_eq!(client.close_browser().unwrap(), acknowledge);
		client.require_settled().unwrap();
		assert_eq!(client.session.as_deref(), Some("fixture-session"));
		assert_eq!(client.stats()["commands_sent"], 1);
		assert_eq!(
			client.stats()["messages_received"],
			2 + usize::from(acknowledge)
		);
		thread.join().unwrap();
	}
}

#[test]
fn capture_close_observes_late_target_network_even_after_close_acknowledgement() {
	let (mut client, mut peer) = close_pair(std::time::Duration::from_secs(2));
	let thread = std::thread::spawn(move || {
		let command = settle_peer_read(&mut peer);
		assert!(command.get("sessionId").is_none());
		settle_peer_send(&mut peer, json!({"id":command["id"],"result":{}}));
		settle_peer_send(
			&mut peer,
			settle_request("late", "http://127.0.0.1:12345/late"),
		);
	});
	let error = client.close_browser().unwrap_err();
	assert!(format!("{error:#}").contains("unsettled"));
	assert!(client.require_settled().is_err());
	assert_eq!(client.stats()["messages_received"], 4);
	thread.join().unwrap();
}

#[test]
fn capture_close_records_late_target_denial_and_propagates_gate_error() {
	let (mut client, mut peer) = close_pair(std::time::Duration::from_secs(2));
	let thread = std::thread::spawn(move || {
		let command = settle_peer_read(&mut peer);
		assert!(command.get("sessionId").is_none());
		settle_peer_send(&mut peer, json!({"id":command["id"],"result":{}}));
		settle_peer_send(
			&mut peer,
			settle_event(
				"Fetch.requestPaused",
				json!({
					"requestId":"late-gate","request":{"url":"http://127.0.0.1:23456/late","method":"GET"}
				}),
			),
		);
		let gate = settle_peer_read(&mut peer);
		assert_eq!(gate["method"], "Fetch.failRequest");
		assert_eq!(gate["sessionId"], "fixture-session");
		settle_peer_send(
			&mut peer,
			json!({"id":gate["id"],"error":{"message":"late close gate failure"}}),
		);
	});
	let error = client.close_browser().unwrap_err();
	assert!(format!("{error:#}")
		.contains("request gate acknowledgement failed: late close gate failure"));
	assert_eq!(client.denied.len(), 1);
	assert_eq!(client.denied[0]["phase"], "after");
	assert_eq!(client.denied[0]["url"], "http://127.0.0.1:23456/late");
	assert_eq!(client.stats()["commands_sent"], 2);
	thread.join().unwrap();
}

#[test]
fn capture_close_refuses_clean_eof_with_an_unconfirmed_late_gate() {
	let (mut client, mut peer) = close_pair(std::time::Duration::from_secs(2));
	let thread = std::thread::spawn(move || {
		let command = settle_peer_read(&mut peer);
		assert_eq!(command["method"], "Browser.close");
		settle_peer_send(
			&mut peer,
			settle_event(
				"Fetch.requestPaused",
				json!({
					"requestId":"late-gate","request":{"url":"http://127.0.0.1:23456/late","method":"GET"}
				}),
			),
		);
		let gate = settle_peer_read(&mut peer);
		assert_eq!(gate["method"], "Fetch.failRequest");
	});
	assert!(
		format!("{:#}", client.close_browser().unwrap_err()).contains("unconfirmed request gate")
	);
	assert_eq!(client.denied.len(), 1);
	thread.join().unwrap();
}

#[test]
fn capture_close_never_treats_protocol_framing_or_budget_errors_as_no_ack() {
	use std::io::Write;
	for kind in [
		"protocol",
		"json",
		"envelope",
		"identity",
		"result",
		"truncated",
		"bytes",
		"count",
	] {
		let (mut client, mut peer) = close_pair(std::time::Duration::from_secs(5));
		let thread = std::thread::spawn(move || {
			let command = settle_peer_read(&mut peer);
			assert_eq!(command["method"], "Browser.close");
			match kind {
				"protocol" => settle_peer_send(
					&mut peer,
					json!({"id":command["id"],"error":{"message":"close refused"}}),
				),
				"json" => peer.write_all(b"{bad\0").unwrap(),
				"envelope" => settle_peer_send(&mut peer, json!([])),
				"identity" => settle_peer_send(&mut peer, json!({"id":"wrong-type","result":{}})),
				"result" => settle_peer_send(&mut peer, json!({"id":command["id"]})),
				"truncated" => peer.write_all(b"{\"method\":").unwrap(),
				"bytes" => {
					let mut bytes = vec![b'x'; 256 * 1024 + 1];
					bytes.push(0);
					peer.write_all(&bytes).unwrap();
				}
				"count" => {
					let mut message =
						serde_json::to_vec(&settle_event("Page.lifecycleEvent", json!({})))
							.unwrap();
					message.push(0);
					peer.write_all(&message.repeat(2049)).unwrap();
				}
				_ => unreachable!(),
			}
		});
		let error = format!("{:#}", client.close_browser().unwrap_err());
		let expected = match kind {
			"protocol" => "close refused",
			"json" => "invalid CDP JSON",
			"envelope" => "lacks response ID or method",
			"identity" => "invalid CDP response identity",
			"result" => "lacks an object result",
			"truncated" => "incomplete message",
			"bytes" => "byte budget exceeded",
			"count" => "event/response count exceeded",
			_ => unreachable!(),
		};
		assert!(error.contains(expected), "{kind}: {error}");
		thread.join().unwrap();
	}
}

#[test]
fn capture_close_acknowledgement_does_not_extend_deadline_or_skip_eof_drain() {
	use std::time::Duration;
	let (mut client, mut peer) = close_pair(Duration::from_secs(1));
	let (release, held_open) = std::sync::mpsc::channel();
	let thread = std::thread::spawn(move || {
		let command = settle_peer_read(&mut peer);
		settle_peer_send(&mut peer, json!({"id":command["id"],"result":{}}));
		held_open.recv_timeout(Duration::from_secs(3)).unwrap();
	});
	let error = client.close_browser().unwrap_err();
	assert!(format!("{error:#}").contains("fixed browser capture deadline exceeded"));
	release.send(()).unwrap();
	thread.join().unwrap();
}

#[test]
fn capture_fixture_receipt_requires_joined_threads_and_final_counters() {
	let mut fixtures = super::fixture::Fixtures::start(Vec::new(), &[]).unwrap();
	fixtures.control_probe().unwrap();
	assert!(format!("{:#}", fixtures.receipt().unwrap_err()).contains("before fixture shutdown"));
	fixtures.shutdown().unwrap();
	let receipt = fixtures.receipt().unwrap();
	assert_eq!(receipt["positive_control_requests_received"], 1);
	assert_eq!(receipt["browser_probe_requests_received"], 0);
}

#[test]
fn capture_fixture_final_receipt_refuses_a_late_probe_request() {
	use std::io::{Read, Write};
	let mut fixtures = super::fixture::Fixtures::start(Vec::new(), &[]).unwrap();
	fixtures.control_probe().unwrap();
	let address = fixtures.probe_origin.strip_prefix("http://").unwrap();
	let mut peer = std::net::TcpStream::connect(address).unwrap();
	peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
		.unwrap();
	peer.set_write_timeout(Some(std::time::Duration::from_secs(2)))
		.unwrap();
	write!(
		peer,
		"GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
		input::PROBE,
		address
	)
	.unwrap();
	let mut response = Vec::new();
	peer.read_to_end(&mut response).unwrap();
	assert!(response.starts_with(b"HTTP/1.1 200 "));
	fixtures.shutdown().unwrap();
	assert!(format!("{:#}", fixtures.receipt().unwrap_err())
		.contains("denial is not independently established"));
}

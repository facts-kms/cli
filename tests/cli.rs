use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    thread,
};

fn assert_indexed_consistent(status: &serde_json::Value) {
    let database = status["database"].as_str().expect("status database");
    let ledger = uuid::Uuid::parse_str(status["ledger_id"].as_str().expect("status ledger"))
        .expect("valid ledger UUID");
    let actor = status["actor_id"]
        .as_str()
        .filter(|actor| !actor.is_empty())
        .map(|actor| uuid::Uuid::parse_str(actor).expect("valid actor UUID"));
    let store = fact_store::Store::open(database).expect("open store");
    let mismatches = store
        .check_indexed_proposition_consistency(
            ledger.as_bytes(),
            actor.as_ref().map(uuid::Uuid::as_bytes),
        )
        .expect("indexed consistency check");
    assert!(
        mismatches.is_empty(),
        "indexed proposition mismatches: {mismatches:?}"
    );
}

fn assert_indented_command_list_is_sorted(output: &str, heading: &str) {
    let list = output
        .split_once(heading)
        .unwrap_or_else(|| panic!("missing help heading: {heading}"))
        .1;
    let commands: Vec<&str> = list
        .lines()
        .skip_while(|line| line.trim().is_empty())
        .take_while(|line| line.starts_with("  "))
        .map(|line| line.split_whitespace().next().unwrap())
        .collect();
    assert!(
        !commands.is_empty(),
        "{heading} did not contain any command lines"
    );
    let mut sorted = commands.clone();
    sorted.sort_unstable();
    assert_eq!(commands, sorted, "{heading} command list is not sorted");
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

fn write_http_json_response(stream: &mut TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/fact+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).unwrap();
}

fn serve_ledger_list_then_pull(
    listener: TcpListener,
    ledger: String,
    response_body: String,
    expected_bearer: Option<&str>,
) {
    let (mut stream, _) = listener.accept().unwrap();
    let request = read_http_request(&mut stream);
    assert!(request.starts_with("GET /facts/ledgers "));
    let list_body = serde_json::json!({
        "schema":"facts-protocol-ledger-list-v0",
        "ledgers":[{"ledger_id":ledger}],
        "next_cursor":null
    })
    .to_string();
    write_http_json_response(&mut stream, &list_body);

    let (mut stream, _) = listener.accept().unwrap();
    let request = read_http_request(&mut stream);
    assert!(request.starts_with(&format!("POST /facts/ledgers/{ledger}/object-pulls ")));
    if let Some(token) = expected_bearer {
        assert!(request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {token}")));
    }
    write_http_json_response(&mut stream, &response_body);
}

fn serve_ledger_lists_then_pull(
    listener: TcpListener,
    ledger: String,
    genesis_hash: String,
    response_body: String,
    expected_bearer: Option<&str>,
    list_count: usize,
) {
    for _ in 0..list_count {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /facts/ledgers "));
        let list_body = serde_json::json!({
            "schema":"facts-protocol-ledger-list-v0",
            "ledgers":[{"ledger_id":ledger.clone(),"genesis_hash":genesis_hash.clone()}],
            "next_cursor":null
        })
        .to_string();
        write_http_json_response(&mut stream, &list_body);
    }

    let (mut stream, _) = listener.accept().unwrap();
    let request = read_http_request(&mut stream);
    assert!(request.starts_with(&format!("POST /facts/ledgers/{ledger}/object-pulls ")));
    if let Some(token) = expected_bearer {
        assert!(request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {token}")));
    }
    write_http_json_response(&mut stream, &response_body);
}

#[test]
fn conformance_command_emits_stable_machine_report() {
    let output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["--json", "conformance", "run"])
        .output()
        .expect("fact binary should run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "pass");
    assert_eq!(report["failed"], 0);
    assert!(report["passed"].as_u64().is_some_and(|passed| passed > 0));
    assert_eq!(
        report["leaf_checks"].as_array().unwrap().len() as u64,
        report["passed"].as_u64().unwrap()
    );
    assert!(report["run_id"].as_str().is_some_and(|id| !id.is_empty()));
    assert!(report["deterministic_seed"].is_string());
    assert!(report["deterministic_clock"].is_string());
    assert_eq!(
        report["implementation_version"],
        include_str!("../VERSION").trim()
    );
    assert!(report["evidence_ids"]
        .as_array()
        .is_some_and(|ids| ids.iter().any(|id| id == "manifest.json")));
}

#[test]
fn ledger_clone_imports_a_bundle_without_creating_a_remote_private_key() {
    let source_home = tempfile::tempdir().unwrap();
    let source_file = source_home.path().join("source.md");
    let bundle = source_home.path().join("source.bundle");
    std::fs::write(&source_file, b"# Shared\n\nShared fact.\n").unwrap();
    let run = |home: &std::path::Path, args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(source_home.path(), &["init"]);
    let proposed: serde_json::Value = serde_json::from_slice(
        &run(
            source_home.path(),
            &[
                "--json",
                "propose",
                source_file.to_str().unwrap(),
                "--decision",
                "accept",
            ],
        )
        .stdout,
    )
    .unwrap();
    let status: serde_json::Value =
        serde_json::from_slice(&run(source_home.path(), &["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status);
    let source_db = source_home.path().join("ledgers/default.sqlite");
    run(
        source_home.path(),
        &[
            "sync",
            "pull",
            source_db.to_str().unwrap(),
            status["ledger_id"].as_str().unwrap(),
            bundle.to_str().unwrap(),
        ],
    );
    let clone_home = tempfile::tempdir().unwrap();
    run(
        clone_home.path(),
        &[
            "ledger",
            "clone",
            bundle.to_str().unwrap(),
            "mirror",
            "--ledger",
            status["ledger_id"].as_str().unwrap(),
        ],
    );
    let cloned_status: serde_json::Value =
        serde_json::from_slice(&run(clone_home.path(), &["--json", "status"]).stdout).unwrap();
    assert_eq!(cloned_status["read_only"], true);
    assert_eq!(cloned_status["actor_id"], "");
    assert_indexed_consistent(&cloned_status);
    let listed: serde_json::Value =
        serde_json::from_slice(&run(clone_home.path(), &["--json", "list"]).stdout).unwrap();
    assert_eq!(listed[0]["proposition_id"], proposed["proposition_id"]);

    let personal_clone_home = tempfile::tempdir().unwrap();
    run(
        personal_clone_home.path(),
        &["clone", bundle.to_str().unwrap()],
    );
    let personal_status: serde_json::Value =
        serde_json::from_slice(&run(personal_clone_home.path(), &["--json", "status"]).stdout)
            .unwrap();
    assert_eq!(personal_status["read_only"], true);
    assert_eq!(personal_status["ledger_id"], status["ledger_id"]);
    assert_indexed_consistent(&personal_status);

    let attached_home = tempfile::tempdir().unwrap();
    let attached: serde_json::Value = serde_json::from_slice(
        &run(
            attached_home.path(),
            &["--json", "from", source_db.to_str().unwrap(), "attached"],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(attached["registered"], true);
    assert_eq!(attached["name"], "attached");
    assert_eq!(attached["ledger_id"], status["ledger_id"]);
    assert_eq!(attached["read_only"], true);
    assert_eq!(attached["active"], true);
    assert_eq!(
        std::path::Path::new(attached["database"].as_str().unwrap()),
        std::fs::canonicalize(&source_db).unwrap()
    );
    let attached_status: serde_json::Value =
        serde_json::from_slice(&run(attached_home.path(), &["--json", "status"]).stdout).unwrap();
    assert_eq!(attached_status["read_only"], true);
    assert_indexed_consistent(&attached_status);
    let attached_list: serde_json::Value =
        serde_json::from_slice(&run(attached_home.path(), &["--json", "list"]).stdout).unwrap();
    assert_eq!(
        attached_list[0]["proposition_id"],
        proposed["proposition_id"]
    );

    let derived_home = tempfile::tempdir().unwrap();
    let derived: serde_json::Value = serde_json::from_slice(
        &run(
            derived_home.path(),
            &["--json", "from", source_db.to_str().unwrap()],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(derived["registered"], true);
    assert_eq!(derived["name"], "default");
    assert_eq!(derived["ledger_id"], status["ledger_id"]);
    let derived_status: serde_json::Value =
        serde_json::from_slice(&run(derived_home.path(), &["--json", "status"]).stdout).unwrap();
    assert_eq!(derived_status["read_only"], true);
    assert_eq!(derived_status["actor_id"], "");
    assert_eq!(derived_status["key_id"], "");
    let derived_signer: serde_json::Value =
        serde_json::from_slice(&run(derived_home.path(), &["--json", "as"]).stdout).unwrap();
    assert_eq!(derived_signer["report"], true);
    assert_eq!(derived_signer["no_current_signer"], true);
    assert!(derived_signer["actor"].is_null());
    let derived_signer_human = run(derived_home.path(), &["as"]);
    let derived_ledger_ref = fact_sdk::reference::short_uuid_reference(
        uuid::Uuid::parse_str(status["ledger_id"].as_str().unwrap()).unwrap(),
    );
    assert!(
        String::from_utf8_lossy(&derived_signer_human.stdout).contains(&format!(
            "no current signer for ledger default ({derived_ledger_ref}) (read-only)"
        ))
    );

    let rejected_write = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", attached_home.path())
        .args(["propose", "--message", "# Read-only\n\nShould fail."])
        .output()
        .expect("fact binary should run");
    assert!(!rejected_write.status.success());
    assert!(
        String::from_utf8_lossy(&rejected_write.stderr).contains("read-only"),
        "stderr: {}",
        String::from_utf8_lossy(&rejected_write.stderr)
    );
    let rejected_tag = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", attached_home.path())
        .args([
            "tags",
            proposed["proposition_id"].as_str().unwrap(),
            "add",
            "read-only",
        ])
        .output()
        .expect("fact binary should run");
    assert!(!rejected_tag.status.success());
    assert!(
        String::from_utf8_lossy(&rejected_tag.stderr).contains("read-only"),
        "stderr: {}",
        String::from_utf8_lossy(&rejected_tag.stderr)
    );
}

#[test]
fn pull_on_fresh_client_points_to_remote_clone_bootstrap() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["pull", "--remote", "test"])
        .output()
        .expect("fact binary should run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("fact clone --remote NAME --ledger LEDGER"),
        "stderr: {stderr}"
    );
}

#[test]
fn remote_clone_bootstraps_fresh_client_with_configured_bearer_token() {
    let source_home = tempfile::tempdir().unwrap();
    let bundle = source_home.path().join("remote-clone.bundle");
    let run = |home: &std::path::Path, args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(source_home.path(), &["init"]);
    run(
        source_home.path(),
        &[
            "propose",
            "--message",
            "# Remote Clone\n\nBootstrap over HTTP.",
            "--decision",
            "accept",
        ],
    );
    let source_status: serde_json::Value =
        serde_json::from_slice(&run(source_home.path(), &["--json", "status"]).stdout).unwrap();
    let ledger = source_status["ledger_id"].as_str().unwrap().to_owned();
    let source_db = source_home.path().join("ledgers/default.sqlite");
    run(
        source_home.path(),
        &[
            "sync",
            "pull",
            source_db.to_str().unwrap(),
            &ledger,
            bundle.to_str().unwrap(),
        ],
    );
    let bundle_bytes = std::fs::read(&bundle).unwrap();
    let decoded = fact_commitment::decode_bundle(&bundle_bytes).unwrap();
    let wire_objects = decoded
        .objects
        .iter()
        .map(|object| {
            let payload = fact_crypto::decode_sign1(object).unwrap().payload;
            serde_json::json!({
                "content_hash": fact_core::Hash::digest(&payload).hex(),
                "cose_sign1": base64url_encode(object)
            })
        })
        .collect::<Vec<_>>();
    let response_body = serde_json::json!({
        "schema":"facts-protocol-pull-response-v0",
        "ledger_id":ledger.clone(),
        "objects":wire_objects,
        "object_count":decoded.objects.len(),
        "commitment":{},
        "inclusion_proofs":[],
        "next_cursor":null,
        "complete":true
    })
    .to_string();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_url = format!("http://{}", listener.local_addr().unwrap());
    let served_ledger = ledger.clone();
    let server = thread::spawn(move || {
        serve_ledger_list_then_pull(listener, served_ledger, response_body, Some("secret-token"));
    });

    let client_home = tempfile::tempdir().unwrap();
    run(
        client_home.path(),
        &["remote", "add", "test", &remote_url, "--ledger", &ledger],
    );
    run(
        client_home.path(),
        &["remote", "auth", "test", "secret-token"],
    );
    let cloned: serde_json::Value = serde_json::from_slice(
        &run(
            client_home.path(),
            &["--json", "clone", "--remote", "test", "--name", "mirror"],
        )
        .stdout,
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(cloned["cloned"], true);
    assert_eq!(cloned["name"], "mirror");
    assert_eq!(cloned["ledger_id"], ledger);
    assert_eq!(cloned["remote"], "test");
    let status: serde_json::Value =
        serde_json::from_slice(&run(client_home.path(), &["--json", "status"]).stdout).unwrap();
    assert_eq!(status["ledger_id"], ledger);
    assert_eq!(status["read_only"], true);
    let remotes = std::fs::read_to_string(client_home.path().join("remotes.toml")).unwrap();
    assert!(!remotes.contains("[remotes.mirror]"));
    assert!(remotes.contains("[remotes.test]"));
    assert!(remotes.contains(&format!("ledger = \"{ledger}\"")));
    assert_eq!(
        remotes.matches("bearer_token = \"secret-token\"").count(),
        1
    );
}

#[test]
fn remote_clone_as_existing_identity_creates_writable_ledger() {
    let home = tempfile::tempdir().unwrap();
    let bundle = home.path().join("remote-clone-as.bundle");
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    run(&[
        "propose",
        "--message",
        "# Writable Remote Clone\n\nBootstrap with local signer.",
        "--decision",
        "accept",
    ]);
    let source_status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let ledger = source_status["ledger_id"].as_str().unwrap().to_owned();
    let actor = source_status["actor_id"].as_str().unwrap().to_owned();
    let source_db = home.path().join("ledgers/default.sqlite");
    run(&[
        "sync",
        "pull",
        source_db.to_str().unwrap(),
        &ledger,
        bundle.to_str().unwrap(),
    ]);

    let bundle_bytes = std::fs::read(&bundle).unwrap();
    let decoded = fact_commitment::decode_bundle(&bundle_bytes).unwrap();
    let wire_objects = decoded
        .objects
        .iter()
        .map(|object| {
            let payload = fact_crypto::decode_sign1(object).unwrap().payload;
            serde_json::json!({
                "content_hash": fact_core::Hash::digest(&payload).hex(),
                "cose_sign1": base64url_encode(object)
            })
        })
        .collect::<Vec<_>>();
    let response_body = serde_json::json!({
        "schema":"facts-protocol-pull-response-v0",
        "ledger_id":ledger.clone(),
        "objects":wire_objects,
        "object_count":decoded.objects.len(),
        "commitment":{},
        "inclusion_proofs":[],
        "next_cursor":null,
        "complete":true
    })
    .to_string();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_url = format!("http://{}", listener.local_addr().unwrap());
    let served_ledger = ledger.clone();
    let server = thread::spawn(move || {
        serve_ledger_list_then_pull(listener, served_ledger, response_body, None);
    });

    run(&["remote", "add", "test", &remote_url, "--ledger", &ledger]);
    let cloned: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json", "clone", "--remote", "test", "--name", "writable", "--as", &actor,
        ])
        .stdout,
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(cloned["cloned"], true);
    assert_eq!(cloned["read_only"], false);
    assert_eq!(cloned["actor_id"], actor);
    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_eq!(status["ledger_id"], ledger);
    assert_eq!(status["read_only"], false);
    assert_eq!(status["actor_id"], actor);
    let remotes = std::fs::read_to_string(home.path().join("remotes.toml")).unwrap();
    assert!(!remotes.contains("[remotes.writable]"));
    assert!(remotes.contains("[remotes.test]"));
}

#[test]
fn status_reports_missing_local_private_key_material() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run")
    };
    let ok = |args: &[&str]| {
        let output = run(args);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    ok(&["init"]);
    let initial_status: serde_json::Value =
        serde_json::from_slice(&ok(&["--json", "status"]).stdout).unwrap();
    assert_eq!(initial_status["read_only"], false);
    assert_eq!(initial_status["local_private_key_material"], true);
    let actor_id = initial_status["actor_id"].as_str().unwrap();
    let seed_file = home
        .path()
        .join("identities")
        .join(format!("{actor_id}.seed"));
    assert!(seed_file.exists());
    std::fs::remove_file(&seed_file).unwrap();

    let missing_status: serde_json::Value =
        serde_json::from_slice(&ok(&["--json", "status"]).stdout).unwrap();
    assert_eq!(missing_status["read_only"], false);
    assert_eq!(missing_status["local_private_key_material"], false);
    let human_status = ok(&["status"]);
    let human_status = String::from_utf8_lossy(&human_status.stdout);
    assert!(human_status.contains("local private key material is missing"));

    let write = run(&["propose", "--message", "# Missing Key\n\nCannot sign."]);
    assert!(!write.status.success());
    let stderr = String::from_utf8_lossy(&write.stderr);
    assert!(stderr.contains("local private key material is missing"));
    assert!(stderr.contains("fact status"));
    assert!(stderr.contains("restore or rotate"));
}

#[test]
fn clone_dependency_error_names_missing_grant_actor_identity() {
    let requester = tempfile::tempdir().unwrap();
    let admin = tempfile::tempdir().unwrap();
    let client = tempfile::tempdir().unwrap();
    let request = requester.path().join("alnewkirk.actor.bndl");
    let bundle = admin.path().join("served.bundle");
    let broken_bundle = admin.path().join("served-missing-actor.bundle");
    let run = |home: &std::path::Path, args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run")
    };
    let ok = |home: &std::path::Path, args: &[&str]| {
        let output = run(home, args);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    let sent: serde_json::Value = serde_json::from_slice(
        &ok(
            requester.path(),
            &[
                "--json",
                "actor",
                "send",
                "Al Newkirk",
                "--alias",
                "alnewkirk",
                "--request",
                "participate",
                "--output",
                request.to_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    let actor_id = sent["actor_id"].as_str().unwrap().to_owned();

    ok(admin.path(), &["init"]);
    ok(
        admin.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://facts.example",
            "--ledger",
            "default",
        ],
    );
    ok(
        admin.path(),
        &["actor", "admit", request.to_str().unwrap(), "--participate"],
    );
    let status: serde_json::Value =
        serde_json::from_slice(&ok(admin.path(), &["--json", "status"]).stdout).unwrap();
    let ledger = status["ledger_id"].as_str().unwrap();
    let admin_db = admin.path().join("ledgers/default.sqlite");
    ok(
        admin.path(),
        &[
            "sync",
            "pull",
            admin_db.to_str().unwrap(),
            ledger,
            bundle.to_str().unwrap(),
        ],
    );

    let decoded = fact_commitment::decode_bundle(&std::fs::read(&bundle).unwrap()).unwrap();
    let filtered = decoded
        .objects
        .into_iter()
        .filter(|object| {
            let payload = fact_crypto::decode_sign1(object).unwrap().payload;
            let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            !(value["object_type"] == "actor" && value["id"] == actor_id)
        })
        .collect::<Vec<_>>();
    let pairs = filtered
        .iter()
        .map(|object| {
            let payload = fact_crypto::decode_sign1(object).unwrap().payload;
            (fact_core::Hash::digest(&payload), object.clone())
        })
        .collect::<Vec<_>>();
    let manifest = fact_canonical::encode(
        &serde_json::to_vec(&serde_json::json!({
            "schema":"facts-protocol-bundle-v0",
            "protocol_version":0,
            "bundle_id":fact_commitment::deterministic_bundle_id(&pairs),
            "object_count":pairs.len(),
            "ledger_id":ledger,
            "objects":pairs.iter().map(|(hash, object)| {
                let payload = fact_crypto::decode_sign1(object).unwrap().payload;
                let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                serde_json::json!({"object_id":value["id"],"content_hash":hash.hex()})
            }).collect::<Vec<_>>(),
            "dependency_refs":[],
            "sender_signature":null,
            "expected_commitment_hash":null,
            "base_commitment_hash":null
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        &broken_bundle,
        fact_commitment::encode_bundle(&manifest, &pairs).unwrap(),
    )
    .unwrap();

    let cloned = run(
        client.path(),
        &["clone", broken_bundle.to_str().unwrap(), "--name", "broken"],
    );
    assert!(!cloned.status.success());
    let stderr = String::from_utf8_lossy(&cloned.stderr);
    assert!(stderr.contains("authorization grant"));
    assert!(stderr.contains(&actor_id));
    assert!(stderr.contains("identity bundle"));
}

#[test]
fn url_clone_reuses_matching_remote_without_copying_token() {
    let home = tempfile::tempdir().unwrap();
    let bundle = home.path().join("url-clone.bundle");
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    run(&[
        "propose",
        "--message",
        "# URL Clone\n\nReuse remote metadata.",
        "--decision",
        "accept",
    ]);
    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let ledger = status["ledger_id"].as_str().unwrap().to_owned();
    let database = home.path().join("ledgers/default.sqlite");
    run(&[
        "sync",
        "pull",
        database.to_str().unwrap(),
        &ledger,
        bundle.to_str().unwrap(),
    ]);
    let bundle_bytes = std::fs::read(&bundle).unwrap();
    let decoded = fact_commitment::decode_bundle(&bundle_bytes).unwrap();
    let wire_objects = decoded
        .objects
        .iter()
        .map(|object| {
            let payload = fact_crypto::decode_sign1(object).unwrap().payload;
            serde_json::json!({
                "content_hash": fact_core::Hash::digest(&payload).hex(),
                "cose_sign1": base64url_encode(object)
            })
        })
        .collect::<Vec<_>>();
    let response_body = serde_json::json!({
        "schema":"facts-protocol-pull-response-v0",
        "ledger_id":ledger.clone(),
        "objects":wire_objects,
        "object_count":decoded.objects.len(),
        "commitment":{},
        "inclusion_proofs":[],
        "next_cursor":null,
        "complete":true
    })
    .to_string();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_url = format!("http://{}", listener.local_addr().unwrap());
    let served_ledger = ledger.clone();
    let server = thread::spawn(move || {
        serve_ledger_list_then_pull(listener, served_ledger, response_body, Some("secret-token"));
    });

    run(&[
        "remote",
        "add",
        "upstream",
        &remote_url,
        "--ledger",
        &ledger,
    ]);
    run(&["remote", "auth", "upstream", "secret-token"]);
    let cloned: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "clone", &remote_url, "--name", "copy"]).stdout)
            .unwrap();
    server.join().unwrap();
    assert_eq!(cloned["cloned"], true);
    assert_eq!(cloned["remote"], "upstream");
    let remotes = std::fs::read_to_string(home.path().join("remotes.toml")).unwrap();
    assert!(remotes.contains("[remotes.upstream]"));
    assert!(!remotes.contains("[remotes.copy]"));
    assert_eq!(
        remotes.matches("bearer_token = \"secret-token\"").count(),
        1
    );
}

#[test]
fn remote_add_records_explicit_and_discovered_ledgers() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let ledger = status["ledger_id"].as_str().unwrap().to_owned();

    let explicit: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "remote",
            "add",
            "explicit",
            "https://facts.example",
            "--ledger",
            "default",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(explicit["ledger"], ledger);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_url = format!("http://{}", listener.local_addr().unwrap());
    let discovered_ledger = ledger.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&request);
        assert!(request.starts_with("GET /facts/ledgers "));
        let body = serde_json::json!({
            "schema":"facts-protocol-ledger-list-v0",
            "ledgers":[{"ledger_id":discovered_ledger}],
            "next_cursor":null
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/fact+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
    });
    let discovered: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "remote", "add", "discovered", &remote_url]).stdout,
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(discovered["ledger"], ledger);

    let listed = String::from_utf8_lossy(&run(&["remote", "list"]).stdout).into_owned();
    assert!(listed.contains(&format!("explicit  https://facts.example  {ledger}")));
    assert!(listed.contains(&format!("discovered  {remote_url}  {ledger}")));
    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_eq!(status["remotes"].as_array().unwrap().len(), 2);
    let ledger_remotes: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "ledger", "remote", "list"]).stdout).unwrap();
    assert_eq!(ledger_remotes.as_array().unwrap().len(), 2);
}

#[test]
fn remote_add_ledger_can_match_remote_advertised_namespace() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    let remote_ledger = uuid::Uuid::now_v7().to_string();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_url = format!("http://{}", listener.local_addr().unwrap());
    let advertised_ledger = remote_ledger.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /facts/ledgers "));
        let body = serde_json::json!({
            "schema":"facts-protocol-response-v0",
            "body":{
                "schema":"facts-protocol-ledger-list-v0",
                "ledgers":[{"ledger_id":advertised_ledger,"namespace":"factory"}],
                "next_cursor":null
            }
        })
        .to_string();
        write_http_json_response(&mut stream, &body);
    });
    let added: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "remote",
            "add",
            "--ledger",
            "factory",
            "example",
            &remote_url,
        ])
        .stdout,
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(added["ledger"], remote_ledger);
    let remotes = std::fs::read_to_string(home.path().join("remotes.toml")).unwrap();
    assert!(remotes.contains(&format!("ledger = \"{remote_ledger}\"")));
}

#[test]
fn remote_add_refuses_to_guess_among_multiple_discovered_ledgers() {
    let home = tempfile::tempdir().unwrap();
    let ok = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    ok(&["init"]);
    let first: serde_json::Value =
        serde_json::from_slice(&ok(&["--json", "status"]).stdout).unwrap();
    let second: serde_json::Value =
        serde_json::from_slice(&ok(&["--json", "new", "other"]).stdout).unwrap();
    let first_ledger = first["ledger_id"].as_str().unwrap().to_owned();
    let second_ledger = second["ledger_id"].as_str().unwrap().to_owned();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_url = format!("http://{}", listener.local_addr().unwrap());
    let response_first = first_ledger.clone();
    let response_second = second_ledger.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let body = serde_json::json!({
            "schema":"facts-protocol-ledger-list-v0",
            "ledgers":[{"ledger_id":response_first},{"ledger_id":response_second}],
            "next_cursor":null
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/fact+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["remote", "add", "origin", &remote_url])
        .output()
        .expect("fact binary should run");
    server.join().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("remote serves multiple ledgers"));
    assert!(stderr.contains(&first_ledger));
    assert!(stderr.contains(&second_ledger));
}

#[test]
fn remote_from_descriptor_upserts_remote_and_keeps_credential_warning() {
    let home = tempfile::tempdir().unwrap();
    let ok = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    ok(&["init"]);
    let status: serde_json::Value =
        serde_json::from_slice(&ok(&["--json", "status"]).stdout).unwrap();
    let ledger = status["ledger_id"].as_str().unwrap().to_owned();
    let genesis_hash = "dfc9a9a769d1f751d2d0c8cbbbeeadc452b9dd77d5b334b0a7e781a028370662";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_url = format!("http://{}", listener.local_addr().unwrap());
    let served_ledger = ledger.clone();
    let served_genesis = genesis_hash.to_owned();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /facts/ledgers "));
        let body = serde_json::json!({
            "schema":"facts-protocol-response-v0",
            "body":{
                "schema":"facts-protocol-ledger-list-v0",
                "ledgers":[{"ledger_id":served_ledger,"genesis_hash":served_genesis}],
                "next_cursor":null
            }
        })
        .to_string();
        write_http_json_response(&mut stream, &body);
    });
    ok(&["remote", "add", "origin", "https://old.example"]);
    let descriptor = home.path().join("remote.json");
    std::fs::write(
        &descriptor,
        serde_json::json!({
            "schema":"fact-remote-actor-response-v0",
            "endpoint":{
                "schema":"fact-remote-v0",
                "url":remote_url,
                "ledger_id":ledger.clone(),
                "genesis_hash":genesis_hash,
                "token":"rotated-token"
            },
            "signed_grants":[]
        })
        .to_string(),
    )
    .unwrap();
    let output = ok(&["remote", "from", descriptor.to_str().unwrap(), "origin"]);
    server.join().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("configured remote origin"));
    assert!(stdout.contains("descriptor file still contains a live credential"));
    let remotes = std::fs::read_to_string(home.path().join("remotes.toml")).unwrap();
    assert!(remotes.contains(&format!("url = \"{remote_url}\"")));
    assert!(remotes.contains(&format!("ledger = \"{ledger}\"")));
    assert!(remotes.contains(&format!("genesis_hash = \"{genesis_hash}\"")));
    assert!(remotes.contains("bearer_token = \"rotated-token\""));
}

#[test]
fn remote_from_descriptor_rejects_genesis_mismatch() {
    let home = tempfile::tempdir().unwrap();
    let ok = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    ok(&["init"]);
    let status: serde_json::Value =
        serde_json::from_slice(&ok(&["--json", "status"]).stdout).unwrap();
    let ledger = status["ledger_id"].as_str().unwrap().to_owned();
    let descriptor_genesis = "dfc9a9a769d1f751d2d0c8cbbbeeadc452b9dd77d5b334b0a7e781a028370662";
    let served_genesis = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_url = format!("http://{}", listener.local_addr().unwrap());
    let served_ledger = ledger.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /facts/ledgers "));
        let body = serde_json::json!({
            "schema":"facts-protocol-ledger-list-v0",
            "ledgers":[{"ledger_id":served_ledger,"genesis_hash":served_genesis}],
            "next_cursor":null
        })
        .to_string();
        write_http_json_response(&mut stream, &body);
    });
    let descriptor = home.path().join("remote.json");
    std::fs::write(
        &descriptor,
        serde_json::json!({
            "schema":"fact-remote-v0",
            "url":remote_url,
            "ledger_id":ledger.clone(),
            "genesis_hash":descriptor_genesis
        })
        .to_string(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["remote", "from", descriptor.to_str().unwrap()])
        .output()
        .expect("fact binary should run");
    server.join().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("remote descriptor genesis mismatch"));
    assert!(!home.path().join("remotes.toml").exists());
}

#[test]
fn remote_from_descriptor_rejects_unknown_schema() {
    let home = tempfile::tempdir().unwrap();
    let descriptor = home.path().join("remote.json");
    std::fs::write(
        &descriptor,
        serde_json::json!({
            "schema":"fact-remote-v9",
            "url":"https://facts.example",
            "ledger_id":uuid::Uuid::now_v7().to_string(),
            "genesis_hash":"dfc9a9a769d1f751d2d0c8cbbbeeadc452b9dd77d5b334b0a7e781a028370662"
        })
        .to_string(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["remote", "from", descriptor.to_str().unwrap()])
        .output()
        .expect("fact binary should run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported remote descriptor format"));
    assert!(!stderr.contains("fact-remote-v9"));
}

#[test]
fn clone_from_descriptor_configures_remote_and_pulls_with_token() {
    let source_home = tempfile::tempdir().unwrap();
    let client_home = tempfile::tempdir().unwrap();
    let run = |home: &std::path::Path, args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(source_home.path(), &["init"]);
    run(
        source_home.path(),
        &[
            "propose",
            "--message",
            "# Descriptor Clone\n\nBootstrap from a descriptor.",
            "--decision",
            "accept",
        ],
    );
    let source_status: serde_json::Value =
        serde_json::from_slice(&run(source_home.path(), &["--json", "status"]).stdout).unwrap();
    let ledger = source_status["ledger_id"].as_str().unwrap().to_owned();
    let source_db = source_home.path().join("ledgers/default.sqlite");
    let bundle = source_home.path().join("descriptor-clone.bundle");
    run(
        source_home.path(),
        &[
            "sync",
            "pull",
            source_db.to_str().unwrap(),
            &ledger,
            bundle.to_str().unwrap(),
        ],
    );
    let bundle_bytes = std::fs::read(&bundle).unwrap();
    let decoded = fact_commitment::decode_bundle(&bundle_bytes).unwrap();
    let wire_objects = decoded
        .objects
        .iter()
        .map(|object| {
            let payload = fact_crypto::decode_sign1(object).unwrap().payload;
            serde_json::json!({
                "content_hash": fact_core::Hash::digest(&payload).hex(),
                "cose_sign1": base64url_encode(object)
            })
        })
        .collect::<Vec<_>>();
    let response_body = serde_json::json!({
        "schema":"facts-protocol-pull-response-v0",
        "ledger_id":ledger.clone(),
        "objects":wire_objects,
        "object_count":decoded.objects.len(),
        "commitment":{},
        "inclusion_proofs":[],
        "next_cursor":null,
        "complete":true
    })
    .to_string();

    let genesis_hash = "dfc9a9a769d1f751d2d0c8cbbbeeadc452b9dd77d5b334b0a7e781a028370662";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_url = format!("http://{}", listener.local_addr().unwrap());
    let served_ledger = ledger.clone();
    let server = thread::spawn({
        let served_genesis = genesis_hash.to_owned();
        move || {
            serve_ledger_lists_then_pull(
                listener,
                served_ledger,
                served_genesis,
                response_body,
                Some("descriptor-token"),
                2,
            );
        }
    });
    let descriptor = client_home.path().join("remote.json");
    std::fs::write(
        &descriptor,
        serde_json::json!({
            "schema":"fact-remote-v0",
            "url":remote_url,
            "ledger_id":ledger.clone(),
            "genesis_hash":genesis_hash,
            "token":"descriptor-token"
        })
        .to_string(),
    )
    .unwrap();
    let cloned: serde_json::Value = serde_json::from_slice(
        &run(
            client_home.path(),
            &[
                "--json",
                "clone",
                "--from",
                descriptor.to_str().unwrap(),
                "--name",
                "mirror",
            ],
        )
        .stdout,
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(cloned["cloned"], true);
    assert_eq!(cloned["name"], "mirror");
    assert_eq!(cloned["ledger_id"], ledger);
    assert_eq!(cloned["remote"], "127-0-0-1");
    assert_eq!(cloned["descriptor_contains_credential"], true);
    let remotes = std::fs::read_to_string(client_home.path().join("remotes.toml")).unwrap();
    assert!(remotes.contains("[remotes.127-0-0-1]"));
    assert!(remotes.contains(&format!("ledger = \"{ledger}\"")));
    assert!(remotes.contains(&format!("genesis_hash = \"{genesis_hash}\"")));
    assert!(remotes.contains("bearer_token = \"descriptor-token\""));
}

#[test]
fn personal_pull_selects_remote_matching_active_ledger() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    let default: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let ledger = default["ledger_id"].as_str().unwrap().to_owned();
    let other: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "new", "other"]).stdout).unwrap();
    let other_ledger = other["ledger_id"].as_str().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_url = format!("http://{}", listener.local_addr().unwrap());
    let served_ledger = ledger.clone();
    let server = thread::spawn(move || {
        let body = serde_json::json!({
            "schema":"facts-protocol-pull-response-v0",
            "ledger_id":served_ledger.clone(),
            "objects":[],
            "object_count":0,
            "commitment":{},
            "inclusion_proofs":[],
            "next_cursor":null,
            "complete":true
        })
        .to_string();
        serve_ledger_list_then_pull(listener, served_ledger, body, None);
    });

    std::fs::write(
        home.path().join("remotes.toml"),
        format!(
            "[remotes.wrong]\nurl = \"http://127.0.0.1:9\"\nledger = \"{other_ledger}\"\n\n[remotes.match]\nurl = \"{remote_url}\"\nledger = \"{ledger}\"\n"
        ),
    )
    .unwrap();
    run(&["pull"]);
    server.join().unwrap();
}

#[test]
fn remote_pull_mismatch_fails_before_object_exchange() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    let local: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let local_ledger = local["ledger_id"].as_str().unwrap().to_owned();
    let remote_ledger = uuid::Uuid::now_v7().to_string();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_url = format!("http://{}", listener.local_addr().unwrap());
    let listed_ledger = remote_ledger.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&request);
        assert!(request.starts_with("GET /facts/ledgers "));
        assert!(!request.contains("object-pulls"));
        let body = serde_json::json!({
            "schema":"facts-protocol-ledger-list-v0",
            "ledgers":[{"ledger_id":listed_ledger}],
            "next_cursor":null
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/fact+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["pull", "--remote", &remote_url])
        .output()
        .expect("fact binary should run");
    server.join().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&local_ledger));
    assert!(stderr.contains(&remote_ledger));
    assert!(stderr.contains("fact clone"));
    assert!(stderr.contains("cannot be turned into a mirror"));
}

fn base64url_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        output.push(TABLE[((n >> 18) & 63) as usize] as char);
        output.push(TABLE[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(n & 63) as usize] as char);
        }
    }
    output
}

fn base64url_decode(value: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut bit_count = 0u8;
    let mut output = Vec::new();
    for byte in value.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        bits = (bits << 6) | value;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push(((bits >> bit_count) & 0xff) as u8);
        }
    }
    Some(output)
}

#[test]
fn from_requires_ledger_for_multi_ledger_database() {
    let run = |home: &std::path::Path, args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    let source = tempfile::tempdir().unwrap();
    let database = source.path().join("multi.sqlite");
    let first =
        fact_sdk::environment::init_ledger_database(&database, "local.first", Some([11; 32]))
            .unwrap();
    let second =
        fact_sdk::environment::init_ledger_database(&database, "local.second", Some([12; 32]))
            .unwrap();

    let target_home = tempfile::tempdir().unwrap();
    let missing_ledger = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", target_home.path())
        .args(["from", database.to_str().unwrap(), "archive"])
        .output()
        .expect("fact binary should run");
    assert!(!missing_ledger.status.success());
    assert!(
        String::from_utf8_lossy(&missing_ledger.stderr)
            .contains("pass --ledger with a ledger reference"),
        "stderr: {}",
        String::from_utf8_lossy(&missing_ledger.stderr)
    );

    let registered: serde_json::Value = serde_json::from_slice(
        &run(
            target_home.path(),
            &[
                "--json",
                "from",
                database.to_str().unwrap(),
                "archive",
                "--ledger",
                &second.ledger_id,
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(registered["registered"], true);
    assert_eq!(registered["name"], "archive");
    assert_eq!(registered["ledger_id"], second.ledger_id);
    assert_ne!(registered["ledger_id"], first.ledger_id);
    assert_eq!(registered["read_only"], true);
    assert_eq!(registered["active"], true);
}

#[test]
fn ledger_options_accept_names_uuids_short_refs_and_remote_names() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["init"]);
    let work: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "new", "work"]).stdout).unwrap();
    let work_ledger = work["ledger_id"].as_str().unwrap().to_owned();
    let work_ref =
        fact_sdk::reference::short_uuid_reference(uuid::Uuid::parse_str(&work_ledger).unwrap());
    std::fs::write(
        home.path().join("remotes.toml"),
        format!("[remotes.origin]\nurl = \"https://example.test\"\nledger = \"{work_ledger}\"\n"),
    )
    .unwrap();

    for reference in [&work_ledger, &work_ref, "origin"] {
        let status: serde_json::Value =
            serde_json::from_slice(&run(&["--json", "status", "--ledger", reference]).stdout)
                .unwrap();
        assert_eq!(status["ledger_name"], "work");
        assert_eq!(status["ledger_id"], work_ledger);
    }

    let token: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "http", "token", "issue", "--ledger", &work_ledger]).stdout,
    )
    .unwrap();
    assert_eq!(token["ledger_id"], work_ledger);

    let source = tempfile::tempdir().unwrap();
    let database = source.path().join("multi.sqlite");
    fact_sdk::environment::init_ledger_database(&database, "local.first", Some([21; 32])).unwrap();
    let second =
        fact_sdk::environment::init_ledger_database(&database, "local.second", Some([22; 32]))
            .unwrap();
    let attached: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "from",
            database.to_str().unwrap(),
            "attached",
            "--ledger",
            &second.ledger_id,
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(attached["ledger_id"], second.ledger_id);

    let bundle = home.path().join("work.bundle");
    let work_db = home.path().join("ledgers/work.sqlite");
    let pulled: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "sync",
            "pull",
            work_db.to_str().unwrap(),
            "origin",
            bundle.to_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert!(pulled["pulled"].as_u64().unwrap() > 0);
    assert!(bundle.exists());
}

#[test]
fn sync_retry_reimports_the_same_bundle_idempotently() {
    let source_home = tempfile::tempdir().unwrap();
    let target_home = tempfile::tempdir().unwrap();
    let bundle = source_home.path().join("retry.bundle");
    let run = |home: &std::path::Path, args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(source_home.path(), &["init"]);
    run(
        source_home.path(),
        &[
            "propose",
            "--message",
            "# Retry\n\nRetryable bundle import.",
            "--decision",
            "accept",
        ],
    );
    let source_status: serde_json::Value =
        serde_json::from_slice(&run(source_home.path(), &["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&source_status);
    let source_db = source_home.path().join("ledgers/default.sqlite");
    run(
        source_home.path(),
        &[
            "sync",
            "pull",
            source_db.to_str().unwrap(),
            source_status["ledger_id"].as_str().unwrap(),
            bundle.to_str().unwrap(),
        ],
    );

    run(target_home.path(), &["init"]);
    let target_db = target_home.path().join("ledgers/default.sqlite");
    let first_retry: serde_json::Value = serde_json::from_slice(
        &run(
            target_home.path(),
            &[
                "--json",
                "sync",
                "retry",
                target_db.to_str().unwrap(),
                bundle.to_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    assert!(first_retry["retried"].as_u64().unwrap() > 0);
    let target_status: serde_json::Value =
        serde_json::from_slice(&run(target_home.path(), &["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&target_status);
    let second_retry: serde_json::Value = serde_json::from_slice(
        &run(
            target_home.path(),
            &[
                "--json",
                "sync",
                "retry",
                target_db.to_str().unwrap(),
                bundle.to_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(second_retry["retried"], 0);
}

#[test]
fn sync_pull_supports_local_limit_and_cursor() {
    let source_home = tempfile::tempdir().unwrap();
    let first_bundle = source_home.path().join("first.bundle");
    let second_bundle = source_home.path().join("second.bundle");
    let run = |home: &std::path::Path, args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(source_home.path(), &["init"]);
    run(
        source_home.path(),
        &[
            "propose",
            "--message",
            "# Cursor Pull\n\nBounded local sync.",
            "--decision",
            "accept",
        ],
    );
    let source_status: serde_json::Value =
        serde_json::from_slice(&run(source_home.path(), &["--json", "status"]).stdout).unwrap();
    let source_db = source_home.path().join("ledgers/default.sqlite");
    let first: serde_json::Value = serde_json::from_slice(
        &run(
            source_home.path(),
            &[
                "--json",
                "sync",
                "pull",
                source_db.to_str().unwrap(),
                source_status["ledger_id"].as_str().unwrap(),
                first_bundle.to_str().unwrap(),
                "--limit",
                "2",
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(first["pulled"], 2);
    assert_eq!(first["complete"], false);
    let cursor = first["next_cursor"].as_str().unwrap();
    assert!(!cursor.is_empty());

    let second: serde_json::Value = serde_json::from_slice(
        &run(
            source_home.path(),
            &[
                "--json",
                "sync",
                "pull",
                source_db.to_str().unwrap(),
                source_status["ledger_id"].as_str().unwrap(),
                second_bundle.to_str().unwrap(),
                "--limit",
                "2",
                "--after",
                cursor,
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(second["pulled"], 2);
    assert_eq!(second["complete"], false);
    assert_ne!(second["next_cursor"], first["next_cursor"]);
}

#[test]
fn object_validate_rejects_noncanonical_unsigned_json() {
    let fixture = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../sdk/fixtures/positive/objects/actor.json"),
    )
    .unwrap();
    let path = std::env::temp_dir().join(format!(
        "fact-noncanonical-object-{}.json",
        uuid::Uuid::now_v7()
    ));
    let mut noncanonical = Vec::with_capacity(fixture.len() + 3);
    noncanonical.extend_from_slice(b" \n");
    noncanonical.extend_from_slice(&fixture);
    std::fs::write(&path, noncanonical).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["object", "validate"])
        .arg(&path)
        .output()
        .expect("fact binary should run");
    std::fs::remove_file(path).unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not canonical"));
}

#[test]
fn import_rejects_noncanonical_markdown_with_plain_message() {
    let home = tempfile::tempdir().unwrap();
    let source = home.path().join("random.md");
    std::fs::write(&source, b"# Title\n\nBody with trailing spaces.  \n").unwrap();
    let init = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["init"])
        .output()
        .expect("fact binary should run");
    assert!(
        init.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["import"])
        .arg(&source)
        .output()
        .expect("fact binary should run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Markdown is not in canonical Fact format"));
    assert!(!stderr.contains("NonCanonical"));
    assert!(!stderr.contains("Markdown(NonCanonical)"));
}

#[test]
fn representative_cli_errors_are_plain_for_casual_users() {
    let home = tempfile::tempdir().unwrap();
    let invalid_markdown = home.path().join("invalid.md");
    let invalid_json = home.path().join("invalid.json");
    let invalid_schema = home.path().join("invalid-schema.json");
    let duplicate_hashes = home.path().join("duplicate-hashes.txt");
    let not_bundle = home.path().join("not.bundle");
    let exported = home.path().join("exported.md");
    std::fs::write(
        &invalid_markdown,
        b"# Title\n\nBody with trailing spaces.  \n",
    )
    .unwrap();
    std::fs::write(&invalid_json, b"{not json}\n").unwrap();
    std::fs::write(&invalid_schema, b"{}").unwrap();
    let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    std::fs::write(&duplicate_hashes, format!("{hash}\n{hash}\n")).unwrap();
    std::fs::write(&not_bundle, b"not a Fact bundle\n").unwrap();
    std::fs::write(&exported, b"already here\n").unwrap();

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run")
    };
    let successful = |args: &[&str]| {
        let output = run(args);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    let failing = |name: &str, args: &[&str]| {
        let output = run(args);
        assert!(
            !output.status.success(),
            "{name} unexpectedly succeeded: stdout={}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_plain_cli_error(name, &output.stderr);
        String::from_utf8_lossy(&output.stderr).into_owned()
    };

    failing("list before init", &["list"]);

    successful(&["init"]);
    let proposed: serde_json::Value = serde_json::from_slice(
        &successful(&[
            "--json",
            "propose",
            "--message",
            "# Searchable alpha\n\nAccepted content.",
            "--decision",
            "accept",
        ])
        .stdout,
    )
    .unwrap();
    let proposition = proposed["proposition_id"].as_str().unwrap();
    let database = home.path().join("ledgers/default.sqlite");

    let markdown_error = failing(
        "import noncanonical Markdown",
        &["import", invalid_markdown.to_str().unwrap()],
    );
    assert!(markdown_error.contains("Markdown is not in canonical Fact format"));

    let overwrite_error = failing(
        "export overwrite",
        &["export", proposition, exported.to_str().unwrap()],
    );
    assert!(overwrite_error.contains("refusing to overwrite"));

    let find_none = failing("find no match", &["find", "definitely-missing"]);
    assert!(find_none.contains("no accepted propositions matched"));

    let find_zero = failing("find pick zero", &["find", "Searchable", "--pick", "0"]);
    assert!(find_zero.contains("--pick starts at 1"));

    let object_json_error = failing(
        "object validate invalid JSON",
        &["object", "validate", invalid_json.to_str().unwrap()],
    );
    assert!(object_json_error.contains("JSON input"));

    let object_schema_error = failing(
        "object validate invalid schema",
        &["object", "validate", invalid_schema.to_str().unwrap()],
    );
    assert!(object_schema_error.contains("missing a required field"));

    let object_uuid_error = failing(
        "object export invalid UUID",
        &[
            "object",
            "export",
            database.to_str().unwrap(),
            "not-a-ledger-id",
            proposition,
            exported.to_str().unwrap(),
        ],
    );
    assert!(object_uuid_error.contains("unknown ledger"));

    let sync_error = failing(
        "sync push wrong file",
        &[
            "sync",
            "push",
            database.to_str().unwrap(),
            not_bundle.to_str().unwrap(),
        ],
    );
    assert!(sync_error.contains("FACTBNDL or FACTSNAP"));

    let proof_error = failing(
        "proof include invalid hash",
        &["proof", "include", "missing", "bad"],
    );
    assert!(
        proof_error.contains("object hashes must be 64 lowercase hexadecimal characters"),
        "stderr: {proof_error}"
    );

    let commitment_error = failing(
        "commitment duplicate hash",
        &["commitment", "create", duplicate_hashes.to_str().unwrap()],
    );
    assert!(commitment_error.contains("same hash more than once"));

    let forwarded_error = failing(
        "find with command failure",
        &["find", "Searchable", "--pick", "1", "--with", "accept"],
    );
    assert!(
        forwarded_error.contains("already settled"),
        "stderr: {forwarded_error}"
    );
    assert!(!forwarded_error.contains("forwarded command exited"));
}

#[test]
fn command_surface_error_output_stays_plain() {
    let home = tempfile::tempdir().unwrap();
    let cases: &[(&str, &[&str])] = &[
        ("accept", &["accept"]),
        ("archive", &["archive"]),
        ("capabilities", &["capabilities", "--unknown-option"]),
        ("clone", &["clone"]),
        ("comment", &["comment"]),
        ("comments", &["comments", "--unknown-option"]),
        ("echo", &["echo"]),
        ("edit", &["edit"]),
        ("export", &["export"]),
        ("find", &["find"]),
        ("from", &["from"]),
        ("here", &["here", "--no-switch"]),
        ("history", &["history", "not-a-reference"]),
        ("import", &["import", "--decision", "maybe"]),
        ("init", &["init", "--unknown-option"]),
        ("invite", &["invite"]),
        ("join", &["join"]),
        ("leave", &["leave"]),
        ("list", &["list"]),
        ("log", &["log", "not-a-reference"]),
        ("new", &["new", "not portable"]),
        ("open", &["open"]),
        ("pending", &["pending"]),
        ("propose", &["propose", "--decision", "maybe"]),
        ("pull", &["pull", "database-only"]),
        ("push", &["push", "database-only"]),
        ("reconcile", &["reconcile"]),
        ("reject", &["reject"]),
        ("remote", &["remote"]),
        ("remote from", &["remote", "from"]),
        ("revise", &["revise"]),
        ("revisions", &["revisions"]),
        ("search", &["search"]),
        ("status", &["status"]),
        ("tags", &["tags", "not-a-reference", "unknown-action"]),
        ("use", &["use"]),
        ("withdraw", &["withdraw"]),
        ("commitment", &["commitment"]),
        ("commitment create", &["commitment", "create"]),
        ("commitment verify", &["commitment", "verify"]),
        ("conformance", &["conformance"]),
        (
            "conformance run",
            &["conformance", "run", "--unknown-option"],
        ),
        ("conformance materialize", &["conformance", "materialize"]),
        ("decision", &["decision"]),
        ("decision cast", &["decision", "cast"]),
        ("deliberate", &["deliberate"]),
        ("deliberations", &["deliberations"]),
        ("deliberation", &["deliberation"]),
        ("deliberation open", &["deliberation", "open"]),
        ("deliberation show", &["deliberation", "show"]),
        (
            "deliberation participants",
            &["deliberation", "participants"],
        ),
        ("identity", &["identity"]),
        ("identity import", &["identity", "import"]),
        (
            "identity export",
            &["identity", "export", "--unknown-option"],
        ),
        ("identity recognize", &["identity", "recognize"]),
        ("identity revoke", &["identity", "revoke"]),
        ("identity rotate", &["identity", "rotate"]),
        ("ledger", &["ledger"]),
        ("ledger clone", &["ledger", "clone"]),
        ("ledger delete", &["ledger", "delete"]),
        ("ledger remote", &["ledger", "remote"]),
        (
            "ledger remote list",
            &["ledger", "remote", "list", "--unknown-option"],
        ),
        ("ledger remote add", &["ledger", "remote", "add"]),
        ("ledger remote remove", &["ledger", "remote", "remove"]),
        ("ledger remote rename", &["ledger", "remote", "rename"]),
        ("ledger create", &["ledger", "create"]),
        ("ledger list", &["ledger", "list", "--unknown-option"]),
        ("ledger init", &["ledger", "init"]),
        ("object", &["object"]),
        ("object validate", &["object", "validate"]),
        ("object import", &["object", "import"]),
        ("object export", &["object", "export"]),
        ("permission", &["permission"]),
        (
            "permission capabilities",
            &["permission", "capabilities", "--unknown-option"],
        ),
        ("permission grant", &["permission", "grant"]),
        ("permission revoke", &["permission", "revoke"]),
        ("proof", &["proof"]),
        ("proof include", &["proof", "include"]),
        ("proof exclude", &["proof", "exclude"]),
        ("proposition", &["proposition"]),
        ("proposition create", &["proposition", "create"]),
        ("proposition revisions", &["proposition", "revisions"]),
        ("proposition inspect", &["proposition", "inspect"]),
        (
            "proposition deliberations",
            &["proposition", "deliberations"],
        ),
        ("proposition comments", &["proposition", "comments"]),
        ("query", &["query"]),
        ("query search", &["query", "search"]),
        ("reconcile create", &["reconcile", "create"]),
        ("settlement", &["settlement"]),
        ("settlement verify", &["settlement", "verify"]),
        ("show-deliberation", &["show-deliberation"]),
        ("state", &["state"]),
        ("state rebuild", &["state", "rebuild"]),
        ("sync", &["sync"]),
        ("sync push", &["sync", "push"]),
        ("sync pull", &["sync", "pull"]),
        ("sync retry", &["sync", "retry"]),
    ];

    for (name, args) in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(*args)
            .output()
            .expect("fact binary should run");
        assert!(
            !output.status.success(),
            "{name} unexpectedly succeeded: stdout={}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_plain_cli_error(name, &output.stderr);

        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .arg("--json")
            .args(*args)
            .output()
            .expect("fact binary should run");
        assert!(
            !output.status.success(),
            "{name} with --json unexpectedly succeeded: stdout={}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_plain_cli_error(&format!("{name} with --json"), &output.stderr);
    }
}

fn assert_plain_cli_error(name: &str, stderr: &[u8]) {
    let stderr = String::from_utf8_lossy(stderr);
    assert!(!stderr.trim().is_empty(), "{name} produced empty stderr");
    let raw_indicators = [
        "Store(",
        "Canonical(",
        "Markdown(",
        "schema:",
        "crypto:",
        "search:",
        "commitment:",
        "InvalidLineage",
        "NonCanonical",
        "Unauthorized",
        "AmbiguousReference",
        "Error: \"",
        "forwarded command exited",
    ];
    for indicator in raw_indicators {
        assert!(
            !stderr.contains(indicator),
            "{name} leaked {indicator:?}: {stderr}"
        );
    }
}

#[test]
fn capabilities_command_lists_grantable_values_for_humans_and_json() {
    let empty_home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", empty_home.path())
        .args(["capabilities"])
        .output()
        .expect("fact binary should run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Available capabilities"));
    assert!(!stdout.contains("Active actor capabilities"));
    for capability in [
        "propose",
        "deliberate",
        "invite",
        "comment",
        "accept",
        "reject",
        "withdraw",
        "archive",
        "admin",
    ] {
        assert!(
            stdout.contains(capability),
            "missing capability {capability}: {stdout}"
        );
    }
    assert!(stdout.contains("highly privileged"));
    assert!(stdout.contains("no separate revise capability"));

    let json_output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", empty_home.path())
        .args(["--json", "capabilities"])
        .output()
        .expect("fact binary should run");
    assert!(
        json_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(
        value["allowed"],
        serde_json::json!([
            "propose",
            "deliberate",
            "invite",
            "comment",
            "accept",
            "reject",
            "withdraw",
            "archive",
            "admin"
        ])
    );
    assert_eq!(value["active_actor"], serde_json::Value::Null);
    assert_eq!(value["capabilities"][8]["name"], "admin");
    assert_eq!(value["capabilities"][8]["privileged"], true);
    assert_eq!(value["capabilities"][8]["held"], false);

    let home = tempfile::tempdir().unwrap();
    let init = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["init"])
        .output()
        .expect("fact binary should run");
    assert!(
        init.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let active_output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["capabilities"])
        .output()
        .expect("fact binary should run");
    assert!(
        active_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&active_output.stderr)
    );
    let active_stdout = String::from_utf8_lossy(&active_output.stdout);
    assert!(active_stdout.contains("Active actor capabilities"));
    assert!(active_stdout.contains("* admin"));

    let active_json = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["--json", "capabilities"])
        .output()
        .expect("fact binary should run");
    assert!(
        active_json.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&active_json.stderr)
    );
    let active: serde_json::Value = serde_json::from_slice(&active_json.stdout).unwrap();
    assert!(active["active_actor"]["actor_id"].is_string());
    assert_eq!(
        active["active_actor"]["capabilities"],
        serde_json::json!(["admin"])
    );
    assert_eq!(active["capabilities"][0]["name"], "propose");
    assert_eq!(active["capabilities"][0]["held"], false);
    assert_eq!(active["capabilities"][8]["name"], "admin");
    assert_eq!(active["capabilities"][8]["held"], true);

    let created = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["--json", "new", "shared"])
        .output()
        .expect("fact binary should run");
    assert!(
        created.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&created.stderr)
    );

    let scoped_json = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["--json", "capabilities", "--ledger", "shared"])
        .output()
        .expect("fact binary should run");
    assert!(
        scoped_json.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&scoped_json.stderr)
    );
    let scoped: serde_json::Value = serde_json::from_slice(&scoped_json.stdout).unwrap();
    assert_eq!(scoped["active_actor"]["ledger"], "shared");
    assert_eq!(
        scoped["active_actor"]["capabilities"],
        serde_json::json!(["admin"])
    );

    let alias_scoped = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["--json", "permission", "capabilities", "--ledger", "shared"])
        .output()
        .expect("fact binary should run");
    assert!(
        alias_scoped.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&alias_scoped.stderr)
    );
    let alias_scoped: serde_json::Value = serde_json::from_slice(&alias_scoped.stdout).unwrap();
    assert_eq!(alias_scoped["active_actor"]["ledger"], "shared");

    let active_after: serde_json::Value = serde_json::from_slice(
        &Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(["--json", "status"])
            .output()
            .expect("fact binary should run")
            .stdout,
    )
    .unwrap();
    assert_eq!(active_after["ledger_name"], "default");
}

#[test]
fn permission_capabilities_is_an_alias_for_capability_discovery() {
    let output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["permission", "capabilities"])
        .output()
        .expect("fact binary should run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Available capabilities"));
    assert!(stdout.contains("admin"));
}

#[test]
fn capability_help_and_validation_are_corrective() {
    let help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["permission", "grant", "--help"])
        .output()
        .expect("fact binary should run");
    assert!(help.status.success());
    let help_stdout = String::from_utf8_lossy(&help.stdout);
    assert!(help_stdout.contains("Allowed: propose, deliberate, invite"));
    assert!(help_stdout.contains("withdraw, archive, admin"));

    let home = tempfile::tempdir().unwrap();
    let init = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["init"])
        .output()
        .expect("fact binary should run");
    assert!(
        init.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let invalid = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args([
            "permission",
            "grant",
            "--identity",
            "missing-actor",
            "--capability",
            "revise",
        ])
        .output()
        .expect("fact binary should run");
    assert!(!invalid.status.success());
    let stderr = String::from_utf8_lossy(&invalid.stderr);
    assert!(stderr.contains("unknown capability \"revise\""), "{stderr}");
    assert!(stderr.contains("Allowed capabilities:"), "{stderr}");
    assert!(stderr.contains("propose, deliberate, invite"), "{stderr}");
    assert!(
        stderr.contains("there is no separate \"revise\" capability"),
        "{stderr}"
    );
}

#[test]
fn identity_export_help_names_optional_file_argument() {
    let help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "identity", "export"])
        .output()
        .expect("fact binary should run");
    assert!(help.status.success());
    let help_stdout = String::from_utf8_lossy(&help.stdout);

    assert!(help_stdout.contains("Usage: fact identity export [OPTIONS] [FILE]"));
    assert!(help_stdout.contains("--actor <ACTOR>"));
    assert!(help_stdout.contains("public identity objects"));
    assert!(help_stdout.contains("private seeds stay under .facts/identities"));
    assert!(!help_stdout.contains("identity key material"));
    assert!(!help_stdout.contains("backup"));
    assert!(!help_stdout.contains("<OUTPUT>"));
}

#[test]
fn object_export_rejects_noncanonical_uuid_scalars_before_opening_store() {
    let ledger = uuid::Uuid::now_v7().to_string().to_uppercase();
    let object = uuid::Uuid::now_v7().to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args([
            "object",
            "export",
            "/no/such/database",
            &ledger,
            &object,
            "/tmp/out",
        ])
        .output()
        .expect("fact binary should run");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("canonical UUIDv7"));
}

#[test]
fn personal_flow_initializes_proposes_accepts_and_lists_effective_fact() {
    let home = tempfile::tempdir().unwrap();
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../sdk/fixtures/README.md");
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    let init: serde_json::Value = serde_json::from_slice(&run(&["--json", "init"]).stdout).unwrap();
    assert_eq!(init["active"], "default");
    let proposed: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "propose", fixture.to_str().unwrap()]).stdout)
            .unwrap();
    let reference = proposed["proposition_id"].as_str().unwrap();
    let reference =
        fact_sdk::reference::short_uuid_reference(uuid::Uuid::parse_str(reference).unwrap());
    let accepted = run(&["--json", "accept", &reference]);
    let accepted: serde_json::Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(accepted["status"], "accepted");
    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status);
    let ledger_id = status["ledger_id"].as_str().unwrap();
    let ledger_ref =
        fact_sdk::reference::short_uuid_reference(uuid::Uuid::parse_str(ledger_id).unwrap());
    let status_text = String::from_utf8_lossy(&run(&["status"]).stdout).into_owned();
    assert!(status_text.contains(&format!("default  {ledger_ref}  ")));
    assert!(!status_text.contains(ledger_id));
    let ledger_list_text = String::from_utf8_lossy(&run(&["ledger", "list"]).stdout).into_owned();
    assert!(ledger_list_text.contains(&format!("* default  {ledger_ref}  ")));
    assert!(!ledger_list_text.contains(ledger_id));
    let ledger_show: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "ledger", "show", ledger_id]).stdout).unwrap();
    assert_eq!(ledger_show["name"], "default");
    assert_eq!(ledger_show["ledger_id"], ledger_id);
    assert_eq!(ledger_show["ledger_ref"], ledger_ref);
    assert_eq!(ledger_show["propositions"]["total"], 1);
    assert_eq!(ledger_show["propositions"]["accepted"], 1);
    assert_eq!(ledger_show["actors"].as_array().unwrap().len(), 1);
    let ledger_show_text =
        String::from_utf8_lossy(&run(&["ledger", "show", ledger_id]).stdout).into_owned();
    assert!(ledger_show_text.contains(&format!("ledger        default  {ledger_ref}")));
    assert!(ledger_show_text.contains("propositions  1 total, 1 accepted"));
    assert!(ledger_show_text.contains("actors\n"));
    assert!(!ledger_show_text.contains(ledger_id));
    let listed: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "list"]).stdout).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["status"], "accepted");
}

#[test]
fn new_creates_local_ledger_without_switching_active_ledger() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    let created_default: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "new"]).stdout).unwrap();
    assert_eq!(created_default["created"], true);
    assert_eq!(created_default["name"], "default");
    assert_eq!(created_default["active"], serde_json::Value::Null);
    assert_eq!(created_default["active_changed"], false);
    assert!(!home.path().join("active").exists());

    let init_default: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "init"]).stdout).unwrap();
    assert_eq!(init_default["active"], "default");
    let created_work: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "new", "work"]).stdout).unwrap();
    assert_eq!(created_work["created"], true);
    assert_eq!(created_work["name"], "work");
    assert_eq!(created_work["active"], "default");
    assert_eq!(created_work["active_changed"], false);

    let existing_work: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "new", "work"]).stdout).unwrap();
    assert_eq!(existing_work["created"], false);
    assert_eq!(existing_work["ledger_id"], created_work["ledger_id"]);
    assert_eq!(existing_work["actor_id"], created_work["actor_id"]);
    assert_eq!(existing_work["active"], "default");
    assert_eq!(
        std::fs::read_to_string(home.path().join("active")).unwrap(),
        "default\n"
    );

    let used_work: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "use", "work"]).stdout).unwrap();
    assert_eq!(used_work["active"], "work");
    assert_eq!(used_work["ledger_id"], created_work["ledger_id"]);
}

#[test]
fn here_creates_project_environment_used_when_fact_home_is_unset() {
    let project = tempfile::tempdir().unwrap();
    let user_home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .current_dir(project.path())
            .env_remove("FACT_HOME")
            .env_remove("XDG_DATA_HOME")
            .env("HOME", user_home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    let here: serde_json::Value = serde_json::from_slice(&run(&["--json", "here"]).stdout).unwrap();
    let local_root = project.path().join(".facts");
    assert_eq!(here["initialized"], true);
    assert_eq!(here["created"], true);
    assert_eq!(
        here["path"],
        local_root.canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(here["ledger"], serde_json::Value::Null);
    assert!(local_root.join("catalog.toml").exists());
    assert!(local_root.join("remotes.toml").exists());
    assert!(local_root.join("identities").is_dir());
    assert!(local_root.join("ledgers").is_dir());
    assert!(!local_root.join("active").exists());

    let init: serde_json::Value = serde_json::from_slice(&run(&["--json", "init"]).stdout).unwrap();
    assert_eq!(init["active"], "default");
    assert_eq!(
        std::fs::read_to_string(local_root.join("active")).unwrap(),
        "default\n"
    );
    assert!(!user_home.path().join(".local/share/fact/active").exists());

    let again: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "here"]).stdout).unwrap();
    assert_eq!(again["initialized"], true);
    assert_eq!(again["created"], false);
}

#[test]
fn here_can_initialize_ledgers_and_respects_fact_home_override() {
    let project = tempfile::tempdir().unwrap();
    let override_home = tempfile::tempdir().unwrap();
    let run_local = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .current_dir(project.path())
            .env_remove("FACT_HOME")
            .env_remove("XDG_DATA_HOME")
            .env("HOME", tempfile::tempdir().unwrap().path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    let created: serde_json::Value =
        serde_json::from_slice(&run_local(&["--json", "here", "--init", "work"]).stdout).unwrap();
    assert_eq!(created["created"], true);
    assert_eq!(created["ledger"]["name"], "work");
    assert_eq!(created["ledger"]["active"], true);
    let local_root = project.path().join(".facts");
    assert_eq!(
        std::fs::read_to_string(local_root.join("active")).unwrap(),
        "work\n"
    );

    let override_init = Command::new(env!("CARGO_BIN_EXE_fact"))
        .current_dir(project.path())
        .env("FACT_HOME", override_home.path())
        .args(["--json", "init", "override"])
        .output()
        .expect("fact binary should run");
    assert!(
        override_init.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&override_init.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(local_root.join("active")).unwrap(),
        "work\n"
    );
    assert_eq!(
        std::fs::read_to_string(override_home.path().join("active")).unwrap(),
        "override\n"
    );

    let project_no_switch = tempfile::tempdir().unwrap();
    let no_switch = Command::new(env!("CARGO_BIN_EXE_fact"))
        .current_dir(project_no_switch.path())
        .env_remove("FACT_HOME")
        .env_remove("XDG_DATA_HOME")
        .env("HOME", tempfile::tempdir().unwrap().path())
        .args(["--json", "here", "--init", "draft", "--no-switch"])
        .output()
        .expect("fact binary should run");
    assert!(
        no_switch.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&no_switch.stderr)
    );
    let no_switch: serde_json::Value = serde_json::from_slice(&no_switch.stdout).unwrap();
    assert_eq!(no_switch["ledger"]["name"], "draft");
    assert_eq!(no_switch["ledger"]["active"], false);
    assert!(!project_no_switch.path().join(".facts/active").exists());

    let fact_home_set = Command::new(env!("CARGO_BIN_EXE_fact"))
        .current_dir(project.path())
        .env("FACT_HOME", override_home.path())
        .args(["--json", "here", "--force"])
        .output()
        .expect("fact binary should run");
    assert!(
        fact_home_set.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&fact_home_set.stderr)
    );
    let fact_home_set: serde_json::Value = serde_json::from_slice(&fact_home_set.stdout).unwrap();
    assert_eq!(fact_home_set["fact_home_set"], true);
}

#[test]
fn here_rejects_unrelated_existing_facts_directory_without_force() {
    let project = tempfile::tempdir().unwrap();
    let facts = project.path().join(".facts");
    std::fs::create_dir(&facts).unwrap();
    std::fs::write(facts.join("notes.txt"), b"not fact config").unwrap();

    let rejected = Command::new(env!("CARGO_BIN_EXE_fact"))
        .current_dir(project.path())
        .env_remove("FACT_HOME")
        .args(["here"])
        .output()
        .expect("fact binary should run");
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("not a Fact environment file"),
        "stderr: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );

    let forced = Command::new(env!("CARGO_BIN_EXE_fact"))
        .current_dir(project.path())
        .env_remove("FACT_HOME")
        .args(["--json", "here", "--force"])
        .output()
        .expect("fact binary should run");
    assert!(
        forced.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&forced.stderr)
    );
    let forced: serde_json::Value = serde_json::from_slice(&forced.stdout).unwrap();
    assert_eq!(forced["initialized"], true);
    assert_eq!(forced["created"], false);
}

#[test]
fn list_limit_bounds_cli_output() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    for index in 0..3 {
        let file = home.path().join(format!("fact-{index}.md"));
        std::fs::write(&file, format!("# Fact {index}\n\nAccepted fact.\n")).unwrap();
        run(&["propose", file.to_str().unwrap(), "--decision", "accept"]);
    }

    let listed: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "list", "--limit", "2"]).stdout).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 2);
    let full_cursor = listed[0]["proposition_id"].as_str().unwrap().to_owned();
    let cursor =
        fact_sdk::reference::short_uuid_reference(uuid::Uuid::parse_str(&full_cursor).unwrap());
    assert_eq!(listed[0]["reference"], cursor);

    let after: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "list", "--limit", "1", "--after", &cursor]).stdout,
    )
    .unwrap();
    assert_eq!(after.as_array().unwrap().len(), 1);
    assert_eq!(after[0]["proposition_id"], listed[1]["proposition_id"]);

    let after_full: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "list", "--limit", "1", "--after", &full_cursor]).stdout,
    )
    .unwrap();
    assert_eq!(after_full.as_array().unwrap().len(), 1);
    assert_eq!(after_full[0]["proposition_id"], listed[1]["proposition_id"]);

    let unbounded: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "list", "--limit", "0"]).stdout).unwrap();
    assert_eq!(unbounded.as_array().unwrap().len(), 3);
    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status);
}

#[test]
fn tags_crud_search_and_sync_use_extension_events() {
    let home = tempfile::tempdir().unwrap();
    let first_file = home.path().join("first.md");
    let second_file = home.path().join("second.md");
    let archived_file = home.path().join("archived.md");
    std::fs::write(&first_file, b"# Policy\n\nSecurity policy.\n").unwrap();
    std::fs::write(&second_file, b"# Checklist\n\nRelease checklist.\n").unwrap();
    std::fs::write(&archived_file, b"# Archived\n\nOld policy.\n").unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["init"]);
    let first: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            first_file.to_str().unwrap(),
            "--decision",
            "accept",
        ])
        .stdout,
    )
    .unwrap();
    let second: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            second_file.to_str().unwrap(),
            "--decision",
            "accept",
        ])
        .stdout,
    )
    .unwrap();
    let archived: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            archived_file.to_str().unwrap(),
            "--decision",
            "accept",
        ])
        .stdout,
    )
    .unwrap();
    run(&["archive", archived["proposition_id"].as_str().unwrap()]);

    let first_ref = first["proposition_id"].as_str().unwrap();
    let second_ref = second["proposition_id"].as_str().unwrap();
    let archived_ref = archived["proposition_id"].as_str().unwrap();
    let added: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "tags", first_ref, "add", "Policy", "urgent"]).stdout,
    )
    .unwrap();
    assert_eq!(added["operation"], "add");
    assert_eq!(added["changed"], true);
    assert_eq!(added["tags"], serde_json::json!(["policy", "urgent"]));

    let repeated: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "tags", first_ref, "create", "policy"]).stdout)
            .unwrap();
    assert_eq!(repeated["changed"], false);
    assert_eq!(repeated["tags"], serde_json::json!(["policy", "urgent"]));

    let shown: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "tags", first_ref, "read"]).stdout).unwrap();
    assert_eq!(shown["operation"], "show");
    assert_eq!(shown["tags"], serde_json::json!(["policy", "urgent"]));

    let removed: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "tags", first_ref, "rm", "urgent"]).stdout)
            .unwrap();
    assert_eq!(removed["operation"], "remove");
    assert_eq!(removed["tags"], serde_json::json!(["policy"]));

    let set: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json", "tags", second_ref, "replace", "policy", "approved",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(set["operation"], "set");
    assert_eq!(set["tags"], serde_json::json!(["approved", "policy"]));
    let limited_search: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "tags", "--search", "approved", "--limit", "1"]).stdout,
    )
    .unwrap();
    assert_eq!(limited_search.as_array().unwrap().len(), 1);
    assert_eq!(
        limited_search[0]["proposition_id"],
        second["proposition_id"]
    );
    let cleared: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "tags", second_ref, "clear"]).stdout).unwrap();
    assert_eq!(cleared["operation"], "clear");
    assert_eq!(cleared["tags"], serde_json::json!([]));

    run(&["tags", archived_ref, "set", "policy"]);
    let bare_list = String::from_utf8_lossy(&run(&["tags"]).stdout).into_owned();
    assert_eq!(bare_list, "policy\n");
    let counted_list =
        String::from_utf8_lossy(&run(&["tags", "--list", "--counts"]).stdout).into_owned();
    assert_eq!(counted_list, "policy  1\n");
    let all_counted: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "tags", "--list", "--counts", "--all"]).stdout)
            .unwrap();
    assert_eq!(
        all_counted,
        serde_json::json!([
            {"tag":"policy","count":2}
        ])
    );
    let hidden_only: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "tags", "--list", "--status", "archived"]).stdout)
            .unwrap();
    assert_eq!(
        hidden_only,
        serde_json::json!([
            {"tag":"policy","count":1}
        ])
    );
    let empty_page =
        String::from_utf8_lossy(&run(&["tags", "--list", "--offset", "1"]).stdout).into_owned();
    assert_eq!(empty_page, "no tags\n");

    let default_search: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "tags", "--search", "policy"]).stdout).unwrap();
    assert_eq!(default_search.as_array().unwrap().len(), 1);
    assert_eq!(default_search[0]["proposition_id"], first["proposition_id"]);
    assert_eq!(default_search[0]["tags"], serde_json::json!(["policy"]));

    let text_filtered_search: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "tags", "--search", "policy", "--text", "Security"]).stdout,
    )
    .unwrap();
    assert_eq!(text_filtered_search.as_array().unwrap().len(), 1);
    assert_eq!(
        text_filtered_search[0]["proposition_id"],
        first["proposition_id"]
    );

    let no_text_match =
        String::from_utf8_lossy(&run(&["tags", "--search", "policy", "--text", "Release"]).stdout)
            .into_owned();
    assert_eq!(no_text_match, "no propositions matched those tags\n");

    let tagged_text_search: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "search", "Security", "--tag", "policy"]).stdout)
            .unwrap();
    assert_eq!(tagged_text_search.as_array().unwrap().len(), 1);
    assert_eq!(
        tagged_text_search[0]["proposition_id"],
        first["proposition_id"]
    );
    let leading_tag_text_search: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "search", "--tag", "policy", "Security"]).stdout)
            .unwrap();
    assert_eq!(
        leading_tag_text_search[0]["proposition_id"],
        first["proposition_id"]
    );

    let untagged_text_search =
        String::from_utf8_lossy(&run(&["search", "Release", "--tag", "policy"]).stdout)
            .into_owned();
    assert_eq!(untagged_text_search, "no results\n");

    let tagged_find: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "find", "Security", "--tag", "policy"]).stdout)
            .unwrap();
    assert_eq!(tagged_find["proposition_id"], first["proposition_id"]);
    let leading_tagged_find: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "find", "--tag", "policy", "Security"]).stdout)
            .unwrap();
    assert_eq!(
        leading_tagged_find["proposition_id"],
        first["proposition_id"]
    );
    let repeated_tagged_find: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json", "find", "--tag", "policy", "--tag", "policy", "Security",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(
        repeated_tagged_find["proposition_id"],
        first["proposition_id"]
    );

    let untagged_find_output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["find", "Release", "--tag", "policy"])
        .output()
        .expect("fact binary should run");
    assert!(!untagged_find_output.status.success());
    let untagged_find = String::from_utf8_lossy(&untagged_find_output.stderr).into_owned();
    assert!(untagged_find.contains("no accepted propositions matched \"Release\""));

    let all_search: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "tags", "--search", "policy", "--all"]).stdout)
            .unwrap();
    assert_eq!(all_search.as_array().unwrap().len(), 2);
    assert!(all_search
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["proposition_id"] == archived["proposition_id"]));

    let any_search: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json", "tags", "--search", "policy", "missing", "--match", "any",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(any_search.as_array().unwrap().len(), 1);

    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let connection = rusqlite::Connection::open(status["database"].as_str().unwrap()).unwrap();
    let extension_events: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM extension_event WHERE extension_name='fact.tags'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(extension_events, 5);
    let projected_policy: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM projected_tag WHERE tag='policy'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(projected_policy, 2);
    let relationship_events: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM protocol_object WHERE object_type='application_relationship'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(relationship_events, 0);

    let bundle = home.path().join("tags.fact-tags.json");
    let export_json: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "tags", "export", bundle.to_str().unwrap()]).stdout,
    )
    .unwrap();
    assert_eq!(export_json["exported"], 5);
    assert!(export_json["bundle_bytes"].as_u64().unwrap() > 0);
    let import_json: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "tags", "import", bundle.to_str().unwrap()]).stdout,
    )
    .unwrap();
    assert_eq!(import_json, serde_json::json!({"imported":0,"skipped":5}));
}

#[test]
fn show_command_summarizes_proposition_context() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["init"]);
    run(&[
        "directory",
        "add",
        "Ledger Admin",
        "--self",
        "--alias",
        "admin",
    ]);
    let created: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            "--message",
            "# Showable\n\nImportant context for overview.",
            "--decision",
            "accept",
        ])
        .stdout,
    )
    .unwrap();
    let proposition_id = created["proposition_id"].as_str().unwrap();
    run(&["tags", proposition_id, "add", "overview", "important"]);
    run(&[
        "comment",
        proposition_id,
        "--message",
        "# Note\n\nThis belongs in the overview.",
    ]);

    let shown: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "show", proposition_id]).stdout).unwrap();
    assert_eq!(shown["query"], proposition_id);
    assert_eq!(shown["matched"]["object_type"], "proposition");
    assert_eq!(shown["proposition"]["proposition_id"], proposition_id);
    assert_eq!(shown["effective_revision"]["effective"], true);
    assert_eq!(shown["tags"], serde_json::json!(["important", "overview"]));
    assert_eq!(shown["conflicts"], serde_json::json!([]));
    assert_eq!(shown["pending"]["current_actor_pending"], false);
    assert_eq!(shown["revisions"].as_array().unwrap().len(), 1);
    assert_eq!(shown["comments"].as_array().unwrap().len(), 1);
    assert_eq!(shown["content_included"], false);
    assert_eq!(shown["content"], serde_json::Value::Null);

    let revision_ref = shown["effective_revision"]["reference"].as_str().unwrap();
    let by_revision: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "show", revision_ref]).stdout).unwrap();
    assert_eq!(by_revision["matched"]["object_type"], "revision");
    assert_eq!(by_revision["proposition"]["proposition_id"], proposition_id);
    assert_eq!(by_revision["revisions"][0]["highlighted"], true);

    let human = String::from_utf8_lossy(
        &run(&[
            "show",
            proposition_id,
            "--content",
            "--participants",
            "--history",
            "--limit",
            "2",
        ])
        .stdout,
    )
    .into_owned();
    assert!(human.contains("Effective revision"));
    assert!(human.contains("Tags"));
    assert!(human.contains("Revisions"));
    assert!(human.contains("Comments"));
    assert!(human.contains("Deliberations"));
    assert!(human.contains("History"));
    assert!(human.contains("Content\n  # Showable"));
    assert!(human.contains("Next\n  no pending actions for you"));
    assert!(human.ends_with("  # Showable\n  \n  Important context for overview.\n"));

    let no_revisions: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "show", proposition_id, "--revisions", "0"]).stdout,
    )
    .unwrap();
    assert_eq!(no_revisions["revisions"], serde_json::json!([]));
}

#[test]
fn conflicts_command_reports_empty_state_for_ordinary_ledgers() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["init"]);
    run(&[
        "propose",
        "--message",
        "# Ordinary\n\nNo conflict here.",
        "--decision",
        "accept",
    ]);
    let human = String::from_utf8_lossy(&run(&["conflicts"]).stdout).into_owned();
    assert_eq!(human, "no revision conflicts\n");
    let json: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "conflicts"]).stdout).unwrap();
    assert_eq!(json, serde_json::json!([]));
}

#[test]
fn lifecycle_and_rejection_keep_indexed_proposition_consistent() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    let rejected_target: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            "--message",
            "# Rejectable\n\nPending rejection.",
        ])
        .stdout,
    )
    .unwrap();
    let rejected: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "reject",
            rejected_target["proposition_id"].as_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(rejected["status"], "rejected");
    let status_after_reject: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status_after_reject);

    let withdrawn_target: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            "--message",
            "# Withdrawable\n\nAccepted before withdrawal.",
            "--decision",
            "accept",
        ])
        .stdout,
    )
    .unwrap();
    let withdrawn: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "withdraw",
            withdrawn_target["proposition_id"].as_str().unwrap(),
            "--reason",
            "not currently true",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(withdrawn["operation"], "withdraw");
    let withdrawn_list: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "list", "--status", "withdrawn"]).stdout).unwrap();
    assert!(withdrawn_list
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["proposition_id"] == withdrawn_target["proposition_id"]));
    let status_after_withdraw: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status_after_withdraw);

    let archived_target: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            "--message",
            "# Archivable\n\nAccepted before archive.",
            "--decision",
            "accept",
        ])
        .stdout,
    )
    .unwrap();
    let archived: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "archive",
            archived_target["proposition_id"].as_str().unwrap(),
            "--reason",
            "kept for history",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(archived["operation"], "archive");
    let archived_list: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "list", "--status", "archived"]).stdout).unwrap();
    assert!(archived_list
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["proposition_id"] == archived_target["proposition_id"]));
    let status_after_archive: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status_after_archive);
}

#[test]
fn reconcile_create_builds_acceptable_reconciliation_proposition() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    let source: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            "--message",
            "# Source\n\nAccepted source.",
            "--decision",
            "accept",
        ])
        .stdout,
    )
    .unwrap();
    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status);
    let conflict = format!(
        "{}:{}:{}",
        source["revision_id"].as_str().unwrap(),
        source["deliberation_id"].as_str().unwrap(),
        source["settlement_id"].as_str().unwrap()
    );
    let reconciliation: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "reconcile",
            "create",
            source["proposition_id"].as_str().unwrap(),
            source["revision_id"].as_str().unwrap(),
            "--conflict",
            &conflict,
            "--mode",
            "select",
            "--selected",
            source["revision_id"].as_str().unwrap(),
            "--resolved-tip",
            source["revision_id"].as_str().unwrap(),
            "--message",
            "# Reconcile\n\nSelect the source.",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(reconciliation["resolution_mode"], "select");
    assert_eq!(reconciliation["selected_participant_count"], 1);

    let accepted: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "accept",
            reconciliation["proposition_id"].as_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(accepted["status"], "accepted");
    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status);
}

#[test]
fn resolve_command_reports_no_revision_conflicts() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    run(&[
        "propose",
        "--message",
        "# Ordinary\n\nNo conflict exists.",
        "--decision",
        "accept",
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args([
            "resolve",
            "--message",
            "# Resolution\n\nNothing to resolve.",
        ])
        .output()
        .expect("fact binary should run");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no revision conflicts"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "resolve"])
        .output()
        .expect("fact binary should run");
    assert!(help.status.success());
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(stdout.contains("resolve [OPTIONS] [REF] [FILE]"));
    assert!(stdout.contains("--keep"));
    assert!(stdout.contains("--merge"));
    assert!(stdout.contains("--pick"));
}

#[test]
fn state_rebuild_repairs_disposable_projected_rows() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    let proposed: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            "--message",
            "# Repairable\n\nProjected state can be rebuilt.",
            "--decision",
            "accept",
        ])
        .stdout,
    )
    .unwrap();
    let database = home.path().join("ledgers/default.sqlite");
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute_batch("DELETE FROM projected_effective; DELETE FROM projected_object;")
        .unwrap();

    let stale = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["--json", "list"])
        .output()
        .expect("fact binary should run");
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("fact state rebuild"));

    let rebuilt: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "state", "rebuild", database.to_str().unwrap()]).stdout,
    )
    .unwrap();
    assert!(rebuilt["rebuilt"].as_bool().unwrap());
    assert!(rebuilt["effective_propositions"].as_u64().unwrap() > 0);
    let listed: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "list"]).stdout).unwrap();
    assert_eq!(listed[0]["proposition_id"], proposed["proposition_id"]);
    assert_eq!(listed[0]["status"], "accepted");
    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status);
}

#[test]
fn personal_content_and_discussion_commands_preserve_read_only_boundaries() {
    let home = tempfile::tempdir().unwrap();
    let source = home.path().join("source.md");
    let comment = home.path().join("comment.md");
    let exported = home.path().join("exported.md");
    let revised = home.path().join("revised.md");
    std::fs::write(&source, b"# Original\n\nCanonical content.\n").unwrap();
    std::fs::write(&comment, b"# Comment\n\nAdditional context.\n").unwrap();
    std::fs::write(&revised, b"# Revised\n\nUpdated content.\n").unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    let proposed: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            source.to_str().unwrap(),
            "--decision",
            "accept",
        ])
        .stdout,
    )
    .unwrap();
    let reference = proposed["proposition_id"].as_str().unwrap();
    let discussion: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "deliberate", reference]).stdout).unwrap();
    assert_eq!(discussion["proposition_id"], reference);
    run(&["comment", reference, comment.to_str().unwrap()]);
    let echoed = run(&["echo", reference]);
    assert_eq!(echoed.stdout, b"# Original\n\nCanonical content.\n");
    run(&["export", reference, exported.to_str().unwrap()]);
    assert_eq!(std::fs::read(&exported).unwrap(), echoed.stdout);
    let revised_result: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "revise", reference, revised.to_str().unwrap()]).stdout,
    )
    .unwrap();
    assert_ne!(revised_result["revision_id"], serde_json::Value::Null);
    assert_eq!(
        run(&["echo", reference]).stdout,
        b"# Original\n\nCanonical content.\n"
    );
    assert_eq!(
        run(&["echo", reference, "--pending"]).stdout,
        b"# Revised\n\nUpdated content.\n"
    );
    assert_eq!(
        run(&["echo", reference, "--latest"]).stdout,
        b"# Revised\n\nUpdated content.\n"
    );
    run(&[
        "export",
        reference,
        exported.to_str().unwrap(),
        "--force",
        "--pending",
    ]);
    assert_eq!(
        std::fs::read(&exported).unwrap(),
        b"# Revised\n\nUpdated content.\n"
    );
    run(&["accept", revised_result["revision_id"].as_str().unwrap()]);
    assert_eq!(
        run(&["echo", reference]).stdout,
        b"# Revised\n\nUpdated content.\n"
    );
}

#[test]
fn identity_import_and_recognition_keep_existence_separate_from_authority() {
    let source_home = tempfile::tempdir().unwrap();
    let identity_bundle = source_home.path().join("identity.bundle");
    let run = |home: &std::path::Path, args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(source_home.path(), &["init"]);
    run(
        source_home.path(),
        &["identity", "export", identity_bundle.to_str().unwrap()],
    );
    let source_actor: serde_json::Value =
        serde_json::from_slice(&run(source_home.path(), &["--json", "status"]).stdout).unwrap();
    let target_home = tempfile::tempdir().unwrap();
    run(target_home.path(), &["init"]);
    let imported: serde_json::Value = serde_json::from_slice(
        &run(
            target_home.path(),
            &[
                "--json",
                "identity",
                "import",
                identity_bundle.to_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(imported["recognized"], false);
    assert_eq!(imported["authority_granted"], false);
    assert_eq!(imported["actors"].as_array().unwrap().len(), 1);
    assert_eq!(imported["actors"][0]["actor_id"], source_actor["actor_id"]);
    let source_actor_ref = fact_sdk::reference::short_uuid_reference(
        uuid::Uuid::parse_str(source_actor["actor_id"].as_str().unwrap()).unwrap(),
    );
    assert_eq!(imported["actors"][0]["actor_ref"], source_actor_ref);
    assert_eq!(imported["actors"][0]["already_present"], false);
    let imported_again: serde_json::Value = serde_json::from_slice(
        &run(
            target_home.path(),
            &[
                "--json",
                "identity",
                "import",
                identity_bundle.to_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(imported_again["imported"], 0);
    assert_eq!(
        imported_again["actors"][0]["actor_id"],
        source_actor["actor_id"]
    );
    assert_eq!(imported_again["actors"][0]["actor_ref"], source_actor_ref);
    assert_eq!(imported_again["actors"][0]["already_present"], true);
    let human_imported_again_output = run(
        target_home.path(),
        &["identity", "import", identity_bundle.to_str().unwrap()],
    );
    let human_imported_again =
        String::from_utf8_lossy(&human_imported_again_output.stdout).into_owned();
    assert!(human_imported_again.contains("imported 0 identity object(s)"));
    assert!(human_imported_again.contains(&source_actor_ref));
    assert!(human_imported_again.contains("already present"));
    let recognized: serde_json::Value = serde_json::from_slice(
        &run(
            target_home.path(),
            &[
                "--json",
                "identity",
                "recognize",
                source_actor["actor_id"].as_str().unwrap(),
                "--participate",
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(recognized["recognized"], true);
    assert_eq!(recognized["authority_granted"], true);
    assert_eq!(
        recognized["capabilities"],
        serde_json::json!(["propose", "deliberate", "comment", "accept", "reject"])
    );
    let revoked: serde_json::Value = serde_json::from_slice(
        &run(
            target_home.path(),
            &[
                "--json",
                "permission",
                "revoke",
                "--identity",
                source_actor["actor_id"].as_str().unwrap(),
                "--participate",
                "--reason",
                "role ended",
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(revoked["participate"], true);
    assert_eq!(revoked["revoked_count"], 1);
    assert_eq!(
        revoked["revocations"][0]["revoked_grant_id"],
        recognized["grant_id"]
    );
}

#[test]
fn actor_send_inspect_reuses_identity_without_a_ledger() {
    let home = tempfile::tempdir().unwrap();
    let request = home.path().join("alnewkirk.actor.json");
    let explicit_request = home.path().join("custom.actor.bndl");
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .current_dir(home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    let sent: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "actor",
            "send",
            "Al Newkirk",
            "--alias",
            "alnewkirk",
            "--request",
            "participate",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(sent["claims"]["display_name"], "Al Newkirk");
    assert_eq!(sent["claims"]["alias"], "alnewkirk");
    assert_eq!(sent["claims"]["actor_type"], "human");
    assert!(sent["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
    assert!(request.exists());
    assert_eq!(sent["output"], "alnewkirk.actor.json");
    assert!(!home.path().join("catalog.toml").exists());

    let inspected: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "actor", "inspect", request.to_str().unwrap()]).stdout,
    )
    .unwrap();
    assert_eq!(inspected["actor_id"], sent["actor_id"]);
    assert_eq!(inspected["fingerprint"], sent["fingerprint"]);
    assert!(inspected["requests"]
        .as_array()
        .unwrap()
        .iter()
        .any(|capability| capability == "propose"));

    let sent_again: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "actor",
            "send",
            "Al Newkirk",
            "--alias",
            "alnewkirk",
            "--output",
            explicit_request.to_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(sent_again["actor_id"], sent["actor_id"]);
    assert!(explicit_request.exists());
    assert_eq!(sent_again["output"], explicit_request.to_str().unwrap());
}

#[test]
fn actor_send_prefers_directory_claims_over_ledgerless_registry() {
    let home = tempfile::tempdir().unwrap();
    let stale_request = home.path().join("stale.actor.bndl");
    let name_request = home.path().join("name.actor.bndl");
    let alias_request = home.path().join("alias.actor.bndl");
    let explicit_request = home.path().join("explicit.actor.bndl");
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    let stale: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "actor",
            "send",
            "alnewkirk",
            "--output",
            stale_request.to_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(stale["claims"]["display_name"], "alnewkirk");
    assert_eq!(stale["claims"]["alias"], serde_json::Value::Null);

    run(&["init"]);
    run(&[
        "directory",
        "add",
        "Al Newkirk",
        "--self",
        "--alias",
        "alnewkirk",
        "--type",
        "human",
    ]);
    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();

    let by_name: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "actor",
            "send",
            "Al Newkirk",
            "--output",
            name_request.to_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(by_name["actor_id"], status["actor_id"]);
    assert_eq!(by_name["claims"]["display_name"], "Al Newkirk");
    assert_eq!(by_name["claims"]["alias"], "alnewkirk");
    assert_eq!(by_name["claims"]["actor_type"], "human");

    let by_alias: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "actor",
            "send",
            "alnewkirk",
            "--output",
            alias_request.to_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(by_alias["actor_id"], status["actor_id"]);
    assert_eq!(by_alias["claims"]["display_name"], "Al Newkirk");
    assert_eq!(by_alias["claims"]["alias"], "alnewkirk");
    assert_eq!(by_alias["claims"]["actor_type"], "human");

    let explicit: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "actor",
            "send",
            "Al Newkirk",
            "--alias",
            "alnewkirk",
            "--type",
            "human",
            "--participate",
            "--output",
            explicit_request.to_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(explicit["actor_id"], status["actor_id"]);
    assert_eq!(explicit["claims"]["display_name"], "Al Newkirk");
    assert_eq!(explicit["claims"]["alias"], "alnewkirk");
    assert_eq!(explicit["claims"]["actor_type"], "human");
    assert_eq!(
        explicit["requests"],
        serde_json::json!(["propose", "deliberate", "comment", "accept", "reject"])
    );
}

#[test]
fn profiles_template_actor_metadata_across_ledgers_and_requests() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .current_dir(home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    let added: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "profile",
            "add",
            "me",
            "--name",
            "Al Newkirk",
            "--alias",
            "alnewkirk",
            "--type",
            "human",
            "--role",
            "maintainer",
            "--default",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(added["profile"], "me");
    assert_eq!(added["display_name"], "Al Newkirk");
    assert_eq!(added["alias"], "alnewkirk");
    assert_eq!(added["actor_type"], "human");
    assert_eq!(added["role"], "maintainer");
    assert_eq!(added["default"], true);
    assert!(home.path().join("profiles.toml").exists());

    let listed: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "profile", "list"]).stdout).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    let shown: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "profile", "show", "me"]).stdout).unwrap();
    assert_eq!(shown["alias"], "alnewkirk");

    run(&["init", "default"]);
    let default_status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let default_directory: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "directory", "show", "alnewkirk"]).stdout).unwrap();
    assert_eq!(default_directory["actor_id"], default_status["actor_id"]);
    assert_eq!(default_directory["display_name"], "Al Newkirk");
    assert_eq!(default_directory["alias"], "alnewkirk");
    assert_eq!(default_directory["actor_type"], "human");
    assert_eq!(default_directory["role"], "maintainer");
    assert_eq!(default_directory["source"], "profile:me");

    run(&["new", "research"]);
    let research_directory: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "directory",
            "show",
            "alnewkirk",
            "--ledger",
            "research",
        ])
        .stdout,
    )
    .unwrap();
    assert_ne!(
        research_directory["actor_id"],
        default_directory["actor_id"]
    );
    assert_eq!(research_directory["display_name"], "Al Newkirk");

    run(&["profile", "update", "me", "--role", "release-manager"]);
    let applied: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "profile", "apply", "me", "--ledger", "default"]).stdout,
    )
    .unwrap();
    assert_eq!(applied["applied"].as_array().unwrap().len(), 1);
    let reapplied_directory: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "directory", "show", "alnewkirk"]).stdout).unwrap();
    assert_eq!(reapplied_directory["role"], "release-manager");

    let profile_actor: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "as", "--profile", "me"]).stdout).unwrap();
    assert_eq!(profile_actor["actor"]["display_name"], "Al Newkirk");
    assert_eq!(profile_actor["actor"]["alias"], "alnewkirk");
    assert_eq!(profile_actor["actor"]["type"], "human");

    let request_file = home.path().join("alnewkirk.actor.json");
    let request: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "actor",
            "send",
            "--profile",
            "me",
            "--output",
            request_file.to_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(request["claims"]["display_name"], "Al Newkirk");
    assert_eq!(request["claims"]["alias"], "alnewkirk");
    assert_eq!(request["claims"]["actor_type"], "human");
    assert!(request_file.exists());

    run(&["profile", "delete", "me"]);
    let empty: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "profile", "list"]).stdout).unwrap();
    assert!(empty.as_array().unwrap().is_empty());
}

#[test]
fn personas_reuse_signing_identity_for_new_ledgers_without_deleting_seed() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .current_dir(home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    let persona: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "persona",
            "add",
            "me",
            "--name",
            "Al Newkirk",
            "--alias",
            "alnewkirk",
            "--default",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(persona["persona"], "me");
    assert_eq!(persona["display_name"], "Al Newkirk");
    assert_eq!(persona["alias"], "alnewkirk");
    assert_eq!(persona["default"], true);
    assert_eq!(persona["local_private_key_material"], true);
    assert!(home.path().join("personas.toml").exists());

    let persona_actor = persona["actor_id"].as_str().unwrap().to_owned();
    let seed = home
        .path()
        .join("identities")
        .join(format!("{persona_actor}.seed"));
    assert!(seed.exists());
    assert!(
        !home
            .path()
            .join("identities")
            .join("personas.sqlite")
            .exists(),
        "new persona creation should not create the legacy sqlite identity store"
    );
    let listed: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "persona", "list"]).stdout).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    let shown: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "persona", "show", "alnewkirk"]).stdout).unwrap();
    assert_eq!(shown["actor_id"], persona_actor);

    let first: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "init", "factory"]).stdout).unwrap();
    assert_eq!(first["actor_id"], persona_actor);
    assert_eq!(first["persona"], "me");
    let first_status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_eq!(first_status["actor_id"], persona_actor);
    assert_eq!(first_status["persona"], "me");
    let first_identity: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "identity", "show", "alnewkirk"]).stdout).unwrap();
    assert_eq!(first_identity["persona"], "me");
    assert_eq!(first_identity["capabilities"], serde_json::json!(["admin"]));
    let actors: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "actor", "list"]).stdout).unwrap();
    assert!(actors.as_array().unwrap().iter().any(|item| {
        item["actor_id"] == persona_actor
            && item["display_name"] == "Al Newkirk"
            && item["persona"] == "me"
    }));
    assert!(actors.as_array().unwrap().iter().any(|item| {
        item["actor_id"] != persona_actor
            && item["display_name"].is_null()
            && item["persona"].is_null()
    }));
    let actor_text = String::from_utf8_lossy(&run(&["actor", "list"]).stdout).into_owned();
    assert!(!actor_text.contains("actor 01a"));
    assert!(!actor_text.contains("persona me"));
    assert!(actor_text.contains("Al Newkirk  alnewkirk  admin  active"));
    assert!(actor_text.contains("No name  No alias  admin"));

    let second: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "new", "research"]).stdout).unwrap();
    assert_eq!(second["actor_id"], persona_actor);
    assert_eq!(second["persona"], "me");
    assert_ne!(second["ledger_id"], first["ledger_id"]);
    let second_status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status", "--ledger", "research"]).stdout).unwrap();
    assert_eq!(second_status["actor_id"], persona_actor);
    assert_eq!(second_status["persona"], "me");

    run(&["ledger", "delete", "factory", "--force"]);
    assert!(seed.exists());
    let persona_after_delete: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "persona", "show", "me"]).stdout).unwrap();
    assert_eq!(persona_after_delete["local_private_key_material"], true);
}

#[test]
fn legacy_store_backed_personas_still_initialize_ledgers() {
    let home = tempfile::tempdir().unwrap();
    let identities = home.path().join("identities");
    std::fs::create_dir_all(&identities).unwrap();
    let persona_database = identities.join("personas.sqlite");
    let store = fact_store::Store::open(&persona_database).unwrap();
    let identity = fact_sdk::workflow::create_identity(
        &store,
        fact_sdk::workflow::CreateIdentityInput {
            namespace: "local.persona.legacy".into(),
            seed: [23; 32],
            actor_type: "human".into(),
        },
    )
    .unwrap();
    std::fs::write(
        identities.join(format!("{}.seed", identity.actor_id)),
        format!("{}\n", hex::encode([23; 32])),
    )
    .unwrap();
    std::fs::write(
        home.path().join("personas.toml"),
        format!(
            r#"default = "legacy"

[personas.legacy]
display_name = "Legacy Persona"
alias = "legacy"
actor_type = "human"
ledger_id = "{}"
actor_id = "{}"
key_id = "{}"
"#,
            identity.ledger_id, identity.actor_id, identity.key_id
        ),
    )
    .unwrap();

    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .current_dir(home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    let ledger: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "new", "legacy-ledger"]).stdout).unwrap();
    assert_eq!(ledger["actor_id"], identity.actor_id.to_string());
    assert_eq!(ledger["persona"], "legacy");
    run(&["use", "legacy-ledger"]);
    let shown: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "identity", "show", "legacy"]).stdout).unwrap();
    assert_eq!(shown["actor_id"], identity.actor_id.to_string());
    assert_eq!(shown["capabilities"], serde_json::json!(["admin"]));
}

#[test]
fn actor_admit_requires_explicit_capabilities() {
    let requester = tempfile::tempdir().unwrap();
    let admin = tempfile::tempdir().unwrap();
    let request = requester.path().join("user.actor.bndl");
    let run = |home: &std::path::Path, args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run")
    };
    let sent = run(
        requester.path(),
        &[
            "actor",
            "send",
            "User A",
            "--alias",
            "user-a",
            "--request",
            "participate",
            "--output",
            request.to_str().unwrap(),
        ],
    );
    assert!(
        sent.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&sent.stderr)
    );
    let init = run(admin.path(), &["init"]);
    assert!(
        init.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let admitted = run(
        admin.path(),
        &[
            "actor",
            "admit",
            request.to_str().unwrap(),
            "--remote",
            "https://facts.example",
        ],
    );
    assert!(!admitted.status.success());
    let stderr = String::from_utf8_lossy(&admitted.stderr);
    assert!(stderr.contains("at least one capability is required"));
}

#[test]
fn actor_admit_requires_remote_before_writing_state() {
    let requester = tempfile::tempdir().unwrap();
    let admin = tempfile::tempdir().unwrap();
    let request = requester.path().join("user.actor.bndl");
    let response = admin.path().join("user.connection.json");
    let run = |home: &std::path::Path, args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run")
    };
    let sent = run(
        requester.path(),
        &[
            "--json",
            "actor",
            "send",
            "User A",
            "--alias",
            "user-a",
            "--output",
            request.to_str().unwrap(),
        ],
    );
    assert!(
        sent.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&sent.stderr)
    );
    let sent: serde_json::Value = serde_json::from_slice(&sent.stdout).unwrap();
    let actor_id = sent["actor_id"].as_str().unwrap();
    let init = run(admin.path(), &["init"]);
    assert!(
        init.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let other = run(admin.path(), &["new", "other"]);
    assert!(
        other.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&other.stderr)
    );
    let remote = run(
        admin.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://facts.example",
            "--ledger",
            "other",
        ],
    );
    assert!(
        remote.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&remote.stderr)
    );

    let admitted = run(
        admin.path(),
        &[
            "actor",
            "admit",
            request.to_str().unwrap(),
            "--participate",
            "--with-token",
            "--output",
            response.to_str().unwrap(),
        ],
    );
    assert!(!admitted.status.success());
    let stderr = String::from_utf8_lossy(&admitted.stderr);
    assert!(stderr.contains("no remote is configured for ledger"));
    assert!(!response.exists());
    assert!(!admin.path().join("remotes/tokens.sqlite").exists());

    let identities = run(admin.path(), &["--json", "identity", "list"]);
    assert!(
        identities.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&identities.stderr)
    );
    let identities: serde_json::Value = serde_json::from_slice(&identities.stdout).unwrap();
    assert!(!identities
        .as_array()
        .unwrap()
        .iter()
        .any(|identity| identity["actor_id"] == actor_id));

    let directory = run(admin.path(), &["--json", "directory", "list"]);
    assert!(
        directory.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&directory.stderr)
    );
    let directory: serde_json::Value = serde_json::from_slice(&directory.stdout).unwrap();
    assert!(!directory
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["actor_id"] == actor_id));
}

#[test]
fn actor_admit_allows_non_genesis_admin() {
    let requester = tempfile::tempdir().unwrap();
    let admin = tempfile::tempdir().unwrap();
    let request = requester.path().join("user.actor.bndl");
    let response = admin.path().join("user.connection.json");
    let run = |home: &std::path::Path, args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(
        requester.path(),
        &[
            "actor",
            "send",
            "User A",
            "--alias",
            "user-a",
            "--output",
            request.to_str().unwrap(),
        ],
    );
    run(admin.path(), &["init"]);
    run(
        admin.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://facts.example",
            "--ledger",
            "default",
        ],
    );
    let delegated_admin: serde_json::Value = serde_json::from_slice(
        &run(
            admin.path(),
            &[
                "--json",
                "as",
                "Delegated Admin",
                "--alias",
                "delegated",
                "--type",
                "human",
                "--permission",
                "admin",
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(
        delegated_admin["created_permission_grants"][0]["capabilities"],
        serde_json::json!(["admin"])
    );

    let admitted: serde_json::Value = serde_json::from_slice(
        &run(
            admin.path(),
            &[
                "--json",
                "actor",
                "admit",
                request.to_str().unwrap(),
                "--participate",
                "--output",
                response.to_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(admitted["admitted"], true);
    assert_eq!(
        admitted["granted"],
        serde_json::json!(["propose", "deliberate", "comment", "accept", "reject"])
    );
    assert!(response.exists());
}

#[test]
fn actor_admit_writes_response_consumed_by_clone() {
    let requester = tempfile::tempdir().unwrap();
    let admin = tempfile::tempdir().unwrap();
    let request = requester.path().join("alnewkirk.actor.bndl");
    let response = requester.path().join("alnewkirk.connection.json");
    let run = |home: &std::path::Path, args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(
        requester.path(),
        &[
            "actor",
            "send",
            "Al Newkirk",
            "--alias",
            "alnewkirk",
            "--request",
            "participate",
            "--output",
            request.to_str().unwrap(),
        ],
    );
    run(admin.path(), &["init"]);
    run(
        admin.path(),
        &[
            "propose",
            "--message",
            "# Actor Admission\n\nRemote actor can clone this ledger.",
            "--decision",
            "accept",
        ],
    );
    let status: serde_json::Value =
        serde_json::from_slice(&run(admin.path(), &["--json", "status"]).stdout).unwrap();
    let ledger = status["ledger_id"].as_str().unwrap().to_owned();
    let admin_db = admin.path().join("ledgers/default.sqlite");
    let store = fact_store::Store::open(&admin_db).unwrap();
    let (_, genesis_hash) = store
        .get_ledger_metadata(uuid::Uuid::parse_str(&ledger).unwrap().as_bytes())
        .unwrap()
        .unwrap();
    let genesis_hash = genesis_hash.unwrap().hex();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_url = format!("http://{}", listener.local_addr().unwrap());
    run(
        admin.path(),
        &[
            "remote",
            "add",
            "origin",
            &remote_url,
            "--ledger",
            "default",
        ],
    );
    let admitted: serde_json::Value = serde_json::from_slice(
        &run(
            admin.path(),
            &[
                "--json",
                "actor",
                "admit",
                request.to_str().unwrap(),
                "--participate",
                "--with-token",
                "--output",
                response.to_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(
        admitted["response"]["schema"],
        "fact-remote-actor-response-v0"
    );
    assert_eq!(admitted["response"]["endpoint"]["schema"], "fact-remote-v0");
    assert_eq!(admitted["response"]["endpoint"]["ledger_id"], ledger);
    assert_eq!(
        admitted["response"]["endpoint"]["genesis_hash"],
        genesis_hash
    );
    assert_eq!(admitted["response"]["claims"]["display_name"], "Al Newkirk");
    assert_eq!(admitted["response"]["claims"]["alias"], "alnewkirk");
    assert_eq!(admitted["response"]["claims"]["actor_type"], "human");
    let token = admitted["response"]["endpoint"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!token.is_empty());
    assert!(admitted["response"]["bundle"].as_str().unwrap().len() > 40);

    let exported = admin.path().join("served.bundle");
    run(
        admin.path(),
        &[
            "sync",
            "pull",
            admin_db.to_str().unwrap(),
            &ledger,
            exported.to_str().unwrap(),
        ],
    );
    let bundle_bytes = std::fs::read(&exported).unwrap();
    let decoded = fact_commitment::decode_bundle(&bundle_bytes).unwrap();
    let wire_objects = decoded
        .objects
        .iter()
        .map(|object| {
            let payload = fact_crypto::decode_sign1(object).unwrap().payload;
            serde_json::json!({
                "content_hash": fact_core::Hash::digest(&payload).hex(),
                "cose_sign1": base64url_encode(object)
            })
        })
        .collect::<Vec<_>>();
    let response_body = serde_json::json!({
        "schema":"facts-protocol-pull-response-v0",
        "ledger_id":ledger.clone(),
        "objects":wire_objects,
        "object_count":decoded.objects.len(),
        "commitment":{},
        "inclusion_proofs":[],
        "next_cursor":null,
        "complete":true
    })
    .to_string();
    let served_ledger = ledger.clone();
    let served_genesis = genesis_hash.clone();
    let served_token = token.to_ascii_lowercase();
    let server = thread::spawn(move || {
        serve_ledger_lists_then_pull(
            listener,
            served_ledger,
            served_genesis,
            response_body,
            Some(&served_token),
            2,
        );
    });
    let temp_parent = tempfile::tempdir().unwrap();
    let hyphen_tmp = temp_parent.path().join("-4-ci-temp");
    std::fs::create_dir(&hyphen_tmp).unwrap();
    let clone_output = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", requester.path())
        .env("TMPDIR", &hyphen_tmp)
        .args(["--json", "clone", "--from", response.to_str().unwrap()])
        .output()
        .expect("fact binary should run");
    assert!(
        clone_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&clone_output.stderr)
    );
    let cloned: serde_json::Value = serde_json::from_slice(&clone_output.stdout).unwrap();
    server.join().unwrap();
    assert_eq!(cloned["cloned"], true);
    assert_eq!(cloned["name"], "default");
    assert_eq!(cloned["ledger_id"], ledger);
    assert_eq!(cloned["read_only"], false);
    assert_eq!(cloned["actor_id"], admitted["actor_id"]);
    assert_eq!(cloned["remote"], "default");
    assert_eq!(cloned["descriptor_contains_credential"], true);
    let remotes = std::fs::read_to_string(requester.path().join("remotes.toml")).unwrap();
    assert!(remotes.contains("[remotes.default]"));
    assert!(remotes.contains(&format!("ledger = \"{ledger}\"")));
    assert!(remotes.contains(&format!("genesis_hash = \"{genesis_hash}\"")));
    assert!(remotes.contains(&format!("bearer_token = \"{token}\"")));
    let current_signer = String::from_utf8_lossy(&run(requester.path(), &["as"]).stdout)
        .trim()
        .to_owned();
    let ledger_ref =
        fact_sdk::reference::short_uuid_reference(uuid::Uuid::parse_str(&ledger).unwrap());
    assert_eq!(
        current_signer,
        format!("current signer for ledger default ({ledger_ref}): Al Newkirk (alnewkirk)")
    );
    let actors: serde_json::Value =
        serde_json::from_slice(&run(requester.path(), &["--json", "actor", "list"]).stdout)
            .unwrap();
    let active = actors
        .as_array()
        .unwrap()
        .iter()
        .find(|actor| actor["active"] == true)
        .unwrap();
    assert_eq!(active["display_name"], "Al Newkirk");
    assert_eq!(active["alias"], "alnewkirk");
}

#[test]
fn clone_as_prefers_active_directory_alias_over_stale_registry() {
    let requester = tempfile::tempdir().unwrap();
    let admin = tempfile::tempdir().unwrap();
    let stale_request = requester.path().join("stale.actor.bndl");
    let request = requester.path().join("alnewkirk.actor.bndl");
    let bundle = admin.path().join("served.bundle");
    let run = |home: &std::path::Path, args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    let stale: serde_json::Value = serde_json::from_slice(
        &run(
            requester.path(),
            &[
                "--json",
                "actor",
                "send",
                "Stale Actor",
                "--alias",
                "alnewkirk",
                "--output",
                stale_request.to_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    run(requester.path(), &["init"]);
    run(
        requester.path(),
        &[
            "directory",
            "add",
            "Al Newkirk",
            "--self",
            "--alias",
            "alnewkirk",
            "--type",
            "human",
        ],
    );
    let requester_status: serde_json::Value =
        serde_json::from_slice(&run(requester.path(), &["--json", "status"]).stdout).unwrap();
    assert_ne!(stale["actor_id"], requester_status["actor_id"]);
    run(
        requester.path(),
        &[
            "actor",
            "send",
            "alnewkirk",
            "--request",
            "participate",
            "--output",
            request.to_str().unwrap(),
        ],
    );

    run(admin.path(), &["init"]);
    run(
        admin.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://facts.example",
            "--ledger",
            "default",
        ],
    );
    run(
        admin.path(),
        &["actor", "admit", request.to_str().unwrap(), "--participate"],
    );
    let admin_status: serde_json::Value =
        serde_json::from_slice(&run(admin.path(), &["--json", "status"]).stdout).unwrap();
    let ledger = admin_status["ledger_id"].as_str().unwrap();
    let admin_db = admin.path().join("ledgers/default.sqlite");
    run(
        admin.path(),
        &[
            "sync",
            "pull",
            admin_db.to_str().unwrap(),
            ledger,
            bundle.to_str().unwrap(),
        ],
    );

    let cloned: serde_json::Value = serde_json::from_slice(
        &run(
            requester.path(),
            &[
                "--json",
                "clone",
                bundle.to_str().unwrap(),
                "--name",
                "factory-rw",
                "--as",
                "alnewkirk",
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(cloned["read_only"], false);
    assert_eq!(cloned["actor_id"], requester_status["actor_id"]);
}

#[test]
fn identity_export_defaults_to_ledger_identity_actor_bundle_filename() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .current_dir(home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["init", "factory"]);
    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let actor_ref = fact_sdk::reference::short_uuid_reference(
        uuid::Uuid::parse_str(status["actor_id"].as_str().unwrap()).unwrap(),
    );
    let expected_file = home
        .path()
        .join(format!("factory.identity.{actor_ref}.bundle"));

    let exported: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "identity", "export"]).stdout).unwrap();

    assert_eq!(
        exported["file"].as_str().unwrap(),
        format!("factory.identity.{actor_ref}.bundle")
    );
    assert!(expected_file.exists());
    assert!(std::fs::metadata(expected_file).unwrap().len() > 0);
}

#[test]
fn identity_export_actor_writes_only_that_local_actor() {
    let source_home = tempfile::tempdir().unwrap();
    let target_home = tempfile::tempdir().unwrap();
    let bundle = source_home.path().join("service.bundle");
    let run = |home: &std::path::Path, args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(source_home.path(), &["init", "factory"]);
    let added: serde_json::Value = serde_json::from_slice(
        &run(
            source_home.path(),
            &[
                "--json",
                "directory",
                "add",
                "Service Actor",
                "--with-identity",
                "--type",
                "service",
                "--alias",
                "svc",
            ],
        )
        .stdout,
    )
    .unwrap();
    let actor_id = added["actor_id"].as_str().unwrap();
    let actor_ref =
        fact_sdk::reference::short_uuid_reference(uuid::Uuid::parse_str(actor_id).unwrap());

    let exported: serde_json::Value = serde_json::from_slice(
        &run(
            source_home.path(),
            &[
                "--json",
                "identity",
                "export",
                "--actor",
                "svc",
                bundle.to_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(exported["objects"], 3);
    assert_eq!(exported["private_key_material"], false);
    assert_eq!(exported["actors"][0]["actor_id"], actor_id);
    assert_eq!(exported["actors"][0]["actor_ref"], actor_ref);

    let exported_file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&bundle).unwrap()).unwrap();
    assert_eq!(exported_file["schema"], "fact-identity-bundle-v0");
    assert!(exported_file["directory_bundle"].as_str().is_some());
    let identity_bundle =
        base64url_decode(exported_file["identity_bundle"].as_str().unwrap()).unwrap();
    let decoded = fact_commitment::decode_bundle(&identity_bundle).unwrap();
    assert_eq!(decoded.objects.len(), 3);
    let mut object_types = decoded
        .objects
        .iter()
        .map(|object| {
            let payload = fact_crypto::decode_sign1(object).unwrap().payload;
            let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(value["actor_id"], actor_id);
            assert_eq!(value.get("ledger_id"), None);
            assert_eq!(value.get("body").and_then(|body| body.get("seed")), None);
            value["object_type"].as_str().unwrap().to_owned()
        })
        .collect::<Vec<_>>();
    object_types.sort();
    assert_eq!(object_types, ["actor", "actor_key_binding", "key"]);

    run(target_home.path(), &["init"]);
    let imported: serde_json::Value = serde_json::from_slice(
        &run(
            target_home.path(),
            &["--json", "identity", "import", bundle.to_str().unwrap()],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(imported["imported"], 3);
    assert_eq!(imported["actors"][0]["actor_id"], actor_id);
    assert_eq!(imported["actors"][0]["actor_ref"], actor_ref);
    assert_eq!(imported["actors"][0]["display_name"], "Service Actor");
    assert_eq!(imported["actors"][0]["already_present"], false);
    assert_eq!(imported["directory"]["imported"], 1);
    let target_directory: serde_json::Value = serde_json::from_slice(
        &run(target_home.path(), &["--json", "directory", "show", "svc"]).stdout,
    )
    .unwrap();
    assert_eq!(target_directory["actor_id"], actor_id);
    assert_eq!(target_directory["display_name"], "Service Actor");
    assert_eq!(target_directory["alias"], "svc");
}

#[test]
fn identity_export_actor_rejects_imported_actor_without_local_seed() {
    let source_home = tempfile::tempdir().unwrap();
    let target_home = tempfile::tempdir().unwrap();
    let imported_bundle = target_home.path().join("identity.bundle");
    let run = |home: &std::path::Path, args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run")
    };
    let successful = |home: &std::path::Path, args: &[&str]| {
        let output = run(home, args);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    successful(source_home.path(), &["init"]);
    successful(target_home.path(), &["init"]);
    let target_status: serde_json::Value =
        serde_json::from_slice(&successful(target_home.path(), &["--json", "status"]).stdout)
            .unwrap();
    successful(
        target_home.path(),
        &["identity", "export", imported_bundle.to_str().unwrap()],
    );
    successful(
        source_home.path(),
        &["identity", "import", imported_bundle.to_str().unwrap()],
    );

    let output = run(
        source_home.path(),
        &[
            "identity",
            "export",
            "--actor",
            target_status["actor_id"].as_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("local key material not found"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn invited_actor_can_join_and_comment_without_decision_authority() {
    let source_home = tempfile::tempdir().unwrap();
    let target_home = tempfile::tempdir().unwrap();
    let proposition_file = source_home.path().join("proposition.md");
    let comment_file = target_home.path().join("comment.md");
    let identity_bundle = target_home.path().join("identity.bundle");
    std::fs::write(&proposition_file, b"# Shared decision\n\nDiscuss this.\n").unwrap();
    std::fs::write(&comment_file, b"# New hire\n\nI reviewed this.\n").unwrap();
    let run = |home: &std::path::Path, args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run")
    };
    let successful = |home: &std::path::Path, args: &[&str]| {
        let output = run(home, args);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    successful(source_home.path(), &["init"]);
    let proposed: serde_json::Value = serde_json::from_slice(
        &successful(
            source_home.path(),
            &["--json", "propose", proposition_file.to_str().unwrap()],
        )
        .stdout,
    )
    .unwrap();
    let source_status: serde_json::Value =
        serde_json::from_slice(&successful(source_home.path(), &["--json", "status"]).stdout)
            .unwrap();
    successful(target_home.path(), &["init"]);
    let target_status: serde_json::Value =
        serde_json::from_slice(&successful(target_home.path(), &["--json", "status"]).stdout)
            .unwrap();
    successful(
        target_home.path(),
        &["identity", "export", identity_bundle.to_str().unwrap()],
    );
    successful(
        source_home.path(),
        &["identity", "import", identity_bundle.to_str().unwrap()],
    );
    successful(
        source_home.path(),
        &[
            "identity",
            "recognize",
            target_status["actor_id"].as_str().unwrap(),
            "--capability",
            "propose",
            "--capability",
            "deliberate",
            "--capability",
            "comment",
        ],
    );
    let invitation: serde_json::Value = serde_json::from_slice(
        &successful(
            source_home.path(),
            &[
                "--json",
                "invite",
                proposed["proposition_id"].as_str().unwrap(),
                target_status["actor_id"].as_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    let sent_invitations: serde_json::Value = serde_json::from_slice(
        &successful(source_home.path(), &["--json", "invitations", "sent"]).stdout,
    )
    .unwrap();
    assert_eq!(sent_invitations.as_array().unwrap().len(), 1);
    assert_eq!(sent_invitations[0]["direction"], "sent");
    assert_eq!(sent_invitations[0]["status"], "active");
    let all_invitations: serde_json::Value =
        serde_json::from_slice(&successful(source_home.path(), &["--json", "invitations"]).stdout)
            .unwrap();
    assert_eq!(all_invitations.as_array().unwrap().len(), 1);
    let listed_invitations: serde_json::Value = serde_json::from_slice(
        &successful(source_home.path(), &["--json", "invitations", "list"]).stdout,
    )
    .unwrap();
    assert_eq!(listed_invitations, all_invitations);
    let no_pending_for_sender: serde_json::Value = serde_json::from_slice(
        &successful(source_home.path(), &["--json", "invitations", "pending"]).stdout,
    )
    .unwrap();
    assert_eq!(no_pending_for_sender.as_array().unwrap().len(), 0);
    let source_db = source_home.path().join("ledgers/default.sqlite");
    let target_db = target_home.path().join("ledgers/shared.sqlite");
    std::fs::copy(&source_db, &target_db).unwrap();
    let target_seed = target_home.path().join("identities").join(format!(
        "{}.seed",
        target_status["actor_id"].as_str().unwrap()
    ));
    let catalog = format!(
        "[ledgers.default]\nledger_id = \"{}\"\ndatabase = \"{}\"\nactor_id = \"{}\"\nkey_id = \"{}\"\nseed_file = \"{}\"\nread_only = false\n",
        source_status["ledger_id"].as_str().unwrap(),
        target_db.display(),
        target_status["actor_id"].as_str().unwrap(),
        target_status["key_id"].as_str().unwrap(),
        target_seed.display(),
    );
    std::fs::write(target_home.path().join("catalog.toml"), catalog).unwrap();
    std::fs::write(target_home.path().join("active"), "default\n").unwrap();
    let received_invitations: serde_json::Value = serde_json::from_slice(
        &successful(target_home.path(), &["--json", "invitations", "received"]).stdout,
    )
    .unwrap();
    assert_eq!(received_invitations.as_array().unwrap().len(), 1);
    assert_eq!(received_invitations[0]["direction"], "received");
    assert_eq!(received_invitations[0]["status"], "active");
    assert_eq!(
        received_invitations[0]["proposition_id"],
        proposed["proposition_id"]
    );
    assert!(received_invitations[0]["next_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action.as_str().unwrap().contains("invitations accept")));
    let pending_invitations: serde_json::Value = serde_json::from_slice(
        &successful(target_home.path(), &["--json", "invitations", "pending"]).stdout,
    )
    .unwrap();
    assert_eq!(pending_invitations.as_array().unwrap().len(), 1);
    let invitation_show: serde_json::Value = serde_json::from_slice(
        &successful(
            target_home.path(),
            &[
                "--json",
                "invitations",
                "show",
                invitation["invitation_id"].as_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(invitation_show["direction"], "received");
    assert_eq!(invitation_show["proposition_summary"], "Shared decision");
    let joined: serde_json::Value = serde_json::from_slice(
        &successful(
            target_home.path(),
            &[
                "--json",
                "join",
                invitation["invitation_id"].as_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(joined["operation"], "join");
    successful(
        target_home.path(),
        &[
            "comment",
            proposed["proposition_id"].as_str().unwrap(),
            comment_file.to_str().unwrap(),
        ],
    );
    let left = run(
        target_home.path(),
        &[
            "--json",
            "leave",
            proposed["proposition_id"].as_str().unwrap(),
        ],
    );
    assert!(left.status.success());
    let left: serde_json::Value = serde_json::from_slice(&left.stdout).unwrap();
    assert_eq!(left["operation"], "leave");
    let after_leave = run(
        target_home.path(),
        &[
            "comment",
            proposed["proposition_id"].as_str().unwrap(),
            comment_file.to_str().unwrap(),
        ],
    );
    assert!(!after_leave.status.success());
    let after_leave_stderr = String::from_utf8_lossy(&after_leave.stderr);
    assert!(
        after_leave_stderr.contains("does not have permission"),
        "stderr: {after_leave_stderr}"
    );
    assert!(!after_leave_stderr.contains("Unauthorized"));
    let rejected = run(
        target_home.path(),
        &["accept", proposed["proposition_id"].as_str().unwrap()],
    );
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("no pending action"),
        "stderr: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}

#[test]
fn invitations_reject_records_declined_lifecycle() {
    let home = tempfile::tempdir().unwrap();
    let proposition_file = home.path().join("proposition.md");
    std::fs::write(&proposition_file, b"# Invite decline\n\nNot this round.\n").unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run")
    };
    let successful = |args: &[&str]| {
        let output = run(args);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    successful(&["init"]);
    let proposed: serde_json::Value = serde_json::from_slice(
        &successful(&["--json", "propose", proposition_file.to_str().unwrap()]).stdout,
    )
    .unwrap();
    let status: serde_json::Value =
        serde_json::from_slice(&successful(&["--json", "status"]).stdout).unwrap();
    let invitation: serde_json::Value = serde_json::from_slice(
        &successful(&[
            "--json",
            "invite",
            proposed["proposition_id"].as_str().unwrap(),
            status["actor_id"].as_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    let rejected: serde_json::Value = serde_json::from_slice(
        &successful(&[
            "--json",
            "invitations",
            "reject",
            invitation["invitation_id"].as_str().unwrap(),
            "--reason",
            "not now",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(rejected["operation"], "decline");
    let shown: serde_json::Value = serde_json::from_slice(
        &successful(&[
            "--json",
            "invitations",
            "show",
            invitation["invitation_id"].as_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(shown["status"], "rejected");
    assert_eq!(shown["direction"], "received");
    assert!(shown["next_actions"].as_array().unwrap().is_empty());
    let pending: serde_json::Value =
        serde_json::from_slice(&successful(&["--json", "invitations", "pending"]).stdout).unwrap();
    assert_eq!(pending.as_array().unwrap().len(), 0);
}

#[test]
fn joined_actor_can_accept_without_settling_for_other_participants() {
    let source_home = tempfile::tempdir().unwrap();
    let target_home = tempfile::tempdir().unwrap();
    let proposition_file = source_home.path().join("proposition.md");
    let identity_bundle = target_home.path().join("identity.bundle");
    std::fs::write(&proposition_file, b"# Shared decision\n\nDiscuss this.\n").unwrap();
    let run = |home: &std::path::Path, args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home)
            .args(args)
            .output()
            .expect("fact binary should run")
    };
    let successful = |home: &std::path::Path, args: &[&str]| {
        let output = run(home, args);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    successful(source_home.path(), &["init"]);
    let proposed: serde_json::Value = serde_json::from_slice(
        &successful(
            source_home.path(),
            &["--json", "propose", proposition_file.to_str().unwrap()],
        )
        .stdout,
    )
    .unwrap();
    let source_status: serde_json::Value =
        serde_json::from_slice(&successful(source_home.path(), &["--json", "status"]).stdout)
            .unwrap();
    successful(target_home.path(), &["init"]);
    let target_status: serde_json::Value =
        serde_json::from_slice(&successful(target_home.path(), &["--json", "status"]).stdout)
            .unwrap();
    successful(
        target_home.path(),
        &["identity", "export", identity_bundle.to_str().unwrap()],
    );
    successful(
        source_home.path(),
        &["identity", "import", identity_bundle.to_str().unwrap()],
    );
    successful(
        source_home.path(),
        &[
            "identity",
            "recognize",
            target_status["actor_id"].as_str().unwrap(),
            "--capability",
            "comment",
            "--capability",
            "accept",
        ],
    );
    let invitation: serde_json::Value = serde_json::from_slice(
        &successful(
            source_home.path(),
            &[
                "--json",
                "invite",
                proposed["proposition_id"].as_str().unwrap(),
                target_status["actor_id"].as_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    let target_db = target_home.path().join("ledgers/shared.sqlite");
    std::fs::copy(
        source_home.path().join("ledgers/default.sqlite"),
        &target_db,
    )
    .unwrap();
    let target_seed = target_home.path().join("identities").join(format!(
        "{}.seed",
        target_status["actor_id"].as_str().unwrap()
    ));
    let catalog = format!(
        "[ledgers.default]\nledger_id = \"{}\"\ndatabase = \"{}\"\nactor_id = \"{}\"\nkey_id = \"{}\"\nseed_file = \"{}\"\nread_only = false\n",
        source_status["ledger_id"].as_str().unwrap(),
        target_db.display(),
        target_status["actor_id"].as_str().unwrap(),
        target_status["key_id"].as_str().unwrap(),
        target_seed.display(),
    );
    std::fs::write(target_home.path().join("catalog.toml"), catalog).unwrap();
    std::fs::write(target_home.path().join("active"), "default\n").unwrap();
    successful(
        target_home.path(),
        &[
            "join",
            proposed["proposition_id"].as_str().unwrap(),
            "--invitation",
            invitation["invitation_id"].as_str().unwrap(),
        ],
    );
    let accepted: serde_json::Value = serde_json::from_slice(
        &successful(
            target_home.path(),
            &[
                "--json",
                "accept",
                proposed["proposition_id"].as_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(accepted["status"], "pending");
    assert_eq!(accepted["settlement_id"], serde_json::Value::Null);
    assert_eq!(accepted["pending_participant_count"], 1);
}

#[test]
fn identity_rotation_keeps_private_keys_local_and_updates_binding() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run")
    };
    let successful = |args: &[&str]| {
        let output = run(args);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    successful(&["init"]);
    let before: serde_json::Value =
        serde_json::from_slice(&successful(&["--json", "status"]).stdout).unwrap();
    let old_key = before["key_id"].as_str().unwrap().to_owned();
    let actor_id = before["actor_id"].as_str().unwrap().to_owned();
    let rotated: serde_json::Value =
        serde_json::from_slice(&successful(&["--json", "identity", "rotate"]).stdout).unwrap();
    assert_eq!(rotated["object_type"], "key_lifecycle");
    assert_eq!(rotated["operation"], "rotate");
    assert_eq!(rotated["old_key_id"], old_key);
    assert_ne!(rotated["key_id"], old_key);
    assert!(home
        .path()
        .join("identities")
        .join(format!("{actor_id}.seed"))
        .exists());
    let after: serde_json::Value =
        serde_json::from_slice(&successful(&["--json", "status"]).stdout).unwrap();
    assert_eq!(after["key_id"], rotated["key_id"]);
    let proposition_file = home.path().join("rotated.md");
    std::fs::write(&proposition_file, b"# Rotated key\n\nStill authorized.\n").unwrap();
    successful(&["propose", proposition_file.to_str().unwrap()]);
    let history = String::from_utf8_lossy(&successful(&["history"]).stdout).into_owned();
    assert!(history.contains("key_lifecycle"));
    let limited_history: serde_json::Value =
        serde_json::from_slice(&successful(&["--json", "history", "--limit", "1"]).stdout).unwrap();
    assert_eq!(limited_history.as_array().unwrap().len(), 1);
}

#[test]
fn directory_names_identities_and_resolves_permission_aliases() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["init"]);
    let initial_status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let initial_directory: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "directory", "list"]).stdout).unwrap();
    assert!(initial_directory.as_array().unwrap().iter().any(|item| {
        item["actor_id"] == initial_status["actor_id"]
            && item["display_name"] == "Ledger Admin"
            && item["key_id"].is_string()
    }));
    let service: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "identity", "new", "--type", "service"]).stdout)
            .unwrap();
    assert_eq!(service["created"], true);
    assert!(home
        .path()
        .join("identities")
        .join(format!("{}.seed", service["actor_id"].as_str().unwrap()))
        .exists());
    let identities_with_key_ids: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "identity", "list"]).stdout).unwrap();
    assert!(identities_with_key_ids
        .as_array()
        .unwrap()
        .iter()
        .all(|item| { item["key_id"].is_string() && item["key_ref"].is_string() }));
    let service_use: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "identity",
            "use",
            service["actor_id"].as_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(service_use["actor_id"], service["actor_id"]);
    run(&[
        "identity",
        "use",
        initial_status["actor_id"].as_str().unwrap(),
    ]);
    run(&[
        "directory",
        "add",
        "Ledger Admin",
        "--self",
        "--alias",
        "admin",
    ]);
    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let actor_short = fact_sdk::reference::short_uuid_reference(
        uuid::Uuid::parse_str(status["actor_id"].as_str().unwrap()).unwrap(),
    );
    run(&[
        "directory",
        "add",
        "Al Newkirk",
        "--actor",
        &actor_short,
        "--alias",
        "alnewkirk",
        "--type",
        "human",
    ]);
    let added: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "directory",
            "add",
            "Research Agent",
            "--with-identity",
            "--type",
            "agent",
            "--alias",
            "research-agent",
            "--role",
            "research",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(added["identity_created"], true);
    assert_eq!(added["display_name"], "Research Agent");
    assert_eq!(added["alias"], "research-agent");
    let actor_id = added["actor_id"].as_str().unwrap();
    assert!(home
        .path()
        .join("identities")
        .join(format!("{actor_id}.seed"))
        .exists());

    let listed: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "directory", "list"]).stdout).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 2);
    assert!(listed
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["actor_id"] == added["actor_id"]));
    let limited_directory: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "directory", "list", "--limit", "1"]).stdout)
            .unwrap();
    assert_eq!(limited_directory.as_array().unwrap().len(), 1);
    let shown_directory: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "directory", "show", "research-agent"]).stdout)
            .unwrap();
    assert_eq!(shown_directory["actor_id"], added["actor_id"]);
    assert_eq!(shown_directory["role"], "research");
    let shown_directory_text =
        String::from_utf8_lossy(&run(&["directory", "show", "research-agent"]).stdout).into_owned();
    assert!(shown_directory_text.contains("Directory entry: research-agent"));
    assert!(shown_directory_text.contains("Display name:  Research Agent"));
    assert!(shown_directory_text.contains("Actor ID:"));
    assert!(shown_directory_text.contains("Key ID:"));

    let resolved: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "directory", "resolve", "research-agent"]).stdout)
            .unwrap();
    assert_eq!(resolved["actor_id"], added["actor_id"]);
    let shown_identity: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "identity", "show", "research-agent"]).stdout)
            .unwrap();
    assert_eq!(shown_identity["actor_id"], added["actor_id"]);
    assert!(shown_identity["key_id"].is_string());
    assert!(shown_identity["key_ref"].is_string());
    assert_eq!(shown_identity["capabilities"], serde_json::json!([]));
    let limited_identities: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "identity", "list", "--limit", "1"]).stdout)
            .unwrap();
    assert_eq!(limited_identities.as_array().unwrap().len(), 1);

    let grant: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "permission",
            "grant",
            "--identity",
            "research-agent",
            "--capability",
            "propose",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(grant["actor_id"], added["actor_id"]);

    let shown_identity: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "identity", "show", "research-agent"]).stdout)
            .unwrap();
    assert_eq!(
        shown_identity["capabilities"],
        serde_json::json!(["propose"])
    );

    let actor_capabilities: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "capabilities", "research-agent"]).stdout).unwrap();
    assert_eq!(
        actor_capabilities["active_actor"]["actor_id"],
        added["actor_id"]
    );
    assert_eq!(
        actor_capabilities["active_actor"]["capabilities"],
        serde_json::json!(["propose"])
    );

    let shown_identity_text =
        String::from_utf8_lossy(&run(&["identity", "show", "research-agent"]).stdout).into_owned();
    assert!(shown_identity_text.contains("capabilities: propose"));

    let identities: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "identity", "list"]).stdout).unwrap();
    assert!(identities.as_array().unwrap().iter().any(|item| {
        item["actor_id"] == added["actor_id"]
            && item["capabilities"] == serde_json::json!(["propose"])
    }));
    assert!(identities.as_array().unwrap().iter().any(|item| {
        item["active"] == true
            && item["admin"] == true
            && item["capabilities"] == serde_json::json!(["admin"])
    }));

    let directory: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "directory", "list"]).stdout).unwrap();
    assert!(directory.as_array().unwrap().iter().any(|item| {
        item["actor_id"] == added["actor_id"]
            && item["capabilities"] == serde_json::json!(["propose"])
    }));
    assert!(directory.as_array().unwrap().iter().any(|item| {
        item["admin"] == true && item["capabilities"] == serde_json::json!(["admin"])
    }));
    let directory_text = String::from_utf8_lossy(&run(&["directory", "list"]).stdout).into_owned();
    assert!(directory_text.contains("Research Agent"));
    assert!(directory_text.contains("propose"));
    assert!(directory_text.contains("admin"));

    let bundle = home.path().join("directory.fact-directory.json");
    let pushed: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "directory", "push", bundle.to_str().unwrap()]).stdout,
    )
    .unwrap();
    assert_eq!(pushed["exported"], 4);
    let exported = home.path().join("directory-export.fact-directory.json");
    let exported_json: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "directory", "export", exported.to_str().unwrap()]).stdout,
    )
    .unwrap();
    assert_eq!(exported_json["exported"], 4);
    let pulled: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "directory", "pull", bundle.to_str().unwrap()]).stdout,
    )
    .unwrap();
    assert_eq!(
        pulled,
        serde_json::json!({"imported":0,"skipped":4,"skipped_unresolved":0})
    );
    let history = String::from_utf8_lossy(&run(&["history"]).stdout).into_owned();
    assert!(history.contains("Al Newkirk"));

    run(&["identity", "use", "research-agent"]);
    let identities: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "identity", "list"]).stdout).unwrap();
    assert!(identities
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["actor_id"] == added["actor_id"] && item["active"] == true));

    let updated: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "directory",
            "update",
            "research-agent",
            "Research Agent 2",
            "--alias",
            "research-agent-2",
            "--type",
            "agent",
            "--role",
            "analysis",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(updated["display_name"], "Research Agent 2");
    assert_eq!(updated["alias"], "research-agent-2");
    let deleted: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "directory", "delete", "research-agent-2"]).stdout)
            .unwrap();
    assert_eq!(deleted["removed"], true);
    let missing = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["directory", "show", "research-agent-2"])
        .output()
        .expect("fact binary should run");
    assert!(!missing.status.success());
}

#[test]
fn as_command_names_switches_and_prepares_actor_home() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    let fail = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .expect("fact binary should run")
    };

    run(&["init"]);
    let initial_status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();

    let named_self: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "as", "Ledger Admin", "--self", "--alias", "admin"]).stdout,
    )
    .unwrap();
    assert_eq!(named_self["self"], true);
    assert_eq!(named_self["switched"], false);
    assert_eq!(named_self["created_directory_entry"], true);
    assert_eq!(named_self["actor"]["actor_id"], initial_status["actor_id"]);

    let current_signer: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "as"]).stdout).unwrap();
    assert_eq!(current_signer["report"], true);
    assert_eq!(current_signer["switched"], false);
    assert_eq!(
        current_signer["actor"]["actor_id"],
        initial_status["actor_id"]
    );
    assert_eq!(current_signer["actor"]["display_name"], "Ledger Admin");
    assert_eq!(current_signer["actor"]["alias"], "admin");

    let current_signer_text = String::from_utf8_lossy(&run(&["as"]).stdout).into_owned();
    let ledger_ref = fact_sdk::reference::short_uuid_reference(
        uuid::Uuid::parse_str(initial_status["ledger_id"].as_str().unwrap()).unwrap(),
    );
    assert_eq!(
        current_signer_text.trim(),
        format!("current signer for ledger default ({ledger_ref}): Ledger Admin (admin)")
    );

    let agent_output = run(&[
        "--json",
        "as",
        "Research Agent",
        "--alias",
        "research",
        "--type",
        "agent",
    ]);
    assert!(String::from_utf8_lossy(&agent_output.stderr)
        .contains("switching away from the only actor with admin capability"));
    let agent: serde_json::Value = serde_json::from_slice(&agent_output.stdout).unwrap();
    assert_eq!(agent["created_identity"], true);
    assert_eq!(agent["created_directory_entry"], true);
    assert_eq!(agent["switched"], true);
    assert_eq!(agent["actor"]["alias"], "research");
    assert_eq!(agent["actor"]["type"], "agent");

    let agent_status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_eq!(agent_status["actor_id"], agent["actor"]["actor_id"]);

    let admin: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "as", "admin"]).stdout).unwrap();
    assert_eq!(admin["actor"]["actor_id"], initial_status["actor_id"]);
    assert_eq!(admin["switched"], true);

    std::fs::remove_file(home.path().join("identities").join(format!(
        "{}.seed",
        agent["actor"]["actor_id"].as_str().unwrap()
    )))
    .unwrap();
    let missing_seed = fail(&["as", "research"]);
    assert!(!missing_seed.status.success());
    assert!(String::from_utf8_lossy(&missing_seed.stderr)
        .contains("local private key material is not available"));

    let alias_conflict = fail(&["as", "Ledger Admin", "--self", "--alias", "research"]);
    assert!(!alias_conflict.status.success());
    assert!(String::from_utf8_lossy(&alias_conflict.stderr).contains("already belongs to"));

    let codex: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "as",
            "Codex Agent",
            "--alias",
            "codex",
            "--type",
            "agent",
            "--home",
            "--print-env",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(codex["created_identity"], true);
    assert_eq!(codex["created_home"], true);
    let actor_home = std::path::PathBuf::from(codex["home"]["path"].as_str().unwrap());
    assert!(actor_home.exists());
    assert!(codex["home"]["print_env"]
        .as_str()
        .unwrap()
        .starts_with("export FACT_HOME="));

    let actor_home_status = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", &actor_home)
        .args(["--json", "status"])
        .output()
        .expect("fact binary should run");
    assert!(
        actor_home_status.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&actor_home_status.stderr)
    );
    let actor_home_status: serde_json::Value =
        serde_json::from_slice(&actor_home_status.stdout).unwrap();
    assert_eq!(actor_home_status["ledger_id"], initial_status["ledger_id"]);
    assert_eq!(actor_home_status["database"], codex["ledger"]["database"]);
    assert_eq!(actor_home_status["actor_id"], codex["actor"]["actor_id"]);

    run(&["as", "admin"]);
    let codex_propose_only: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "permission",
            "grant",
            "--identity",
            "codex",
            "--capability",
            "propose",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(
        codex_propose_only["capabilities"],
        serde_json::json!(["propose"])
    );
    let codex_participate: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "identity", "recognize", "codex", "--participate"]).stdout,
    )
    .unwrap();
    assert_eq!(
        codex_participate["capabilities"],
        serde_json::json!(["propose", "deliberate", "comment", "accept", "reject"])
    );
    run(&["as", "codex"]);
    let codex_source = home.path().join("codex.md");
    std::fs::write(&codex_source, b"# Codex\n\nParticipation import works.\n").unwrap();
    let imported: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "import", codex_source.to_str().unwrap()]).stdout)
            .unwrap();
    assert_eq!(imported["status"], "pending");

    run(&["as", "admin"]);
    let alice: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json", "as", "Alice", "--alias", "alice", "--type", "human",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(alice["created_identity"], true);
    let identities_before_failed_grant: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "identity", "list"]).stdout).unwrap();
    let directory_before_failed_grant: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "directory", "list"]).stdout).unwrap();
    let seed_files_before_failed_grant = std::fs::read_dir(home.path().join("identities"))
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "seed")
        })
        .count();
    let failed_granting_as = fail(&[
        "as",
        "Bob",
        "--alias",
        "bob",
        "--type",
        "human",
        "--participate",
    ]);
    assert!(!failed_granting_as.status.success());
    assert!(
        String::from_utf8_lossy(&failed_granting_as.stderr).contains("does not have permission")
    );
    let identities_after_failed_grant: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "identity", "list"]).stdout).unwrap();
    assert_eq!(
        identities_after_failed_grant.as_array().unwrap().len(),
        identities_before_failed_grant.as_array().unwrap().len()
    );
    assert!(!identities_after_failed_grant
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["alias"] == "bob" || item["display_name"] == "Bob"));
    let directory_after_failed_grant: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "directory", "list"]).stdout).unwrap();
    assert_eq!(
        directory_after_failed_grant.as_array().unwrap().len(),
        directory_before_failed_grant.as_array().unwrap().len()
    );
    assert!(!directory_after_failed_grant
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["alias"] == "bob" || item["display_name"] == "Bob"));
    let seed_files_after_failed_grant = std::fs::read_dir(home.path().join("identities"))
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "seed")
        })
        .count();
    assert_eq!(
        seed_files_after_failed_grant,
        seed_files_before_failed_grant
    );

    run(&["as", "admin"]);
    let late_actor: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "as",
            "Late Grant Agent",
            "--alias",
            "late",
            "--type",
            "agent",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(late_actor["created_identity"], true);
    run(&["as", "admin"]);
    run(&[
        "permission",
        "grant",
        "--identity",
        "late",
        "--capability",
        "propose",
        "--capability",
        "deliberate",
    ]);
    run(&["as", "late"]);
    let late_source = home.path().join("late.md");
    std::fs::write(&late_source, b"# Late\n\nAccept authority arrives later.\n").unwrap();
    let late_imported: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "import", late_source.to_str().unwrap()]).stdout)
            .unwrap();
    assert_eq!(late_imported["status"], "pending");

    run(&["as", "admin"]);
    run(&["identity", "recognize", "late", "--participate"]);
    run(&["as", "late"]);
    let accepted: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "accept",
            late_imported["proposition_id"].as_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(accepted["status"], "accepted");
}

#[test]
fn actor_porcelain_manages_participants_over_identity_directory_and_permission() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .current_dir(home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["init"]);
    let admin_status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let admin_actor = admin_status["actor_id"].as_str().unwrap();

    let bob: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "actor",
            "new",
            "Bob User",
            "--alias",
            "bob",
            "--type",
            "human",
            "--participate",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(bob["created_identity"], true);
    assert_eq!(bob["created_directory_entry"], true);
    assert_eq!(bob["actor"]["display_name"], "Bob User");
    assert_eq!(bob["actor"]["alias"], "bob");
    assert_eq!(bob["ledger"]["name"], "default");
    let bob_actor = bob["actor"]["actor_id"].as_str().unwrap();

    let list: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "actor", "list"]).stdout).unwrap();
    assert!(list.as_array().unwrap().iter().any(|item| {
        item["actor_id"] == bob_actor
            && item["display_name"] == "Bob User"
            && item["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|capability| capability == "propose")
    }));

    let show_bob: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "actor", "show", "bob"]).stdout).unwrap();
    assert_eq!(show_bob["actor_id"], bob_actor);
    assert_eq!(show_bob["local_private_key_material"], true);

    let restored_admin: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "actor", "use", admin_actor]).stdout).unwrap();
    assert_eq!(restored_admin["actor_id"], admin_actor);

    let named: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "actor",
            "name",
            "bob",
            "Robert User",
            "--alias",
            "robert",
            "--role",
            "reviewer",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(named["display_name"], "Robert User");
    assert_eq!(named["alias"], "robert");

    let granted: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "actor",
            "grant",
            "robert",
            "--capability",
            "admin",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(granted["actor_id"], bob_actor);
    assert_eq!(granted["capabilities"], serde_json::json!(["admin"]));

    let admin_bob: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "actor", "show", "robert"]).stdout).unwrap();
    assert!(admin_bob["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|capability| capability == "admin"));

    let revoked: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "actor",
            "revoke",
            granted["grant_id"].as_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(revoked["revoked_grant_id"], granted["grant_id"]);
}

#[test]
fn help_text_refactor_and_inline_markdown_input_are_available() {
    let default_help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(default_help.status.success());
    let default_help = String::from_utf8_lossy(&default_help.stdout);
    assert!(default_help.contains("A simple, adaptable substrate for trusted knowledge"));
    assert!(default_help.contains("accept"));
    assert!(default_help.contains("as"));
    assert!(default_help.contains("clone"));
    assert!(default_help.contains("echo"));
    assert!(default_help.contains("find"));
    assert!(default_help.contains("help"));
    assert!(default_help.contains("init"));
    assert!(default_help.contains("list"));
    assert!(default_help.contains("open"));
    assert!(default_help.contains("pending"));
    assert!(default_help.contains("propose"));
    assert!(default_help.contains("pull"));
    assert!(default_help.contains("push"));
    assert!(default_help.contains("reject"));
    assert!(default_help.contains("remote"));
    assert!(default_help.contains("resolve"));
    assert!(default_help.contains("revise"));
    assert!(default_help.contains("show"));
    assert!(default_help.contains("status"));
    assert!(default_help.contains("tags"));
    assert!(default_help.contains("use"));
    assert!(default_help.contains("Print results as JSON for scripts"));
    assert!(default_help.contains("fact help --all"));
    assert!(!default_help.contains("\n  archive "));
    assert!(!default_help.contains("\n  comment "));
    assert!(!default_help.contains("\n  comments "));
    assert!(!default_help.contains("\n  conflicts "));
    assert!(!default_help.contains("\n  directory "));
    assert!(!default_help.contains("\n  export "));
    assert!(!default_help.contains("\n  here "));
    assert!(!default_help.contains("\n  http "));
    assert!(!default_help.contains("\n  identity "));
    assert!(!default_help.contains("\n  import "));
    assert!(!default_help.contains("\n  invitations "));
    assert!(!default_help.contains("\n  new "));
    assert!(!default_help.contains("\n  search "));
    assert!(!default_help.contains("deliberate"));
    assert!(!default_help.contains("show-deliberation"));
    assert!(!default_help.contains("\n  read "));
    assert!(!default_help.contains("\n  write "));
    assert_indented_command_list_is_sorted(&default_help, "Commands:");

    let focused_help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help"])
        .output()
        .unwrap();
    assert!(focused_help.status.success());
    let focused_help = String::from_utf8_lossy(&focused_help.stdout);
    assert!(focused_help.contains("Commands:"));
    assert!(focused_help.contains("fact help --all"));
    assert!(focused_help.contains("\n  accept "));
    assert!(focused_help.contains("\n  as "));
    assert!(focused_help.contains("\n  show "));
    assert!(focused_help.contains("\n  tags "));
    assert!(!focused_help.contains("\n  comment "));
    assert!(!focused_help.contains("\n  comments "));
    assert!(!focused_help.contains("\n  export "));
    assert!(!focused_help.contains("\n  here "));
    assert!(!focused_help.contains("\n  http "));
    assert!(!focused_help.contains("\n  import "));
    assert!(!focused_help.contains("\n  invitations "));
    assert!(!focused_help.contains("\n  new "));
    assert!(!focused_help.contains("\n  read\n"));
    assert!(!focused_help.contains("\n  write\n"));
    assert!(!focused_help.contains("Facts Protocol v0 reference implementation"));
    assert!(!focused_help.contains("Implicit commands"));
    assert!(!focused_help.contains("Explicit commands"));
    assert_indented_command_list_is_sorted(&focused_help, "Commands:");

    let propose_help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "propose"])
        .output()
        .unwrap();
    assert!(propose_help.status.success());
    let propose_help = String::from_utf8_lossy(&propose_help.stdout);
    assert!(propose_help.contains("A Markdown file, - for standard input"));
    assert!(propose_help.contains("Use this short Markdown text"));

    let clone_help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "clone"])
        .output()
        .unwrap();
    assert!(clone_help.status.success());
    let clone_help = String::from_utf8_lossy(&clone_help.stdout);
    assert!(clone_help.contains("Copy a shared ledger into a local mirror"));
    assert!(clone_help.contains("Create a writable clone as a local identity"));
    assert!(clone_help.contains("already recognized and granted"));
    assert!(clone_help.contains("A remote descriptor to configure and clone from"));
    assert!(!clone_help.contains("Copy a shared ledger into a read-only local ledger"));
    assert!(!clone_help.contains("fact-remote-v0"));

    let remote_from_help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "remote", "from"])
        .output()
        .unwrap();
    assert!(remote_from_help.status.success());
    let remote_from_help = String::from_utf8_lossy(&remote_from_help.stdout);
    assert!(remote_from_help.contains("Configure a remote from a descriptor"));
    assert!(remote_from_help.contains("A remote descriptor, or an actor response containing one"));
    assert!(!remote_from_help.contains("fact-remote-v0"));

    let actor_admit_help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "actor", "admit"])
        .output()
        .unwrap();
    assert!(actor_admit_help.status.success());
    let actor_admit_help = String::from_utf8_lossy(&actor_admit_help.stdout);
    assert!(actor_admit_help.contains("A remote actor request artifact"));
    assert!(!actor_admit_help.contains("fact-remote-actor-request-v0"));

    let tags_help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "tags"])
        .output()
        .unwrap();
    assert!(tags_help.status.success());
    let tags_help = String::from_utf8_lossy(&tags_help.stdout);
    assert!(tags_help.contains("tags --search TAG_1"));
    assert!(tags_help.contains("--list"));
    assert!(tags_help.contains("--counts"));
    assert!(tags_help.contains("--text"));

    let conflicts_help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "conflicts"])
        .output()
        .unwrap();
    assert!(conflicts_help.status.success());
    let conflicts_help = String::from_utf8_lossy(&conflicts_help.stdout);
    assert!(conflicts_help.contains("Usage: fact conflicts [OPTIONS] [REFERENCE]"));
    assert!(conflicts_help.contains("--all"));

    let comment_help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "comment"])
        .output()
        .unwrap();
    assert!(comment_help.status.success());
    let comment_help = String::from_utf8_lossy(&comment_help.stdout);
    assert!(comment_help.contains("Usage: fact comment [OPTIONS] <REFERENCE> [FILE]"));
    assert!(comment_help.contains("Add a comment to a proposition or its discussion"));

    let http_help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "http"])
        .output()
        .unwrap();
    assert!(http_help.status.success());
    let http_help = String::from_utf8_lossy(&http_help.stdout);
    assert!(http_help.contains("Usage: fact http [OPTIONS] <COMMAND>"));
    assert!(http_help.contains("Run and administer a Facts HTTP collaboration server"));

    let invitations_accept_help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "invitations", "accept"])
        .output()
        .unwrap();
    assert!(invitations_accept_help.status.success());
    let invitations_accept_help = String::from_utf8_lossy(&invitations_accept_help.stdout);
    assert!(
        invitations_accept_help.contains("Usage: fact invitations accept [OPTIONS] <REFERENCE>")
    );

    let invitations_pending_help = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "invitations", "pending"])
        .output()
        .unwrap();
    assert!(invitations_pending_help.status.success());
    let invitations_pending_help = String::from_utf8_lossy(&invitations_pending_help.stdout);
    assert!(invitations_pending_help.contains("Usage: fact invitations pending [OPTIONS]"));

    let expanded = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "--all"])
        .output()
        .unwrap();
    assert!(expanded.status.success());
    let expanded = String::from_utf8_lossy(&expanded.stdout);
    assert!(expanded.contains("Starting and Selecting Ledgers:"));
    assert!(expanded.contains("Propositions:"));
    assert!(expanded.contains("Revisions and History:"));
    assert!(expanded.contains("Discussion and Decisions:"));
    assert!(expanded.contains("Conflicts and Reconciliation:"));
    assert!(expanded.contains("Organization:"));
    assert!(expanded.contains("Identity and Directory:"));
    assert!(expanded.contains("Sync and Remotes:"));
    assert!(expanded.contains("Protocol and Administration:"));
    assert!(expanded.contains("archive"));
    assert!(expanded.contains("clone"));
    assert!(expanded.contains("comment"));
    assert!(expanded.contains("comments"));
    assert!(expanded.contains("conflicts"));
    assert!(expanded.contains("directory"));
    assert!(expanded.contains("export"));
    assert!(expanded.contains("http"));
    assert!(expanded.contains("identity"));
    assert!(expanded.contains("import"));
    assert!(expanded.contains("new"));
    assert!(expanded.contains("revisions"));
    assert!(expanded.contains("search"));
    assert!(expanded.contains("commitment"));
    assert!(expanded.contains("conformance"));
    assert!(expanded.contains("settlement"));
    assert!(!expanded.contains("Implicit commands"));
    assert!(!expanded.contains("Explicit commands"));
    assert!(!expanded.contains("deliberate"));
    assert!(!expanded.contains("show-deliberation"));
    assert!(!expanded.contains("\n  read\n"));
    assert!(!expanded.contains("\n  write\n"));

    let old_category = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["help", "--category", "explicit"])
        .output()
        .unwrap();
    assert!(!old_category.status.success());

    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    let proposed: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            "--message",
            "# Inline\n\nCreated from a message.",
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(proposed["summary"], "Inline");
}

#[cfg(unix)]
#[test]
fn pager_flags_page_human_help_and_can_be_disabled() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let pager = temp.path().join("capture-pager.sh");
    let capture = temp.path().join("pager-output.txt");
    std::fs::write(&pager, "#!/bin/sh\ncat > \"$FACT_PAGER_CAPTURE\"\n").unwrap();
    let mut permissions = std::fs::metadata(&pager).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&pager, permissions).unwrap();

    let paged = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_PAGER", &pager)
        .env("FACT_PAGER_CAPTURE", &capture)
        .args(["--pager", "help", "--all"])
        .output()
        .expect("fact binary should run");
    assert!(
        paged.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&paged.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&paged.stdout), "");
    let captured = std::fs::read_to_string(&capture).unwrap();
    assert!(captured.contains("Starting and Selecting Ledgers:"));
    assert!(captured.contains("Protocol and Administration:"));

    std::fs::remove_file(&capture).unwrap();
    let no_pager = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_PAGER", &pager)
        .env("FACT_PAGER_CAPTURE", &capture)
        .args(["--no-pager", "help", "--all"])
        .output()
        .expect("fact binary should run");
    assert!(
        no_pager.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&no_pager.stderr)
    );
    assert!(String::from_utf8_lossy(&no_pager.stdout).contains("Starting and Selecting Ledgers:"));
    assert!(!capture.exists());

    let conflicting = Command::new(env!("CARGO_BIN_EXE_fact"))
        .args(["--pager", "--no-pager", "help", "--all"])
        .output()
        .expect("fact binary should run");
    assert!(!conflicting.status.success());
}

#[test]
fn proposition_revisions_comments_and_scoped_history_are_inspectable() {
    let home = tempfile::tempdir().unwrap();
    let source = home.path().join("source.md");
    std::fs::write(&source, b"# Original\n\nInitial content.\n").unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    let initial_status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let active_actor = initial_status["actor_id"].as_str().unwrap();
    let proposed: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            source.to_str().unwrap(),
            "--decision",
            "accept",
        ])
        .stdout,
    )
    .unwrap();
    let proposition = proposed["proposition_id"].as_str().unwrap();
    let initial_revision = proposed["revision_id"].as_str().unwrap();
    run(&[
        "comment",
        proposition,
        "--message",
        "# Review\n\nNeeds a second look.",
    ]);
    run(&[
        "comment",
        proposition,
        "--message",
        &format!("# Mention\n\n{active_actor} should review this."),
    ]);
    let revised: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "revise",
            proposition,
            "--message",
            "# Revised\n\nUpdated content.",
        ])
        .stdout,
    )
    .unwrap();
    let status_after_revise: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status_after_revise);

    assert_eq!(
        run(&["echo", revised["revision_id"].as_str().unwrap()]).stdout,
        b"# Revised\n\nUpdated content.\n"
    );

    let revisions: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "revisions", proposition]).stdout).unwrap();
    assert_eq!(revisions.as_array().unwrap().len(), 2);
    let comments: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "comments", proposition]).stdout).unwrap();
    assert_eq!(comments.as_array().unwrap().len(), 2);
    let initial_comments: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "comments",
            proposition,
            "--revision",
            initial_revision,
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(initial_comments.as_array().unwrap().len(), 2);
    let comments_by_revision: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "comments", initial_revision]).stdout).unwrap();
    assert_eq!(comments_by_revision.as_array().unwrap().len(), 2);
    let global_comments: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "comments"]).stdout).unwrap();
    assert_eq!(global_comments.as_array().unwrap().len(), 2);
    assert!(global_comments
        .as_array()
        .unwrap()
        .iter()
        .all(|comment| comment["proposition_id"] == serde_json::json!(proposition)));
    assert!(global_comments
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["summary"] == "Review"
            && comment["content"] == "# Review\n\nNeeds a second look.\n"));
    let text_comments: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "comments", "--text", "second look"]).stdout)
            .unwrap();
    assert_eq!(text_comments.as_array().unwrap().len(), 1);
    let review_comment_ref = text_comments[0]["reference"].as_str().unwrap();
    let comment_content = run(&["comments", review_comment_ref, "--content"]);
    let comment_content = String::from_utf8_lossy(&comment_content.stdout);
    assert!(comment_content.contains("# Review\n\nNeeds a second look.\n"));
    let single_comment: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "comments", review_comment_ref, "--content"]).stdout,
    )
    .unwrap();
    assert_eq!(single_comment.as_array().unwrap().len(), 1);
    assert_eq!(
        single_comment[0]["content"],
        "# Review\n\nNeeds a second look.\n"
    );
    let mine_comments: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "comments", "--mine"]).stdout).unwrap();
    assert_eq!(mine_comments.as_array().unwrap().len(), 2);
    let author_comments: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "comments", "--author", active_actor]).stdout)
            .unwrap();
    assert_eq!(author_comments.as_array().unwrap().len(), 2);
    let mentioned_comments: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "comments", "--mentions-me"]).stdout).unwrap();
    assert_eq!(mentioned_comments.as_array().unwrap().len(), 1);
    assert_eq!(mentioned_comments[0]["summary"], "Mention");
    let since_comments: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "comments", "--since", "1970-01-01T00:00:00Z"]).stdout,
    )
    .unwrap();
    assert_eq!(since_comments.as_array().unwrap().len(), 2);
    let limited_comments: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "comments", "--limit", "0"]).stdout).unwrap();
    assert!(limited_comments.as_array().unwrap().is_empty());
    let human_global = run(&["comments"]);
    let human_global = String::from_utf8_lossy(&human_global.stdout);
    assert!(human_global.contains(&proposition[..5]));
    assert!(human_global.contains("Review"));
    let unresolved = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["comments", "--unresolved"])
        .output()
        .unwrap();
    assert!(!unresolved.status.success());
    assert!(String::from_utf8_lossy(&unresolved.stderr).contains("not available yet"));
    let history: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "history", proposition]).stdout).unwrap();
    assert!(history
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["object_type"] == "deliberation_comment"));

    let status: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status);
    let inspected: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "proposition",
            "inspect",
            status["database"].as_str().unwrap(),
            status["ledger_id"].as_str().unwrap(),
            proposition,
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(inspected["effective_state"]["proposition_id"], proposition);
    assert_eq!(inspected["revision_state"]["effective_status"], "accepted");
    assert_eq!(
        inspected["revision_state"]["latest_revision"],
        revised["revision_id"]
    );
    assert_eq!(
        inspected["revision_state"]["latest_revision_status"],
        "pending"
    );
    assert_eq!(inspected["revision_state"]["has_pending_revision"], true);
    assert_eq!(inspected["comments"].as_array().unwrap().len(), 2);

    let pending = String::from_utf8_lossy(&run(&["pending"]).stdout).into_owned();
    assert!(pending.contains("Original"));
    assert_eq!(pending.lines().count(), 1);
}

#[cfg(unix)]
#[test]
fn revise_without_input_starts_from_the_latest_revision() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().unwrap();
    let source = home.path().join("source.md");
    let editor = home.path().join("editor.sh");
    std::fs::write(&source, b"# Original\n\nInitial content.\n").unwrap();
    std::fs::write(
        &editor,
        b"#!/bin/sh\nprintf '\\nFollow-up content.\\n' >> \"$1\"\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&editor).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&editor, permissions).unwrap();

    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    let proposed: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "propose",
            source.to_str().unwrap(),
            "--decision",
            "accept",
        ])
        .stdout,
    )
    .unwrap();
    let proposition = proposed["proposition_id"].as_str().unwrap();
    let revised: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "revise",
            proposition,
            "--message",
            "# Latest\n\nCurrent content.",
        ])
        .stdout,
    )
    .unwrap();

    let continued = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .env("VISUAL", editor.to_str().unwrap())
        .env("EDITOR", editor.to_str().unwrap())
        .args(["--json", "revise", proposition])
        .output()
        .unwrap();
    assert!(
        continued.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&continued.stderr)
    );
    let continued: serde_json::Value = serde_json::from_slice(&continued.stdout).unwrap();
    assert_ne!(continued["revision_id"], revised["revision_id"]);
    let status_after_pending_update: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status_after_pending_update);
    assert_eq!(
        run(&["echo", continued["revision_id"].as_str().unwrap()]).stdout,
        b"# Latest\n\nCurrent content.\n\nFollow-up content.\n"
    );
    let pending: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "list", "--all"]).stdout).unwrap();
    assert_eq!(pending[0]["effective_status"], "accepted");
    assert_eq!(pending[0]["has_pending_revision"], true);
    assert_eq!(pending[0]["pending_revision_id"], continued["revision_id"]);
    let pending_search: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "search", "Follow"]).stdout).unwrap();
    assert!(pending_search.as_array().unwrap().is_empty());
    let accepted: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "accept",
            continued["revision_id"].as_str().unwrap(),
        ])
        .stdout,
    )
    .unwrap();
    assert_eq!(accepted["status"], "accepted");
    assert_eq!(accepted["revision_id"], continued["revision_id"]);
    let status_after_accept_update: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    assert_indexed_consistent(&status_after_accept_update);
    let settled: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "list", "--all"]).stdout).unwrap();
    assert_eq!(settled[0]["effective_status"], "accepted");
    assert_eq!(settled[0]["has_pending_revision"], false);
    assert_eq!(settled[0]["revision_id"], continued["revision_id"]);
    assert_eq!(settled[0]["summary"], "Latest");
    assert_eq!(
        run(&["echo", proposition]).stdout,
        b"# Latest\n\nCurrent content.\n\nFollow-up content.\n"
    );
    let settled_search: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "search", "Follow"]).stdout).unwrap();
    assert!(!settled_search.as_array().unwrap().is_empty());

    std::fs::write(&editor, b"#!/bin/sh\nexit 0\n").unwrap();
    let unchanged = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .env("VISUAL", editor.to_str().unwrap())
        .env("EDITOR", editor.to_str().unwrap())
        .args(["find", "Latest", "--pick", "1", "--with", "edit"])
        .output()
        .unwrap();
    assert!(!unchanged.status.success());
    let stderr = String::from_utf8_lossy(&unchanged.stderr);
    assert!(stderr.contains("no changes made; the proposition was left unchanged"));
    assert!(!stderr.contains("InvalidLineage"));
    assert!(!stderr.contains("forwarded command exited"));

    let unchanged_file = home.path().join("unchanged.md");
    std::fs::write(
        &unchanged_file,
        b"# Latest\n\nCurrent content.\n\nFollow-up content.\n",
    )
    .unwrap();
    let unchanged = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["revise", proposition, unchanged_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!unchanged.status.success());
    let stderr = String::from_utf8_lossy(&unchanged.stderr);
    assert!(stderr.contains("no changes made; the proposition was left unchanged"));
    assert!(!stderr.contains("InvalidLineage"));

    let next: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "revise",
            proposition,
            "--message",
            "# Final\n\nFinal content.",
        ])
        .stdout,
    )
    .unwrap();
    let accepted_again: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "accept", proposition]).stdout).unwrap();
    assert_eq!(accepted_again["status"], "accepted");
    assert_eq!(accepted_again["revision_id"], next["revision_id"]);
}

#[test]
fn permission_and_personal_remote_commands_mirror_legacy_workflows() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    run(&["remote", "add", "origin", "https://facts.example"]);
    let listed = String::from_utf8_lossy(&run(&["remote", "list"]).stdout).into_owned();
    assert!(listed.contains("origin"));
    run(&["remote", "rename", "origin", "backup"]);
    run(&["remote", "remove", "backup"]);

    let source = home.path().join("identity.bundle");
    run(&["identity", "export", source.to_str().unwrap()]);
    let actor: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "status"]).stdout).unwrap();
    let grant = run(&[
        "--json",
        "permission",
        "grant",
        "--identity",
        actor["actor_id"].as_str().unwrap(),
        "--participate",
    ]);
    let grant: serde_json::Value = serde_json::from_slice(&grant.stdout).unwrap();
    assert_eq!(grant["authority_granted"], true);
    assert_eq!(
        grant["capabilities"],
        serde_json::json!(["propose", "deliberate", "comment", "accept", "reject"])
    );
    let revoked = run(&[
        "--json",
        "permission",
        "revoke",
        "--identity",
        actor["actor_id"].as_str().unwrap(),
        "--participate",
    ]);
    let revoked: serde_json::Value = serde_json::from_slice(&revoked.stdout).unwrap();
    assert_eq!(revoked["revoked_count"], 1);
    assert_eq!(
        revoked["revocations"][0]["revoked_grant_id"],
        grant["grant_id"]
    );
}

#[test]
fn remote_auth_stores_tokens_without_listing_them() {
    let home = tempfile::tempdir().unwrap();
    let token_file = home.path().join("token.txt");
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    let run_with_stdin = |args: &[&str], stdin: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("fact binary should run");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["init"]);
    run(&["remote", "add", "origin", "https://facts.example"]);
    let help = run(&["remote", "auth", "--help"]);
    let help_stdout = String::from_utf8_lossy(&help.stdout);
    assert!(help_stdout.contains("-i, --input <FILE>"));
    assert!(help_stdout.contains("Read the bearer token from FILE, or - for stdin"));
    assert!(help_stdout.contains("--stdin"));

    let auth: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "remote", "auth", "origin", "secret-token"]).stdout,
    )
    .unwrap();
    assert_eq!(auth["authenticated"], true);
    assert_eq!(auth["name"], "origin");

    let listed = run(&["--json", "remote", "list"]);
    let listed_text = String::from_utf8_lossy(&listed.stdout);
    assert!(!listed_text.contains("secret-token"));
    assert!(!listed_text.contains("bearer_token"));
    let stored = std::fs::read_to_string(home.path().join("remotes.toml")).unwrap();
    assert!(stored.contains("bearer_token = \"secret-token\""));

    std::fs::write(&token_file, b"file-token\n").unwrap();
    run(&[
        "remote",
        "auth",
        "origin",
        "--input",
        token_file.to_str().unwrap(),
    ]);
    let stored = std::fs::read_to_string(home.path().join("remotes.toml")).unwrap();
    assert!(stored.contains("bearer_token = \"file-token\""));

    run_with_stdin(
        &["remote", "auth", "origin", "--input", "-"],
        "stdin-token\n",
    );
    let stored = std::fs::read_to_string(home.path().join("remotes.toml")).unwrap();
    assert!(stored.contains("bearer_token = \"stdin-token\""));

    run_with_stdin(&["remote", "auth", "origin", "--stdin"], "legacy-token\n");
    let stored = std::fs::read_to_string(home.path().join("remotes.toml")).unwrap();
    assert!(stored.contains("bearer_token = \"legacy-token\""));

    let cleared: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "remote", "auth", "origin", "--clear"]).stdout)
            .unwrap();
    assert_eq!(cleared["authenticated"], false);
    let stored = std::fs::read_to_string(home.path().join("remotes.toml")).unwrap();
    assert!(!stored.contains("secret-token"));
    assert!(!stored.contains("bearer_token"));
}

#[test]
fn http_token_commands_manage_sqlite_token_metadata() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["init"]);
    let issued: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "http",
            "token",
            "issue",
            "--expires-days",
            "1",
            "--label",
            "test",
            "--show-token",
        ])
        .stdout,
    )
    .unwrap();
    let token = issued["token"].as_str().expect("token");
    let token_id = issued["token_id"].as_str().expect("token id");
    assert!(!token.is_empty());
    assert!(home.path().join("remotes/tokens.sqlite").exists());

    let listed = run(&["--json", "http", "token", "list"]);
    let listed_text = String::from_utf8_lossy(&listed.stdout);
    assert!(!listed_text.contains(token));
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["tokens"].as_array().unwrap().len(), 1);
    assert_eq!(listed["tokens"][0]["token_id"], token_id);
    assert_eq!(listed["tokens"][0]["label"], "test");
    assert!(listed["tokens"][0].get("token").is_none());

    let revoked: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "http", "token", "revoke", token_id]).stdout)
            .unwrap();
    assert_eq!(revoked["revoked"], true);

    let pruned: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "http", "token", "prune"]).stdout).unwrap();
    assert_eq!(pruned["pruned"], 1);
    let listed: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "http", "token", "list"]).stdout).unwrap();
    assert_eq!(listed["tokens"].as_array().unwrap().len(), 0);
}

#[test]
fn http_token_issue_controls_secret_output_destination() {
    let home = tempfile::tempdir().unwrap();
    let token_file = home.path().join("issued.token");
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["init"]);
    let help = run(&["http", "token", "issue", "--help"]);
    let help_stdout = String::from_utf8_lossy(&help.stdout);
    assert!(help_stdout.contains("-o, --output <FILE>"));
    assert!(help_stdout.contains("Write the bearer token to FILE, or - for stdout"));
    assert!(help_stdout.contains("--show-token"));

    let metadata_only: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "http", "token", "issue"]).stdout).unwrap();
    assert!(metadata_only.get("token").is_none());
    assert!(metadata_only["token_id"]
        .as_str()
        .unwrap()
        .starts_with("01"));

    let written: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "http",
            "token",
            "issue",
            "--output",
            token_file.to_str().unwrap(),
            "--label",
            "file",
        ])
        .stdout,
    )
    .unwrap();
    assert!(written.get("token").is_none());
    assert_eq!(
        written["credential_output"].as_str().unwrap(),
        token_file.to_str().unwrap()
    );
    let token = std::fs::read_to_string(&token_file).unwrap();
    assert!(!token.trim().is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(&token_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let stdout_token: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "http", "token", "issue", "--output", "-"]).stdout)
            .unwrap();
    assert_eq!(stdout_token["credential_output"], "stdout");
    assert!(!stdout_token["token"].as_str().unwrap().is_empty());

    let human = run(&["http", "token", "issue", "--label", "human"]);
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    assert!(human_stdout.contains("issued token "));
    assert!(human_stdout.contains("label human"));
    assert!(human_stdout.contains("shown only once; store it now"));
}

#[test]
fn http_token_issue_resolves_actor_short_refs_and_directory_aliases() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["init"]);
    let added: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "directory",
            "add",
            "Service Actor",
            "--with-identity",
            "--type",
            "service",
            "--alias",
            "svc",
        ])
        .stdout,
    )
    .unwrap();
    let actor_id = added["actor_id"].as_str().unwrap();
    let actor_ref = added["actor_ref"].as_str().unwrap();

    let by_ref: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "http", "token", "issue", "--actor", actor_ref]).stdout,
    )
    .unwrap();
    assert_eq!(by_ref["actor_id"], actor_id);

    let by_alias: serde_json::Value = serde_json::from_slice(
        &run(&["--json", "http", "token", "issue", "--actor", "svc"]).stdout,
    )
    .unwrap();
    assert_eq!(by_alias["actor_id"], actor_id);
}

#[test]
fn http_token_store_defaults_to_discovered_fact_environment() {
    let project = tempfile::tempdir().unwrap();
    let user_home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .current_dir(project.path())
            .env_remove("FACT_HOME")
            .env_remove("XDG_DATA_HOME")
            .env("HOME", user_home.path())
            .args(args)
            .output()
            .expect("fact binary should run");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["here", "--init", "work"]);
    let issued: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "http", "token", "issue"]).stdout).unwrap();
    let local_store = project.path().join(".facts/remotes/tokens.sqlite");
    assert!(local_store.exists());
    assert_eq!(
        std::fs::canonicalize(issued["token_store"].as_str().unwrap()).unwrap(),
        std::fs::canonicalize(&local_store).unwrap()
    );
    assert!(!user_home
        .path()
        .join(".local/share/fact/remotes/tokens.sqlite")
        .exists());
}

#[test]
fn directory_add_with_token_mints_http_access_token() {
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    run(&["init"]);
    let added: serde_json::Value = serde_json::from_slice(
        &run(&[
            "--json",
            "directory",
            "add",
            "Token Actor",
            "--with-identity",
            "--type",
            "service",
            "--alias",
            "token-actor",
            "--with-token",
            "--token-expires-days",
            "1",
            "--token-label",
            "bootstrap",
        ])
        .stdout,
    )
    .unwrap();
    let access_token = &added["access_token"];
    assert!(access_token.get("token").is_none());
    assert_eq!(access_token["actor_id"], added["actor_id"]);
    assert_eq!(access_token["label"], "bootstrap");
    assert!(home.path().join("remotes/tokens.sqlite").exists());

    let listed: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "http", "token", "list"]).stdout).unwrap();
    assert_eq!(listed["tokens"].as_array().unwrap().len(), 1);
    assert_eq!(listed["tokens"][0]["actor_id"], added["actor_id"]);
    assert_eq!(listed["tokens"][0]["label"], "bootstrap");
    assert!(listed["tokens"][0].get("token").is_none());
}

#[test]
fn participant_leave_after_decision_is_rejected_without_erasing_history() {
    let home = tempfile::tempdir().unwrap();
    let source = home.path().join("source.md");
    std::fs::write(&source, b"# Settled\n\nA settled proposition.\n").unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fact"))
            .env("FACT_HOME", home.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(&["init"]);
    let proposed: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "propose", source.to_str().unwrap()]).stdout)
            .unwrap();
    let proposition = proposed["proposition_id"].as_str().unwrap();
    run(&["accept", proposition]);
    let left = Command::new(env!("CARGO_BIN_EXE_fact"))
        .env("FACT_HOME", home.path())
        .args(["--json", "leave", proposition])
        .output()
        .unwrap();
    assert!(!left.status.success());
    assert!(String::from_utf8_lossy(&left.stderr)
        .contains("cannot leave a deliberation after submitting a decision"));
    let history: serde_json::Value =
        serde_json::from_slice(&run(&["--json", "history", proposition]).stdout).unwrap();
    assert!(history
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["object_type"] == "decision"));
}

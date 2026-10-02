use std::{
    fs,
    process::{Command, Output},
};
use tempfile::TempDir;

fn call(dir: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nnlan"))
        .current_dir(dir.path())
        .arg("--config")
        .arg(dir.path().join("node/nnlan.toml"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn init_check_identity_plan_and_no_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let created = call(&dir, &["init"]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let key_before = fs::read(dir.path().join("node/identity.key")).unwrap();
    assert!(call(&dir, &["check"]).status.success());
    let public = call(&dir, &["identity"]);
    assert!(public.status.success());
    assert_eq!(String::from_utf8(public.stdout).unwrap().trim().len(), 64);
    for command in [&["plan"][..], &["run", "--dry-run"][..]] {
        let output = call(&dir, command);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(plan["network_running"], false);
        assert_eq!(plan["kernel_exit_guard_installed"], false);
        assert_eq!(plan["addresses_claimed"], false);
        assert_eq!(plan["relay_enabled"], true);
        assert_eq!(plan["ipv6_pool"], "fd33::/16");
    }
    assert!(!call(&dir, &["init"]).status.success());
    assert_eq!(
        fs::read(dir.path().join("node/identity.key")).unwrap(),
        key_before
    );
    // Fail before any runtime/TUN changes, including when tests run as root.
    fs::remove_file(dir.path().join("node/identity.key")).unwrap();
    let run = call(&dir, &["run"]);
    assert!(!run.status.success());
    assert!(!run.stderr.is_empty());
}

#[test]
fn invalid_config_and_wrong_key_permissions_fail() {
    let dir = tempfile::tempdir().unwrap();
    assert!(call(&dir, &["init"]).status.success());
    let path = dir.path().join("node/nnlan.toml");
    let original = fs::read_to_string(&path).unwrap();
    fs::write(&path, original.replace("relay = true", "relai = true")).unwrap();
    assert!(!call(&dir, &["check"]).status.success());
    fs::write(&path, original).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        dir.path().join("node/identity.key"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(!call(&dir, &["plan"]).status.success());
}

#[test]
fn checked_in_example_is_valid() {
    nnlan::config::Config::load(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/nnlan.toml"
    )))
    .unwrap();
}

#[test]
fn nnlan_brand_defaults_and_deferred_cp() {
    let dir = tempfile::tempdir().unwrap();
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nnlan"))
            .current_dir(dir.path())
            .args(args)
            .output()
            .unwrap()
    };
    let version = invoke(&["--version"]);
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        "nnlan 0.1.0"
    );
    let help = invoke(&["--help"]);
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("Usage: nnlan"));
    assert!(help.contains("nnlan.toml"));
    assert!(
        !help
            .lines()
            .any(|line| line.trim_start().starts_with("cp "))
    );
    assert!(!invoke(&["cp", "local", "peer:remote"]).status.success());
    assert!(invoke(&["init"]).status.success());
    let config = nnlan::config::Config::load(&dir.path().join("nnlan.toml")).unwrap();
    assert_eq!(config.name, "nnlan");
    assert_eq!(config.tun.name, "nnlan0");
    assert!(
        !fs::read_to_string(dir.path().join("nnlan.toml"))
            .unwrap()
            .contains("[files]")
    );
    assert!(invoke(&["check"]).status.success());
    assert!(invoke(&["plan"]).status.success());
}

#[test]
fn init_template_allows_appending_peers_without_deletion() {
    let dir = tempfile::tempdir().unwrap();
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nnlan"))
            .current_dir(dir.path())
            .args(args)
            .output()
            .unwrap()
    };
    assert!(invoke(&["init"]).status.success());
    let toml_path = dir.path().join("nnlan.toml");
    let content = fs::read_to_string(&toml_path).unwrap();
    // Must not write `peers = []` which clashes with `[[peers]]`
    assert!(!content.lines().any(|l| l.trim() == "peers = []"));

    // User can immediately append a [[peers]] block without syntax errors
    let append = "\n[[peers]]\nendpoint = \"192.0.2.1:7331\"\npublic_key = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n";
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&toml_path)
        .unwrap();
    file.write_all(append.as_bytes()).unwrap();
    drop(file);

    // Config must be fully valid and loadable
    let check = invoke(&["check"]);
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let config = nnlan::config::Config::load(&toml_path).unwrap();
    assert_eq!(config.peers.len(), 1);
    assert_eq!(config.peers[0].endpoint, "192.0.2.1:7331");
}

#[test]
fn peer_subcommands_add_list_remove() {
    let dir = tempfile::tempdir().unwrap();
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nnlan"))
            .current_dir(dir.path())
            .args(args)
            .output()
            .unwrap()
    };
    assert!(invoke(&["init"]).status.success());

    // 1. Initial list is empty (test --human)
    let list_initial = invoke(&["peer", "list", "--human"]);
    assert!(list_initial.status.success());
    assert!(
        String::from_utf8(list_initial.stdout)
            .unwrap()
            .contains("0 total")
    );

    // 2. Add peer
    let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let add = invoke(&["peer", "add", "198.51.100.1:7331", key]);
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );

    // 3. List shows added peer in both human and JSON format
    let list_human = invoke(&["peer", "list", "--human"]);
    assert!(list_human.status.success());
    let human_out = String::from_utf8(list_human.stdout).unwrap();
    assert!(human_out.contains("198.51.100.1:7331"));
    assert!(human_out.contains("1 total"));

    let list_json = invoke(&["peer", "list", "--json"]);
    assert!(list_json.status.success());
    let peers_val: serde_json::Value = serde_json::from_slice(&list_json.stdout).unwrap();
    assert_eq!(peers_val.as_array().unwrap().len(), 1);
    assert_eq!(peers_val[0]["endpoint"], "198.51.100.1:7331");

    // 4. Duplicate add is prevented
    let add_dup = invoke(&["peer", "add", "198.51.100.2:7331", key]);
    assert!(!add_dup.status.success());

    // 5. Remove peer
    let remove = invoke(&["peer", "remove", "198.51.100.1:7331"]);
    assert!(
        remove.status.success(),
        "{}",
        String::from_utf8_lossy(&remove.stderr)
    );

    // 6. List is empty again (piped defaults to JSON)
    let list_after = invoke(&["peer", "list"]);
    assert!(list_after.status.success());
    let empty_peers: serde_json::Value = serde_json::from_slice(&list_after.stdout).unwrap();
    assert_eq!(empty_peers.as_array().unwrap().len(), 0);
}

#[test]
fn doctor_runs_in_both_human_and_json_modes() {
    let dir = tempfile::tempdir().unwrap();
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nnlan"))
            .current_dir(dir.path())
            .args(args)
            .output()
            .unwrap()
    };
    assert!(invoke(&["init"]).status.success());

    // Explicit human output
    let doc_human = invoke(&["doctor", "--human"]);
    let out = String::from_utf8_lossy(&doc_human.stdout);
    assert!(out.contains("System Diagnostics"));
    assert!(out.contains("Linux Kernel"));

    // Piped output defaults to JSON, or can be forced with --json
    for command in [&["doctor"][..], &["doctor", "--json"][..]] {
        let doc_json = invoke(command);
        let checks: serde_json::Value = serde_json::from_slice(&doc_json.stdout).unwrap();
        let checks_arr = checks.as_array().unwrap();
        assert!(!checks_arr.is_empty());
        assert!(checks_arr.iter().any(|c| c["title"] == "Linux Kernel"));
        assert!(checks_arr.iter().any(|c| c["title"] == "Config File"));
    }
}

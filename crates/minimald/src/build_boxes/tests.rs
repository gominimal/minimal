use std::sync::Arc;

use op::BuildBoxes as _;

use super::BoxBuildBoxes;

/// A box record for these tests, in `mode` and under `egress`.
fn record(mode: boxes::NetworkMode, egress: Option<boxes::EgressPolicy>) -> boxes::Record {
    boxes::Record {
        id: boxes::SessionId::nil(),
        name: Some("sealed".to_string()),
        username: None,
        project_path: paths::HostAbsPath::try_new("/tmp/project").unwrap(),
        network: mode,
        policy: boxes::BoxPolicy::new(egress, None),
        task_addresses: Vec::new(),
        box_addresses: None,
        status: boxes::BoxState::Active,
        reason: None,
        exit_code: None,
        signal: None,
        hooks_enabled: true,
        host_ip_enforcement: None,
        box_id: None,
        host_row_bound: false,
        bound_ports: std::collections::BTreeSet::new(),
        ends_with_run: false,
        sealed_deliveries: Vec::new(),
        root_certificate: None,
        box_type: None,
        parent: None,
        project_root: None,
        attrs: Default::default(),
    }
}

/// A switch on a host with no VM, so a lookup reads the table on disk.
fn switch() -> Arc<tokio::sync::Mutex<crate::net::SwitchClient>> {
    Arc::new(tokio::sync::Mutex::new(crate::net::SwitchClient::new(
        "/usr/bin/gvproxy",
        "/run/minimal/gvproxy",
    )))
}

fn boxes_of(
    mode: boxes::NetworkMode,
    egress: Option<boxes::EgressPolicy>,
    state: &std::path::Path,
) -> BoxBuildBoxes {
    BoxBuildBoxes::new(record(mode, egress), switch(), false, state.to_path_buf())
}

fn open_egress() -> boxes::EgressPolicy {
    minimald_rpc::build_box_egress(&std::collections::BTreeSet::new(), true)
}

fn hash(byte: u8) -> common::SpecHash {
    common::SpecHash(blake3::hash(&[byte]))
}

fn table_of(spec_hash: &common::SpecHash) -> minimald_rpc::BuildGrantTable {
    std::collections::BTreeMap::from([(
        spec_hash.0.to_hex().to_string(),
        minimald_rpc::BuildGrant {
            sources: Vec::new(),
            internet: true,
        },
    )])
}

/// NET-155: every build of a box gets a build box, whatever the box's mode,
/// and no mode reaches the host's network: a build box's network is its own
/// or none. A build that needs a network its build box does not have says
/// why: the box has none, or its rules admit nothing.
#[tokio::test]
async fn box_package_build_runs_in_a_build_box() {
    let state = tempfile::tempdir().unwrap();
    for (mode, egress, why) in [
        (boxes::NetworkMode::NoNet, None, op::NEEDS_NETWORK),
        (
            boxes::NetworkMode::OwnIp,
            Some(boxes::EgressPolicy::deny_all()),
            op::NEEDS_NETWORK_RULES,
        ),
        (
            boxes::NetworkMode::HostNet,
            Some(boxes::EgressPolicy::deny_all()),
            op::NEEDS_NETWORK_RULES,
        ),
    ] {
        let build_box = boxes_of(mode, egress, state.path()).build_box("pkg", Some(&hash(1)));
        assert!(build_box.network().await.is_none(), "{mode:?}");
        assert_eq!(
            build_box.needs_network().to_string(),
            format!("other: {why}")
        );
    }
}

/// NET-169: a build no table covers follows the box. A box that allows the
/// destination gives the build a network, and a `none` box gives it none.
#[tokio::test]
async fn workspace_build_box_follows_the_requester() {
    let state = tempfile::tempdir().unwrap();
    let open = boxes_of(boxes::NetworkMode::OwnIp, Some(open_egress()), state.path());
    let build_box = open.build_box("pkg", Some(&hash(1)));
    assert!(build_box.network().await.is_some());

    let none = boxes_of(boxes::NetworkMode::NoNet, None, state.path());
    let build_box = none.build_box("pkg", Some(&hash(1)));
    assert!(build_box.network().await.is_none());
}

/// NET-169: a deny-all box gives a build no table covers no network, declared
/// or by default, so the build is refused before any packet.
#[tokio::test]
async fn workspace_build_refused_in_deny_all_box() {
    let state = tempfile::tempdir().unwrap();
    for egress in [Some(boxes::EgressPolicy::deny_all()), None] {
        let sealed = boxes_of(boxes::NetworkMode::OwnIp, egress, state.path());
        let build_box = sealed.build_box("pkg", Some(&hash(1)));
        assert!(build_box.network().await.is_none());
    }
}

/// NET-165: a build the table covers gets its grant whenever it asks, in a
/// deny-all box, and `min add` in a running box asks the same way. A patched
/// build never looks, so its spec follows the box.
#[tokio::test]
async fn install_through_minenv_sock_takes_the_same_lookup() {
    let state = tempfile::tempdir().unwrap();
    let sealed = boxes_of(boxes::NetworkMode::OwnIp, None, state.path());
    super::file_table(state.path(), boxes::SessionId::nil(), &table_of(&hash(1))).unwrap();

    let added = sealed.build_box("claude-code", Some(&hash(1)));
    assert!(added.network().await.is_some());

    let patched = sealed.build_box("claude-code", None);
    assert!(patched.network().await.is_none());
}

/// NET-166: a grant reaches its spec hash and no other build, whatever the
/// package's name. An ended table grants nothing.
#[tokio::test]
async fn grant_applies_only_to_the_expanded_spec_hash() {
    let state = tempfile::tempdir().unwrap();
    let sealed = boxes_of(boxes::NetworkMode::OwnIp, None, state.path());
    super::file_table(state.path(), boxes::SessionId::nil(), &table_of(&hash(1))).unwrap();

    let other = sealed.build_box("pkg", Some(&hash(2)));
    assert!(other.network().await.is_none());
    let granted = sealed.build_box("another-name", Some(&hash(1)));
    assert!(granted.network().await.is_some());

    super::drop_table(state.path(), boxes::SessionId::nil(), &switch()).await;
    let ended = sealed.build_box("pkg", Some(&hash(1)));
    assert!(ended.network().await.is_none());
}

/// NET-155: a box's rules decide a source by its host before any packet,
/// as the box's own name query would be answered. A box that lists hosts
/// admits those alone. A grant admits its sources whatever the box lists.
#[tokio::test]
async fn a_box_refuses_a_source_host_it_does_not_list() {
    use op::BuildReach as _;
    let state = tempfile::tempdir().unwrap();
    let listed = boxes::EgressPolicy {
        allow_subnets: Some(Vec::new()),
        allow_dns_hosts: Some(vec!["Downloads.Example.org".to_string()]),
        allow_protocols: None,
        deny_subnets: None,
    };
    let reach = |egress: Option<boxes::EgressPolicy>, spec_hash: Option<String>| super::BoxReach {
        shared: Arc::clone(&boxes_of(boxes::NetworkMode::OwnIp, egress, state.path()).0),
        package: "pkg".to_string(),
        spec_hash,
        granted: std::sync::OnceLock::new(),
    };
    let own = reach(Some(listed.clone()), None);
    assert!(own.admits_source("downloads.example.org"));
    assert!(!own.admits_source("elsewhere.example"));
    assert!(reach(Some(open_egress()), None).admits_source("elsewhere.example"));
    assert!(reach(None, None).admits_source("elsewhere.example"));

    super::file_table(state.path(), boxes::SessionId::nil(), &table_of(&hash(1))).unwrap();
    let granted = reach(Some(listed), Some(hash(1).0.to_hex().to_string()));
    assert!(granted.open().await.is_some());
    assert!(granted.admits_source("elsewhere.example"));
}

/// NET-171: a build box lists while it runs, with the reach the host side
/// granted it, and leaves when the build ends. A box with no build lists none.
#[tokio::test]
async fn a_running_build_box_lists_until_its_build_ends() {
    let state = tempfile::tempdir().unwrap();
    let mut listed = record(boxes::NetworkMode::OwnIp, None);
    listed.id = boxes::SessionId::mint();
    let id = listed.id;
    let box_id = id.to_string();
    let expanded = hash(1);
    super::file_table(state.path(), id, &table_of(&expanded)).unwrap();
    let boxes = BoxBuildBoxes::new(listed, switch(), false, state.path().to_path_buf());
    assert!(super::running_build_boxes(&box_id).is_empty());

    boxes.note_running("pkg", &expanded, true);
    let running = super::running_build_boxes(&box_id);
    assert_eq!(running.len(), 1);
    assert_eq!(running[0].package, "pkg");
    assert!(!running[0].granted, "it has not asked yet");

    let build_box = boxes.build_box("pkg", Some(&expanded));
    assert!(build_box.network().await.is_some());
    let running = super::running_build_boxes(&box_id);
    assert!(running[0].granted);
    assert_eq!(running[0].egress, Some(open_egress()));

    boxes.note_running("pkg", &expanded, false);
    assert!(super::running_build_boxes(&box_id).is_empty());
}

/// NET-155: `__build-fetch` takes a URL, a hash and a file, and says so.
#[test]
fn fetch_process_names_its_arguments() {
    assert_eq!(
        super::fetch_main(Vec::new()),
        Err("__build-fetch takes a URL, a sha256 and a file".to_string())
    );
}

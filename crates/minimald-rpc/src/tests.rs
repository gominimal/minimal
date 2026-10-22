use super::*;
use boxes::wire::request::{ContributionResponse, WireContribution};

/// A failed finalize must decode as an error, not as a success with
/// nothing in it.
///
/// [`Errorable`] is `#[serde(untagged)]`, so it takes `Ok(S)` if `S`
/// parses at all — and a response whose fields are all optional
/// parses from any object, an error payload included. Adding
/// `activate_hooks` reopened exactly that hole, and the symptom is
/// silent: every activation, including a failing one, reads as
/// successful. `deny_unknown_fields` is what closes it, and this is
/// what keeps it closed.
#[test]
fn a_finalize_error_does_not_decode_as_a_successful_finalize() {
    let err: Errorable<FinalizeSessionResponse> =
        serde_json_lenient::from_str(r#"{"error":"activation hook failed"}"#)
            .expect("an error payload must decode");
    match err {
        Errorable::Err { error } => assert!(error.contains("activation hook failed")),
        Errorable::Ok(ok) => {
            panic!("an error decoded as success: {ok:?}")
        }
    }

    // The success shapes still decode: with hooks, and without.
    let bare: Errorable<FinalizeSessionResponse> =
        serde_json_lenient::from_str("{}").expect("an empty success must decode");
    assert_eq!(bare, Errorable::Ok(FinalizeSessionResponse::default()));
    let with_hooks: Errorable<FinalizeSessionResponse> = serde_json_lenient::from_str(
        r#"{"activate_hooks":[{"declared_by":"user loadout `dev`"}]}"#,
    )
    .expect("a populated success must decode");
    match with_hooks {
        Errorable::Ok(ok) => {
            assert_eq!(ok.activate_hooks.len(), 1);
            assert_eq!(ok.activate_hooks[0].declared_by, "user loadout `dev`");
        }
        Errorable::Err { error } => panic!("a success decoded as an error: {error}"),
    }
}

/// A hook's captured output must cross the wire, so the client can
/// show what the hook said rather than only its author-supplied
/// description.
#[test]
fn a_ran_hook_carries_its_captured_output() {
    let resp = FinalizeSessionResponse {
        activate_hooks: vec![RanHook {
            declared_by: "user loadout `dev`".to_string(),
            description: Some("emit to stdout and stderr".to_string()),
            output: "HOOK_STDOUT_VISIBLE\nHOOK_STDERR_VISIBLE\n".to_string(),
        }],
        ..Default::default()
    };
    let wire = serde_json_lenient::to_string(&resp).expect("must serialize");
    let back: FinalizeSessionResponse = serde_json_lenient::from_str(&wire).expect("must decode");
    assert_eq!(back, resp);
    assert_eq!(
        back.activate_hooks[0].output,
        "HOOK_STDOUT_VISIBLE\nHOOK_STDERR_VISIBLE\n"
    );

    // A daemon predating the field still decodes, with empty output.
    let old: Errorable<FinalizeSessionResponse> = serde_json_lenient::from_str(
        r#"{"activate_hooks":[{"declared_by":"user loadout `dev`"}]}"#,
    )
    .expect("a field-less hook must decode");
    match old {
        Errorable::Ok(ok) => assert!(ok.activate_hooks[0].output.is_empty()),
        Errorable::Err { error } => panic!("a success decoded as an error: {error}"),
    }
}

/// `package_check_skipped` is omitted from the wire when false, so a
/// client that predates the field still decodes the common success
/// payload; when true it is present so the client can warn.
#[test]
fn package_check_skipped_is_omitted_when_false() {
    let wire =
        serde_json_lenient::to_string(&FinalizeSessionResponse::default()).expect("must serialize");
    assert!(
        !wire.contains("package_check_skipped"),
        "a false skip must not be serialized, got {wire:?}"
    );

    let skipped = FinalizeSessionResponse {
        package_check_skipped: true,
        ..Default::default()
    };
    let wire = serde_json_lenient::to_string(&skipped).expect("must serialize");
    assert!(
        wire.contains("package_check_skipped"),
        "a true skip must be serialized, got {wire:?}"
    );
    let back: FinalizeSessionResponse = serde_json_lenient::from_str(&wire).expect("must decode");
    assert!(back.package_check_skipped);
}

/// `shared_port_collisions` is omitted from the wire when empty, so a
/// client that predates the field still decodes the common success
/// payload; when a port was yielded it is present, naming the port and
/// the box that holds it so the client can warn.
#[test]
fn shared_port_collisions_are_omitted_when_empty() {
    let wire =
        serde_json_lenient::to_string(&FinalizeSessionResponse::default()).expect("must serialize");
    assert!(
        !wire.contains("shared_port_collisions"),
        "an empty collision list must not be serialized, got {wire:?}"
    );

    let yielded = FinalizeSessionResponse {
        shared_port_collisions: vec![SharedPortCollision {
            port: 8080,
            held_by: "first.min.internal".to_string(),
        }],
        ..Default::default()
    };
    let wire = serde_json_lenient::to_string(&yielded).expect("must serialize");
    assert!(
        wire.contains("shared_port_collisions"),
        "a yielded port must be serialized, got {wire:?}"
    );
    let back: FinalizeSessionResponse = serde_json_lenient::from_str(&wire).expect("must decode");
    assert_eq!(
        back.shared_port_collisions,
        vec![SharedPortCollision {
            port: 8080,
            held_by: "first.min.internal".to_string(),
        }],
        "the collision list must round-trip"
    );
}

/// A client and a daemon on either side of the
/// `report_shared_port_collisions` flag still finalize. An older
/// client's request (no flag) reads as not asking, so a newer daemon
/// leaves the collision list off a reply that client's
/// `deny_unknown_fields` type would refuse; a newer client's request
/// that does not ask is byte-for-byte the older one; and a newer
/// client that asks still decodes an older daemon's reply, which has
/// no list, as empty.
#[test]
fn finalize_collision_report_survives_version_skew_both_ways() {
    let id = SessionId::nil();
    let older_request = format!(r#"{{"session_id":"{}"}}"#, id.as_ref());
    let decoded: FinalizeSessionRequest =
        serde_json_lenient::from_str(&older_request).expect("an older request must decode");
    assert!(
        !decoded.report_shared_port_collisions,
        "an older client never asked for the list"
    );

    let not_asking = FinalizeSessionRequest {
        session_id: id,
        report_shared_port_collisions: false,
    };
    assert_eq!(
        serde_json_lenient::to_string(&not_asking).expect("must serialize"),
        older_request,
        "a request that does not ask is the one an older client sends"
    );

    let asking = FinalizeSessionRequest {
        session_id: id,
        report_shared_port_collisions: true,
    };
    let wire = serde_json_lenient::to_string(&asking).expect("must serialize");
    assert!(
        wire.contains("report_shared_port_collisions"),
        "a request that asks says so: {wire}"
    );

    let older_reply: Errorable<FinalizeSessionResponse> =
        serde_json_lenient::from_str("{}").expect("an older daemon's reply must decode");
    assert_eq!(
        older_reply,
        Errorable::Ok(FinalizeSessionResponse::default()),
        "an older daemon's reply reads as no collisions"
    );
}

/// An empty request body must decode with the documented defaults so a
/// bare `{}` probe (or an older client) still gets a full bundle.
#[test]
fn diag_bundle_request_defaults_from_empty_object() {
    let req: DiagBundleRequest = serde_json_lenient::from_str("{}").expect("deserialize");
    assert_eq!(req, DiagBundleRequest::default());
    assert_eq!(req.log_tail_bytes, 0);
    assert!(req.include_state_listing);
}

#[test]
fn diag_bundle_request_round_trips() {
    let req = DiagBundleRequest::default()
        .with_log_tail_bytes(1024)
        .with_state_listing(false);
    assert_eq!(round_trip(&req), req);
    assert_eq!(
        DIAG_BUNDLE_SUBSYSTEM, "minimald-v1-DiagBundleTarZst",
        "subsystem name is wire contract; changing it breaks old clients"
    );
}

/// The clean-cache framing is wire contract: an empty request body means
/// the daemon's defaults, the updates are self-describing by `kind`, and
/// the subsystem name can't drift without breaking old clients.
#[test]
fn clean_cache_wire_shapes_round_trip() {
    let req: CleanCacheRequest = serde_json_lenient::from_str("{}").expect("deserialize");
    assert_eq!(req, CleanCacheRequest::default());
    assert_eq!(req.older_than_secs, 0);
    assert_eq!(
        round_trip(&req.clone().with_older_than_secs(3600)).older_than_secs,
        3600
    );

    for update in [
        CleanCacheUpdate::Removed {
            detail: "Deleting package curl [abc]".to_string(),
        },
        CleanCacheUpdate::Done {
            entries: 2,
            dirs: 1,
        },
        CleanCacheUpdate::Failed {
            error: "nope".to_string(),
        },
    ] {
        assert_eq!(round_trip(&update), update);
    }
    assert!(
        !CleanCacheUpdate::Removed {
            detail: String::new()
        }
        .is_terminal()
    );
    assert!(
        CleanCacheUpdate::Done {
            entries: 0,
            dirs: 0
        }
        .is_terminal()
    );
    assert!(
        CleanCacheUpdate::Failed {
            error: String::new()
        }
        .is_terminal()
    );

    assert_eq!(
        CLEAN_CACHE_SUBSYSTEM, "minimald-v1-CleanCache",
        "subsystem name is wire contract; changing it breaks old clients"
    );
}

#[test]
fn policy_types_are_present_and_serializable() {
    // PortMapping construction and round-trip
    let mapping = PortMapping {
        external_port: 8080,
        internal_port: 80,
        proto: IpProto::Tcp,
    };
    let json = serde_json_lenient::to_string(&mapping).unwrap();
    let rt: PortMapping = serde_json_lenient::from_str(&json).unwrap();
    assert_eq!(rt, mapping);

    // IngressPolicy default and round-trip
    let ingress = IngressPolicy {
        port_mappings: vec![mapping],
        dynamic_allowed_range: Some((10000, 20000)),
        dynamic_ingress: Some(boxes::DynamicIngress::Ask),
    };
    let json = serde_json_lenient::to_string(&ingress).unwrap();
    let rt: IngressPolicy = serde_json_lenient::from_str(&json).unwrap();
    assert_eq!(rt, ingress);

    // EgressPolicy default serializes without error
    let egress = EgressPolicy::default();
    let json = serde_json_lenient::to_string(&egress).unwrap();
    let _: EgressPolicy = serde_json_lenient::from_str(&json).unwrap();

    // BoxPolicy with null egress and default ingress matches expected CLI output
    let policy = BoxPolicy {
        egress: None,
        ingress: Some(IngressPolicy::default()),
        credentialed_upstream: None,
    };
    let json = serde_json_lenient::to_string(&policy).unwrap();
    assert!(json.contains("\"egress\":null"), "got: {json}");
    assert!(json.contains("\"port_mappings\":[]"), "got: {json}");
    assert!(
        json.contains("\"dynamic_allowed_range\":null"),
        "got: {json}"
    );
    assert!(json.contains("\"dynamic_ingress\":null"), "got: {json}");
}

/// A daemon that predates `hook_failures` answers a destroy with the
/// old unit shape, `null`; it must still read as a clean success, and
/// a clean success must still go out as `null` for an older client.
/// An error must not read as a success with no failures.
#[test]
fn destroy_session_response_decodes_the_old_shape() {
    let old: Errorable<DestroySessionResponse> =
        serde_json_lenient::from_str("null").expect("the old shape must decode");
    assert_eq!(old, Errorable::Ok(DestroySessionResponse::default()));
    assert_eq!(
        serde_json_lenient::to_string(&Errorable::Ok(DestroySessionResponse::default())).unwrap(),
        "null"
    );

    let failed = DestroySessionResponse {
        hook_failures: vec!["user loadout `dev`: exited with status 3".to_string()],
    };
    assert_eq!(round_trip(&failed), failed);

    let err: Errorable<DestroySessionResponse> =
        serde_json_lenient::from_str(r#"{"error":"no such session"}"#)
            .expect("an error payload must decode");
    assert!(
        matches!(err, Errorable::Err { .. }),
        "an error decoded as success: {err:?}"
    );
}

fn round_trip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let json = serde_json_lenient::to_string(value).expect("serialize");
    serde_json_lenient::from_str(&json).expect("deserialize")
}

/// Regression: the daemon reports "no such session" from `GetSessionPolicy`
/// as `Errorable::Err { error }` (`{"error":"..."}`). Because `Errorable`
/// is untagged and every `BoxPolicy` field is optional, that object
/// once decoded as `Ok(BoxPolicy { egress: None, ingress: None })` —
/// exit 0, "no restrictions" — for any nonexistent session. It must decode
/// as `Err` instead.
#[test]
fn errorable_session_policy_decodes_daemon_error_as_err() {
    let decoded: Errorable<BoxPolicy> =
        serde_json_lenient::from_str(r#"{"error":"no session found"}"#).expect("deserialize");
    assert_eq!(
        decoded,
        Errorable::Err {
            error: "no session found".to_string()
        }
    );

    // A real policy response still decodes as the `Ok` arm.
    let decoded: Errorable<BoxPolicy> =
        serde_json_lenient::from_str(r#"{"egress":null,"ingress":null}"#).expect("deserialize");
    assert_eq!(
        decoded,
        Errorable::Ok(BoxPolicy {
            egress: None,
            ingress: None,
            credentialed_upstream: None
        })
    );
}

/// The live-ingress response (NET-044) round-trips, and — because it rides
/// an untagged `Errorable` — the daemon's `{"error":"..."}` reply for an
/// unknown session must still decode as `Err` rather than as an empty
/// mapping list, which would read as "the box published nothing" for a box
/// that does not exist.
#[test]
fn live_ingress_response_round_trips_and_decodes_daemon_error() {
    let live = vec![
        LiveMapping {
            local: "127.0.64.2:3000".to_string(),
            internal_port: 3000,
            proto: IpProto::Tcp,
            // A runtime publish the relay gate has not admitted yet:
            // bound on the host, but the box's own gate still refuses it.
            pending: Some(true),
        },
        LiveMapping {
            local: "127.0.64.2:5353".to_string(),
            internal_port: 5353,
            proto: IpProto::Udp,
            pending: Some(false),
        },
    ];
    assert_eq!(
        round_trip(&Errorable::Ok(live.clone())),
        Errorable::Ok(live.clone())
    );

    // The reachability half rides the wire by name: a pending publish
    // says so in the JSON any client of the RPC reads.
    let json = serde_json_lenient::to_string(&live[0]).unwrap();
    assert!(
        json.contains("\"pending\":true"),
        "the mapping's pending state is part of its wire shape: {json}"
    );

    // A reply from a daemon older than the field carries no `pending`
    // key: it decodes as `None` — unknown, the renderings' own spelling
    // — never as the reachable reading a missing key could default
    // itself into.
    let mut pre_field: serde_json_lenient::Value = serde_json_lenient::from_str(&json).unwrap();
    pre_field
        .as_object_mut()
        .expect("a mapping encodes as an object")
        .remove("pending");
    let decoded: LiveMapping =
        serde_json_lenient::from_str(&serde_json_lenient::to_string(&pre_field).unwrap()).unwrap();
    assert_eq!(
        decoded.pending, None,
        "a pre-field reply decodes as unknown, not as not-pending: {json}"
    );

    let decoded: Errorable<Vec<LiveMapping>> =
        serde_json_lenient::from_str(r#"{"error":"no session found"}"#).expect("deserialize");
    assert_eq!(
        decoded,
        Errorable::Err {
            error: "no session found".to_string()
        },
        "a daemon error must not decode as an empty mapping list"
    );

    // The split a renderer reads: `local` is a `host:port` pair.
    let mapping = LiveMapping {
        local: "127.0.64.2:3000".to_string(),
        internal_port: 3000,
        proto: IpProto::Tcp,
        pending: Some(false),
    };
    assert_eq!(mapping.host_port(), Some(("127.0.64.2", 3000)));
}

/// `SessionDelta` distinguishes proven-clean VCS state, the
/// activation-delta fallback, and "unavailable"; all three shapes must
/// survive the wire, tagged by `kind`.
#[test]
fn session_delta_response_round_trips() {
    let vcs = SessionDeltaResponse::Vcs {
        uncommitted: vec!["A notes.md".to_string(), "M src/main.rs".to_string()],
        unpushed_commits: 3,
    };
    assert_eq!(round_trip(&vcs), vcs);
    let json = serde_json_lenient::to_string(&vcs).unwrap();
    assert!(json.contains(r#""kind":"vcs""#), "got: {json}");

    let fallback = SessionDeltaResponse::ChangedSinceActivation {
        rows: vec!["A scratch.txt".to_string()],
    };
    assert_eq!(round_trip(&fallback), fallback);
    let json = serde_json_lenient::to_string(&fallback).unwrap();
    assert!(
        json.contains(r#""kind":"changed_since_activation""#),
        "got: {json}"
    );

    let unavailable = SessionDeltaResponse::Unavailable;
    assert_eq!(round_trip(&unavailable), unavailable);
    let json = serde_json_lenient::to_string(&unavailable).unwrap();
    assert!(json.contains(r#""kind":"unavailable""#), "got: {json}");
}

#[test]
fn create_session_request_round_trips() {
    let req = CreateSessionRequest {
        config: BoxConfig {
            name: Some("my-session".into()),
            project_path: paths::HostAbsPath::try_new("/home/u/proj").unwrap(),
            network: NetworkMode::OwnIp,
            policy: BoxPolicy::default(),
            // The non-`None` shape of the handed addresses: a fixture
            // leaving it `None` would round-trip green even if the
            // field never reached the wire.
            task_addresses: Vec::new(),
            box_id: None,
            box_addresses: Some(BoxAddresses {
                switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
                loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
            }),
            // The non-default (`--no-hooks`): `true` is the serde
            // default, so a fixture using it would round-trip green
            // even if the field never reached the wire.
            hooks_enabled: false,
            attrs: [("color".to_string(), "blue".to_string())]
                .into_iter()
                .collect(),
            // Non-empty, so a fixture cannot round-trip green with the
            // deliveries and the certificate left off the wire.
            sealed_deliveries: vec![boxes::SealedDelivery {
                variable: "GH_TOKEN".into(),
                sealed: "sealed-value".into(),
            }],
            root_certificate: Some("-----BEGIN CERTIFICATE-----".into()),
        },
        must_match_version: Some("0.6.0".into()),
    };
    assert_eq!(round_trip(&req), req);
}

/// The one constructor every daemon-side create goes through: it fills
/// each field it does not take with the value a plain create sends, and
/// the request it builds survives the wire unchanged.
#[test]
fn create_request_constructor_round_trips() {
    let req = CreateSessionRequest::new(
        "my-session",
        paths::HostAbsPath::try_new("/home/u/proj").unwrap(),
        NetworkMode::OwnIp,
        BoxPolicy::default(),
    );
    assert_eq!(
        req,
        CreateSessionRequest {
            config: BoxConfig {
                name: Some("my-session".into()),
                project_path: paths::HostAbsPath::try_new("/home/u/proj").unwrap(),
                network: NetworkMode::OwnIp,
                policy: BoxPolicy::default(),
                task_addresses: Vec::new(),
                box_id: None,
                box_addresses: None,
                hooks_enabled: true,
                attrs: Default::default(),
                sealed_deliveries: Vec::new(),
                root_certificate: None,
            },
            must_match_version: None,
        }
    );
    assert_eq!(round_trip(&req), req);
}

/// A client that predates `must_match_version` sends no such field, and
/// the daemon must read that as "assert nothing" rather than fail to
/// decode the request. `CreateSessionRequest` is deliberately *not*
/// `deny_unknown_fields`, which is the same property read the other way:
/// a daemon that predates the field ignores it instead of rejecting the
/// create outright.
#[test]
fn create_session_request_predating_must_match_version_asserts_nothing() {
    let json = r#"{"config":{
        "name": "s",
        "project_path": "/p",
        "network": "host_net",
        "attrs": {}
    }}"#;
    let req: CreateSessionRequest =
        serde_json_lenient::from_str(json).expect("legacy request must load");
    assert!(req.must_match_version.is_none());

    // And the forward direction: an old daemon's serde ignores the new
    // field rather than refusing the request.
    let with_field = r#"{"config":{
        "name": "s",
        "project_path": "/p",
        "network": "host_net",
        "attrs": {}
    },"must_match_version":"0.6.0"}"#;
    let req: CreateSessionRequest =
        serde_json_lenient::from_str(with_field).expect("the new field must decode");
    assert_eq!(req.must_match_version.as_deref(), Some("0.6.0"));
}

/// The skew wording names both builds, the recovery, and the override —
/// and says nothing at all when the two builds agree.
#[test]
fn version_skew_message_names_both_builds_the_recovery_and_the_override() {
    assert!(version_skew_message("0.6.0", "0.6.0").is_none());
    let msg = version_skew_message("0.6.0", "0.5.0-dev.12.g86ce5c3a")
        .expect("differing builds are a skew");
    assert!(msg.contains("0.6.0"), "missing the CLI version: {msg}");
    assert!(
        msg.contains("0.5.0-dev.12.g86ce5c3a"),
        "missing the daemon version: {msg}"
    );
    assert!(msg.contains("min stop"), "missing the recovery: {msg}");
    assert!(
        msg.contains(SKEW_OVERRIDE_VAR),
        "missing the override: {msg}"
    );
}

/// A `BoxConfig` from a client that predates `hooks_enabled`
/// deserializes with hooks **on**. A bare `#[serde(default)]` would
/// give `false` and silently disable hooks for every older client.
#[test]
fn session_config_predating_hooks_enabled_defaults_to_on() {
    let json = r#"{
        "name": "s",
        "project_path": "/p",
        "network": "host_net",
        "attrs": {}
    }"#;
    let c: BoxConfig = serde_json_lenient::from_str(json).expect("legacy config must load");
    assert!(c.hooks_enabled);
}

#[test]
fn create_session_response_round_trips() {
    let resp = CreateSessionResponse {
        id: SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        daemon_version: Some("0.6.0".into()),
        hostname_routing_unavailable: None,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        // The interim flag survives the wire: the re-advise a client
        // prints on it (NET-123) must not be able to silently drop off.
        interim_loopback: true,
        deny_all_opt_out: None,
        // So does the answerer's half of the name-surface report: the
        // line `min session activate` prints from it (NET-018) must not
        // be able to silently drop off.
        answerer_bound: true,
        // And the classifier state (NET-079): the advisory a start
        // prints and the enforcement a host-address box runs under
        // must not be able to silently drop off either.
        classifier_advisory: None,
        host_ip_enforcement: None,
    };
    let json = serde_json_lenient::to_string(&resp).expect("serializes");
    assert!(
        json.contains(r#""answerer_bound":true"#),
        "a daemon whose answerer is bound must say so on the wire, got: {json}",
    );
    assert_eq!(round_trip(&resp), resp);
}

/// The opt-out a daemon reports on its create reply (NET-077) survives
/// the wire both ways, and is *absent* — not `false` — when the daemon
/// has not set it, so a daemon that keeps the default and a daemon that
/// predates the field stay distinguishable to the client deciding
/// whether the coming change applies to it (NET-076's notice).
#[test]
fn create_session_response_carries_the_deny_all_opt_out() {
    let opted_out = CreateSessionResponse {
        deny_all_opt_out: Some(true),
        id: SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        daemon_version: Some("0.6.0".into()),
        hostname_routing_unavailable: None,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        interim_loopback: false,
        answerer_bound: false,
        classifier_advisory: None,
        host_ip_enforcement: None,
    };
    let json = serde_json_lenient::to_string(&opted_out).expect("serializes");
    assert!(
        json.contains(r#""deny_all_opt_out":true"#),
        "an opted-out daemon must say so on the wire, got: {json}",
    );
    assert_eq!(
        serde_json_lenient::from_str::<CreateSessionResponse>(&json)
            .expect("decodes back")
            .deny_all_opt_out,
        Some(true),
    );

    let opted_in = CreateSessionResponse {
        deny_all_opt_out: Some(false),
        ..opted_out
    };
    assert_eq!(round_trip(&opted_in), opted_in);
}

/// The classifier state a host that cannot decide per box puts on its
/// create replies (NET-079), pinned on the wire: the unenforced state
/// as `host_ip_enforcement: none` in the machine spelling — `per_box` on
/// a host that decides, so the two hosts stay distinguishable to
/// whatever reads the field — the cause in words inside the advisory,
/// and the install command only for the cause it clears. A daemon
/// that predates both fields decodes with neither: silence, never a
/// decided `per_box`.
#[test]
fn create_response_carries_the_classifier_state() {
    // The host whose step is missing: the advisory names the cause in
    // words, names the state it leaves the box in, and carries the
    // exact command that installs the privileged step.
    let step_missing = CreateSessionResponse {
        id: SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        daemon_version: Some("0.6.0".into()),
        hostname_routing_unavailable: None,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        interim_loopback: false,
        deny_all_opt_out: None,
        answerer_bound: false,
        classifier_advisory: Some(
            "note: this host cannot decide a host-address box's egress \
             verdict per box: the classifier's privileged step is not \
             installed on this host. While it cannot, its host-address \
             boxes run unenforced — whatever the boxes' declarations \
             say. Install the classifier's privileged step with:\n  \
             min finalize-install"
                .to_string(),
        ),
        host_ip_enforcement: Some("none".into()),
    };
    let json = serde_json_lenient::to_string(&step_missing).expect("serializes");
    assert!(
        json.contains(r#""host_ip_enforcement":"none""#),
        "the unenforced state must ride the wire in the machine spelling, got: {json}",
    );
    assert!(
        json.contains("the classifier's privileged step is not installed"),
        "the advisory names its cause in words, got: {json}",
    );
    assert!(
        json.contains("min finalize-install"),
        "the step's cause names the exact command that installs it, got: {json}",
    );
    assert_eq!(round_trip(&step_missing), step_missing);

    // The host that cannot confine a box: the same state, named without
    // a command — installing the step over such a tree would leave the
    // cause standing, so the advisory must not name one.
    let cannot_confine = CreateSessionResponse {
        classifier_advisory: Some(
            "note: this host cannot decide a host-address box's egress \
             verdict per box: no cgroup2 mount with nsdelegate covers \
             the classifier tree, so a box could migrate out of its \
             leaf. While it cannot, its host-address boxes run \
             unenforced — whatever the boxes' declarations say."
                .to_string(),
        ),
        host_ip_enforcement: Some("none".into()),
        ..step_missing
    };
    let json = serde_json_lenient::to_string(&cannot_confine).expect("serializes");
    assert!(
        !json.contains("min finalize-install"),
        "a cause no command clears names no command, got: {json}",
    );
    assert_eq!(round_trip(&cannot_confine), cannot_confine);

    // The decided host: nothing to say, so nothing on the wire — a
    // client of either build reads the reply it always read.
    let decided = CreateSessionResponse {
        classifier_advisory: None,
        host_ip_enforcement: Some("per_box".into()),
        ..cannot_confine
    };
    let json = serde_json_lenient::to_string(&decided).expect("serializes");
    assert!(
        json.contains(r#""host_ip_enforcement":"per_box""#),
        "a host that decides per box says so in the machine spelling, got: {json}",
    );
    assert!(
        !json.contains("classifier_advisory"),
        "a decided host carries no advisory, got: {json}",
    );
    assert_eq!(round_trip(&decided), decided);

    // A daemon that predates both fields: the reply it always sent
    // decodes with neither, and absence must not read as a decided
    // `per_box` — an older daemon's silence is not evidence of
    // anything, and a client that reads nothing claims nothing.
    let pre_field: Errorable<CreateSessionResponse> = serde_json_lenient::from_str(
        r#"{"id":"00000000-0000-0000-0000-000000000001","daemon_version":"0.5.0"}"#,
    )
    .expect("a pre-field CreateSession reply must still decode");
    match pre_field {
        Errorable::Ok(c) => {
            assert!(c.classifier_advisory.is_none());
            assert_eq!(c.host_ip_enforcement, None);
        }
        Errorable::Err { error } => panic!("expected Ok, got {error}"),
    }
}

/// NET-079's enforcement state never rides the strict policy reply: an
/// older `min` built against the two-field [`EffectiveBoxPolicy`] —
/// `deny_unknown_fields`, the strictness that keeps an all-optional
/// struct from swallowing the daemon's `{"error":...}` replies under
/// the untagged [`Errorable`] — rejects a key it has no field for, so a
/// policy reply that grew the state would make every old client fail
/// `min session policy` outright. Pinned here as the contract that keeps
/// that from regressing: the state answers over
/// [`GetSessionRuntimeFacts`] — a reply an old client simply never asks
/// for, and this build's own answer to it stays anchored the same way
/// the policy's `egress` is. NET-134's lane is the one deliberate
/// exception, and this test pins both of its halves: a lane-less reply
/// serializes without the lane's key and so still decodes in the old
/// client's strict shape, while a laned reply — a fact `min session
/// policy` reads from no other reply — is refused by that client, the
/// visible error the lane's issue took over a lane the report is
/// silent about.
#[test]
fn effective_policy_reply_decodes_in_the_old_clients_strict_shape() {
    // The reply this build serves for a lane-less box: no enforcement
    // key, and no lane key either — the shape every earlier client
    // reads.
    let reply = Errorable::Ok(EffectiveBoxPolicy {
        egress: EffectiveEgress::DenyAll,
        ingress: None,
        credentialed_upstream: None,
    });
    let json = serde_json_lenient::to_string(&reply).expect("the policy reply serializes");
    assert!(
        !json.contains("host_ip_enforcement"),
        "the strict policy reply must carry no enforcement key, got: {json}",
    );
    assert!(
        !json.contains("credentialed_upstream"),
        "a lane-less reply must carry no lane key, so the old shape still \
         reads it, got: {json}",
    );

    // The old client: the strict two-field shape it was built against,
    // spelled as its own derive would spell it. It decodes the reply
    // above because a lane-less reply never grew a key — and it refuses
    // a reply that did, which is why the enforcement state must ride its
    // own RPC, and why a laned box's reply is a visible error to this
    // client rather than a silently missing lane.
    #[derive(serde::Deserialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct OldClientPolicy {
        egress: EffectiveEgress,
        ingress: Option<IngressPolicy>,
    }
    let decoded: Errorable<OldClientPolicy> = serde_json_lenient::from_str(&json)
        .expect("the reply this build serves decodes in the old client's shape");
    assert_eq!(
        decoded,
        Errorable::Ok(OldClientPolicy {
            egress: EffectiveEgress::DenyAll,
            ingress: None,
        })
    );
    assert!(
        serde_json_lenient::from_str::<Errorable<OldClientPolicy>>(
            r#"{"egress":"deny_all","ingress":null,"host_ip_enforcement":"none"}"#
        )
        .is_err(),
        "the old client refuses a policy reply that grew the key — the \
         reason the state answers over its own runtime-facts reply",
    );
    assert!(
        serde_json_lenient::from_str::<Errorable<OldClientPolicy>>(
            r#"{"egress":"deny_all","ingress":null,"credentialed_upstream":{}}"#
        )
        .is_err(),
        "the old client refuses a laned reply too — `min session policy` \
         reads no other reply that carries the lane, so the refusal is the \
         visible error the lane's issue chose over a silent omission",
    );

    // The runtime-facts reply keeps the property the strict shapes
    // exist for without being strict: its required `id` is a field the
    // daemon's `{"error":...}` never carries, so an error answer falls
    // through the untagged decode to `Err` rather than decoding as a
    // facts object with nothing to report — while a facts reply that
    // grew a key this client has no field for still decodes, because
    // runtime facts grow and an older client keeps the ones it knows.
    let facts = BoxRuntimeFacts {
        id: SessionId::nil(),
        host_ip_enforcement: Some(HostIpEnforcement::None),
        unaudited_listen_ports: Vec::new(),
        audit_log: None,
        shared_port_collisions: Vec::new(),
    };
    assert_eq!(round_trip(&facts), facts);
    let unaudited = BoxRuntimeFacts {
        unaudited_listen_ports: vec![3000, 3001],
        audit_log: Some("/state/audit/decisions.log".to_string()),
        ..facts.clone()
    };
    assert_eq!(round_trip(&unaudited), unaudited);
    let empty = serde_json_lenient::to_string(&facts).expect("facts serialize");
    assert!(
        !empty.contains("unaudited_listen_ports") && !empty.contains("audit_log"),
        "an empty unaudited list is omitted from the wire: {empty}"
    );
    match serde_json_lenient::from_str::<Errorable<BoxRuntimeFacts>>(
        r#"{"error":"no session found"}"#,
    )
    .expect("an error reply is one of the untagged arms")
    {
        Errorable::Err { error } => assert_eq!(error, "no session found"),
        Errorable::Ok(facts) => {
            panic!("an error reply must not decode as facts, got {facts:?}")
        }
    }
    match serde_json_lenient::from_str::<Errorable<BoxRuntimeFacts>>(
        r#"{"id":"00000000-0000-0000-0000-000000000000","host_ip_enforcement":"per_box","a_later_fact":true}"#,
    )
    .expect("a facts reply with a key this client does not know still decodes")
    {
        Errorable::Ok(decoded) => assert_eq!(
            decoded,
            BoxRuntimeFacts {
                id: SessionId::nil(),
                host_ip_enforcement: Some(HostIpEnforcement::PerBox),
                unaudited_listen_ports: Vec::new(),
                audit_log: None,
                shared_port_collisions: Vec::new(),
            },
            "the facts this client knows decode beside a key it does not"
        ),
        Errorable::Err { error } => {
            panic!("a facts reply must not decode as an error, got {error}")
        }
    }
}

/// A daemon that predates `hostname_routing_unavailable` must still decode,
/// with the field absent. Absent has to mean "said nothing", not "reported
/// a fault": an older daemon is not evidence that routing is down, and a
/// client that read it that way would warn on every session it lists.
/// `deny_all_opt_out` rides the same reply and reads the same way — absent
/// from a daemon that predates it, which is a daemon that cannot have
/// opted out (NET-077), so the client prints the notice it always did.
/// `answerer_bound` rides the same replies and reads the same way — absent
/// from a daemon that predates it, which decodes as `false`, the read that
/// changes nothing: an older daemon's silence is not evidence its
/// answerer serves, and a client that assumed it would name native DNS on
/// a host that may not have one (NET-018).
#[test]
fn responses_predating_hostname_routing_field_decode_as_absent() {
    let list: ListSessionsResponse =
        serde_json_lenient::from_str(r#"{"sessions":[],"daemon_version":"0.5.0"}"#)
            .expect("a pre-field ListSessions reply must still decode");
    assert!(list.hostname_routing_unavailable.is_none());
    assert!(list.hostname_proxy_port.is_none());
    assert!(list.zone_answerer_port.is_none());
    assert!(!list.answerer_bound);

    let create: Errorable<CreateSessionResponse> = serde_json_lenient::from_str(
        r#"{"id":"00000000-0000-0000-0000-000000000001","daemon_version":"0.5.0"}"#,
    )
    .expect("a pre-field CreateSession reply must still decode");
    match create {
        Errorable::Ok(c) => {
            assert!(c.hostname_routing_unavailable.is_none());
            assert!(c.hostname_proxy_port.is_none());
            assert!(c.zone_answerer_port.is_none());
            // The interim flag's legacy default is `false`, the read that
            // changes nothing: an older daemon's reply is not evidence the
            // reserved range is absent, and nothing downstream is gated
            // on the flag.
            assert!(!c.interim_loopback);
            assert!(c.deny_all_opt_out.is_none());
            assert!(!c.answerer_bound);
        }
        Errorable::Err { error } => panic!("expected Ok, got {error}"),
    }
}

/// The field is omitted from the wire when there is nothing wrong, so the
/// healthy path costs no bytes and an older client sees exactly what it
/// saw before.
#[test]
fn hostname_routing_field_is_omitted_when_healthy() {
    let resp = ListSessionsResponse {
        daemon_version: Some("0.6.0".into()),
        hostname_routing_unavailable: None,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        answerer_bound: false,
        resource_pool: None,
        sessions: vec![],
    };
    let json = serde_json_lenient::to_string(&resp).expect("serializes");
    assert!(
        !json.contains("hostname_routing_unavailable"),
        "healthy reply should omit the field, got {json}"
    );
    assert!(
        !json.contains("hostname_proxy_port"),
        "a reply that has not discovered its port should omit the field, got {json}"
    );
    assert!(
        !json.contains("zone_answerer_port"),
        "a reply that has not discovered its answerer port should omit the field, got {json}"
    );

    let down = ListSessionsResponse {
        hostname_routing_unavailable: Some("port 7654 is held".into()),
        ..resp.clone()
    };
    let json = serde_json_lenient::to_string(&down).expect("serializes");
    let back: ListSessionsResponse = serde_json_lenient::from_str(&json).expect("round trips");
    assert_eq!(
        back.hostname_routing_unavailable.as_deref(),
        Some("port 7654 is held")
    );

    let discovered = ListSessionsResponse {
        hostname_proxy_port: Some(41234),
        ..resp.clone()
    };
    let json = serde_json_lenient::to_string(&discovered).expect("serializes");
    let back: ListSessionsResponse = serde_json_lenient::from_str(&json).expect("round trips");
    assert_eq!(back.hostname_proxy_port, Some(41234));

    // The list reply carries the answerer's half the same way (NET-018):
    // `min ls` reads it off this reply, not the activation one.
    let bound = ListSessionsResponse {
        answerer_bound: true,
        ..resp.clone()
    };
    let json = serde_json_lenient::to_string(&bound).expect("serializes");
    let back: ListSessionsResponse = serde_json_lenient::from_str(&json).expect("round trips");
    assert!(back.answerer_bound);
}

/// The reply a daemon that predates `daemon_version` sends must still
/// decode — with `None`, which is what tells the client it is talking to
/// a build older than the handshake and therefore a skewed one.
#[test]
fn create_session_response_predating_daemon_version_decodes_as_absent() {
    let resp: Errorable<CreateSessionResponse> =
        serde_json_lenient::from_str(r#"{"id":"00000000-0000-0000-0000-000000000001"}"#)
            .expect("a legacy reply must decode");
    assert!(resp.unwrap().daemon_version.is_none());
}

/// Same for the two read RPCs the attach/exec paths gate on.
#[test]
fn read_responses_predating_daemon_version_decode_as_absent() {
    let listed: ListSessionsResponse =
        serde_json_lenient::from_str(r#"{"sessions":[]}"#).expect("deserialize");
    assert!(listed.daemon_version.is_none());
    let record: GetSessionRecordResponse =
        serde_json_lenient::from_str(r#"{"record":null}"#).expect("deserialize");
    assert!(record.daemon_version.is_none());
}

#[test]
fn list_sessions_accepts_response_without_resource_pool() {
    let resp: ListSessionsResponse =
        serde_json_lenient::from_str(r#"{"sessions":[]}"#).expect("deserialize");
    assert!(resp.resource_pool.is_none());
    assert!(resp.sessions.is_empty());
}

/// A daemon that predates `project_path` and `status` on
/// `ListSessionsEntry` omits both fields; the client must accept that
/// response (project_path → `None`, status → `Active`) rather than fail
/// deserialization.
#[test]
fn list_sessions_entry_accepts_response_without_project_path_and_status() {
    let resp: ListSessionsResponse = serde_json_lenient::from_str(
        r#"{"sessions":[{"id":"00000000-0000-0000-0000-000000000001","name":"old"}]}"#,
    )
    .expect("deserialize");
    assert_eq!(resp.sessions.len(), 1);
    let entry = &resp.sessions[0];
    assert_eq!(
        entry.id,
        SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    );
    assert_eq!(entry.name.as_deref(), Some("old"));
    assert!(entry.project_path.is_none(), "missing project_path → None");
    assert_eq!(
        entry.status,
        boxes::BoxState::Active,
        "missing status → default Active"
    );
}

#[test]
fn configure_loadout_request_round_trips_with_explicit_contribution() {
    let req = ConfigureLoadoutRequest {
        session_id: SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        contribution: WireContribution::default(),
    };
    assert_eq!(round_trip(&req), req);
}

/// A caller that doesn't compose a session omits `contribution`
/// entirely; it defaults to empty rather than failing to parse.
#[test]
fn configure_loadout_request_accepts_missing_contribution_field() {
    let raw = serde_json_lenient::json!({
        "session_id": "00000000-0000-0000-0000-000000000001",
    });
    let req: ConfigureLoadoutRequest = serde_json_lenient::from_value(raw).expect("deserialize");
    assert_eq!(req.contribution, WireContribution::default());
}

#[test]
fn configure_loadout_response_materialized_round_trips() {
    let resp = ConfigureLoadoutResponse::Materialized;
    assert_eq!(round_trip(&resp), resp);
    let json = serde_json_lenient::to_string(&resp).unwrap();
    assert!(json.contains(r#""kind":"materialized""#), "got: {json}");
}

#[test]
fn configure_loadout_response_pending_round_trips() {
    let id = SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let resp = ConfigureLoadoutResponse::Pending {
        response: ContributionResponse {
            session_id: id,
            vars: vec![],
            patches: vec![],
            lifecycle_hooks: vec![],
        },
    };
    assert_eq!(round_trip(&resp), resp);
    let json = serde_json_lenient::to_string(&resp).unwrap();
    assert!(json.contains(r#""kind":"pending""#), "got: {json}");
}

/// Back-compat both directions: a daemon that predates `git` omits the
/// field and decodes to `None`; an extra field in the payload is
/// accepted (no `deny_unknown_fields`), so a new daemon still serves
/// old clients.
#[test]
fn list_sessions_entry_decodes_with_and_without_git() {
    let bare = r#"{
        "id": "00000000-0000-0000-0000-000000000001",
        "name": "api",
        "project_path": "/src/api",
        "status": "active",
        "attrs": null
    }"#;
    let without: ListSessionsEntry = serde_json_lenient::from_str(bare).expect("pre-git payload");
    assert_eq!(without.git, None);

    let with_git = serde_json_lenient::json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "name": "api",
        "project_path": "/src/api",
        "status": "active",
        "git": {
            "branch": "main",
            "repo_root": "/src/api",
            "is_worktree": true
        },
        "attrs": null
    });
    let with: ListSessionsEntry =
        serde_json_lenient::from_value(with_git).expect("post-git payload");
    assert_eq!(
        with.git,
        Some(Box::new(GitInfo {
            branch: "main".to_string(),
            repo_root: "/src/api".to_string(),
            is_worktree: true,
        }))
    );
    assert_eq!(round_trip(&with), with);
}

/// NET-129's listing half survives version skew both ways without a
/// request flag, because neither [`ListSessionsResponse`] nor
/// [`ListSessionsEntry`] is `deny_unknown_fields`. A newer daemon's
/// populated entry carries one key more than an older client knows, and
/// these types skip a key they do not know — shown here with a key this
/// build does not know either, the position an older client is in. An
/// older daemon's entry carries no list and decodes as empty, and an
/// empty list stays off the wire.
#[test]
fn list_sessions_shared_port_collisions_survive_version_skew_both_ways() {
    let entry = |collisions: Vec<SharedPortCollision>| ListSessionsEntry {
        id: SessionId::nil(),
        name: Some("second".to_string()),
        project_path: None,
        status: boxes::BoxState::Active,
        git: None,
        attrs: None,
        host_ip_enforcement: None,
        shared_port_collisions: collisions,
    };
    let response = |sessions| ListSessionsResponse {
        resource_pool: None,
        sessions,
        daemon_version: None,
        hostname_routing_unavailable: None,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        answerer_bound: false,
    };

    let quiet =
        serde_json_lenient::to_string(&response(vec![entry(Vec::new())])).expect("must serialize");
    assert!(
        !quiet.contains("shared_port_collisions"),
        "an empty list must not be serialized, got {quiet}"
    );

    let yielded = entry(vec![SharedPortCollision {
        port: 8080,
        held_by: "first.min.internal".to_string(),
    }]);
    let mut wire =
        serde_json_lenient::to_value(response(vec![yielded.clone()])).expect("serializes");
    assert_eq!(
        wire["sessions"][0]["shared_port_collisions"],
        serde_json_lenient::json!([{"port": 8080, "held_by": "first.min.internal"}]),
        "a yielded port is listed under its wire key: {wire}"
    );

    // A newer daemon's reply, one key past what this build knows: still
    // decodes, so an older client's listing survives a populated list.
    wire["sessions"][0]["a_later_field"] = serde_json_lenient::json!([1]);
    wire["a_later_field"] = serde_json_lenient::json!(true);
    let newer: ListSessionsResponse =
        serde_json_lenient::from_value(wire).expect("unknown keys are ignored");
    assert_eq!(newer.sessions, vec![yielded]);

    // An older daemon's entry: no list, decoded as empty.
    let older: ListSessionsResponse = serde_json_lenient::from_str(
        r#"{"sessions":[{"id":"00000000-0000-0000-0000-000000000000","name":"second","attrs":null}]}"#,
    )
    .expect("a pre-field entry must decode");
    assert!(older.sessions[0].shared_port_collisions.is_empty());
}

/// The port-report verbs (NET-138) round-trip as the fixed, size-bounded
/// messages they are: the tagged line names its verb, the request carries
/// the row key, the port, the protocol and the reporting source, and the
/// one reply both verbs answer with cannot be mistaken for any other
/// reply shape — the discrimination the untagged reply depends on, since
/// a report the grant refused is answered as `Error` and a publish that
/// unwinds must be able to tell which it got.
/// A withdrawal's box id is optional on the wire: a client that
/// predates it sends none and decodes as `None`, and `None` is not
/// written, so a daemon that predates it reads the line it always did.
#[test]
fn withdraw_box_id_is_optional_on_the_wire() {
    let old_client: WithdrawBoxRequest = serde_json_lenient::from_str(
        r#"{"name":"web","switch_address":"100.64.127.255","loopback_address":"127.0.64.2"}"#,
    )
    .expect("a pre-epoch withdrawal decodes");
    assert_eq!(old_client.box_id, None);
    let wire = serde_json_lenient::to_string(&old_client).expect("serialize");
    assert!(
        !wire.contains("box_id"),
        "an absent id is not written: {wire}"
    );

    let with_id = WithdrawBoxRequest {
        box_id: Some(BoxId::from_bytes([7; 16])),
        ..old_client
    };
    let wire = serde_json_lenient::to_string(&with_id).expect("serialize");
    assert!(
        wire.contains(r#""box_id":"07070707070707070707070707070707""#),
        "the id crosses as its hex spelling: {wire}"
    );
    let decoded: WithdrawBoxRequest = serde_json_lenient::from_str(&wire).expect("decode");
    assert_eq!(decoded, with_id);
}

#[test]
fn box_control_admit_and_withdraw_round_trip() {
    let admit = BoxControlRequest::AdmitPort(AdmitPortRequest {
        switch_address: std::net::Ipv4Addr::new(100, 64, 127, 255),
        port: 8080,
        proto: IpProto::Tcp,
        source: PortReportSource::Ask,
    });
    let wire = serde_json_lenient::to_string(&admit).expect("serialize");
    assert!(
        wire.contains(r#""verb":"admit_port""#),
        "the tagged line names its verb: {wire}"
    );
    assert_eq!(round_trip(&admit), admit);

    let withdraw = BoxControlRequest::WithdrawPort(WithdrawPortRequest {
        switch_address: std::net::Ipv4Addr::new(100, 64, 127, 255),
        port: 8080,
        proto: IpProto::Udp,
        source: PortReportSource::Listen,
    });
    let wire = serde_json_lenient::to_string(&withdraw).expect("serialize");
    assert!(
        wire.contains(r#""verb":"withdraw_port""#),
        "the tagged line names its verb: {wire}"
    );
    assert_eq!(round_trip(&withdraw), withdraw);
    assert!(
        wire.contains(r#""source":"listen""#) && wire.contains(r#""proto":"udp""#),
        "the source and the protocol cross in their wire spellings: {wire}"
    );

    // The reply a recorded report answers with round-trips, and a
    // document of no other variant's shape decodes as it — the
    // untagged discrimination, checked from the other side.
    let recorded = BoxControlReply::PortRecorded {
        port: 8080,
        proto: IpProto::Tcp,
    };
    assert_eq!(round_trip(&recorded), recorded);
    let decoded: BoxControlReply = serde_json_lenient::from_str(r#"{"port":8080,"proto":"tcp"}"#)
        .expect("a recorded report's reply decodes");
    assert_eq!(decoded, recorded);

    // The refusal a grant-refused report answers with still decodes as
    // the error it is — the shape the guest unwinds its publish by.
    let refused: BoxControlReply = serde_json_lenient::from_str(
        r#"{"error":"the reported port is outside the box's allowed range"}"#,
    )
    .expect("a refusal decodes");
    assert_eq!(
        refused,
        BoxControlReply::Error {
            error: "the reported port is outside the box's allowed range".to_string()
        }
    );

    // The report port is the wire contract between the two ends that
    // depend on this crate — the in-VM daemon that dials it and the VM
    // host daemon that bridges it — pinned beside the guest's boot
    // marker, one port per purpose, and clear of the timekeep bridge's
    // own number, which runs the opposite direction.
    assert_eq!(
        VM_HOST_BOX_REPORT_PORT, 7352,
        "the report port is wire contract; changing it breaks both ends"
    );
}

/// The ask verbs' offer half (NET-045) round-trips: the guest's ask
/// admit carries only the row key, the port and the protocol — no name
/// or free text a guest could smuggle a prompt with — the subscription
/// keys itself by the row's box id, and the offer the daemon pushes to
/// an attached client carries the host row's own fields. Every ask
/// reply stays distinct from every older shape in the untagged order —
/// an offered ask is never a recorded port, and a registration's
/// id-carrying answer is never a subscription's.
#[test]
fn box_control_pending_ask_offer_round_trip() {
    let box_id = BoxId::from_bytes([
        0x01, 0x95, 0x65, 0x5f, 0x7f, 0x1e, 0x7a, 0xbc, 0x9d, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e,
        0x7f,
    ]);

    // The guest's ask admit: the row key, the port, the protocol, and
    // nothing else — the one fixed shape a guest may raise a question
    // in.
    let admit_ask = BoxControlRequest::AdmitAsk(AdmitAskRequest {
        switch_address: std::net::Ipv4Addr::new(100, 64, 127, 255),
        port: 8080,
        proto: IpProto::Tcp,
    });
    let wire = serde_json_lenient::to_string(&admit_ask).expect("serialize");
    assert!(
        wire.contains(r#""verb":"admit_ask""#)
            && wire.contains(r#""port":8080"#)
            && wire.contains(r#""proto":"tcp""#),
        "the tagged line names its verb and the port and protocol it asks for: {wire}"
    );
    assert!(
        !wire.contains("name") && !wire.contains("source") && !wire.contains("answer"),
        "the ask admit carries no name, no source and no answer — the guest can raise a \
         question but neither phrase it nor answer it: {wire}"
    );
    assert_eq!(round_trip(&admit_ask), admit_ask);

    // The subscription: keyed by the row's box id, never a name.
    let subscribe = BoxControlRequest::SubscribeAsks(SubscribeAsksRequest { box_id });
    let wire = serde_json_lenient::to_string(&subscribe).expect("serialize");
    assert!(
        wire.contains(r#""verb":"subscribe_asks""#)
            && wire.contains(r#""box_id":"0195655f7f1e7abc9d1f2a3b4c5d6e7f""#),
        "the subscription names its verb and the box id it keys by: {wire}"
    );
    assert_eq!(round_trip(&subscribe), subscribe);

    // The subscription's answer: subscribed marks the shape, so a
    // registration's id-carrying answer — a strict superset of the
    // marker-less fields — still decodes as the registration it is,
    // from either side of the order.
    let subscribed = BoxControlReply::AsksSubscribed {
        subscribed: true,
        box_id,
    };
    assert_eq!(round_trip(&subscribed), subscribed);
    assert_eq!(
        serde_json_lenient::from_str::<BoxControlReply>(
            r#"{"subscribed":true,"box_id":"0195655f7f1e7abc9d1f2a3b4c5d6e7f"}"#
        )
        .expect("the subscription's answer decodes"),
        subscribed
    );
    let registered: BoxControlReply = serde_json_lenient::from_str(
        r#"{"switch_address":"100.64.127.255","loopback_address":"127.0.0.2","box_id":"0195655f7f1e7abc9d1f2a3b4c5d6e7f"}"#,
    )
    .expect("a registration reply still decodes");
    assert!(
        matches!(registered, BoxControlReply::Registered(_)),
        "a registration's answer is never a subscription's: {registered:?}"
    );

    // The offer: the host row's own fields — ask id, box id, name,
    // port, protocol — and a document of it decodes as nothing else,
    // the recorded-port reply its fields are a superset of included.
    let ask_id = AskId::from_bytes([
        0x9f, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0x0f, 0x1a, 0x2b, 0x3c, 0x4d,
        0x5e,
    ]);
    let offer = BoxControlReply::PendingAskOffer(PendingAskOffer {
        ask_id,
        box_id,
        name: "web".to_string(),
        port: 8080,
        proto: IpProto::Tcp,
    });
    let wire = serde_json_lenient::to_string(&offer).expect("serialize");
    for field in [
        r#""ask_id":"9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e""#,
        r#""box_id":"0195655f7f1e7abc9d1f2a3b4c5d6e7f""#,
        r#""name":"web""#,
        r#""port":8080"#,
        r#""proto":"tcp""#,
    ] {
        assert!(wire.contains(field), "the offer spells {field}: {wire}");
    }
    assert_eq!(round_trip(&offer), offer);
    assert_eq!(
        serde_json_lenient::from_str::<BoxControlReply>(&wire)
            .expect("an offered ask decodes as its own reply"),
        offer,
        "the offer is placed before the recorded-port reply its fields \
         are a superset of"
    );

    // The dismissal: the marker keeps it distinct, both directions.
    let dismissed = BoxControlReply::PendingAskDismissed {
        ask_id,
        dismissed: true,
    };
    assert_eq!(round_trip(&dismissed), dismissed);
    assert_eq!(
        serde_json_lenient::from_str::<BoxControlReply>(
            r#"{"ask_id":"9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e","dismissed":true}"#
        )
        .expect("a dismissal decodes"),
        dismissed
    );
}

/// The ask verbs' answer half (NET-045) round-trips: the client's
/// recorded answer carries the offer's ask id and one of the three
/// answers — a human's yes, a human's no, a render that found no
/// terminal — and the admit's reply carries the ask's end, as a
/// `ask`-tagged document the recorded-port reply cannot be mistaken
/// for in either direction.
#[test]
fn box_control_record_ask_answer_round_trip() {
    let ask_id = AskId::from_bytes([
        0x9f, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0x0f, 0x1a, 0x2b, 0x3c, 0x4d,
        0x5e,
    ]);

    for (answer, spelling) in [
        (AskAnswer::Yes, r#""answer":"yes""#),
        (AskAnswer::No, r#""answer":"no""#),
        (AskAnswer::NoTty, r#""answer":"no_tty""#),
    ] {
        let record = BoxControlRequest::RecordAskAnswer(RecordAskAnswerRequest { ask_id, answer });
        let wire = serde_json_lenient::to_string(&record).expect("serialize");
        assert!(
            wire.contains(r#""verb":"record_ask_answer""#)
                && wire.contains(r#""ask_id":"9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e""#)
                && wire.contains(spelling),
            "the recorded answer names its verb, its ask and its answer: {wire}"
        );
        assert_eq!(round_trip(&record), record);
    }

    // The record's answer: the first answer is acknowledged, the
    // marker keeps the shape distinct, and an id the daemon never
    // minted or already consumed is the error it is instead.
    let recorded = BoxControlReply::AskAnswerRecorded {
        ask_id,
        recorded: true,
    };
    assert_eq!(round_trip(&recorded), recorded);
    assert_eq!(
        serde_json_lenient::from_str::<BoxControlReply>(
            r#"{"ask_id":"9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e","recorded":true}"#
        )
        .expect("a recorded answer's reply decodes"),
        recorded
    );

    // The admit's answer: admitted names the port the host now holds
    // and the ask it was admitted under; refused names the typed end
    // the ask met. Both are `ask`-tagged documents, and the older
    // recorded-port reply — a strict subset of admitted's fields —
    // decodes as the port record it is, not as an ask.
    let admitted = BoxControlReply::AskAdmit(AskAdmitOutcome::Admitted {
        ask_id,
        port: 8080,
        proto: IpProto::Tcp,
    });
    let wire = serde_json_lenient::to_string(&admitted).expect("serialize");
    assert!(
        wire.contains(r#""ask":"admitted""#)
            && wire.contains(r#""ask_id":"9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e""#)
            && wire.contains(r#""port":8080"#),
        "the admitted answer spells its tag, its ask and its port: {wire}"
    );
    assert_eq!(round_trip(&admitted), admitted);
    assert_eq!(
        serde_json_lenient::from_str::<BoxControlReply>(&wire)
            .expect("the admitted answer decodes as its own reply"),
        admitted,
        "the admitted answer is placed before the recorded-port reply its \
         fields are a superset of"
    );

    for (reason, spelling) in [
        (AskRefused::Denied, r#""reason":"denied""#),
        (AskRefused::NoClient, r#""reason":"no_client""#),
        (AskRefused::QueueFull, r#""reason":"queue_full""#),
        (AskRefused::OutsideGrant, r#""reason":"outside_grant""#),
        (AskRefused::NoTty, r#""reason":"no_tty""#),
        (AskRefused::Cancelled, r#""reason":"cancelled""#),
        (AskRefused::NoRow, r#""reason":"no_row""#),
        (AskRefused::StanceNotAsk, r#""reason":"stance_not_ask""#),
    ] {
        let cause = (reason == AskRefused::Cancelled).then_some(AskCancelCause::LastDetach);
        let refused = BoxControlReply::AskAdmit(AskAdmitOutcome::Refused {
            ask_id,
            reason,
            cause,
        });
        let wire = serde_json_lenient::to_string(&refused).expect("serialize");
        assert!(
            wire.contains(r#""ask":"refused""#) && wire.contains(spelling),
            "the refused answer spells its tag and its typed end: {wire}"
        );
        assert_eq!(
            wire.contains(r#""cause":"last-detach""#),
            cause.is_some(),
            "only a cancellation carries its cause: {wire}"
        );
        assert_eq!(round_trip(&refused), refused);
    }

    // A late answer for an ended ask is answered with how it ended, a
    // shape no other reply decodes as.
    for (end, spelling) in [
        (AskLateEnd::Allowed, r#""end":"allowed""#),
        (AskLateEnd::Denied, r#""end":"denied""#),
        (
            AskLateEnd::Cancelled {
                cause: AskCancelCause::MinvmdStopping,
            },
            r#""cause":"minvmd-stopping""#,
        ),
    ] {
        let late = BoxControlReply::AskAlreadyEnded {
            ask_id,
            port: 8080,
            proto: IpProto::Tcp,
            already_ended: end,
        };
        let wire = serde_json_lenient::to_string(&late).expect("serialize");
        assert!(
            wire.contains(spelling),
            "the late end spells {spelling}: {wire}"
        );
        assert_eq!(
            serde_json_lenient::from_str::<BoxControlReply>(&wire).expect("decodes"),
            late
        );
    }

    // The older recorded-port reply still decodes as the port record
    // it is — no ask-shaped variant claims a document with no ask in
    // it.
    let decoded: BoxControlReply = serde_json_lenient::from_str(r#"{"port":8080,"proto":"tcp"}"#)
        .expect("a recorded report's reply still decodes");
    assert_eq!(
        decoded,
        BoxControlReply::PortRecorded {
            port: 8080,
            proto: IpProto::Tcp
        }
    );
}

/// The read-only row verb round-trips under its key, and its two
/// answers stay two answers: a live row's reply cannot decode as the
/// no-row marker or as any older reply shape, so a host-side read can
/// say "destroyed" without an error standing in for the fact.
#[test]
fn box_control_read_row_round_trip() {
    let read = BoxControlRequest::ReadRow(ReadRowRequest {
        name: "web".to_string(),
    });
    let wire = serde_json_lenient::to_string(&read).expect("serialize");
    assert!(
        wire.contains(r#""verb":"read_row""#) && wire.contains(r#""name":"web""#),
        "the tagged line names its verb and its key: {wire}"
    );
    assert_eq!(round_trip(&read), read);

    let row = BoxControlReply::Row(BoxRow {
        name: "web".to_string(),
        box_id: BoxId::from_bytes([
            0x01, 0x95, 0x65, 0x5f, 0x7f, 0x1e, 0x7a, 0xbc, 0x9d, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d,
            0x6e, 0x7f,
        ]),
        switch_address: std::net::Ipv4Addr::new(100, 64, 127, 255),
        egress_allow_list: vec!["10.0.0.0/8".to_string()],
        declared_ports: vec![8080, 9090],
        runtime_ports: vec![3000],
    });
    let wire = serde_json_lenient::to_string(&row).expect("serialize");
    for field in [
        r#""switch_address":"100.64.127.255""#,
        r#""box_id":"0195655f7f1e7abc9d1f2a3b4c5d6e7f""#,
        r#""egress_allow_list":["10.0.0.0/8"]"#,
        r#""declared_ports":[8080,9090]"#,
        r#""runtime_ports":[3000]"#,
    ] {
        assert!(
            wire.contains(field),
            "the row answer spells {field}: {wire}"
        );
    }
    assert_eq!(round_trip(&row), row);
    assert_eq!(
        serde_json_lenient::from_str::<BoxControlReply>(&wire).expect("decodes as its own reply"),
        row
    );

    // No live box: the marker answer, discriminated from the row by the
    // `no_row` field and from every older shape by the same.
    let no_row = BoxControlReply::NoRow {
        name: "web".to_string(),
        no_row: true,
    };
    assert_eq!(round_trip(&no_row), no_row);
    assert_eq!(
        serde_json_lenient::from_str::<BoxControlReply>(r#"{"name":"web","no_row":true}"#)
            .expect("the no-row answer decodes"),
        no_row
    );
    assert_ne!(
        serde_json_lenient::from_str::<BoxControlReply>(r#"{"name":"web","no_row":true}"#)
            .expect("the no-row answer decodes"),
        row,
        "a no-row answer is never a live row's answer"
    );

    // The older replies still decode after the new variants joined the
    // untagged order: a registration's answer keeps its id, and an
    // error stays an error.
    let registered: BoxControlReply = serde_json_lenient::from_str(
        r#"{"switch_address":"100.64.127.255","loopback_address":"127.0.0.2","box_id":"0195655f7f1e7abc9d1f2a3b4c5d6e7f"}"#,
    )
    .expect("a registration reply still decodes");
    assert!(matches!(registered, BoxControlReply::Registered(_)));
    let error: BoxControlReply =
        serde_json_lenient::from_str(r#"{"error":"the row's creator did not present its pair"}"#)
            .expect("an error reply still decodes");
    assert!(matches!(error, BoxControlReply::Error { .. }));
}

/// The answerer-status reply's shape (T93): the answerer's state
/// rides flat — `state` at the document's top level, exactly where
/// every reader of the status verb looks for it — with the hostname
/// proxy's publish outcome a sibling key beside it, never in place of
/// it. The sibling is optional in both directions: a client that
/// predates it ignores it, and a client that knows it reads `None`
/// from a daemon that predates it.
#[test]
fn box_control_answerer_status_reply_round_trip() {
    // Without a proxy-down cause the wire is the status's own document,
    // byte for byte the shape it always was.
    let plain = BoxControlReply::Status(AnswererStatusReply {
        answerer: ZoneAnswererStatus::Holder { port: 7_656 },
        proxy_down: None,
    });
    let wire = serde_json_lenient::to_string(&plain).expect("serialize");
    assert_eq!(
        wire, r#"{"state":"holder","port":7656}"#,
        "no cause to name means no sibling key: the wire is the old shape"
    );
    assert_eq!(round_trip(&plain), plain);

    // With the proxy down the reply carries both facts: the answerer's
    // state in its own place, the cause named beside it — not in place
    // of it.
    let with_cause = BoxControlReply::Status(AnswererStatusReply {
        answerer: ZoneAnswererStatus::Holder { port: 7_656 },
        proxy_down: Some(ProxyDown {
            port: 19_911,
            cause: ProxyDownCause::PortHeld,
        }),
    });
    let wire = serde_json_lenient::to_string(&with_cause).expect("serialize");
    for field in [
        r#""state":"holder""#,
        r#""port":7656"#,
        r#""proxy_down":{"port":19911,"cause":"port_held"}"#,
    ] {
        assert!(wire.contains(field), "the reply spells {field}: {wire}");
    }
    assert_eq!(round_trip(&with_cause), with_cause);
    // An older client decodes the status payload as the bare
    // `ZoneAnswererStatus` its `Status` variant held: the sibling key is
    // an unknown field it ignores, never a decode failure.
    let older_client: ZoneAnswererStatus =
        serde_json_lenient::from_str(&wire).expect("an older client still decodes the reply");
    assert_eq!(older_client, ZoneAnswererStatus::Holder { port: 7_656 });

    // The unconfirmed publish rides the sibling the same way, beside
    // whatever state the answerer itself is in.
    let unconfirmed = BoxControlReply::Status(AnswererStatusReply {
        answerer: ZoneAnswererStatus::Starting,
        proxy_down: Some(ProxyDown {
            port: 19_916,
            cause: ProxyDownCause::PublishUnconfirmed,
        }),
    });
    let wire = serde_json_lenient::to_string(&unconfirmed).expect("serialize");
    assert!(
        wire.contains(r#""state":"starting""#) && wire.contains(r#""cause":"publish_unconfirmed""#),
        "the unconfirmed publish is a sibling of the answerer's state: {wire}"
    );
    assert_eq!(round_trip(&unconfirmed), unconfirmed);

    // A daemon that predates the sibling — its reply names only the
    // state — decodes with the cause `None` an absent fact is.
    let older: BoxControlReply =
        serde_json_lenient::from_str(r#"{"state":"manager_held","port":7656}"#)
            .expect("an older daemon's status still decodes");
    assert_eq!(
        older,
        BoxControlReply::Status(AnswererStatusReply {
            answerer: ZoneAnswererStatus::ManagerHeld { port: 7_656 },
            proxy_down: None,
        }),
        "a reply that says nothing about the proxy reads as no proxy fact"
    );

    // The old substituting shape still parses: a daemon that answers
    // the proxy failure in the state's own place is read as exactly
    // that, claiming no answerer facts the reply does not carry.
    let substituting: BoxControlReply = serde_json_lenient::from_str(
        r#"{"state":"proxy_not_serving","port":19911,"cause":"redraws_ran_out"}"#,
    )
    .expect("the substituting shape still decodes");
    assert_eq!(
        substituting,
        BoxControlReply::Status(AnswererStatusReply {
            answerer: ZoneAnswererStatus::ProxyNotServing {
                port: 19_911,
                cause: ProxyDownCause::RedrawsRanOut,
            },
            proxy_down: None,
        }),
        "the state the older daemon answered is the state the read returns"
    );

    // A newer daemon's cause this client does not know still yields
    // the answerer's state: the unparseable sibling reads as no proxy
    // fact instead of failing the whole Status decode.
    let future: BoxControlReply = serde_json_lenient::from_str(
        r#"{"state":"holder","port":7656,"proxy_down":{"port":1,"cause":"future"}}"#,
    )
    .expect("an unknown proxy-down cause still decodes the status");
    assert_eq!(
        future,
        BoxControlReply::Status(AnswererStatusReply {
            answerer: ZoneAnswererStatus::Holder { port: 7_656 },
            proxy_down: None,
        }),
        "an unknown cause drops the sibling, never the answerer's state"
    );
}

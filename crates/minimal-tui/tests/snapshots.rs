//! Snapshot tests for the `view` half: render a fixed model into a
//! `TestBackend` buffer and compare against the checked-in snapshots.

use chrono::DateTime;
use minimal_tui::app::{self, Detail, Model, Msg, SessionKey};
use minimal_tui::render;
use minimal_tui::rpc::ProviderData;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use sessions::{NetworkMode, SessionId};

fn id(n: u128) -> SessionId {
    SessionId::parse_str(&format!("00000000-0000-0000-0000-{n:012x}")).unwrap()
}

fn entry(n: u128, name: Option<&str>, project: &str) -> minimald_rpc::ListSessionsEntry {
    minimald_rpc::ListSessionsEntry {
        id: id(n),
        name: name.map(str::to_owned),
        project_path: Some(paths::HostAbsPath::try_new(project).unwrap()),
        status: sessions::SessionStatus::Active,
        attrs: None,
    }
}

fn provider(label: &str, sessions: Vec<minimald_rpc::ListSessionsEntry>) -> ProviderData {
    ProviderData {
        label: label.to_string(),
        version: "0.1".to_string(),
        sessions,
    }
}

fn fixed_model(providers: Vec<ProviderData>) -> Model {
    let now = DateTime::parse_from_rfc3339("2026-07-29T12:00:00Z")
        .unwrap()
        .to_utc();
    let mut model = Model::new(now);
    app::update(
        &mut model,
        Msg::Refreshed {
            ok: providers,
            failed: Vec::new(),
        },
    );
    model
}

fn record(name: Option<&str>, network: NetworkMode) -> sessions::Record {
    sessions::Record {
        id: id(1),
        name: name.map(str::to_owned),
        username: Some("chroma".to_string()),
        project_path: paths::HostAbsPath::try_new("/src/api").unwrap(),
        network,
        policy: sessions::SessionPolicy::default(),
        status: sessions::SessionStatus::Active,
        hooks_enabled: true,
        attrs: Default::default(),
    }
}

fn render(model: &mut Model) -> String {
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render::view(model, frame)).unwrap();
    format!("{}", terminal.backend())
}

#[test]
fn empty_list() {
    insta::assert_snapshot!(render(&mut fixed_model(vec![])));
}

#[test]
fn single_provider() {
    let mut model = fixed_model(vec![provider(
        "host",
        vec![
            entry(1, Some("api-staging"), "/src/api"),
            entry(2, None, "/src/web"),
        ],
    )]);
    insta::assert_snapshot!(render(&mut model));
}

#[test]
fn two_providers() {
    let mut model = fixed_model(vec![
        provider("host", vec![entry(1, Some("api-staging"), "/src/api")]),
        provider("vm", vec![entry(3, Some("bench"), "/src/bench")]),
    ]);
    insta::assert_snapshot!(render(&mut model));
}

#[test]
fn filtered() {
    let mut model = fixed_model(vec![
        provider("host", vec![entry(1, Some("api-staging"), "/src/api")]),
        provider("vm", vec![entry(3, Some("bench"), "/src/bench")]),
    ]);
    model.filter.input = "bench".to_string();
    model.clamp_cursor();
    insta::assert_snapshot!(render(&mut model));
}

#[test]
fn preview_section_with_screen_snapshot() {
    let mut model = fixed_model(vec![provider(
        "host",
        vec![entry(1, Some("api-staging"), "/src/api")],
    )]);
    let key = SessionKey {
        provider: "host".to_string(),
        id: id(1),
    };
    // A synthetic live screen: a build log over a shell prompt, with one
    // styled line to exercise span grouping.
    let row = |text: &str| minimald_rpc::ScreenRow {
        cells: text
            .chars()
            .map(|ch| minimald_rpc::ScreenCell {
                ch,
                fg: None,
                bg: None,
                bold: false,
                italic: false,
                underline: false,
                reverse: false,
            })
            .collect(),
    };
    let mut bold_line = row("    Finished `dev` profile in 3m 04s");
    for cell in &mut bold_line.cells {
        cell.bold = true;
        cell.fg = Some("idx:2".to_string());
    }
    model.screens.insert(
        key,
        Ok(Some(minimald_rpc::ScreenSnapshot {
            rows: 4,
            cols: 44,
            cursor_row: Some(3),
            cursor_col: Some(2),
            lines: vec![
                row("$ cargo run"),
                row("    Compiling minimal v0.1 (1457 deps)…"),
                bold_line,
                row("$ "),
            ],
        })),
    );
    model.cursor = 1;
    insta::assert_snapshot!(render(&mut model));
}

#[test]
fn detail_pane_with_policy() {
    let mut model = fixed_model(vec![provider(
        "host",
        vec![entry(1, Some("api-staging"), "/src/api")],
    )]);
    let key = SessionKey {
        provider: "host".to_string(),
        id: id(1),
    };
    model.details.insert(
        key,
        Detail {
            record: Some(record(Some("api-staging"), NetworkMode::OwnIp)),
            policy: Some(sessions::SessionPolicy::new(
                Some(sessions::EgressPolicy {
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    allow_protocols: None,
                }),
                Some(sessions::IngressPolicy {
                    port_mappings: vec![sessions::PortMapping {
                        external_port: 8080,
                        internal_port: 80,
                        proto: sessions::IpProto::Tcp,
                    }],
                    dynamic_allowed_range: None,
                }),
            )),
        },
    );
    // Focus the session.
    model.cursor = 1;
    insta::assert_snapshot!(render(&mut model));
}

/// A session with fresh stdout renders its activity spinner in the sidebar
/// (TestBackend text, not a stored snapshot — the glyph is what matters).
#[test]
fn sidebar_shows_activity_indicator_for_recent_stdout() {
    let now = DateTime::parse_from_rfc3339("2026-07-29T12:00:00Z")
        .unwrap()
        .to_utc();
    let mut hot = entry(1, Some("busy"), "/src/busy");
    hot.attrs = Some(minimald_rpc::RunningSessionAttrs {
        last_stdout: Some(now - chrono::Duration::seconds(2)),
        last_stdin: None,
        title: None,
        audible_bell: None,
        visual_bell: None,
    });
    let mut model = fixed_model(vec![provider("host", vec![hot])]);
    model.now = now;
    assert!(render(&mut model).contains('◐'));
}

/// An unacknowledged bell renders `●`; focusing the session acknowledges
/// it (covered at the model level), so the glyph disappears on the next
/// render.
#[test]
fn sidebar_shows_bell_indicator() {
    let now = DateTime::parse_from_rfc3339("2026-07-29T12:00:00Z")
        .unwrap()
        .to_utc();
    let mut ringing = entry(1, Some("loud"), "/src/loud");
    ringing.attrs = Some(minimald_rpc::RunningSessionAttrs {
        last_stdout: None,
        last_stdin: None,
        title: None,
        audible_bell: Some(minimald_rpc::Bell {
            count: 1,
            last: now,
        }),
        visual_bell: None,
    });
    let mut model = fixed_model(vec![provider("host", vec![ringing])]);
    model.now = now;
    assert!(render(&mut model).contains('●'));
    // Provider headers also render ● (health); the bell assert above counts
    // on both. After focusing the session, its bell is acknowledged and only
    // the header dot remains — check the session row specifically.
    model.cursor = 1;
    minimal_tui::app::update(
        &mut model,
        Msg::Key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Enter,
            crossterm::event::KeyModifiers::NONE,
        )),
    );
    let rendered = render(&mut model);
    let row = rendered
        .lines()
        .find(|l| l.contains("loud"))
        .expect("session row");
    assert!(!row.contains('●'), "bell must clear on focus: {row}");
}

/// The sidebar scrolls so the cursor's row is always drawn: with more
/// sessions than the pane has rows, moving the cursor to the last session
/// must bring it (and its selection marker) into view.
#[test]
fn sidebar_scrolls_to_keep_the_cursor_visible() {
    // 40 sessions overflow the ~25-row list pane.
    let sessions = (0..40)
        .map(|n| entry(n, Some(&format!("s{n:02}")), "/src/x"))
        .collect();
    let mut model = fixed_model(vec![provider("host", sessions)]);
    model.cursor = model.visible_rows().len() - 1;
    let rendered = render(&mut model);
    assert!(
        rendered.contains("▸ s39"),
        "the cursor's row must be drawn:\n{rendered}"
    );
    // And the top of the list has scrolled away.
    assert!(
        !rendered.lines().any(|l| l.contains("s00")),
        "s00 should be scrolled off:\n{rendered}"
    );
}

/// A provider whose refresh failed keeps its group header, marked
/// unreachable (red health dot), instead of vanishing from the sidebar.
#[test]
fn sidebar_marks_a_failed_provider_unreachable() {
    let mut model = fixed_model(vec![
        provider("host", vec![entry(1, Some("api"), "/src/api")]),
        provider("vm", vec![entry(3, Some("bench"), "/src/bench")]),
    ]);
    app::update(
        &mut model,
        Msg::Refreshed {
            ok: vec![provider("host", vec![entry(1, Some("api"), "/src/api")])],
            failed: vec!["vm".to_string()],
        },
    );
    let rendered = render(&mut model);
    let header = rendered
        .lines()
        .find(|l| l.contains("vm"))
        .expect("vm group header must survive");
    assert!(
        header.contains("unreachable"),
        "expected the unreachable mark: {header}"
    );
}

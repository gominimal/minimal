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
    app::update(&mut model, Msg::Refreshed(providers));
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
        attrs: Default::default(),
    }
}

fn render(model: &Model) -> String {
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render::view(model, frame)).unwrap();
    format!("{}", terminal.backend())
}

#[test]
fn empty_list() {
    insta::assert_snapshot!(render(&fixed_model(vec![])));
}

#[test]
fn single_provider() {
    let model = fixed_model(vec![provider(
        "host",
        vec![
            entry(1, Some("api-staging"), "/src/api"),
            entry(2, None, "/src/web"),
        ],
    )]);
    insta::assert_snapshot!(render(&model));
}

#[test]
fn two_providers() {
    let model = fixed_model(vec![
        provider("host", vec![entry(1, Some("api-staging"), "/src/api")]),
        provider("vm", vec![entry(3, Some("bench"), "/src/bench")]),
    ]);
    insta::assert_snapshot!(render(&model));
}

#[test]
fn filtered() {
    let mut model = fixed_model(vec![
        provider("host", vec![entry(1, Some("api-staging"), "/src/api")]),
        provider("vm", vec![entry(3, Some("bench"), "/src/bench")]),
    ]);
    model.filter.input = "bench".to_string();
    model.clamp_cursor();
    insta::assert_snapshot!(render(&model));
}

#[test]
fn preview_tab_with_screen_snapshot() {
    let mut model = fixed_model(vec![provider(
        "host",
        vec![entry(1, Some("api-staging"), "/src/api")],
    )]);
    let key = SessionKey {
        provider: 0,
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
    model.tab = app::DetailTab::Preview;
    insta::assert_snapshot!(render(&model));
}

#[test]
fn detail_pane_with_policy() {
    let mut model = fixed_model(vec![provider(
        "host",
        vec![entry(1, Some("api-staging"), "/src/api")],
    )]);
    let key = SessionKey {
        provider: 0,
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
    // Focus the session and switch to the Policy tab.
    model.cursor = 1;
    model.tab = app::DetailTab::Policy;
    insta::assert_snapshot!(render(&model));
}

//! The Elm-style core of `min dash`: a [`Model`] of everything on screen,
//! a [`Msg`] enum of everything that can happen, and a pure [`update`]
//! producing follow-up [`Effect`]s that the tokio driver executes against
//! the daemon connections.
//!
//! Deliberately hand-rolled rather than built on a TEA framework: the
//! reusable machinery is ~200 lines of boring Rust, and our pure
//! `update -> Vec<Effect>` doesn't fit component-centric frameworks. If
//! `min dash` grows beyond a single screen (multiple views, reusable
//! widgets), reevaluate adopting `tui-realm` instead of extending this.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

use anyhow::Context as _;
use chrono::{DateTime, Utc};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use sessions::{NetworkMode, SessionId};

use crate::filter;
use crate::rpc::{self, ProviderData};
use crate::state::{self, DashState};

/// How often the session list refreshes.
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// How often the driver attempts to (re)connect missing providers, so a
/// daemon restarted after startup rejoins the dashboard.
const REDISCOVERY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Identifies a session in the model: its provider's label plus its
/// daemon-assigned id. The label — not a list index — is the identity, so
/// a provider dropping out of one refresh can't re-index every key onto
/// the wrong daemon.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub provider: String,
    pub id: SessionId,
}

/// A provider group in the sidebar.
#[derive(Debug, Clone)]
pub struct ProviderView {
    pub label: String,
    pub version: String,
    pub collapsed: bool,
    /// False when the last refresh couldn't reach the daemon: the group
    /// stays in the sidebar (with its sessions cleared — stale sessions
    /// aren't actionable) so it can rejoin when the daemon comes back.
    pub reachable: bool,
    pub sessions: Vec<minimald_rpc::ListSessionsEntry>,
}

/// The record + policy behind the detail pane, cached per session.
#[derive(Debug, Clone, Default)]
pub struct Detail {
    pub record: Option<sessions::Record>,
    pub policy: Option<sessions::SessionPolicy>,
}

/// A modal prompt capturing footer input, if one is open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `d` on a session: "Destroy <name>? y/n".
    ConfirmDestroy(SessionKey, String),
    /// `r` on a session: inline rename input.
    Rename { key: SessionKey, input: String },
    /// `n`: the create form.
    Create(CreateForm),
}

/// The create form's fields. `field` is which one has input focus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateForm {
    pub name: String,
    pub path: String,
    /// Index into [`NETWORK_MODES`].
    pub net_idx: usize,
    pub field: CreateField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateField {
    Name,
    Path,
    Network,
}

impl CreateForm {
    /// The focused text field's buffer, if it is one (`Network` cycles
    /// modes instead of taking text).
    fn input_mut(&mut self) -> Option<&mut String> {
        match self.field {
            CreateField::Name => Some(&mut self.name),
            CreateField::Path => Some(&mut self.path),
            CreateField::Network => None,
        }
    }
}

/// The network modes the create form cycles through, in cycle order.
pub const NETWORK_MODES: &[NetworkMode] =
    &[NetworkMode::HostNet, NetworkMode::OwnIp, NetworkMode::NoNet];

/// The Preview section's state for a session: the screen snapshot, a soft
/// "not active", or the fetch error (e.g. a daemon too old to serve
/// `GetSessionScreen`) — rendered legibly rather than loading forever.
pub type ScreenFetch = Result<Option<minimald_rpc::ScreenSnapshot>, String>;

/// Everything that can happen to the model.
#[derive(Debug)]
pub enum Msg {
    Key(KeyEvent),
    Tick,
    /// A refresh pass: every reachable provider's data, plus the labels of
    /// providers whose connection failed mid-run.
    Refreshed {
        ok: Vec<ProviderData>,
        failed: Vec<String>,
    },
    /// Detail-pane data for a session.
    DetailLoaded(SessionKey, Box<Detail>),
    /// A screen fetch for the Preview section.
    ScreenLoaded(SessionKey, ScreenFetch),
    /// A destroy/rename completed.
    ActionDone(Result<String, String>),
    /// A create completed; the new session gets focused after the refresh.
    Created {
        provider: String,
        id: SessionId,
    },
}

/// Side effects [`update`] asks the driver to run.
#[derive(Debug)]
pub enum Effect {
    /// Re-list every provider.
    Refresh,
    FetchDetail(SessionKey),
    FetchScreen(SessionKey),
    Destroy(SessionKey),
    Rename(SessionKey, String),
    Create {
        provider: String,
        name: Option<String>,
        path: String,
        network: NetworkMode,
    },
    /// Suspend the TUI, attach to the session over ssh, and resume when the
    /// user detaches.
    Attach(SessionKey),
    /// Persist the last-focused session to `dash-state.json`.
    SaveState,
}

/// One line in the flattened sidebar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Row {
    ProviderHeader(usize),
    Session(SessionKey),
}

/// The full TUI state. Pure data; rendering reads it, [`update`] mutates
/// it, and neither talks to a daemon directly.
#[derive(Debug)]
pub struct Model {
    pub providers: Vec<ProviderView>,
    /// Index into [`Model::visible_rows`].
    pub cursor: usize,
    /// Sidebar scroll offset (a row index), adjusted at render time to
    /// keep the cursor inside the viewport.
    pub scroll: usize,
    pub filter: FilterState,
    pub details: HashMap<SessionKey, Detail>,
    pub screens: HashMap<SessionKey, ScreenFetch>,
    /// The most recent bell timestamp acknowledged for a session; a bell
    /// newer than this lights the `●` indicator.
    pub bells_seen: HashMap<SessionKey, DateTime<Utc>>,
    pub action: Option<Action>,
    /// A transient status line (action outcomes, refresh errors).
    pub status: Option<String>,
    pub spinner_frame: usize,
    /// Wall clock of the last refresh; idle times and activity windows are
    /// computed against it so rendering is deterministic in tests.
    pub now: DateTime<Utc>,
    /// Focus to apply after the next refresh (startup restore, or a
    /// freshly created session).
    pub pending_focus: Option<(String, SessionId)>,
    pub quit: bool,
}

impl Default for Model {
    fn default() -> Self {
        Self::new(Utc::now())
    }
}

/// The `/` filter line's state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FilterState {
    pub editing: bool,
    pub input: String,
}

impl Model {
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            providers: Vec::new(),
            cursor: 0,
            scroll: 0,
            filter: FilterState::default(),
            details: HashMap::new(),
            screens: HashMap::new(),
            bells_seen: HashMap::new(),
            action: None,
            status: None,
            spinner_frame: 0,
            now,
            pending_focus: None,
            quit: false,
        }
    }

    /// The flattened sidebar rows after collapsing and filtering, in render
    /// order. Provider grouping is preserved under a filter; a provider with
    /// no matching sessions keeps its header (so the group structure stays
    /// visible while narrowing).
    pub fn visible_rows(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        for (p, provider) in self.providers.iter().enumerate() {
            rows.push(Row::ProviderHeader(p));
            if provider.collapsed {
                continue;
            }
            let mut matched: Vec<_> = provider
                .sessions
                .iter()
                .filter_map(|entry| {
                    match filter::session_match(&self.filter.input, entry) {
                        Some(rank) => Some((Some(rank), entry.id)),
                        // An empty filter means "no filter": keep everything
                        // in daemon order rather than ranking.
                        None if self.filter.input.is_empty() => Some((None, entry.id)),
                        None => None,
                    }
                })
                .collect();
            // Best match first within the group when filtering; list order
            // (daemon order) when not.
            if !self.filter.input.is_empty() {
                matched.sort_by_key(|m| std::cmp::Reverse(m.0));
            }
            rows.extend(matched.into_iter().map(|(_, id)| {
                Row::Session(SessionKey {
                    provider: provider.label.clone(),
                    id,
                })
            }));
        }
        rows
    }

    /// The row under the cursor.
    pub fn cursor_row(&self) -> Option<Row> {
        self.visible_rows().get(self.cursor).cloned()
    }

    /// The session under the cursor, if the cursor is on a session row.
    pub fn focused(&self) -> Option<SessionKey> {
        match self.cursor_row() {
            Some(Row::Session(key)) => Some(key),
            _ => None,
        }
    }

    /// Look up a session's list entry by key.
    pub fn entry(&self, key: &SessionKey) -> Option<&minimald_rpc::ListSessionsEntry> {
        self.providers
            .iter()
            .find(|p| p.label == key.provider)?
            .sessions
            .iter()
            .find(|e| e.id == key.id)
    }

    /// A session's display name: its assigned name, or the generated short
    /// form `<project>-<id-suffix>` for anonymous sessions.
    pub fn display_name(&self, key: &SessionKey) -> String {
        match self.entry(key) {
            Some(entry) => display_name_of(entry),
            None => key.id.to_string(),
        }
    }

    /// Clamp the cursor into the visible row range. When the filter narrows
    /// the list under the cursor, land on the first visible session row (a
    /// provider header is a poor focus — it shows no detail pane).
    pub fn clamp_cursor(&mut self) {
        let rows = self.visible_rows();
        if rows.is_empty() || self.cursor >= rows.len() {
            self.cursor = rows
                .iter()
                .position(|r| matches!(r, Row::Session(_)))
                .unwrap_or(0);
        }
    }

    /// The latest bell timestamp in a session's live attrs.
    fn latest_bell(&self, key: &SessionKey) -> Option<DateTime<Utc>> {
        let attrs = &self.entry(key)?.attrs;
        [
            attrs.as_ref()?.audible_bell.as_ref().map(|b| b.last),
            attrs.as_ref()?.visual_bell.as_ref().map(|b| b.last),
        ]
        .into_iter()
        .flatten()
        .max()
    }

    /// Whether an unacknowledged bell lights the session's `●` indicator.
    pub fn has_unseen_bell(&self, key: &SessionKey) -> bool {
        match self.latest_bell(key) {
            Some(latest) => self.bells_seen.get(key).is_none_or(|seen| latest > *seen),
            None => false,
        }
    }

    /// The activity indicator glyph for a session row, computed from the
    /// live attrs: `◌` while the session is still coming up (a create's
    /// upload/compose is in flight, or a verdict is pending), a cycling
    /// spinner when stdout flowed in the last 5s, `○` when the user typed
    /// recently but nothing came back, `●` for an unacknowledged bell,
    /// blank when idle.
    pub fn indicator(&self, key: &SessionKey) -> String {
        const SPINNER: &[&str] = &["◐", "◓", "◑", "◒"];
        const RECENT: chrono::Duration = chrono::Duration::seconds(5);
        if let Some(entry) = self.entry(key)
            && !matches!(entry.status, sessions::SessionStatus::Active)
        {
            return "◌".to_string();
        }
        if self.has_unseen_bell(key) {
            return "●".to_string();
        }
        let attrs = self.entry(key).and_then(|e| e.attrs.as_ref());
        let recent = |t: Option<DateTime<Utc>>| {
            t.is_some_and(|t| self.now.signed_duration_since(t) <= RECENT)
        };
        let stdout_hot = recent(attrs.and_then(|a| a.last_stdout));
        let stdin_hot = recent(attrs.and_then(|a| a.last_stdin));
        if stdout_hot {
            SPINNER[self.spinner_frame % SPINNER.len()].to_string()
        } else if stdin_hot {
            "○".to_string()
        } else {
            String::new()
        }
    }

    /// The provider label + session id of the current focus, for the state
    /// file.
    fn focus_for_state(&self) -> Option<(String, SessionId)> {
        let key = self.focused()?;
        Some((key.provider, key.id))
    }
}

/// The display name for a list entry: the assigned name, or `(unnamed)`
/// for anonymous sessions (the full id is always visible in the Info tab).
pub fn display_name_of(entry: &minimald_rpc::ListSessionsEntry) -> String {
    match &entry.name {
        Some(name) => name.clone(),
        None => "(unnamed)".to_string(),
    }
}

/// Render a network mode the way the sidebar shows it.
pub fn network_mode_label(mode: NetworkMode) -> &'static str {
    match mode {
        NetworkMode::HostNet => "Host",
        NetworkMode::OwnIp => "OwnIp",
        NetworkMode::NoNet => "NoNet",
        // NetworkMode is #[non_exhaustive]; render future variants by debug.
        _ => "Custom",
    }
}

/// The canonical sidebar order for provider groups; unknown labels sort
/// last, alphabetically.
fn provider_rank(label: &str) -> u8 {
    match label {
        "host" => 0,
        "vm" => 1,
        _ => 2,
    }
}

/// The pure state transition. Returns the effects the driver should run.
pub fn update(model: &mut Model, msg: Msg) -> Vec<Effect> {
    match msg {
        Msg::Tick => {
            model.spinner_frame += 1;
            model.now = Utc::now();
            // The detail pane stacks Info, Policy, and Preview vertically,
            // so the focused session's screen refreshes on every tick.
            let mut effects = vec![Effect::Refresh];
            if let Some(key) = model.focused() {
                effects.push(Effect::FetchScreen(key));
            }
            effects
        }
        Msg::Refreshed { ok, failed } => {
            model.now = Utc::now();
            // Upsert providers by label: one whose refresh failed keeps its
            // slot (marked unreachable, sessions cleared) instead of
            // dropping out and re-indexing every session key onto the wrong
            // daemon.
            let focused_before = model.focused().map(|key| (key.provider.clone(), key.id));
            let mut views: HashMap<String, ProviderView> = model
                .providers
                .drain(..)
                .map(|v| (v.label.clone(), v))
                .collect();
            for data in ok {
                let view = views
                    .entry(data.label.clone())
                    .or_insert_with(|| ProviderView {
                        label: data.label.clone(),
                        version: String::new(),
                        collapsed: false,
                        reachable: true,
                        sessions: Vec::new(),
                    });
                view.version = data.version;
                view.sessions = data.sessions;
                view.reachable = true;
            }
            for label in &failed {
                if let Some(view) = views.get_mut(label) {
                    view.reachable = false;
                    view.sessions.clear();
                }
            }
            model.providers = views.into_values().collect();
            model.providers.sort_by(|a, b| {
                provider_rank(&a.label)
                    .cmp(&provider_rank(&b.label))
                    .then_with(|| a.label.cmp(&b.label))
            });

            // The cursor tracks the focused session's identity across
            // refreshes, not its row index — a session appearing or
            // disappearing above the cursor must not silently move focus.
            // Restore the pending focus (startup's last-session memory, or a
            // freshly created session) if it still exists; otherwise keep
            // the previously focused session when it survives the refresh,
            // else fall back to the first session row — row 0 is a provider
            // header, where d/r are dead keys.
            let focus_target = model.pending_focus.take().or(focused_before);
            if let Some((label, id)) = focus_target {
                let target = model.visible_rows().iter().position(|row| {
                    matches!(row, Row::Session(key)
                            if key.id == id
                                && key.provider == label)
                });
                model.cursor = target.unwrap_or_else(|| {
                    model
                        .visible_rows()
                        .iter()
                        .position(|r| matches!(r, Row::Session(_)))
                        .unwrap_or(0)
                });
            }
            model.clamp_cursor();
            // Keep detail/screen caches only for sessions that still exist.
            let live: std::collections::HashSet<SessionKey> = model
                .providers
                .iter()
                .flat_map(|pv| {
                    pv.sessions.iter().map(|e| SessionKey {
                        provider: pv.label.clone(),
                        id: e.id,
                    })
                })
                .collect();
            model.details.retain(|k, _| live.contains(k));
            model.screens.retain(|k, _| live.contains(k));
            model.bells_seen.retain(|k, _| live.contains(k));
            // The cursor may have (re)landed on a session — restore from the
            // state file, a create, or plain list churn — without a key
            // press, so pull its detail data here too. Bells are NOT
            // acknowledged here: only an explicit focus change does that,
            // or the ● indicator would clear on every refresh tick.
            fetch_focused(model)
        }
        Msg::DetailLoaded(key, detail) => {
            model.details.insert(key, *detail);
            Vec::new()
        }
        Msg::ScreenLoaded(key, screen) => {
            model.screens.insert(key, screen);
            Vec::new()
        }
        Msg::ActionDone(result) => {
            match result {
                Ok(text) => model.status = Some(text),
                Err(e) => model.status = Some(format!("error: {e}")),
            }
            vec![Effect::Refresh]
        }
        Msg::Created { provider, id } => {
            model.status = Some("session created".to_string());
            model.pending_focus = Some((provider, id));
            vec![Effect::Refresh]
        }
        Msg::Key(key) => update_key(model, key),
    }
}

fn update_key(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    // A modal captures all keys until it resolves.
    if model.action.is_some() {
        return update_modal(model, key);
    }
    if model.filter.editing {
        return update_filter(model, key);
    }

    let rows = model.visible_rows();
    // Char bindings require no modifiers: a wildcard modifier match would
    // reroute chords like Ctrl-D into the destroy prompt.
    match (key.code, key.modifiers) {
        (KeyCode::Char('q'), KeyModifiers::NONE) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            model.quit = true;
            vec![Effect::SaveState]
        }
        (KeyCode::Char('/'), KeyModifiers::NONE) => {
            model.filter.editing = true;
            Vec::new()
        }
        (KeyCode::Up, _) | (KeyCode::Char('k'), KeyModifiers::NONE) => {
            model.cursor = model.cursor.saturating_sub(1);
            on_focus_change(model)
        }
        (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE) => {
            if model.cursor + 1 < rows.len() {
                model.cursor += 1;
            }
            on_focus_change(model)
        }
        (KeyCode::Enter, _) => match model.cursor_row() {
            Some(Row::ProviderHeader(p)) => {
                if let Some(provider) = model.providers.get_mut(p) {
                    provider.collapsed = !provider.collapsed;
                }
                model.clamp_cursor();
                Vec::new()
            }
            // Enter on a session attaches to it (suspend TUI → ssh →
            // resume on detach); its bells count as seen either way.
            Some(Row::Session(key)) => {
                acknowledge_bells(model, &key);
                vec![Effect::Attach(key), Effect::SaveState]
            }
            None => Vec::new(),
        },
        (KeyCode::Char('d'), KeyModifiers::NONE) => match model.focused() {
            Some(key) => {
                let name = model.display_name(&key);
                model.action = Some(Action::ConfirmDestroy(key, name));
                Vec::new()
            }
            None => Vec::new(),
        },
        (KeyCode::Char('r'), KeyModifiers::NONE) => match model.focused() {
            Some(key) => {
                let input = model
                    .entry(&key)
                    .and_then(|e| e.name.clone())
                    .unwrap_or_default();
                model.action = Some(Action::Rename { key, input });
                Vec::new()
            }
            None => Vec::new(),
        },
        (KeyCode::Char('n'), KeyModifiers::NONE) => {
            let path = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            model.action = Some(Action::Create(CreateForm {
                name: String::new(),
                path,
                net_idx: 0,
                field: CreateField::Name,
            }));
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// Keys while the `/` filter line is editing.
fn update_filter(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    match key.code {
        KeyCode::Esc => {
            model.filter = FilterState::default();
            model.clamp_cursor();
        }
        KeyCode::Enter => {
            model.filter.editing = false;
        }
        KeyCode::Backspace => {
            model.filter.input.pop();
            model.clamp_cursor();
        }
        KeyCode::Char(c) if matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) => {
            model.filter.input.push(c);
            model.clamp_cursor();
        }
        _ => {}
    }
    on_focus_change(model)
}

/// Keys while a modal action (destroy confirm / rename / create) is open.
fn update_modal(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    let Some(action) = model.action.clone() else {
        return Vec::new();
    };
    match action {
        Action::ConfirmDestroy(target, _) => match (key.code, key.modifiers) {
            (KeyCode::Char('y'), KeyModifiers::NONE) => {
                model.action = None;
                vec![Effect::Destroy(target)]
            }
            (KeyCode::Char('n'), KeyModifiers::NONE) | (KeyCode::Esc, _) => {
                model.action = None;
                Vec::new()
            }
            _ => Vec::new(),
        },
        Action::Rename {
            key: target,
            mut input,
        } => match key.code {
            KeyCode::Enter => {
                model.action = None;
                if input.trim().is_empty() {
                    model.status = Some("rename cancelled: empty name".to_string());
                    Vec::new()
                } else {
                    vec![Effect::Rename(target, input.trim().to_string())]
                }
            }
            KeyCode::Esc => {
                model.action = None;
                Vec::new()
            }
            _ => {
                line_edit(&mut input, &key);
                model.action = Some(Action::Rename { key: target, input });
                Vec::new()
            }
        },
        Action::Create(mut form) => {
            match (key.code, form.field) {
                (KeyCode::Esc, _) => {
                    model.action = None;
                }
                (KeyCode::BackTab, _) => {
                    form.field = prev_field(form.field);
                    model.action = Some(Action::Create(form));
                }
                (KeyCode::Tab, _) => {
                    form.field = next_field(form.field);
                    model.action = Some(Action::Create(form));
                }
                // Left/right cycle the network mode when that field is focused.
                (KeyCode::Left, CreateField::Network) => {
                    form.net_idx = (form.net_idx + NETWORK_MODES.len() - 1) % NETWORK_MODES.len();
                    model.action = Some(Action::Create(form));
                }
                (KeyCode::Right, CreateField::Network) => {
                    form.net_idx = (form.net_idx + 1) % NETWORK_MODES.len();
                    model.action = Some(Action::Create(form));
                }
                (KeyCode::Char(' '), CreateField::Network) => {
                    form.net_idx = (form.net_idx + 1) % NETWORK_MODES.len();
                    model.action = Some(Action::Create(form));
                }
                // Enter advances through the fields and submits on the last.
                (KeyCode::Enter, CreateField::Name) | (KeyCode::Enter, CreateField::Path) => {
                    form.field = next_field(form.field);
                    model.action = Some(Action::Create(form));
                }
                (KeyCode::Enter, CreateField::Network) => {
                    // Create on the provider the user is pointing at: the
                    // focused session's provider, or the provider whose
                    // group header the cursor sits on.
                    let label = match model.cursor_row() {
                        Some(Row::Session(key)) => Some(key.provider),
                        Some(Row::ProviderHeader(p)) => {
                            model.providers.get(p).map(|pv| pv.label.clone())
                        }
                        None => None,
                    };
                    let Some(provider) = label else {
                        model.status = Some("no provider to create on".to_string());
                        model.action = Some(Action::Create(form));
                        return Vec::new();
                    };
                    if !model
                        .providers
                        .iter()
                        .any(|pv| pv.label == provider && pv.reachable)
                    {
                        model.status = Some(format!("error: provider '{provider}' is unreachable"));
                        model.action = Some(Action::Create(form));
                        return Vec::new();
                    }
                    model.action = None;
                    return vec![Effect::Create {
                        provider,
                        name: match form.name.trim() {
                            "" => None,
                            n => Some(n.to_string()),
                        },
                        path: form.path.trim().to_string(),
                        network: NETWORK_MODES[form.net_idx],
                    }];
                }
                _ => {
                    if let Some(input) = form.input_mut() {
                        line_edit(input, &key);
                    }
                    model.action = Some(Action::Create(form));
                }
            }
            Vec::new()
        }
    }
}

/// Apply one line-editing key to an input buffer: backspace deletes,
/// ctrl-u clears, a printable char appends; anything else is a no-op.
fn line_edit(input: &mut String, key: &KeyEvent) {
    match key.code {
        KeyCode::Backspace => {
            input.pop();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => input.clear(),
        // Only plain (or shifted) chars are text: a Ctrl chord is a command,
        // not input.
        KeyCode::Char(c) if matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) => {
            input.push(c);
        }
        _ => {}
    }
}

fn next_field(field: CreateField) -> CreateField {
    match field {
        CreateField::Name => CreateField::Path,
        CreateField::Path => CreateField::Network,
        CreateField::Network => CreateField::Name,
    }
}

fn prev_field(field: CreateField) -> CreateField {
    match field {
        CreateField::Name => CreateField::Network,
        CreateField::Path => CreateField::Name,
        CreateField::Network => CreateField::Path,
    }
}

/// Mark the focused session's bells as seen up to now.
fn acknowledge_bells(model: &mut Model, key: &SessionKey) {
    let seen = model.latest_bell(key).unwrap_or_else(Utc::now);
    model.bells_seen.insert(key.clone(), seen);
}

/// Effects triggered by the cursor landing on a (possibly different)
/// session: acknowledge its bells and fetch detail data not yet cached.
fn on_focus_change(model: &mut Model) -> Vec<Effect> {
    if let Some(key) = model.focused() {
        acknowledge_bells(model, &key);
    }
    fetch_focused(model)
}

/// Fetch detail data for the focused session when it isn't cached. The
/// screen preview is covered by the 2s tick, not per-keystroke fetches.
fn fetch_focused(model: &Model) -> Vec<Effect> {
    let Some(key) = model.focused() else {
        return Vec::new();
    };
    if model.details.contains_key(&key) {
        return Vec::new();
    }
    vec![Effect::FetchDetail(key)]
}

/// Options for [`run`].
#[derive(Debug, Default, Clone)]
pub struct DashOptions {
    /// `--minimal-dir` override; `None` uses the platform default state dir.
    pub minimal_dir: Option<PathBuf>,
    /// The loadout contribution the CLI composed at startup (default
    /// loadouts + user policy), re-sent with every create so `n` in dash
    /// matches `min session activate`. Composition needs the CLI crate's
    /// config plumbing, which lives above this crate.
    pub contribution: sessions::wire::request::WireContribution,
}

/// Entry point for `min dash`: discover providers, then drive the
/// Elm loop until the user quits.
pub async fn run(opts: DashOptions) -> Result<(), anyhow::Error> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdout())
        || !std::io::IsTerminal::is_terminal(&std::io::stdin())
    {
        // stdin too: crossterm falls back to /dev/tty for input, so a
        // redirected stdin would still yield a working TUI — whose attach
        // then spawns `ssh -tt` reading /dev/null, the #953 hang.
        anyhow::bail!("min dash requires an interactive terminal on stdin and stdout");
    }

    let mut providers = rpc::discover(opts.minimal_dir.as_deref()).await;
    let contribution = opts.contribution.clone();
    let mut last_rediscovery = std::time::Instant::now();
    let saved = state::load(opts.minimal_dir.as_deref());
    let mut model = Model::new(Utc::now());
    model.pending_focus = saved
        .last_session_id
        .as_deref()
        .and_then(|id| SessionId::parse_str(id).ok())
        .map(|id| (saved.last_provider.clone().unwrap_or_default(), id));

    // Guard restores the terminal on every exit path, including `?`.
    let mut terminal = TerminalGuard::enter()?;

    let mut events = crossterm::event::EventStream::new();
    let mut tick = tokio::time::interval(REFRESH_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Background tasks (the create flow runs its upload off the UI loop)
    // report back over this channel.
    let (bg_tx, mut bg_rx) = tokio::sync::mpsc::channel::<Msg>(8);

    // Prime the list immediately rather than waiting out the first tick.
    let mut inbox: VecDeque<Msg> = VecDeque::from([Msg::Tick]);
    loop {
        terminal
            .draw(|frame| crate::render::view(&mut model, frame))
            .context("draw frame")?;

        let msg = match inbox.pop_front() {
            Some(msg) => msg,
            None => {
                use futures::StreamExt as _;
                tokio::select! {
                    maybe_event = events.next() => match maybe_event {
                        Some(Ok(event)) => match crate::event::into_msg(event) {
                            Some(msg) => msg,
                            // Resizes and friends just trigger a redraw.
                            None => continue,
                        },
                        Some(Err(e)) => return Err(e).context("reading terminal events"),
                        None => break,
                    },
                    Some(bg) = bg_rx.recv() => bg,
                    _ = tick.tick() => Msg::Tick,
                }
            }
        };

        for effect in update(&mut model, msg) {
            match effect {
                // State persistence is local disk, not a daemon call, so it
                // runs inline rather than going through `exec_effect`.
                Effect::SaveState => save_state(&model, opts.minimal_dir.as_deref()),
                // Attach suspends the TUI around a blocking ssh child; it
                // needs the terminal guard, so it can't live in exec_effect.
                Effect::Attach(key) => match providers.iter().find(|p| p.label == key.provider) {
                    Some(p) => {
                        let sock = p.sock.clone();
                        attach_and_resume(&mut terminal, &sock, key.id, &mut model);
                        inbox.push_back(Msg::Tick);
                    }
                    None => {
                        model.status =
                            Some(format!("error: provider '{}' is unreachable", key.provider));
                    }
                },
                // Create runs the upload+compose flow on a background task
                // with its own connection, so the UI keeps redrawing (the
                // status line shows progress).
                Effect::Create {
                    provider,
                    name,
                    path,
                    network,
                } => match providers.iter().find(|p| p.label == provider) {
                    Some(p) => {
                        let sock = p.sock.clone();
                        let tx = bg_tx.clone();
                        let contribution = contribution.clone();
                        model.status = Some(format!(
                            "creating {}…",
                            name.as_deref().unwrap_or("session")
                        ));
                        tokio::spawn(async move {
                            let result = async {
                                let canonical =
                                    std::fs::canonicalize(&path).with_context(|| {
                                        format!("cannot resolve project path '{path}'")
                                    })?;
                                let utf8 = camino::Utf8PathBuf::from_path_buf(canonical).map_err(
                                    |_| anyhow::anyhow!("project path is not valid UTF-8"),
                                )?;
                                let abs = paths::HostAbsPath::try_new(utf8)
                                    .context("invalid project path")?;
                                rpc::activate(&sock, name, abs, network, contribution).await
                            }
                            .await;
                            let msg = match result {
                                Ok(id) => Msg::Created { provider, id },
                                Err(e) => Msg::ActionDone(Err(format!("{e:#}"))),
                            };
                            let _ = tx.send(msg).await;
                        });
                    }
                    None => {
                        model.status = Some(format!("error: provider '{provider}' is unreachable"));
                    }
                },
                other => {
                    if let Some(follow_up) = exec_effect(
                        &mut providers,
                        other,
                        opts.minimal_dir.as_deref(),
                        &mut last_rediscovery,
                    )
                    .await
                    {
                        inbox.push_back(follow_up);
                    }
                }
            }
        }
        if model.quit {
            break;
        }
    }

    drop(terminal);
    save_state(&model, opts.minimal_dir.as_deref());
    Ok(())
}

/// Persist the last-focused session. Called on quit and on explicit
/// selection (Enter on a session row) rather than every key press.
fn save_state(model: &Model, minimal_dir: Option<&std::path::Path>) {
    let (provider, id) = match model.focus_for_state() {
        Some(f) => f,
        None => return,
    };
    let state = DashState {
        last_session_id: Some(id.to_string()),
        last_provider: Some(provider),
    };
    if let Err(e) = state::save(minimal_dir, &state) {
        tracing::warn!(error = %e, "failed to write dash-state.json");
    }
}

/// Execute one effect against the daemon connections, producing the
/// follow-up message for [`update`].
async fn exec_effect(
    providers: &mut Vec<rpc::Provider>,
    effect: Effect,
    minimal_dir: Option<&std::path::Path>,
    last_rediscovery: &mut std::time::Instant,
) -> Option<Msg> {
    match effect {
        Effect::Refresh => {
            // Give a daemon that (re)appeared since startup a chance to
            // join, throttled so a wedged acceptor can't stall the loop.
            if last_rediscovery.elapsed() >= REDISCOVERY_INTERVAL {
                *last_rediscovery = std::time::Instant::now();
                rpc::connect_missing(providers, minimal_dir).await;
            }
            let mut ok = Vec::with_capacity(providers.len());
            let mut failed = Vec::new();
            let mut i = 0;
            while i < providers.len() {
                match rpc::refresh(&mut providers[i]).await {
                    Ok(d) => {
                        ok.push(d);
                        i += 1;
                    }
                    Err(e) => {
                        // A failed refresh means a dead connection: drop it
                        // so the rediscovery pass can rebuild it, and mark
                        // the provider unreachable in the model rather than
                        // re-indexing its sessions onto another daemon.
                        let gone = providers.remove(i);
                        tracing::warn!(provider = gone.label, error = %e, "refresh failed; dropping the connection");
                        failed.push(gone.label.to_string());
                    }
                }
            }
            Some(Msg::Refreshed { ok, failed })
        }
        Effect::FetchDetail(key) => {
            let provider = providers.iter_mut().find(|p| p.label == key.provider)?;
            match rpc::fetch_detail(provider, key.id).await {
                Ok((record, policy)) => {
                    Some(Msg::DetailLoaded(key, Box::new(Detail { record, policy })))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "detail fetch failed");
                    None
                }
            }
        }
        Effect::FetchScreen(key) => {
            let provider = providers.iter_mut().find(|p| p.label == key.provider)?;
            let fetch = rpc::fetch_screen(provider, key.id)
                .await
                .map_err(|e| format!("{e:#}"));
            Some(Msg::ScreenLoaded(key, fetch))
        }
        Effect::Destroy(key) => {
            let result = match providers.iter_mut().find(|p| p.label == key.provider) {
                Some(provider) => rpc::destroy(provider, key.id)
                    .await
                    .map(|()| "session destroyed".to_string())
                    .map_err(|e| format!("{e:#}")),
                None => Err(format!("provider '{}' is unreachable", key.provider)),
            };
            Some(Msg::ActionDone(result))
        }
        Effect::Rename(key, new_name) => {
            let result = match providers.iter_mut().find(|p| p.label == key.provider) {
                Some(provider) => rpc::rename(provider, key.id, &new_name)
                    .await
                    .map(|()| format!("renamed to {new_name}"))
                    .map_err(|e| format!("{e:#}")),
                None => Err(format!("provider '{}' is unreachable", key.provider)),
            };
            Some(Msg::ActionDone(result))
        }
        // Handled inline by the run loop: SaveState is local disk, Attach
        // needs the terminal guard, Create spawns a background task.
        Effect::SaveState | Effect::Attach(_) | Effect::Create { .. } => None,
    }
}

/// Suspend the TUI, attach to the session over ssh (blocking until the user
/// detaches), then resume. The daemon recognizes `Ctrl-W` as detach.
fn attach_and_resume(
    terminal: &mut TerminalGuard,
    sock: &std::path::Path,
    id: SessionId,
    model: &mut Model,
) {
    let result = minimal_client::attach::attach_command(sock, id, &[]).and_then(|mut cmd| {
        terminal.suspend();
        let status = cmd.status();
        // A failed resume leaves the TUI unusable; report it over the
        // attach outcome.
        terminal
            .resume()
            .context("restoring terminal after detach")?;
        status.context("running ssh attach")
    });
    match result {
        Ok(status) => {
            model.status = Some(match status.code() {
                Some(0) => "detached".to_string(),
                _ => format!("attach ended: {status}"),
            });
        }
        Err(e) => model.status = Some(format!("error: attach failed: {e:#}")),
    }
}

/// Enters the alternate screen on construction and restores the terminal
/// on drop, so every exit path — including `?` early returns — leaves the
/// terminal usable. `suspend`/`resume` hand the terminal to a child process
/// (attach) and take it back.
struct TerminalGuard(Option<ratatui::DefaultTerminal>);

impl TerminalGuard {
    fn enter() -> std::io::Result<Self> {
        let mut terminal = ratatui::init();
        terminal.clear()?;
        Ok(Self(Some(terminal)))
    }

    fn draw(
        &mut self,
        f: impl FnOnce(&mut ratatui::Frame<'_>),
    ) -> std::io::Result<ratatui::CompletedFrame<'_>> {
        match self.0.as_mut() {
            Some(t) => t.draw(f),
            // Suspended (an attach child owns the terminal): nothing to draw.
            None => Err(std::io::Error::other("terminal suspended")),
        }
    }

    /// Leave the alternate screen and drop the terminal, handing the TTY to
    /// a child process.
    fn suspend(&mut self) {
        if self.0.take().is_some() {
            ratatui::restore();
        }
    }

    /// Re-enter the alternate screen after the child exits.
    fn resume(&mut self) -> std::io::Result<()> {
        let mut terminal = ratatui::init();
        terminal.clear()?;
        self.0 = Some(terminal);
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.0.is_some() {
            ratatui::restore();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::ProviderData;

    fn id(n: u128) -> SessionId {
        SessionId::parse_str(&format!("00000000-0000-0000-0000-{n:012x}")).unwrap()
    }

    fn skey(provider: &str, n: u128) -> SessionKey {
        SessionKey {
            provider: provider.to_string(),
            id: id(n),
        }
    }

    fn entry(n: u128, name: Option<&str>) -> minimald_rpc::ListSessionsEntry {
        entry_at(n, name, "/src/api")
    }

    fn entry_at(n: u128, name: Option<&str>, project: &str) -> minimald_rpc::ListSessionsEntry {
        minimald_rpc::ListSessionsEntry {
            id: id(n),
            name: name.map(str::to_owned),
            project_path: Some(paths::HostAbsPath::try_new(project).unwrap()),
            status: sessions::SessionStatus::Active,
            git: None,
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

    fn model_with(providers: Vec<ProviderData>) -> Model {
        let now = DateTime::parse_from_rfc3339("2026-07-29T12:00:00Z")
            .unwrap()
            .to_utc();
        let mut model = Model::new(now);
        update(
            &mut model,
            Msg::Refreshed {
                ok: providers,
                failed: Vec::new(),
            },
        );
        model
    }

    fn key(code: KeyCode) -> Msg {
        Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn two_providers() -> Model {
        model_with(vec![
            provider("host", vec![entry(1, Some("api-staging")), entry(2, None)]),
            provider("vm", vec![entry_at(3, Some("bench"), "/src/bench")]),
        ])
    }

    #[test]
    fn q_quits_and_saves_state() {
        let mut model = two_providers();
        let effects = update(&mut model, key(KeyCode::Char('q')));
        assert!(model.quit);
        assert!(effects.iter().any(|e| matches!(e, Effect::SaveState)));
    }

    #[test]
    fn arrow_keys_move_the_cursor_with_bounds() {
        let mut model = two_providers();
        // Rows: host header, api-staging, (unnamed), vm header, bench.
        assert_eq!(model.cursor, 0);
        update(&mut model, key(KeyCode::Down));
        assert_eq!(model.cursor, 1);
        assert_eq!(model.focused(), Some(skey("host", 1)));
        update(&mut model, key(KeyCode::Up));
        assert_eq!(model.cursor, 0);
        // Can't move above the first row.
        update(&mut model, key(KeyCode::Up));
        assert_eq!(model.cursor, 0);
        // Or past the last row.
        for _ in 0..10 {
            update(&mut model, key(KeyCode::Down));
        }
        assert_eq!(model.cursor, model.visible_rows().len() - 1);
    }

    #[test]
    fn enter_on_a_header_toggles_collapse() {
        let mut model = two_providers();
        update(&mut model, key(KeyCode::Enter));
        assert!(model.providers[0].collapsed);
        // Collapsing hides the host's sessions from the row list.
        assert_eq!(model.visible_rows().len(), 3);
        update(&mut model, key(KeyCode::Enter));
        assert!(!model.providers[0].collapsed);
    }

    #[test]
    fn filter_narrows_and_esc_clears() {
        let mut model = two_providers();
        update(&mut model, key(KeyCode::Char('/')));
        assert!(model.filter.editing);
        for c in "bench".chars() {
            update(&mut model, key(KeyCode::Char(c)));
        }
        // Only the vm provider's "bench" session matches; headers stay.
        let rows = model.visible_rows();
        let sessions: Vec<_> = rows
            .iter()
            .filter(|r| matches!(r, Row::Session(_)))
            .collect();
        assert_eq!(sessions, [&Row::Session(skey("vm", 3))]);
        update(&mut model, key(KeyCode::Esc));
        assert!(!model.filter.editing);
        assert!(model.filter.input.is_empty());
        assert_eq!(model.visible_rows().len(), 5);
    }

    #[test]
    fn cursor_clamps_to_first_visible_row_when_filtered_out() {
        let mut model = two_providers();
        // Focus "bench" (last row).
        for _ in 0..4 {
            update(&mut model, key(KeyCode::Down));
        }
        assert_eq!(model.cursor, 4);
        // Filter it out: the cursor lands on the first visible session row
        // (a provider header would show no detail pane).
        update(&mut model, key(KeyCode::Char('/')));
        for c in "api".chars() {
            update(&mut model, key(KeyCode::Char(c)));
        }
        assert_eq!(model.focused(), Some(skey("host", 1)));
    }

    #[test]
    fn refresh_keeps_the_cursor_on_the_same_session() {
        let mut model = two_providers();
        update(&mut model, key(KeyCode::Down));
        assert_eq!(model.focused().map(|k| k.id), Some(id(1)));
        // A refresh that inserts a new session above the focused one must
        // not move focus.
        update(
            &mut model,
            Msg::Refreshed {
                ok: vec![
                    provider(
                        "host",
                        vec![
                            entry(9, Some("new")),
                            entry(1, Some("api-staging")),
                            entry(2, None),
                        ],
                    ),
                    provider("vm", vec![entry(3, Some("bench"))]),
                ],
                failed: Vec::new(),
            },
        );
        assert_eq!(model.focused().map(|k| k.id), Some(id(1)));
    }

    #[test]
    fn pending_focus_restores_the_last_session() {
        let now = DateTime::parse_from_rfc3339("2026-07-29T12:00:00Z")
            .unwrap()
            .to_utc();
        let mut model = Model::new(now);
        model.pending_focus = Some(("vm".to_string(), id(3)));
        update(
            &mut model,
            Msg::Refreshed {
                ok: vec![
                    provider("host", vec![entry(1, Some("api-staging"))]),
                    provider("vm", vec![entry(3, Some("bench"))]),
                ],
                failed: Vec::new(),
            },
        );
        assert_eq!(model.focused(), Some(skey("vm", 3)));
    }

    #[test]
    fn pending_focus_falls_back_when_the_session_is_gone() {
        let now = DateTime::parse_from_rfc3339("2026-07-29T12:00:00Z")
            .unwrap()
            .to_utc();
        let mut model = Model::new(now);
        model.pending_focus = Some(("vm".to_string(), id(99)));
        update(
            &mut model,
            Msg::Refreshed {
                ok: vec![provider("host", vec![entry(1, Some("api"))])],
                failed: Vec::new(),
            },
        );
        // The fallback is the first session row, not row 0 (a provider
        // header, where d/r are dead keys).
        assert_eq!(model.focused(), Some(skey("host", 1)));
    }

    #[test]
    fn destroy_flow_prompts_then_effects() {
        let mut model = two_providers();
        update(&mut model, key(KeyCode::Down));
        update(&mut model, key(KeyCode::Char('d')));
        assert!(matches!(
            model.action,
            Some(Action::ConfirmDestroy(_, ref name)) if name == "api-staging"
        ));
        // 'n' cancels.
        let effects = update(&mut model, key(KeyCode::Char('n')));
        assert!(model.action.is_none());
        assert!(effects.is_empty());
        // 'y' issues the destroy.
        update(&mut model, key(KeyCode::Char('d')));
        let effects = update(&mut model, key(KeyCode::Char('y')));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Destroy(k) if k.id == id(1)))
        );
    }

    #[test]
    fn rename_prefills_and_submits() {
        let mut model = two_providers();
        update(&mut model, key(KeyCode::Down));
        update(&mut model, key(KeyCode::Char('r')));
        assert!(matches!(
            &model.action,
            Some(Action::Rename { input, .. }) if input == "api-staging"
        ));
        update(&mut model, key(KeyCode::Char('x')));
        let effects = update(&mut model, key(KeyCode::Enter));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Rename(k, n) if k.id == id(1) && n == "api-stagingx"))
        );
    }

    #[test]
    fn create_form_submits_on_last_field() {
        let mut model = two_providers();
        update(&mut model, key(KeyCode::Char('n')));
        assert!(matches!(model.action, Some(Action::Create(_))));
        update(&mut model, key(KeyCode::Enter)); // name -> path
        update(&mut model, key(KeyCode::Enter)); // path -> network
        let effects = update(&mut model, key(KeyCode::Enter)); // submit
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::Create {
                network: NetworkMode::HostNet,
                ..
            }
        )));
        assert!(model.action.is_none());
    }

    #[test]
    fn focusing_a_session_acknowledges_its_bell() {
        let now = DateTime::parse_from_rfc3339("2026-07-29T12:00:00Z")
            .unwrap()
            .to_utc();
        let mut with_bell = entry(1, Some("api"));
        with_bell.attrs = Some(minimald_rpc::RunningSessionAttrs {
            last_stdout: None,
            last_stdin: None,
            title: None,
            audible_bell: Some(minimald_rpc::Bell {
                count: 2,
                last: now,
            }),
            visual_bell: None,
        });
        let mut model = model_with(vec![provider("host", vec![with_bell])]);
        // Focus the session (row 1) — the bell was already in the attrs at
        // focus time, so it's acknowledged and doesn't light the indicator.
        update(&mut model, key(KeyCode::Down));
        assert!(!model.has_unseen_bell(&skey("host", 1)));
    }

    #[test]
    fn focusing_fetches_detail_once() {
        let mut model = two_providers();
        let effects = update(&mut model, key(KeyCode::Down));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::FetchDetail(k) if k.id == id(1)))
        );
        // A second focus of the same session is served from the cache.
        update(
            &mut model,
            Msg::DetailLoaded(skey("host", 1), Box::default()),
        );
        update(&mut model, key(KeyCode::Down));
        let effects = update(&mut model, key(KeyCode::Up));
        assert!(!effects.iter().any(|e| matches!(e, Effect::FetchDetail(_))));
    }

    #[test]
    fn indicator_shows_spinner_for_recent_stdout() {
        let now = DateTime::parse_from_rfc3339("2026-07-29T12:00:00Z")
            .unwrap()
            .to_utc();
        let mut hot = entry(1, Some("hot"));
        hot.attrs = Some(minimald_rpc::RunningSessionAttrs {
            last_stdout: Some(now - chrono::Duration::seconds(2)),
            last_stdin: None,
            title: None,
            audible_bell: None,
            visual_bell: None,
        });
        // Refreshed overwrites `now` with the wall clock; pin it back.
        let mut model = model_with(vec![provider("host", vec![hot])]);
        model.now = now;
        assert_eq!(model.indicator(&skey("host", 1)), "◐");
    }

    #[test]
    fn indicator_shows_waiting_for_stdin_without_stdout() {
        let now = DateTime::parse_from_rfc3339("2026-07-29T12:00:00Z")
            .unwrap()
            .to_utc();
        let mut waiting = entry(1, Some("wait"));
        waiting.attrs = Some(minimald_rpc::RunningSessionAttrs {
            last_stdout: Some(now - chrono::Duration::seconds(60)),
            last_stdin: Some(now - chrono::Duration::seconds(2)),
            title: None,
            audible_bell: None,
            visual_bell: None,
        });
        let mut model = model_with(vec![provider("host", vec![waiting])]);
        model.now = now;
        assert_eq!(model.indicator(&skey("host", 1)), "○");
    }

    #[test]
    fn indicator_blank_when_idle() {
        let model = two_providers();
        assert_eq!(model.indicator(&skey("host", 1)), "");
    }
    #[test]
    fn tick_fetches_the_focused_sessions_screen() {
        let mut model = two_providers();
        update(&mut model, key(KeyCode::Down));
        let effects = update(&mut model, Msg::Tick);
        assert!(effects.iter().any(|e| matches!(e, Effect::Refresh)));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::FetchScreen(k) if k.id == id(1)))
        );
    }

    /// Ctrl-D is a shell reflex, not "destroy": modified chords must not
    /// reach the bare-key bindings.
    #[test]
    fn ctrl_chords_do_not_reach_the_bare_key_bindings() {
        let mut model = two_providers();
        update(&mut model, key(KeyCode::Down));
        for code in [KeyCode::Char('d'), KeyCode::Char('r'), KeyCode::Char('n')] {
            let effects = update(
                &mut model,
                Msg::Key(KeyEvent::new(code, KeyModifiers::CONTROL)),
            );
            assert!(model.action.is_none(), "{code:?} opened a modal");
            assert!(effects.is_empty(), "{code:?} produced effects");
        }
        // Ctrl-C still quits (it is an explicit binding).
        update(
            &mut model,
            Msg::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        );
        assert!(model.quit);
    }

    /// A failed refresh keeps the provider's slot (marked unreachable)
    /// instead of dropping it and re-indexing every session key onto the
    /// surviving daemon.
    #[test]
    fn a_failed_refresh_marks_the_provider_unreachable() {
        let mut model = two_providers();
        update(
            &mut model,
            Msg::Refreshed {
                ok: vec![provider("host", vec![entry(1, Some("api-staging"))])],
                failed: vec!["vm".to_string()],
            },
        );
        let vm = model
            .providers
            .iter()
            .find(|p| p.label == "vm")
            .expect("the vm slot must survive its failed refresh");
        assert!(!vm.reachable);
        assert!(vm.sessions.is_empty());
        // The host's sessions still resolve to the host provider by label.
        assert_eq!(model.entry(&skey("host", 1)).map(|e| e.id), Some(id(1)));
    }

    /// A provider that comes back rejoins with its sessions and is marked
    /// reachable again.
    #[test]
    fn a_reconnected_provider_rejoins() {
        let mut model = two_providers();
        update(
            &mut model,
            Msg::Refreshed {
                ok: vec![provider("host", vec![entry(1, Some("api-staging"))])],
                failed: vec!["vm".to_string()],
            },
        );
        update(
            &mut model,
            Msg::Refreshed {
                ok: vec![
                    provider("host", vec![entry(1, Some("api-staging"))]),
                    provider("vm", vec![entry(3, Some("bench"))]),
                ],
                failed: Vec::new(),
            },
        );
        let vm = model.providers.iter().find(|p| p.label == "vm").unwrap();
        assert!(vm.reachable);
        assert_eq!(model.entry(&skey("vm", 3)).map(|e| e.id), Some(id(3)));
        // Canonical group order is preserved after the rejoin.
        let labels: Vec<&str> = model.providers.iter().map(|p| p.label.as_str()).collect();
        assert_eq!(labels, ["host", "vm"]);
    }

    /// Opening the create form from a provider's group header targets THAT
    /// provider, not the first one in the list.
    #[test]
    fn create_from_a_provider_header_targets_that_provider() {
        let mut model = two_providers();
        // Rows: host header, api-staging, (unnamed), vm header, bench.
        for _ in 0..3 {
            update(&mut model, key(KeyCode::Down));
        }
        assert!(matches!(model.cursor_row(), Some(Row::ProviderHeader(1))));
        update(&mut model, key(KeyCode::Char('n')));
        update(&mut model, key(KeyCode::Enter)); // name -> path
        update(&mut model, key(KeyCode::Enter)); // path -> network
        let effects = update(&mut model, key(KeyCode::Enter)); // submit
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Create { provider, .. } if provider == "vm")),
            "expected a create targeted at vm, got {effects:?}"
        );
    }

    /// Creating on a provider marked unreachable fails loudly instead of
    /// silently targeting another daemon.
    #[test]
    fn create_on_an_unreachable_provider_errors() {
        let mut model = two_providers();
        update(
            &mut model,
            Msg::Refreshed {
                ok: vec![provider("host", vec![entry(1, Some("api-staging"))])],
                failed: vec!["vm".to_string()],
            },
        );
        // Rows: host header, api-staging, vm header (sessions cleared).
        for _ in 0..2 {
            update(&mut model, key(KeyCode::Down));
        }
        assert!(matches!(model.cursor_row(), Some(Row::ProviderHeader(_))));
        update(&mut model, key(KeyCode::Char('n')));
        update(&mut model, key(KeyCode::Enter));
        update(&mut model, key(KeyCode::Enter));
        let effects = update(&mut model, key(KeyCode::Enter));
        assert!(!effects.iter().any(|e| matches!(e, Effect::Create { .. })));
        assert_eq!(
            model.status.as_deref(),
            Some("error: provider 'vm' is unreachable")
        );
    }
}

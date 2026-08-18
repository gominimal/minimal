//! The `view` half of the Elm loop: pure ratatui rendering of [`Model`].
//! No side effects, no daemon calls.

use chrono::Utc;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app::{
    Action, CreateField, Model, Row, SessionKey, display_name_of, network_mode_label,
};

/// Render the whole frame: sidebar left, detail pane right, footer line at
/// the bottom. Takes `&mut Model` because the sidebar adjusts the model's
/// scroll offset to keep the cursor inside its viewport.
pub fn view(model: &mut Model, frame: &mut Frame) {
    let [main, footer] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());
    let [sidebar, detail] =
        Layout::horizontal([Constraint::Percentage(32), Constraint::Percentage(68)]).areas(main);

    render_sidebar(model, frame, sidebar);
    render_detail(model, frame, detail);
    render_footer(model, frame, footer);
}

/// Truncate `s` to at most `w` display columns, appending `…` when cut.
fn truncate(s: &str, w: usize) -> String {
    // w == 0 must yield the empty string: the ellipsis alone is one column
    // and would overflow a zero-width allocation.
    if w == 0 {
        return String::new();
    }
    if UnicodeWidthStr::width(s) <= w {
        return s.to_string();
    }
    let budget = w.saturating_sub(1);
    let mut used = 0;
    let cut: String = s
        .chars()
        .map_while(|ch| {
            let cw = UnicodeWidthChar::width(ch).unwrap_or(0);
            (used + cw <= budget).then(|| {
                used += cw;
                ch
            })
        })
        .collect();
    format!("{cut}…")
}

/// Truncate `s` to at most `w` display columns (appending `…` when cut), or
/// pad it with trailing spaces to exactly `w`. Widths are terminal display
/// widths, so CJK/emoji session names don't misalign the sidebar.
fn pad_truncate(s: &str, w: usize) -> String {
    let out = truncate(s, w);
    let pad = w.saturating_sub(UnicodeWidthStr::width(out.as_str()));
    format!("{out}{}", " ".repeat(pad))
}

fn render_sidebar(model: &mut Model, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .padding(ratatui::widgets::Padding::horizontal(1))
        .title(Span::styled(
            " sessions ",
            Style::default().add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    let inner_width = inner.width as usize;
    frame.render_widget(block, area);

    // The filter line and its separator pin to the top, per the spec's
    // layout mock (dim while the filter isn't being edited); the session
    // list scrolls beneath them.
    let [filter_area, list_area] =
        Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).areas(inner);
    let filter_style = if model.filter.editing {
        Style::default()
    } else {
        Style::default().fg(Color::Gray)
    };
    let filter_lines = vec![
        Line::from(vec![
            Span::styled("/ ", filter_style),
            Span::styled(
                if model.filter.editing {
                    format!("{}▏", model.filter.input)
                } else {
                    model.filter.input.clone()
                },
                filter_style,
            ),
        ]),
        Line::styled("─".repeat(inner_width), Style::default().fg(Color::Gray)),
    ];
    frame.render_widget(Paragraph::new(filter_lines), filter_area);

    let rows = model.visible_rows();
    // Keep the cursor inside the viewport: with no scroll offset it (and
    // the sessions d/r would act on) can sit on rows nobody can see.
    let height = usize::from(list_area.height);
    if model.cursor < model.scroll {
        model.scroll = model.cursor;
    } else if height > 0 && model.cursor >= model.scroll + height {
        model.scroll = model.cursor + 1 - height;
    }
    model.scroll = model.scroll.min(rows.len().saturating_sub(height));

    let mut lines: Vec<Line> = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let selected = i == model.cursor;
        let line = match row {
            Row::ProviderHeader(p) => {
                let provider = &model.providers[*p];
                let arrow = if provider.collapsed { "▸" } else { "▼" };
                // The dot is the group's health mark: green while the last
                // refresh reached the daemon, red once it drops.
                let (status, dot) = match provider.reachable {
                    true => (format!("v{}", provider.version), Color::Green),
                    false => ("unreachable".to_string(), Color::Red),
                };
                let status = pad_truncate(
                    &status,
                    inner_width.saturating_sub(UnicodeWidthStr::width(provider.label.as_str()) + 7),
                );
                Line::from(vec![
                    Span::styled(
                        format!("{arrow} {}  ", provider.label),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(status, Style::default().fg(Color::Gray)),
                    Span::styled(" ●", Style::default().fg(dot)),
                ])
            }
            Row::Session(key) => {
                let Some(entry) = model.entry(key) else {
                    continue;
                };
                let name = display_name_of(entry);
                let indicator = model.indicator(key);
                // The list RPC carries no network mode; it fills in once
                // the session's detail has been fetched.
                let net = model
                    .details
                    .get(key)
                    .and_then(|d| d.record.as_ref())
                    .map(|r| network_mode_label(r.network))
                    .unwrap_or("-");
                // Selected rows get a `▸` marker and bold text; unselected
                // rows indent past the marker. Indicator stays flush right.
                // The row must total exactly `inner_width` columns: one over
                // and the terminal swallows the indicator cell at the right
                // edge (this was the "no activity indicator" bug).
                let marker = if selected { "▸ " } else { "  " };
                // Branch segment (` ⎇ feature` + two-space gutter) only
                // when the daemon answered git info; skipping it entirely
                // keeps the no-git layout byte-identical to before. Cap it
                // to whatever the row can spare after the right-aligned
                // network/indicator block, so a long branch name truncates
                // instead of pushing those cells off the right edge.
                let right = format!("{net} {indicator:>2}");
                let max_branch_width =
                    inner_width.saturating_sub(UnicodeWidthStr::width(right.as_str()) + 2);
                let branch = entry
                    .git
                    .as_ref()
                    .map(|g| format!(" ⎇ {}", g.branch))
                    .filter(|_| max_branch_width > UnicodeWidthStr::width(" ⎇ "))
                    .map(|b| truncate(&b, max_branch_width))
                    .unwrap_or_default();
                let right_w = UnicodeWidthStr::width(right.as_str())
                    + if branch.is_empty() {
                        0
                    } else {
                        UnicodeWidthStr::width(branch.as_str()) + 2
                    };
                let left = pad_truncate(
                    &format!("  {marker}{name}"),
                    inner_width.saturating_sub(right_w),
                );
                let gap = inner_width
                    .saturating_sub(UnicodeWidthStr::width(left.as_str()))
                    .saturating_sub(right_w);
                let name_span = Span::styled(
                    format!("{left}{}", " ".repeat(gap)),
                    if selected {
                        Style::default().add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    },
                );
                let mut spans = vec![name_span];
                if !branch.is_empty() {
                    spans.push(Span::styled(branch, Style::default().fg(Color::Gray)));
                    spans.push(Span::raw("  "));
                }
                spans.push(Span::styled(
                    net.to_string(),
                    Style::default().fg(Color::Gray),
                ));
                spans.push(Span::styled(
                    format!(" {indicator:>2}"),
                    Style::default().fg(Color::Yellow),
                ));
                Line::from(spans)
            }
        };
        lines.push(line);
    }
    if rows.is_empty() {
        lines.push(Line::styled(
            "no sessions (n to create)",
            Style::default().fg(Color::Gray),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).scroll((model.scroll as u16, 0)),
        list_area,
    );
}

/// A dim section divider with a centered-left label, e.g.
/// `─ Policy ─────────────`.
fn divider(label: &str, width: u16) -> Line<'static> {
    let head = format!("─ {label} ");
    Line::styled(
        format!(
            "{head}{}",
            "─".repeat((width as usize).saturating_sub(head.chars().count()))
        ),
        Style::default().fg(Color::Gray),
    )
}

fn render_detail(model: &Model, frame: &mut Frame, area: Rect) {
    // The detail pane is one vertical stack: Info fields, a Policy section,
    // then the live Preview filling the rest. No tabs.
    let focused = model.focused();
    let mut block = Block::default()
        .borders(Borders::ALL)
        .padding(ratatui::widgets::Padding::horizontal(1));
    if let Some(ref key) = focused {
        let name = model.display_name(key);
        let id = key.id.to_string();
        let short = id.split('-').next().unwrap_or(&id);
        block = block.title(Line::from(vec![
            Span::styled(
                format!(" {name} "),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("· {short} "), Style::default().fg(Color::Gray)),
        ]));
    }

    let Some(key) = focused else {
        frame.render_widget(
            Paragraph::new("no session selected")
                .style(Style::default().fg(Color::Gray))
                .block(block),
            area,
        );
        return;
    };
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Fixed-size sections first; Preview takes the remainder. The policy
    // section is sized by its WRAPPED height — the lines render wrapped,
    // and sizing by the unwrapped count would clip long lines — and
    // capped so an over-long policy clips itself instead of collapsing
    // the preview to one row.
    const INFO_HEIGHT: u16 = 4;
    let policy_height = wrapped_height(&policy_lines(model, &key), inner.width)
        .min(usize::from(inner.height.saturating_sub(INFO_HEIGHT + 5)))
        .max(1) as u16;
    let [
        info_area,
        policy_div,
        policy_area,
        preview_div,
        preview_area,
    ] = Layout::vertical([
        Constraint::Length(INFO_HEIGHT),
        Constraint::Length(1),
        Constraint::Length(policy_height),
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .areas(inner);
    render_info(model, &key, frame, info_area);
    frame.render_widget(Paragraph::new(divider("Policy", inner.width)), policy_div);
    render_policy(model, &key, frame, policy_area);
    frame.render_widget(
        Paragraph::new(divider("Preview (live screen snapshot)", inner.width)),
        preview_div,
    );
    render_preview_body(model, &key, frame, preview_area);
}

/// The number of terminal rows `lines` occupy when wrapped to `width`.
fn wrapped_height(lines: &[Line], width: u16) -> usize {
    let w = usize::from(width).max(1);
    lines
        .iter()
        .map(|line| line.width().max(1).div_ceil(w))
        .sum::<usize>()
        .max(1)
}

/// Shorten the user's home directory prefix to `~`, the way the spec's
/// mock renders project paths (`~/src/api`). The match must land on a
/// path boundary: `/home/norrie-scratch` is not under `/home/norrie`.
fn shorten_home(path: &str) -> String {
    let Some(home) = dirs::home_dir().and_then(|h| h.to_str().map(str::to_owned)) else {
        return path.to_string();
    };
    if path == home {
        return "~".to_string();
    }
    match path.strip_prefix(&home) {
        Some(rest) if rest.starts_with('/') => format!("~{rest}"),
        _ => path.to_string(),
    }
}

fn render_info(model: &Model, key: &SessionKey, frame: &mut Frame, area: Rect) {
    let detail = model.details.get(key);
    let entry = model.entry(key);

    // Two-column field layout, per the spec's mock:
    //   project  ~/src/api    net   OwnIp
    //   user     chroma       idle  12s
    //   title    vim: …
    //   bells    ●2 (last 3m)
    let project = entry
        .and_then(|e| e.project_path.as_ref())
        .map(|p| shorten_home(p.as_utf8_path().as_str()))
        .unwrap_or_else(|| "?".to_string());
    let user = detail
        .and_then(|d| d.record.as_ref())
        .and_then(|r| r.username.clone())
        .unwrap_or_else(|| "?".to_string());
    let title = entry
        .and_then(|e| e.attrs.as_ref())
        .and_then(|a| a.title.as_ref())
        .map(|t| t.value.clone())
        .unwrap_or_else(|| "-".to_string());
    // The repo's toplevel, tagged when the project lives in a linked
    // worktree (its .git lives in the main repo). Absent entirely for
    // non-repo projects so their layout doesn't shift.
    let repo = entry.and_then(|e| e.git.as_ref()).map(|g| {
        let root = shorten_home(&g.repo_root);
        match g.is_worktree {
            true => format!("{root} (worktree)"),
            false => root,
        }
    });
    let left = [
        ("project", project),
        ("user", user),
        ("title", title),
        ("bells", bell_text(model, key)),
    ];
    let net = detail
        .and_then(|d| d.record.as_ref())
        .map(|r| format!("{:?}", r.network))
        .unwrap_or_else(|| "?".to_string());
    // The Info section is four rows tall; the branch rides in the sidebar
    // row, so only the repo root joins the right column here.
    let mut right = vec![("net", net), ("idle", idle_text(model, key))];
    if let Some(repo) = repo {
        right.push(("repo", repo));
    }

    // Left column takes half the pane; the right column starts after a
    // two-space gutter. Labels are dim in both columns.
    let dim = Style::default().fg(Color::Gray);
    let left_w = (area.width as usize) / 2;
    let lines: Vec<Line> = (0..left.len().max(right.len()))
        .map(|i| {
            let mut spans = Vec::new();
            match left.get(i) {
                Some((label, value)) => {
                    spans.push(Span::styled(pad_truncate(label, 8), dim));
                    spans.push(Span::raw(pad_truncate(value, left_w.saturating_sub(8))));
                }
                None => spans.push(Span::raw(" ".repeat(left_w))),
            }
            if let Some((label, value)) = right.get(i) {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(pad_truncate(label, 6), dim));
                spans.push(Span::raw(value.clone()));
            }
            Line::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn idle_text(model: &Model, key: &SessionKey) -> String {
    let Some(attrs) = model.entry(key).and_then(|e| e.attrs.as_ref()) else {
        return "-".to_string();
    };
    let last = [attrs.last_stdout, attrs.last_stdin]
        .into_iter()
        .flatten()
        .max();
    match last {
        None => "-".to_string(),
        Some(t) => format_duration(model.now.signed_duration_since(t)),
    }
}

/// Bells in the spec mock's form: `●2 (last 3m)` — total count across
/// audible and visual bells, and the age of the most recent one.
fn bell_text(model: &Model, key: &SessionKey) -> String {
    let Some(attrs) = model.entry(key).and_then(|e| e.attrs.as_ref()) else {
        return "-".to_string();
    };
    let bells: Vec<&minimald_rpc::Bell> = [&attrs.audible_bell, &attrs.visual_bell]
        .into_iter()
        .flatten()
        .collect();
    if bells.is_empty() {
        return "-".to_string();
    }
    let count: usize = bells.iter().map(|b| b.count).sum();
    let last = bells.iter().map(|b| b.last).max().unwrap_or_else(Utc::now);
    format!(
        "●{count} (last {})",
        format_duration(model.now.signed_duration_since(last))
    )
}

/// Render a duration as a compact age ("12s", "3m 04s", "2h 10m").
fn format_duration(d: chrono::Duration) -> String {
    let secs = d.num_seconds().max(0);
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m {:02}s", secs / 60, secs % 60),
        _ => format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60),
    }
}

fn render_policy(model: &Model, key: &SessionKey, frame: &mut Frame, area: Rect) {
    frame.render_widget(
        Paragraph::new(policy_lines(model, key)).wrap(Wrap { trim: false }),
        area,
    );
}

/// The Policy section's lines. The stacked layout sizes the section by
/// these lines' wrapped height ([`wrapped_height`]), so height and
/// content can't drift apart.
fn policy_lines(model: &Model, key: &SessionKey) -> Vec<Line<'static>> {
    let detail = model.details.get(key);
    let record = detail.and_then(|d| d.record.as_ref());
    let mut lines: Vec<Line> = Vec::new();

    if record.is_some() && record.map(|r| r.network) != Some(sessions::NetworkMode::OwnIp) {
        lines.push(Line::styled(
            "No network policy (HostNet/NoNet)",
            Style::default().fg(Color::Gray),
        ));
    } else {
        match detail.and_then(|d| d.policy.as_ref()) {
            None => lines.push(Line::styled(
                "loading policy…",
                Style::default().fg(Color::Gray),
            )),
            Some(policy) => {
                lines.push(Line::styled(
                    "egress",
                    Style::default().add_modifier(Modifier::BOLD),
                ));
                match &policy.egress {
                    None => lines.push(Line::raw("  allow all")),
                    Some(egress) => {
                        policy_list(&mut lines, "subnets", &egress.allow_subnets);
                        policy_list(&mut lines, "dns hosts", &egress.allow_dns_hosts);
                        match &egress.allow_protocols {
                            None => lines.push(Line::raw("  protocols  allow all")),
                            Some(protos) => lines.push(Line::raw(format!(
                                "  protocols  {}",
                                protos
                                    .iter()
                                    .map(|p| p.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ))),
                        }
                    }
                }
                lines.push(Line::styled(
                    "ingress",
                    Style::default().add_modifier(Modifier::BOLD),
                ));
                match &policy.ingress {
                    None => lines.push(Line::raw("  deny all")),
                    Some(ingress) => {
                        if ingress.port_mappings.is_empty()
                            && ingress.dynamic_allowed_range.is_none()
                        {
                            lines.push(Line::raw("  deny all"));
                        }
                        for mapping in &ingress.port_mappings {
                            lines.push(Line::raw(format!(
                                "  {}  :{} → :{}",
                                mapping.proto, mapping.external_port, mapping.internal_port
                            )));
                        }
                        if let Some((lo, hi)) = ingress.dynamic_allowed_range {
                            lines.push(Line::raw(format!("  dynamic ports  {lo}–{hi}")));
                        }
                    }
                }
            }
        }
    }

    lines
}

fn policy_list(lines: &mut Vec<Line>, label: &str, values: &Option<Vec<String>>) {
    match values {
        None => lines.push(Line::raw(format!("  {label}  allow all"))),
        Some(values) => lines.push(Line::raw(format!("  {label}  {}", values.join(", ")))),
    }
}

/// The Preview section's body (its divider is drawn by [`render_detail`]).
fn render_preview_body(model: &Model, key: &SessionKey, frame: &mut Frame, area: Rect) {
    let Some(fetch) = model.screens.get(key) else {
        frame.render_widget(
            Paragraph::new("loading preview…").style(Style::default().fg(Color::Gray)),
            area,
        );
        return;
    };
    match fetch {
        Err(e) => {
            // A subsystem refusal means the running daemon predates
            // GetSessionScreen; everything else is transient.
            let text = if e.contains("request subsystem") {
                "preview unavailable: this minimald is too old — restart it (min stop --force)"
                    .to_string()
            } else {
                format!("preview unavailable: {e}")
            };
            frame.render_widget(
                Paragraph::new(text)
                    .style(Style::default().fg(Color::Red))
                    .wrap(Wrap { trim: false }),
                area,
            );
        }
        Ok(None) => {
            frame.render_widget(
                Paragraph::new("session not active — enter to attach")
                    .style(Style::default().fg(Color::Gray)),
                area,
            );
        }
        Ok(Some(snapshot)) => {
            let text = snapshot_to_text(snapshot);
            // If the session's terminal is taller than the pane, scroll so
            // the session's cursor row stays visible.
            let visible_height = area.height as usize;
            let offset = match snapshot.cursor_row {
                Some(cursor) if snapshot.rows as usize > visible_height => {
                    let cursor = cursor as usize;
                    cursor
                        .saturating_sub(visible_height.saturating_sub(1))
                        .min(snapshot.rows as usize - visible_height) as u16
                }
                _ => 0,
            };
            frame.render_widget(Paragraph::new(text).scroll((offset, 0)), area);
        }
    }
}

/// Convert a wire [`ScreenSnapshot`](minimald_rpc::ScreenSnapshot) into
/// styled ratatui text, grouping runs of identically styled cells into one
/// span per run.
fn snapshot_to_text(snapshot: &minimald_rpc::ScreenSnapshot) -> Text<'static> {
    let lines: Vec<Line> = snapshot
        .lines
        .iter()
        .map(|row| {
            let mut spans: Vec<Span> = Vec::new();
            let mut current = String::new();
            let mut current_style = None;
            for cell in &row.cells {
                let style = cell_style(cell);
                if Some(style) != current_style {
                    if !current.is_empty() {
                        spans.push(Span::styled(
                            std::mem::take(&mut current),
                            current_style.unwrap_or_default(),
                        ));
                    }
                    current_style = Some(style);
                }
                current.push(cell.ch);
            }
            if !current.is_empty() {
                spans.push(Span::styled(current, current_style.unwrap_or_default()));
            }
            Line::from(spans)
        })
        .collect();
    Text::from(lines)
}

fn cell_style(cell: &minimald_rpc::ScreenCell) -> Style {
    let mut style = Style::default();
    if let Some(fg) = &cell.fg {
        style = style.fg(wire_color(fg));
    }
    if let Some(bg) = &cell.bg {
        style = style.bg(wire_color(bg));
    }
    if cell.bold {
        style = style.add_modifier(Modifier::BOLD);
    }
    if cell.italic {
        style = style.add_modifier(Modifier::ITALIC);
    }
    if cell.underline {
        style = style.add_modifier(Modifier::UNDERLINED);
    }
    if cell.reverse {
        style = style.add_modifier(Modifier::REVERSED);
    }
    style
}

/// Parse the wire color form (`"idx:<n>"` or `"#rrggbb"`) into a ratatui
/// color. Unparseable values fall back to the terminal default.
fn wire_color(s: &str) -> Color {
    if let Some(idx) = s.strip_prefix("idx:")
        && let Ok(n) = idx.parse()
    {
        return Color::Indexed(n);
    }
    if let Some(hex) = s.strip_prefix('#')
        && hex.len() == 6
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
        && let (Ok(r), Ok(g), Ok(b)) = (
            u8::from_str_radix(&hex[0..2], 16),
            u8::from_str_radix(&hex[2..4], 16),
            u8::from_str_radix(&hex[4..6], 16),
        )
    {
        return Color::Rgb(r, g, b);
    }
    Color::Reset
}

fn render_footer(model: &Model, frame: &mut Frame, area: Rect) {
    use ratatui::layout::Alignment;
    match &model.action {
        Some(Action::ConfirmDestroy(_, name)) => {
            let line = Line::from(vec![
                Span::styled(
                    format!(" destroy {name}? "),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" y / n ", Style::default().fg(Color::Gray)),
            ]);
            frame.render_widget(Paragraph::new(line), area);
        }
        Some(Action::Rename { input, .. }) => {
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(" rename: ", Style::default().fg(Color::Gray)),
                    Span::raw(format!("{input}▏")),
                    Span::styled(
                        " (enter applies, esc cancels)",
                        Style::default().fg(Color::Gray),
                    ),
                ])),
                area,
            );
        }
        Some(Action::Create(form)) => {
            let field = |label: &str, value: &str, focused: bool| {
                let style = match focused {
                    true => Style::default().add_modifier(Modifier::REVERSED),
                    false => Style::default().fg(Color::Gray),
                };
                Span::styled(format!(" {label}: {value} "), style)
            };
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    field("name", &form.name, form.field == CreateField::Name),
                    field("path", &form.path, form.field == CreateField::Path),
                    field(
                        "net",
                        network_mode_label(crate::app::NETWORK_MODES[form.net_idx]),
                        form.field == CreateField::Network,
                    ),
                    Span::styled(
                        " (tab moves, enter creates, esc cancels)",
                        Style::default().fg(Color::Gray),
                    ),
                ])),
                area,
            );
        }
        None if model.filter.editing => {
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(" / ", Style::default().fg(Color::Gray)),
                    Span::raw(format!("{}▏", model.filter.input)),
                ])),
                area,
            );
        }
        None => {
            // Key hints flush left; the transient status line flush right.
            frame.render_widget(
                Paragraph::new(Line::styled(
                    " ↑↓ move · / filter · enter attach · d destroy · r rename · n new · q quit ",
                    Style::default().fg(Color::Gray),
                )),
                area,
            );
            if let Some(status) = &model.status {
                let style = if status.starts_with("error:") {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                frame.render_widget(
                    Paragraph::new(Line::styled(format!("{status} "), style))
                        .alignment(Alignment::Right),
                    area,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_durations_compactly() {
        assert_eq!(format_duration(chrono::Duration::seconds(12)), "12s");
        assert_eq!(format_duration(chrono::Duration::seconds(184)), "3m 04s");
        assert_eq!(format_duration(chrono::Duration::seconds(7800)), "2h 10m");
    }

    #[test]
    fn parses_wire_colors() {
        assert_eq!(wire_color("idx:196"), Color::Indexed(196));
        assert_eq!(wire_color("#ff0080"), Color::Rgb(255, 0, 128));
        assert_eq!(wire_color("bogus"), Color::Reset);
        // A 6-byte non-ASCII payload must not panic on char-boundary slicing.
        assert_eq!(wire_color("#€bcd"), Color::Reset);
    }

    #[test]
    fn styles_cells_from_wire_flags() {
        let cell = minimald_rpc::ScreenCell {
            ch: 'x',
            fg: Some("idx:1".to_string()),
            bg: None,
            bold: true,
            italic: false,
            underline: true,
            reverse: false,
        };
        let style = cell_style(&cell);
        assert_eq!(style.fg, Some(Color::Indexed(1)));
        assert!(style.add_modifier.contains(Modifier::BOLD));
        assert!(style.add_modifier.contains(Modifier::UNDERLINED));
    }

    #[test]
    fn truncation_respects_a_zero_width_budget() {
        assert_eq!(truncate("abc", 0), "");
        assert_eq!(truncate("", 0), "");
        // Width 1 has room for the ellipsis itself when the input is cut.
        assert_eq!(truncate("abc", 1), "…");
        // pad_truncate inherits the zero-width guard instead of overflowing.
        assert_eq!(pad_truncate("abc", 0), "");
        assert_eq!(pad_truncate("", 3), "   ");
    }

    #[test]
    fn shorten_home_only_shortens_at_a_path_boundary() {
        let Some(home) = dirs::home_dir() else {
            return;
        };
        let Some(home) = home.to_str() else {
            return;
        };
        assert_eq!(shorten_home(&format!("{home}/src/api")), "~/src/api");
        assert_eq!(shorten_home(home), "~");
        // A sibling that merely shares the home prefix is not under home.
        let sibling = format!("{home}-scratch/api");
        assert_eq!(shorten_home(&sibling), sibling);
    }

    #[test]
    fn wrapped_height_counts_terminal_rows() {
        let lines = vec![Line::raw("short"), Line::raw("a".repeat(25)), Line::raw("")];
        // Width 10: 1 + 3 + 1 rows.
        assert_eq!(wrapped_height(&lines, 10), 5);
    }
}

//! The `view` half of the Elm loop: pure ratatui rendering of [`Model`].
//! No side effects, no daemon calls.

use chrono::Utc;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::{
    Action, CreateField, Model, Row, SessionKey, display_name_of, network_mode_label,
};

/// Render the whole frame: sidebar left, detail pane right, footer line at
/// the bottom.
pub fn view(model: &Model, frame: &mut Frame) {
    let [main, footer] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());
    let [sidebar, detail] =
        Layout::horizontal([Constraint::Percentage(32), Constraint::Percentage(68)]).areas(main);

    render_sidebar(model, frame, sidebar);
    render_detail(model, frame, detail);
    render_footer(model, frame, footer);
}

/// Truncate `s` to at most `w` columns (appending `…` when cut), or pad it
/// with trailing spaces to exactly `w`.
fn pad_truncate(s: &str, w: usize) -> String {
    let len = s.chars().count();
    if len > w {
        let cut: String = s.chars().take(w.saturating_sub(1)).collect();
        format!("{cut}…")
    } else {
        format!("{s:<width$}", width = w.saturating_sub(len) + len)
    }
}

fn render_sidebar(model: &Model, frame: &mut Frame, area: Rect) {
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

    let mut lines: Vec<Line> = Vec::new();
    // The filter line and its separator sit atop the list, per the spec's
    // layout mock. Dim while the filter isn't being edited.
    let filter_style = if model.filter.editing {
        Style::default()
    } else {
        Style::default().fg(Color::Gray)
    };
    lines.push(Line::from(vec![
        Span::styled("/ ", filter_style),
        Span::styled(
            if model.filter.editing {
                format!("{}▏", model.filter.input)
            } else {
                model.filter.input.clone()
            },
            filter_style,
        ),
    ]));
    lines.push(Line::styled(
        "─".repeat(inner_width),
        Style::default().fg(Color::Gray),
    ));

    let rows = model.visible_rows();
    for (i, row) in rows.iter().enumerate() {
        let selected = i == model.cursor;
        let line = match row {
            Row::ProviderHeader(p) => {
                let provider = &model.providers[*p];
                let arrow = if provider.collapsed { "▸" } else { "▼" };
                // A listed provider is reachable by construction; the dot is
                // the group's health mark.
                let version = pad_truncate(
                    &format!("v{}", provider.version),
                    inner_width.saturating_sub(provider.label.chars().count() + 7),
                );
                Line::from(vec![
                    Span::styled(
                        format!("{arrow} {}  ", provider.label),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(version, Style::default().fg(Color::Gray)),
                    Span::styled(" ●", Style::default().fg(Color::Green)),
                ])
            }
            Row::Session(key) => {
                let Some(entry) = model.entry(*key) else {
                    continue;
                };
                let name = display_name_of(entry);
                let indicator = model.indicator(*key);
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
                let marker = if selected { "▸ " } else { "  " };
                let name_w =
                    inner_width.saturating_sub(marker.chars().count() + net.chars().count() + 4);
                Line::from(vec![
                    Span::styled(
                        format!("  {marker}{}", pad_truncate(&name, name_w)),
                        if selected {
                            Style::default().add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        },
                    ),
                    Span::styled(net, Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{:>3}", indicator),
                        Style::default().fg(Color::Yellow),
                    ),
                ])
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
    frame.render_widget(Paragraph::new(lines), inner);
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
    if let Some(key) = focused {
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

    // Fixed-size sections first; Preview takes the remainder.
    const INFO_HEIGHT: u16 = 4;
    let policy_height = policy_height(model, key);
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
    render_info(model, key, frame, info_area);
    frame.render_widget(Paragraph::new(divider("Policy", inner.width)), policy_div);
    render_policy(model, key, frame, policy_area);
    frame.render_widget(
        Paragraph::new(divider("Preview (live screen snapshot)", inner.width)),
        preview_div,
    );
    render_preview_body(model, key, frame, preview_area);
}

/// The Policy section's rendered height in rows, so the stacked layout can
/// size it exactly.
fn policy_height(model: &Model, key: SessionKey) -> u16 {
    let detail = model.details.get(&key);
    let record = detail.and_then(|d| d.record.as_ref());
    if record.is_some() && record.map(|r| r.network) != Some(sessions::NetworkMode::OwnIp) {
        return 1;
    }
    match detail.and_then(|d| d.policy.as_ref()) {
        None => 1,
        Some(policy) => {
            let egress_rows = match &policy.egress {
                None => 2,
                Some(_) => 4,
            };
            let ingress_rows = match &policy.ingress {
                None => 2,
                Some(ingress) => {
                    1 + (ingress.port_mappings.len() as u16
                        + u16::from(ingress.dynamic_allowed_range.is_some()))
                    .max(1)
                }
            };
            egress_rows + ingress_rows
        }
    }
}

/// Shorten the user's home directory prefix to `~`, the way the spec's
/// mock renders project paths (`~/src/api`).
fn shorten_home(path: &str) -> String {
    match dirs::home_dir().and_then(|h| h.to_str().map(str::to_owned)) {
        Some(home) if path.starts_with(&home) => format!("~{}", &path[home.len()..]),
        _ => path.to_string(),
    }
}

fn render_info(model: &Model, key: SessionKey, frame: &mut Frame, area: Rect) {
    let detail = model.details.get(&key);
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
    let right = [("net", net), ("idle", idle_text(model, key))];

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

fn idle_text(model: &Model, key: SessionKey) -> String {
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
fn bell_text(model: &Model, key: SessionKey) -> String {
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

fn render_policy(model: &Model, key: SessionKey, frame: &mut Frame, area: Rect) {
    let detail = model.details.get(&key);
    let record = detail.and_then(|d| d.record.as_ref());
    let mut lines: Vec<Line> = Vec::new();

    let network_known = record.is_some();
    if network_known && record.map(|r| r.network) != Some(sessions::NetworkMode::OwnIp) {
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

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn policy_list(lines: &mut Vec<Line>, label: &str, values: &Option<Vec<String>>) {
    match values {
        None => lines.push(Line::raw(format!("  {label}  allow all"))),
        Some(values) => lines.push(Line::raw(format!("  {label}  {}", values.join(", ")))),
    }
}

/// The Preview section's body (its divider is drawn by [`render_detail`]).
fn render_preview_body(model: &Model, key: SessionKey, frame: &mut Frame, area: Rect) {
    let Some(fetch) = model.screens.get(&key) else {
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
}

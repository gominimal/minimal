//! `min box show`: one box record with its state, how it ended and the
//! identity it runs under, and the provider and host it runs on (BOX-159,
//! rendered as BCLI-003 pulls it forward into the first slice). The box is
//! found by its address on any local host (BCLI-002, BCLI-064).

use super::*;

/// Shows one box: its record, its state with how it ended, and its
/// identity, and the provider and host it runs on. `target` is a box
/// address: the box's id, a unique start of its id, its name, or
/// `provider/host/name`, looked up on every local host.
pub async fn cmd_box_show(global: &GlobalArgs, args: BoxShowArgs) -> Result<(), anyhow::Error> {
    use minimald_rpc::{Errorable, ShowBox, ShowBoxRequest};

    ensure_daemon(global)?;
    let ResolvedBox { host, box_id: id } =
        resolve_box_on_local_hosts(global, &args.target, "box show").await?;
    let mut client = box_host_client(&host).await?;
    let shown = match client
        .oneshot_rpc::<ShowBox>(ShowBoxRequest { id })
        .await
        .context("ShowBox RPC failed")?
    {
        Errorable::Ok(shown) => shown,
        Errorable::Err { error } if error.starts_with(minimald_rpc::UNKNOWN_SESSION_ID_LEAD) => {
            // The box was removed after the address resolved.
            tracing::info!(verb = "box show", box_id = %id, outcome = "not found");
            return Err(BoxAddressRefusal::NotFound {
                address: args.target,
            }
            .into());
        }
        Errorable::Err { error } => {
            tracing::info!(verb = "box show", box_id = %id, outcome = "error", "{error}");
            bail!("{error}")
        }
    };
    if args.network {
        // BCLI-025: the network section the box was created with.
        let mut section = Vec::new();
        show_stored_network(&mut section, &mut client, id, &args.target).await?;
        tracing::info!(verb = "box show", box_id = %id, network = true, outcome = "ok", host = %host.host);
        std::io::Write::write_all(&mut std::io::stdout().lock(), &section)?;
        return Ok(());
    }
    tracing::info!(verb = "box show", box_id = %id, outcome = "ok", host = %host.host);
    let mut out = std::io::stdout().lock();
    match args.output {
        None => render_box_show(&mut out, &shown, host.provider, &host.host)?,
        Some(format) => render_box_show_as(&mut out, format, &shown, host.provider, &host.host)?,
    }
    Ok(())
}

/// One box as `min box show -o` writes it (BCLI-033): the `min/v1/box`
/// object with the fields the text form shows, and the box's live execs
/// as `min/v1/exec` objects in `execs`. A value the record does not carry
/// is `null` in JSON, and is left out of YAML.
#[derive(Debug, serde::Serialize)]
pub(crate) struct ShownBoxDoc {
    schema: &'static str,
    id: String,
    name: Option<String>,
    #[serde(rename = "type")]
    box_type: Option<String>,
    parent: Option<String>,
    project: Option<String>,
    state: String,
    reason: Option<String>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    disk_bytes: Option<u64>,
    identity: &'static str,
    provider: String,
    host: String,
    execs: Vec<ShownExecDoc>,
}

/// One live exec of a box, as a `min/v1/exec` object (BCLI-033, BCLI-053).
/// `mode` is `terminal`, `detached` or `attached`, as the text form says.
#[derive(Debug, serde::Serialize)]
pub(crate) struct ShownExecDoc {
    schema: &'static str,
    id: String,
    mode: &'static str,
    argv: Vec<String>,
}

/// How an exec meets its client, in the words `min box show` prints.
fn exec_mode_word(mode: &minimald_rpc::exec::ExecMode) -> &'static str {
    match mode {
        minimald_rpc::exec::ExecMode::Tty => "terminal",
        minimald_rpc::exec::ExecMode::Detached => "detached",
        minimald_rpc::exec::ExecMode::Attached => "attached",
    }
}

/// The identity a box runs under, in the words `min box show` prints.
fn identity_word(identity: &minimald_rpc::BoxIdentity) -> &'static str {
    match identity {
        minimald_rpc::BoxIdentity::None => "none",
        minimald_rpc::BoxIdentity::Unknown => "unknown",
    }
}

/// The document `min box show -o` writes for `shown`, on `host` of
/// `provider`.
pub(crate) fn shown_box_doc(
    shown: &minimald_rpc::ShowBoxResponse,
    provider: &str,
    host: &str,
) -> ShownBoxDoc {
    use crate::output::ObjectType;
    let record = &shown.record;
    ShownBoxDoc {
        schema: ObjectType::Box.schema(),
        id: record.box_id.to_string(),
        name: record.name.clone(),
        box_type: record.box_type.clone(),
        parent: record.parent.map(|parent| parent.to_string()),
        project: record.project_root.as_ref().map(|root| root.to_string()),
        state: record.state.clone(),
        reason: record.reason.clone(),
        exit_code: record.exit_code,
        signal: record.signal,
        disk_bytes: shown.disk_bytes,
        identity: identity_word(&shown.identity),
        provider: provider.to_owned(),
        host: host.to_owned(),
        execs: shown
            .live_execs
            .iter()
            .map(|exec| ShownExecDoc {
                schema: ObjectType::Exec.schema(),
                id: exec.id.clone(),
                mode: exec_mode_word(&exec.mode),
                argv: exec.argv.clone(),
            })
            .collect(),
    }
}

/// Writes one box in `format`: one pretty JSON object or one YAML
/// mapping. Both carry the same document.
///
/// # Errors
///
/// Fails when the document does not encode or `out` fails.
pub(crate) fn render_box_show_as(
    out: &mut impl std::io::Write,
    format: BoxShowOutputFormat,
    shown: &minimald_rpc::ShowBoxResponse,
    provider: &str,
    host: &str,
) -> std::io::Result<()> {
    let doc = shown_box_doc(shown, provider, host);
    match format {
        BoxShowOutputFormat::Json => {
            serde_json_lenient::to_writer_pretty(&mut *out, &doc)?;
            writeln!(out)
        }
        BoxShowOutputFormat::Yaml => {
            let text = toml::to_string(&doc).map_err(std::io::Error::other)?;
            let table: toml_edit::DocumentMut = text.parse().map_err(std::io::Error::other)?;
            let mut yaml = String::new();
            yaml_table(&mut yaml, table.as_table(), 0);
            out.write_all(yaml.as_bytes())
        }
    }
}

/// Writes `table` as a YAML block mapping at `indent`, in the order of
/// its keys. The keys of a box document are plain words, so they need no
/// quotes.
fn yaml_table(out: &mut String, table: &toml_edit::Table, indent: usize) {
    let pad = " ".repeat(indent);
    for (key, item) in table.iter() {
        match item {
            toml_edit::Item::Value(value) => {
                out.push_str(&format!("{pad}{key}:"));
                yaml_value(out, value, indent + 2);
            }
            toml_edit::Item::Table(inner) => {
                out.push_str(&format!("{pad}{key}:\n"));
                yaml_table(out, inner, indent + 2);
            }
            toml_edit::Item::ArrayOfTables(tables) => {
                out.push_str(&format!("{pad}{key}:\n"));
                for inner in tables.iter() {
                    let mut nested = String::new();
                    yaml_table(&mut nested, inner, indent + 2);
                    // The first key goes on the line of its dash.
                    out.push_str(&format!("{pad}- "));
                    out.push_str(nested.get(indent + 2..).unwrap_or_default());
                }
            }
            toml_edit::Item::None => {}
        }
    }
}

/// Writes the rest of the line for `value`: ` <scalar>` and a newline, or
/// a newline and a block sequence at `indent` for a non-empty array.
fn yaml_value(out: &mut String, value: &toml_edit::Value, indent: usize) {
    match value {
        toml_edit::Value::Array(items) if !items.is_empty() => {
            out.push('\n');
            for item in items.iter() {
                out.push_str(&format!("{}-", " ".repeat(indent)));
                yaml_value(out, item, indent + 2);
            }
        }
        toml_edit::Value::Array(_) => out.push_str(" []\n"),
        toml_edit::Value::InlineTable(inner) => {
            out.push('\n');
            yaml_table(out, &inner.clone().into_table(), indent);
        }
        toml_edit::Value::String(text) => out.push_str(&format!(" {}\n", yaml_quote(text.value()))),
        toml_edit::Value::Integer(number) => out.push_str(&format!(" {}\n", number.value())),
        toml_edit::Value::Boolean(flag) => out.push_str(&format!(" {}\n", flag.value())),
        toml_edit::Value::Float(number) => out.push_str(&format!(" {}\n", number.value())),
        toml_edit::Value::Datetime(time) => {
            out.push_str(&format!(" {}\n", yaml_quote(&time.value().to_string())));
        }
    }
}

/// `text` as a double-quoted YAML scalar. A control character is escaped,
/// so a command line in the document cannot reach a terminal raw.
fn yaml_quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for c in text.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            c if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{feff}') => {
                quoted.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

/// Writes the `[network]` section that box `id` stores on the host `client`
/// talks to (BCLI-025), overrides included. `target` is the address the
/// caller gave, for the refusal when the host has no such box.
///
/// # Errors
///
/// Fails when the record cannot be read, the host has no box `id`, or
/// `out` fails.
pub(crate) async fn show_stored_network(
    out: &mut impl std::io::Write,
    client: &mut client::Client,
    id: boxes::SessionId,
    target: &str,
) -> Result<(), anyhow::Error> {
    let record = stored_box_record(client, id)
        .await
        .inspect_err(|error| {
            tracing::info!(verb = "box show", box_id = %id, network = true, outcome = "error", "{error}");
        })?
        .ok_or_else(|| {
            // The box was removed after the address resolved.
            tracing::info!(verb = "box show", box_id = %id, network = true, outcome = "not found");
            BoxAddressRefusal::NotFound {
                address: target.to_owned(),
            }
        })?;
    write_stored_network(out, record.network, &record.policy)
}

/// The record box `id` has on the host `client` talks to, with the network
/// mode and the policy it was created with. `None` when the host has no box
/// with that id.
pub(crate) async fn stored_box_record(
    client: &mut client::Client,
    id: boxes::SessionId,
) -> Result<Option<boxes::Record>, anyhow::Error> {
    use minimald_rpc::{GetSessionRecord, GetSessionRecordRequest};
    let response = client
        .oneshot_rpc::<GetSessionRecord>(GetSessionRecordRequest::Id(id))
        .await
        .context("GetSessionRecord RPC failed")?;
    Ok(response.record)
}

/// The id of the box `target` names in one host's `listing`, as
/// [`match_on_host`] finds it, except that a full id that is not listed is
/// still given back. When no box matches, the refusal names `host` and ends
/// with `remedy`.
#[cfg(test)]
pub(crate) fn find_listed_box(
    listing: &[minimald_rpc::BoxListingEntry],
    target: &str,
    host: &str,
    remedy: &str,
) -> Result<boxes::SessionId, anyhow::Error> {
    if let Ok(id) = boxes::SessionId::parse_str(target) {
        return Ok(id);
    }
    match match_on_host(listing, target) {
        HostMatch::One(id) => Ok(id),
        HostMatch::SeveralIdStarts => bail!(
            "More than one box has an id that starts with `{target}`. \
             Run `min box show` with more of the id."
        ),
        HostMatch::None => bail!("No box has the name or id `{target}` on host {host}. {remedy}"),
    }
}

/// The next step the single-host not-found refusal of
/// [`find_listed_box`] gives on `host`. With several hosts, the box can be
/// on another VM, so the refusal names `--vm`. A named VM's host is
/// `<name>.<base>`, as `ssh_host_alias` names it.
#[cfg(test)]
pub(crate) fn not_found_remedy(host: &str, several_hosts: bool) -> String {
    if !several_hosts {
        return "Run `min box list --all` to see the boxes on this host.".to_owned();
    }
    let base = host.rsplit('.').next().unwrap_or(host);
    format!(
        "Run `min box list --all` to see the boxes on every host. \
         For a box on host <name>.{base}, run `min box show` again with `--vm <name>`."
    )
}

/// Writes one box record as `Label: value` lines, with the `provider`
/// and `host` it came from. A value the record does not carry prints as
/// `-`. A `Live execs:` block follows when the box runs execs, with one
/// row for each: its exec id, `terminal`, `detached` or `attached`, and its
/// command.
pub(crate) fn render_box_show(
    out: &mut impl std::io::Write,
    shown: &minimald_rpc::ShowBoxResponse,
    provider: &str,
    host: &str,
) -> std::io::Result<()> {
    let record = &shown.record;
    let or_none = |value: Option<String>| value.unwrap_or_else(|| NO_VALUE.to_string());
    let identity = identity_word(&shown.identity);
    let mut lines = vec![
        ("ID", record.box_id.to_string()),
        ("Name", or_none(record.name.clone())),
        ("Type", or_none(record.box_type.clone())),
        (
            "Parent",
            or_none(record.parent.map(|parent| parent.to_string())),
        ),
        (
            "Project",
            or_none(record.project_root.as_ref().map(|root| root.to_string())),
        ),
        ("State", record.state.clone()),
    ];
    if matches!(record.state.as_str(), "stopped" | "exited") {
        lines.push(("Reason", or_none(record.reason.clone())));
        lines.push((
            "Exit code",
            or_none(record.exit_code.map(|c| c.to_string())),
        ));
        lines.push(("Signal", or_none(record.signal.map(|s| s.to_string()))));
        // BCLI-006: the disk a reap of the box frees. The daemon gives it
        // only for a stopped or exited box, and `-` means it did not.
        lines.push(("Disk", or_none(shown.disk_bytes.map(format_disk))));
    }
    lines.push(("Identity", identity.to_string()));
    lines.push(("Provider", provider.to_string()));
    lines.push(("Host", host.to_string()));
    for (label, value) in lines {
        let label = format!("{label}:");
        writeln!(out, "{label:<11} {value}")?;
    }
    // BCLI-067: one row for each live exec, with its id, whether it holds a
    // terminal, and its command.
    if !shown.live_execs.is_empty() {
        writeln!(out, "Live execs:")?;
        for exec in &shown.live_execs {
            let mode = exec_mode_word(&exec.mode);
            let command: Vec<String> = exec.argv.iter().map(|word| shell_word(word)).collect();
            writeln!(out, "  {}  {mode:<8}  {}", exec.id, command.join(" "))?;
        }
    }
    Ok(())
}

/// `word` as a shell reads it back as one word: as it is when it holds only
/// safe characters, in single quotes when its other characters print, and
/// in `$'...'` with escapes when it holds a control character. So a newline
/// or a terminal escape in an exec's argv never breaks the row or reaches
/// the terminal raw.
fn shell_word(word: &str) -> String {
    let safe = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c));
    if safe {
        return word.to_owned();
    }
    if !word.chars().any(char::is_control) {
        return format!("'{}'", word.replace('\'', r"'\''"));
    }
    let mut quoted = String::from("$'");
    for c in word.chars() {
        match c {
            '\\' => quoted.push_str(r"\\"),
            '\'' => quoted.push_str(r"\'"),
            '\n' => quoted.push_str(r"\n"),
            '\t' => quoted.push_str(r"\t"),
            '\r' => quoted.push_str(r"\r"),
            c if c.is_control() => {
                let code = u32::from(c);
                if code <= 0xff {
                    quoted.push_str(&format!(r"\x{code:02x}"));
                } else {
                    quoted.push_str(&format!(r"\u{code:04x}"));
                }
            }
            c => quoted.push(c),
        }
    }
    quoted.push('\'');
    quoted
}

/// Formats a disk figure in bytes in the largest binary unit that keeps it
/// at 1 or more, with one decimal above bytes: `512 B`, `4.0 KiB`,
/// `1.5 GiB`.
pub(crate) fn format_disk(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = UNITS[0];
    for next in &UNITS[1..] {
        // Pick the unit from the value as it prints, rounded to one
        // decimal, so 1048575 bytes prints `1.0 MiB`, not `1024.0 KiB`.
        if (value * 10.0).round() / 10.0 < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    format!("{value:.1} {unit}")
}

#[cfg(test)]
mod shell_word_tests {
    use super::shell_word;

    #[test]
    fn box_show_exec_command_escapes_control_characters() {
        assert_eq!(shell_word("ls"), "ls");
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("it's"), r"'it'\''s'");
        assert_eq!(shell_word("a\nb"), r"$'a\nb'");
        assert_eq!(shell_word("\u{1b}[2J"), r"$'\x1b[2J'");
        assert_eq!(shell_word("x\\'\u{7f}"), r"$'x\\\'\x7f'");
    }
}

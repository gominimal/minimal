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

    // The policy has a text form and a JSON document, and no YAML one: the
    // usage error comes before any box is looked up.
    if args.network && args.output == Some(BoxShowOutputFormat::Yaml) {
        return Err(NetworkFlagRefusal {
            message: "`min box show --network` does not write YAML. \
                      Run it with `-o json`, or with no `-o` for text."
                .to_owned(),
        }
        .into());
    }
    ensure_daemon(global)?;
    let ResolvedBox { host, box_id: id } =
        resolve_box_on_local_hosts(global, &args.target, "box show").await?;
    let mut client = box_host_client(&host).await?;
    if args.network {
        // BCLI-025: the box's effective network policy, with the ports it
        // published while running.
        let record = stored_box_record(&mut client, id)
            .await
            .inspect_err(|error| {
                tracing::info!(verb = "box show", box_id = %id, network = true, outcome = "error", "{error}");
            })?
            .ok_or_else(|| {
                // The box was removed after the address resolved.
                tracing::info!(verb = "box show", box_id = %id, network = true, outcome = "not found");
                BoxAddressRefusal::NotFound {
                    address: args.target.clone(),
                }
            })?;
        let mut out = std::io::stdout();
        write_box_network(
            &mut out,
            &mut client,
            &record,
            local_host_kind(&host),
            args.output == Some(BoxShowOutputFormat::Json),
        )
        .await?;
        tracing::info!(verb = "box show", box_id = %id, network = true, outcome = "ok", host = %host.host);
        return Ok(());
    }
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
/// `mode` is `tty`, `detached` or `attached`, as the text form says.
#[derive(Debug, serde::Serialize)]
pub(crate) struct ShownExecDoc {
    schema: &'static str,
    id: String,
    mode: &'static str,
    argv: Vec<String>,
}

/// How an exec meets its client, in the words `min box show` prints. A
/// terminal exec is `tty`, the word its `exec_started` event stores and
/// `min box exec --tty` takes (BCLI-067).
fn exec_mode_word(mode: &minimald_rpc::exec::ExecMode) -> &'static str {
    match mode {
        minimald_rpc::exec::ExecMode::Tty => "tty",
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

/// The kind of daemon `host` is: a VM host for the `local-minvmd`
/// provider, else the native daemon.
pub(crate) fn local_host_kind(host: &crate::cmd::list::LocalHost) -> paths::HostKind {
    if host.provider == crate::cmd::list::LOCAL_MINVMD_PROVIDER {
        paths::HostKind::Minvmd
    } else {
        paths::HostKind::Minimald
    }
}

/// Writes the effective network policy of the box `record` names, on the
/// host `client` talks to, a host of `host_kind` (BCLI-025): the rules the
/// gate enforces, the ports the box published while running, and the
/// listen ports the audit log held back. With `json`, it writes the one
/// `min/v1/session-policy` document in their place.
///
/// `min box show <box> --network` and `min session policy` both render
/// through this.
///
/// # Errors
///
/// Fails when the daemon cannot give the effective policy, or `out` fails.
pub(crate) async fn write_box_network(
    out: &mut impl std::io::Write,
    client: &mut client::Client,
    record: &boxes::Record,
    host_kind: paths::HostKind,
    json: bool,
) -> Result<(), anyhow::Error> {
    // BCLI-024: the VPN networks the box's stored spec keeps, from the
    // entry and from `--vpn-network-names`.
    let vpn_network_names = stored_vpn_network_names(client, record.id).await;
    if json {
        return write_box_policy_json(out, client, record, host_kind, &vpn_network_names).await;
    }
    // The follow-up lookups go by the resolved id, so a box named by an id
    // prefix reaches the same box they do.
    let box_id = record.id.to_string();

    // The daemon resolves the effective egress (NET-074/NET-077), because
    // the rollout phase and its opt-out are the daemon's own facts.
    use minimald_rpc::{GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest};
    let lookup = match SessionLookup::parse(&box_id) {
        SessionLookup::Id(id) => GetEffectiveSessionPolicyRequest::Id(id),
        SessionLookup::Name(n) => GetEffectiveSessionPolicyRequest::Name(n),
    };
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(lookup)
        .await
        .context("GetEffectiveSessionPolicy RPC failed")?;

    // NET-079's per-box enforcement answers beside the rules, over its own
    // runtime-facts reply — never as a field on the policy, because the
    // policy struct is `deny_unknown_fields`. A client that cannot get it
    // — an older daemon, a box mid-teardown — renders the rules with no
    // enforcement row, silently.
    let facts_lookup = match SessionLookup::parse(&box_id) {
        SessionLookup::Id(id) => minimald_rpc::GetSessionRuntimeFactsRequest::Id(id),
        SessionLookup::Name(n) => minimald_rpc::GetSessionRuntimeFactsRequest::Name(n),
    };
    let facts = match client
        .oneshot_rpc::<minimald_rpc::GetSessionRuntimeFacts>(facts_lookup)
        .await
    {
        Ok(minimald_rpc::Errorable::Ok(facts)) => Some(facts),
        Ok(minimald_rpc::Errorable::Err { .. }) | Err(_) => None,
    };
    // (NET-044) — the rows that make a `min net expose` visible rather than
    // only permitted. The text walk warns on stderr and prints no section
    // when the daemon cannot list them.
    let live = fetch_live_ingress_degrading(client, &box_id).await;

    // NET-171: a read that fails shows no build box. The box's own policy
    // stands either way.
    let build_boxes = match client
        .oneshot_rpc::<minimald_rpc::ShowBox>(minimald_rpc::ShowBoxRequest { id: record.id })
        .await
    {
        Ok(minimald_rpc::Errorable::Ok(shown)) => shown.record.build_boxes,
        Ok(minimald_rpc::Errorable::Err { .. }) | Err(_) => Vec::new(),
    };

    let policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => bail!("{error}"),
    };
    render_box_network(
        out,
        &policy,
        record.network,
        facts.as_ref(),
        &live,
        &build_boxes,
        host_kind,
    )?;
    write_vpn_network_names(out, &vpn_network_names)
}

/// The `network.vpn_network_names` of the spec box `id` stores, in its
/// order (BCLI-024). Empty when the box stores no spec, its spec lists no
/// names, or the host cannot give the spec. A failure goes to the log, and
/// the policy still shows.
pub(crate) async fn stored_vpn_network_names(
    client: &mut client::Client,
    id: boxes::SessionId,
) -> Vec<String> {
    use minimald_rpc::{Errorable, GetBoxSpec, GetBoxSpecRequest};
    let spec = match client
        .oneshot_rpc::<GetBoxSpec>(GetBoxSpecRequest { id })
        .await
    {
        Ok(Errorable::Ok(reply)) => reply.spec,
        Ok(Errorable::Err { error }) => {
            tracing::debug!(box_id = %id, "vpn networks: the box's spec is not readable: {error}");
            None
        }
        Err(e) => {
            tracing::debug!(box_id = %id, "vpn networks: could not read the box's spec: {e:#}");
            None
        }
    };
    spec.as_ref()
        .and_then(|spec| {
            spec.get("network")?
                .get("vpn_network_names")?
                .as_array()
                .cloned()
        })
        .unwrap_or_default()
        .iter()
        .filter_map(|name| name.as_str().map(str::to_owned))
        .collect()
}

/// Writes the text rows of the box's VPN networks, one name to a row,
/// under the policy (BCLI-024). Writes nothing when `names` is empty.
///
/// # Errors
///
/// Fails when `out` fails.
pub(crate) fn write_vpn_network_names(
    out: &mut impl std::io::Write,
    names: &[String],
) -> Result<(), anyhow::Error> {
    if names.is_empty() {
        return Ok(());
    }
    // `minimald` keeps the names and does not connect the box to a VPN.
    writeln!(out, "vpn networks (not connected yet)").context(OutputWriteError)?;
    for name in names {
        writeln!(out, "  {name}").context(OutputWriteError)?;
    }
    out.flush().context(OutputWriteError)?;
    Ok(())
}

/// Writes the text form of a box's effective network policy: `policy` for a
/// box of `network` mode on a host of `host_kind`, with the runtime `facts`
/// the host gave, if any, the `live` ports the box published, and the
/// `build_boxes` running for it.
///
/// # Errors
///
/// Fails when `out` fails.
pub(crate) fn render_box_network(
    out: &mut impl std::io::Write,
    policy: &boxes::EffectiveBoxPolicy,
    network: boxes::NetworkMode,
    facts: Option<&minimald_rpc::BoxRuntimeFacts>,
    live: &[minimald_rpc::LiveMapping],
    build_boxes: &[minimald_rpc::RunningBuildBox],
    host_kind: paths::HostKind,
) -> Result<(), anyhow::Error> {
    let host_ip_enforcement = facts.and_then(|facts| facts.host_ip_enforcement);
    let shared_port_collisions = facts
        .map(|facts| facts.shared_port_collisions.as_slice())
        .unwrap_or_default();
    // The fabric the display builds the baseline set from: the microVM
    // backend's run path builds its registry and the helper's enumeration
    // from the default plan, so that is the plan the display can name for
    // it. The native daemon's own per-daemon switch is a plan the reply
    // does not carry, so that arm passes `None` and the block is left out.
    let fabric = (host_kind == paths::HostKind::Minvmd).then_some(switch::SwitchSubnet::default());
    // NET-160: the host exposures row turns on the host kind itself, not on
    // `fabric`.
    let native_host = host_kind == paths::HostKind::Minimald;
    format_policy_on_host(
        out,
        policy,
        network,
        host_ip_enforcement,
        shared_port_collisions,
        fabric,
        native_host,
    )?;
    write_live_ingress(out, live)?;
    write_build_boxes(out, build_boxes)?;
    if let Some(facts) = facts {
        write_unaudited_listen_ports(
            out,
            &facts.unaudited_listen_ports,
            facts.audit_log.as_deref(),
        )?;
    }
    out.flush().context("Failed to write policy")?;
    Ok(())
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
/// row for each: its exec id, `tty`, `detached` or `attached`, and its
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
    write_build_boxes(out, &record.build_boxes)
}

/// What one build box may reach, in a person's words (NET-171).
fn build_box_reach(build: &minimald_rpc::RunningBuildBox) -> String {
    if build.no_network {
        return "no network".to_string();
    }
    // A build with no grant yet, or none to get, is on this box's rules.
    if !build.granted {
        return "no grant, this box's rules".to_string();
    }
    let Some(egress) = &build.egress else {
        return "any destination".to_string();
    };
    let internet = egress
        .allow_subnets
        .as_ref()
        .is_some_and(|subnets| subnets.iter().any(|subnet| subnet == "0.0.0.0/0"));
    let hosts = egress.allow_dns_hosts.clone().unwrap_or_default();
    if internet {
        "the public internet".to_string()
    } else if hosts.is_empty() {
        "no destination".to_string()
    } else {
        hosts.join(", ")
    }
}

/// Writes the block of the build boxes running for a box, and nothing when
/// none runs (NET-171). Their reach is theirs: the box's own rules do not
/// change.
pub(crate) fn write_build_boxes(
    out: &mut impl std::io::Write,
    builds: &[minimald_rpc::RunningBuildBox],
) -> std::io::Result<()> {
    if builds.is_empty() {
        return Ok(());
    }
    writeln!(out, "build boxes (their own reach, not this box's)")?;
    for build in builds {
        writeln!(out, "  {}: {}", build.package, build_box_reach(build))?;
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
mod build_box_tests {
    use super::*;

    /// NET-171: the block says what each build box may reach, and that it
    /// is the build box's reach. No build box, no block.
    #[test]
    fn policy_shows_build_box_egress() {
        let declared = boxes::EgressPolicy {
            allow_subnets: Some(Vec::new()),
            allow_dns_hosts: Some(vec!["storage.googleapis.com".to_string()]),
            allow_protocols: None,
            deny_subnets: None,
        };
        let internet = boxes::EgressPolicy {
            allow_subnets: Some(vec!["0.0.0.0/0".to_string()]),
            allow_dns_hosts: Some(Vec::new()),
            allow_protocols: None,
            deny_subnets: None,
        };
        let nothing = boxes::EgressPolicy {
            allow_subnets: Some(Vec::new()),
            allow_dns_hosts: Some(Vec::new()),
            allow_protocols: None,
            deny_subnets: None,
        };
        let running = |package: &str, egress, granted| minimald_rpc::RunningBuildBox {
            package: package.to_string(),
            egress,
            granted,
            no_network: false,
        };
        let ended = minimald_rpc::RunningBuildBox {
            no_network: true,
            ..running("fetched", Some(nothing.clone()), true)
        };
        let mut out = Vec::new();
        write_build_boxes(
            &mut out,
            &[
                running("bucket", Some(declared), true),
                running("tooling", Some(internet), true),
                running("mine", None, false),
                running("unlisted", Some(nothing), true),
                ended,
            ],
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "build boxes (their own reach, not this box's)\n  \
             bucket: storage.googleapis.com\n  \
             tooling: the public internet\n  \
             mine: no grant, this box's rules\n  \
             unlisted: no destination\n  \
             fetched: no network\n"
        );

        let mut none = Vec::new();
        write_build_boxes(&mut none, &[]).unwrap();
        assert!(none.is_empty());
    }
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

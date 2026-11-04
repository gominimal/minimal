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
    tracing::info!(verb = "box show", box_id = %id, outcome = "ok", host = %host.host);
    let mut out = std::io::stdout().lock();
    render_box_show(&mut out, &shown, host.provider, &host.host)?;
    Ok(())
}

/// The id of the box `target` names in one host's `listing`, as
/// [`match_on_host`] finds it, except that a full id that is not listed is
/// still given back. When no box matches, the refusal names `host` and ends
/// with `remedy`. This is the single-host lookup that `min box stop` and
/// `min box rm` use.
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
/// `-`. The live execs line prints only when
/// the daemon names an exec, because today's daemon gives no exec an id.
pub(crate) fn render_box_show(
    out: &mut impl std::io::Write,
    shown: &minimald_rpc::ShowBoxResponse,
    provider: &str,
    host: &str,
) -> std::io::Result<()> {
    let record = &shown.record;
    let or_none = |value: Option<String>| value.unwrap_or_else(|| NO_VALUE.to_string());
    let identity = match shown.identity {
        minimald_rpc::BoxIdentity::None => "none",
        minimald_rpc::BoxIdentity::Unknown => "unknown",
    };
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
    }
    lines.push(("Identity", identity.to_string()));
    lines.push(("Provider", provider.to_string()));
    lines.push(("Host", host.to_string()));
    if !shown.live_execs.is_empty() {
        lines.push(("Live execs", shown.live_execs.join(", ")));
    }
    for (label, value) in lines {
        let label = format!("{label}:");
        writeln!(out, "{label:<11} {value}")?;
    }
    Ok(())
}

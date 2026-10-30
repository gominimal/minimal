//! `min box show`: one box record with its state, how it ended and the
//! identity it runs under (BOX-159, rendered as BCLI-003 pulls it forward
//! into the first slice).

use super::*;

/// Shows one box: its record, its state with how it ended, and its
/// identity. `target` is the box's id, a unique start of its id, or its
/// name.
pub async fn cmd_box_show(global: &GlobalArgs, args: BoxShowArgs) -> Result<(), anyhow::Error> {
    use minimald_rpc::{Errorable, ShowBox, ShowBoxRequest};

    ensure_daemon(global)?;
    let mut client = connect_daemon(global).await?;
    // A box name is not scoped to a project, so the lookup reads every box.
    let listing = list_box_records(&mut client, None).await?;
    let id = find_listed_box(&listing, &args.target)?;
    let shown = match client
        .oneshot_rpc::<ShowBox>(ShowBoxRequest { id })
        .await
        .context("ShowBox RPC failed")?
    {
        Errorable::Ok(shown) => shown,
        Errorable::Err { error } if error.starts_with(minimald_rpc::UNKNOWN_SESSION_ID_LEAD) => {
            bail!(
                "No box has the id `{id}`. Run `min box list --all` to see the boxes on this host."
            )
        }
        Errorable::Err { error } => bail!("{error}"),
    };
    let mut out = std::io::stdout().lock();
    render_box_show(&mut out, &shown)?;
    Ok(())
}

/// The id of the box `target` names in `listing`: a full id as given,
/// else the box with that name compared without ASCII case, as the daemon
/// compares names, else the one box whose id starts with it. The id start is
/// compared without dashes and ignoring case, as `min session attach`
/// compares it. Several boxes can hold one name over time, so a name
/// resolves to the running box that holds it, else to the most recent
/// creation, which is the greatest id.
pub(crate) fn find_listed_box(
    listing: &[minimald_rpc::BoxListingEntry],
    target: &str,
) -> Result<boxes::SessionId, anyhow::Error> {
    if let Ok(id) = boxes::SessionId::parse_str(target) {
        return Ok(id);
    }
    let folded = |entry: &&minimald_rpc::BoxListingEntry| {
        entry
            .name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(target))
    };
    if let Some(id) = newest_named(listing.iter().filter(folded)) {
        return Ok(id);
    }
    if is_id_prefix(target) {
        let start = target.replace('-', "").to_ascii_lowercase();
        let mut matches = listing.iter().filter(|entry| {
            entry
                .box_id
                .as_ref()
                .simple()
                .to_string()
                .starts_with(&start)
        });
        if let Some(first) = matches.next() {
            if matches.next().is_some() {
                bail!(
                    "More than one box has an id that starts with `{target}`. \
                     Run `min box show` with more of the id."
                );
            }
            return Ok(first.box_id);
        }
    }
    bail!(
        "No box has the name or id `{target}`. \
         Run `min box list --all` to see the boxes on this host."
    )
}

/// Of the boxes that hold one name, the running one, else the one with the
/// greatest id. Box ids are UUIDv7, so the greatest id is the latest
/// creation.
fn newest_named<'a>(
    named: impl Iterator<Item = &'a minimald_rpc::BoxListingEntry>,
) -> Option<boxes::SessionId> {
    named
        .max_by_key(|entry| (entry.state == "running", *entry.box_id.as_ref()))
        .map(|entry| entry.box_id)
}

/// Writes one box record as `Label: value` lines. A value the record
/// does not carry prints as `-`. The live execs line prints only when
/// the daemon names an exec, because today's daemon gives no exec an id.
pub(crate) fn render_box_show(
    out: &mut impl std::io::Write,
    shown: &minimald_rpc::ShowBoxResponse,
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
    if !shown.live_execs.is_empty() {
        lines.push(("Live execs", shown.live_execs.join(", ")));
    }
    for (label, value) in lines {
        let label = format!("{label}:");
        writeln!(out, "{label:<11} {value}")?;
    }
    Ok(())
}

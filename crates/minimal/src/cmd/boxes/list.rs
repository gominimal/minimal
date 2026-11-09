//! `min box list`: the box records the daemon of each local host keeps for
//! the current project, or for every project with `--all`, in any state
//! (BOX-158, rendered as BCLI-001 and BCLI-051 pull it forward into the
//! first slice).

use super::*;

/// The `schema` every `min box list -o json` object carries (BCLI-001).
pub(crate) const BOX_SCHEMA: &str = "min/v1/box";

/// One box record with the provider and host it came from. The daemon
/// knows only its own boxes, so the client attributes each record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListedBox {
    /// The provider that serves the box's host.
    pub provider: String,
    /// The host the box runs on.
    pub host: String,
    /// The record that host's daemon returned.
    pub record: minimald_rpc::BoxListingEntry,
}

/// Lists the boxes of the current project with their state, one row for
/// each box on each local host. With `--all`, lists every box.
pub async fn cmd_box_list(global: &GlobalArgs, args: BoxListArgs) -> Result<(), anyhow::Error> {
    let scope = if args.all {
        None
    } else {
        let cwd = crate::attach::cwd_host_path(global)?;
        Some(box_list_scope(cwd.as_ref())?)
    };
    ensure_daemon(global)?;
    let scoped = scope.is_some();
    let hosts = crate::cmd::list::local_hosts(global)?;
    let mut listed = Vec::new();
    for host in hosts {
        match list_host_boxes(&host, scope.clone()).await {
            Ok(records) => listed.extend(records.into_iter().map(|record| ListedBox {
                provider: host.provider.to_string(),
                host: host.host.clone(),
                record,
            })),
            Err(HostRead::Selected(err)) => {
                tracing::info!(verb = "box list", outcome = "error", host = %host.host, "{err:#}");
                return Err(err);
            }
            Err(HostRead::Unreachable(err)) => {
                tracing::info!(
                    verb = "box list",
                    outcome = "host unreachable",
                    host = %host.host,
                    "{err:#}"
                );
                eprintln!("{}", unreachable_host_line(&host.host));
            }
        }
    }
    tracing::info!(verb = "box list", outcome = "ok", boxes = listed.len());
    let mut out = std::io::stdout().lock();
    match args.output {
        Some(BoxListOutputFormat::Json) => render_box_list_json(&mut out, &listed)?,
        None => render_box_list(&mut out, &listed, scoped)?,
    }
    Ok(())
}

/// The stderr line for a host whose boxes the listing could not read.
pub(crate) fn unreachable_host_line(host: &str) -> String {
    format!("Could not reach host {host}; its boxes are not listed.")
}

/// Why one host gave no records.
enum HostRead {
    /// The selected host failed. [`ensure_daemon`] started it, so the
    /// command fails as it does with one host.
    Selected(anyhow::Error),
    /// Another host did not answer. The listing goes on without it.
    Unreachable(anyhow::Error),
}

/// The records of one host. A host that is not running holds no live
/// daemon to ask, so it gives none.
async fn list_host_boxes(
    host: &crate::cmd::list::LocalHost,
    scope: Option<paths::HostAbsPath>,
) -> Result<Vec<minimald_rpc::BoxListingEntry>, HostRead> {
    if host.selected {
        list_selected_host(&host.sock, scope)
            .await
            .map_err(HostRead::Selected)
    } else {
        list_other_host(&host.sock, scope)
            .await
            .map_err(HostRead::Unreachable)
    }
}

/// The records of the selected host, gated as `min ls` gates its selected
/// VM: connect with the retry window, then assert the daemon's build.
async fn list_selected_host(
    sock: &std::path::Path,
    scope: Option<paths::HostAbsPath>,
) -> Result<Vec<minimald_rpc::BoxListingEntry>, anyhow::Error> {
    let mut client = client::Client::connect(sock)
        .await
        .with_context(|| format!("Failed to connect to the daemon at {}", sock.display()))?;
    client::ensure_version_match(&mut client).await?;
    list_box_records(&mut client, scope).await
}

/// The records of a host this process did not start, probed ungated as
/// `min ls` probes its other VMs. A host that is not running gives none.
async fn list_other_host(
    sock: &std::path::Path,
    scope: Option<paths::HostAbsPath>,
) -> Result<Vec<minimald_rpc::BoxListingEntry>, anyhow::Error> {
    #[expect(
        clippy::map_err_ignore,
        reason = "the elapsed marker carries nothing the message lacks"
    )]
    let read = tokio::time::timeout(client::PROBE_TIMEOUT, async {
        let mut client = match client::Client::probe(sock).await {
            Ok(client) => client,
            Err(client::ProbeRefusal::NotRunning) => return Ok(Vec::new()),
            Err(client::ProbeRefusal::Unreachable(e)) => return Err(e),
        };
        list_box_records(&mut client, scope).await
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "daemon at {} did not answer within {:?}",
            sock.display(),
            client::PROBE_TIMEOUT
        )
    });
    read.and_then(|records| records)
}

/// The project root that a scoped listing sends for `dir`: the root a
/// create from `dir` stamps on its box, as `stamp_project_root` resolves
/// it, so the listing finds the boxes this project created.
pub(crate) fn box_list_scope(dir: &camino::Utf8Path) -> Result<paths::HostAbsPath, anyhow::Error> {
    let root = resolve_upload_root(dir)?;
    paths::HostAbsPath::try_new(root).context("Invalid project root")
}

/// The `ListBoxes` request for a listing scoped to `project_root`, or for
/// every box on the host when it is `None`.
pub(crate) fn list_boxes_request(
    project_root: Option<paths::HostAbsPath>,
) -> minimald_rpc::ListBoxesRequest {
    minimald_rpc::ListBoxesRequest { project_root }
}

/// The box records the daemon keeps, through `ListBoxes`: those of
/// `project_root`, or every box on the host when it is `None`.
pub(crate) async fn list_box_records(
    client: &mut client::Client,
    project_root: Option<paths::HostAbsPath>,
) -> Result<Vec<minimald_rpc::BoxListingEntry>, anyhow::Error> {
    use minimald_rpc::{Errorable, ListBoxes};

    match client
        .oneshot_rpc::<ListBoxes>(list_boxes_request(project_root))
        .await
        .context("ListBoxes RPC failed")?
    {
        Errorable::Ok(listing) => Ok(listing.boxes),
        Errorable::Err { error } => bail!("{error}"),
    }
}

/// The line a scoped listing prints when the current project has no box.
pub(crate) const EMPTY_PROJECT_LIST: &str = "This project has no boxes. \
     Run `min box list --all` to list the boxes of every project.";

/// The line `min box list --all` prints when no local host has a box.
pub(crate) const EMPTY_HOST_LIST: &str = "No boxes on this machine.";

/// A value the record does not carry prints as this.
pub(crate) const NO_VALUE: &str = "-";

/// The state as BOX-011 names it, with how a `stopped` or `exited` box
/// ended: `exited (exit 0)`, `exited (timeout)`, `exited (oom, exit 137)`,
/// `stopped (signal 15)`, `stopped (exit 3)`, or `stopped` alone when no
/// exit code and no signal ended it.
pub(crate) fn box_state_label(entry: &minimald_rpc::BoxListingEntry) -> String {
    let mut ending = Vec::new();
    // The reason `stopped` repeats the state, so only the other reasons
    // print.
    if let Some(reason) = entry.reason.as_deref()
        && reason != "exit"
        && reason != entry.state
    {
        ending.push(reason.to_string());
    }
    if let Some(code) = entry.exit_code {
        ending.push(format!("exit {code}"));
    }
    if let Some(signal) = entry.signal {
        ending.push(format!("signal {signal}"));
    }
    if ending.is_empty() {
        entry.state.clone()
    } else {
        format!("{} ({})", entry.state, ending.join(", "))
    }
}

/// Writes the listing as a table: a header row, then one row for each
/// box in the order the hosts returned them. With no box, one line says
/// so: for the current project when `scoped`, else for the host.
pub(crate) fn render_box_list(
    out: &mut impl std::io::Write,
    boxes: &[ListedBox],
    scoped: bool,
) -> std::io::Result<()> {
    if boxes.is_empty() {
        if scoped {
            return writeln!(out, "{EMPTY_PROJECT_LIST}");
        }
        return writeln!(out, "{EMPTY_HOST_LIST}");
    }
    let header = [
        "ID", "NAME", "TYPE", "PARENT", "PROJECT", "STATE", "PROVIDER", "HOST",
    ];
    let rows: Vec<[String; 8]> = boxes
        .iter()
        .map(|listed| {
            let entry = &listed.record;
            [
                entry.box_id.to_string(),
                entry.name.clone().unwrap_or_else(|| NO_VALUE.to_string()),
                entry
                    .box_type
                    .clone()
                    .unwrap_or_else(|| NO_VALUE.to_string()),
                entry
                    .parent
                    .map_or_else(|| NO_VALUE.to_string(), |parent| parent.to_string()),
                entry
                    .project_root
                    .as_ref()
                    .map_or_else(|| NO_VALUE.to_string(), |root| root.to_string()),
                box_state_label(entry),
                listed.provider.clone(),
                listed.host.clone(),
            ]
        })
        .collect();
    let mut widths = header.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: [&str; 8]| {
        let mut text = String::new();
        for (index, (cell, width)) in cells.iter().zip(widths).enumerate() {
            if index + 1 == cells.len() {
                text.push_str(cell);
            } else {
                text.push_str(&format!("{cell:<width$}  "));
            }
        }
        text
    };
    writeln!(out, "{}", line(header))?;
    for row in &rows {
        writeln!(out, "{}", line(row.each_ref().map(String::as_str)))?;
    }
    Ok(())
}

/// One box as its `"schema": "min/v1/box"` object. A value the record
/// does not carry is `null`.
pub(crate) fn box_json(listed: &ListedBox) -> serde_json_lenient::Value {
    let entry = &listed.record;
    serde_json_lenient::json!({
        "schema": BOX_SCHEMA,
        "id": entry.box_id.to_string(),
        "name": entry.name,
        "type": entry.box_type,
        "state": entry.state,
        "provider": listed.provider,
        "host": listed.host,
        "parent": entry.parent.map(|parent| parent.to_string()),
        "project": entry.project_root.as_ref().map(|root| root.to_string()),
        "reason": entry.reason,
        "exit_code": entry.exit_code,
        "signal": entry.signal,
    })
}

/// Writes the listing under `-o json`: one JSON array of the box objects,
/// and nothing else, also when the listing is empty.
pub(crate) fn render_box_list_json(
    out: &mut impl std::io::Write,
    boxes: &[ListedBox],
) -> std::io::Result<()> {
    let objects: Vec<serde_json_lenient::Value> = boxes.iter().map(box_json).collect();
    serde_json_lenient::to_writer_pretty(&mut *out, &objects)?;
    writeln!(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use minimald_rpc::{BoxIdentity, BoxListingEntry, ShowBoxResponse};

    /// `entry` as the native host `local0` lists it.
    fn local(entry: BoxListingEntry) -> ListedBox {
        ListedBox {
            provider: "local".to_string(),
            host: "local0".to_string(),
            record: entry,
        }
    }

    fn entry(id: &str, name: Option<&str>, box_type: &str, state: &str) -> BoxListingEntry {
        BoxListingEntry {
            box_id: boxes::SessionId::parse_str(id).unwrap(),
            name: name.map(str::to_string),
            box_type: Some(box_type.to_string()),
            parent: None,
            project_root: Some(paths::HostAbsPath::try_new("/home/dev/proj").unwrap()),
            state: state.to_string(),
            reason: None,
            exit_code: None,
            signal: None,
            pty_enabled: true,
        }
    }

    /// BOX-158, BOX-159 (BCLI-001, BCLI-003): the listing renders every
    /// retained record with its type, parent, project and state with its
    /// ending, and a read of one renders the same record with its
    /// identity. A name, an id and a unique start of an id each find the
    /// box the listing prints.
    #[test]
    fn box_list_and_show_render_retained_records() {
        let mut stopped = entry(
            "0199e0a0-0000-7000-8000-000000000001",
            Some("kept-session"),
            "session",
            "stopped",
        );
        stopped.reason = Some("stopped".to_string());
        stopped.signal = Some(15);
        let mut task = entry(
            "0199e0a0-0000-7000-8000-000000000002",
            None,
            "task",
            "exited",
        );
        task.reason = Some("exit".to_string());
        task.exit_code = Some(0);
        task.parent = Some(stopped.box_id);
        let mut oom = entry(
            "0199e0a0-0000-7000-8000-000000000003",
            Some("big-build"),
            "task",
            "exited",
        );
        oom.reason = Some("oom".to_string());
        oom.exit_code = Some(137);
        let mut restarted = entry(
            "0199e0b0-0000-7000-8000-000000000004",
            Some("left-task"),
            "task",
            "stopped",
        );
        restarted.reason = Some("stopped".to_string());
        let mut running = entry(
            "0199e0c0-0000-7000-8000-000000000005",
            Some("live"),
            "session",
            "running",
        );
        running.project_root = None;
        let listing = vec![
            stopped.clone(),
            task.clone(),
            oom,
            restarted.clone(),
            running,
        ];

        let rows: Vec<ListedBox> = listing.iter().cloned().map(local).collect();
        let mut out = Vec::new();
        render_box_list(&mut out, &rows, true).unwrap();
        let text = String::from_utf8(out).unwrap();
        let expected = "\
ID                                    NAME          TYPE     PARENT                                PROJECT         STATE                   PROVIDER  HOST
0199e0a0-0000-7000-8000-000000000001  kept-session  session  -                                     /home/dev/proj  stopped (signal 15)     local     local0
0199e0a0-0000-7000-8000-000000000002  -             task     0199e0a0-0000-7000-8000-000000000001  /home/dev/proj  exited (exit 0)         local     local0
0199e0a0-0000-7000-8000-000000000003  big-build     task     -                                     /home/dev/proj  exited (oom, exit 137)  local     local0
0199e0b0-0000-7000-8000-000000000004  left-task     task     -                                     /home/dev/proj  stopped                 local     local0
0199e0c0-0000-7000-8000-000000000005  live          session  -                                     -               running                 local     local0
";
        assert_eq!(text, expected);

        // An empty listing says so: for the project when scoped, and for
        // the host with `--all`.
        let mut out = Vec::new();
        render_box_list(&mut out, &[], true).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "This project has no boxes. \
             Run `min box list --all` to list the boxes of every project.\n"
        );
        let mut out = Vec::new();
        render_box_list(&mut out, &[], false).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "No boxes on this machine.\n"
        );

        // A scoped listing sends the root a create from the same directory
        // stamps. `--all` sends none.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(mfile::MFILE_NAME),
            "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
        )
        .unwrap();
        let root = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let mut create = minimald_rpc::CreateSessionRequest::new(
            "rooted",
            paths::HostAbsPath::try_new(sub.clone()).unwrap(),
            boxes::NetworkMode::HostNet,
            boxes::BoxPolicy::default(),
        );
        stamp_project_root(&mut create, &sub).unwrap();
        let scope = box_list_scope(&sub).unwrap();
        assert_eq!(
            Some(scope.clone()),
            Some(paths::HostAbsPath::try_new(root.to_path_buf()).unwrap())
        );
        assert_eq!(Some(scope.clone()), create.config.project_root);
        assert_eq!(
            list_boxes_request(Some(scope.clone())).project_root,
            Some(scope)
        );
        assert_eq!(list_boxes_request(None).project_root, None);

        // A read of the stopped session box.
        let shown = ShowBoxResponse {
            record: stopped.clone(),
            identity: BoxIdentity::None,
            live_execs: Vec::new(),
            disk_bytes: None,
        };
        let mut out = Vec::new();
        render_box_show(&mut out, &shown, "local", "local0").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\
ID:         0199e0a0-0000-7000-8000-000000000001
Name:       kept-session
Type:       session
Parent:     -
Project:    /home/dev/proj
State:      stopped
Reason:     stopped
Exit code:  -
Signal:     15
Disk:       -
Identity:   none
Provider:   local
Host:       local0
"
        );

        // A read of a child task box that exited, with a live exec.
        let shown = ShowBoxResponse {
            record: task.clone(),
            identity: BoxIdentity::Unknown,
            live_execs: vec!["exec-1".to_string()],
            disk_bytes: None,
        };
        let mut out = Vec::new();
        render_box_show(&mut out, &shown, "local", "local0").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\
ID:         0199e0a0-0000-7000-8000-000000000002
Name:       -
Type:       task
Parent:     0199e0a0-0000-7000-8000-000000000001
Project:    /home/dev/proj
State:      exited
Reason:     exit
Exit code:  0
Signal:     -
Disk:       -
Identity:   unknown
Provider:   local
Host:       local0
Live execs: exec-1
"
        );

        // The argument to `min box show` finds the box the listing prints.
        let remedy = not_found_remedy("local0", false);
        let find = |arg: &str| find_listed_box(&listing, arg, "local0", &remedy);
        assert_eq!(find("kept-session").unwrap(), stopped.box_id);
        assert_eq!(find(&task.box_id.to_string()).unwrap(), task.box_id);
        assert_eq!(find("0199e0b0").unwrap(), restarted.box_id);
        // A start that several ids share finds none.
        let shared = find("0199e0a0").unwrap_err().to_string();
        assert_eq!(
            shared,
            "More than one box has an id that starts with `0199e0a0`. \
             Run `min box show` with more of the id."
        );
        let missing = find("no-such-box").unwrap_err().to_string();
        assert_eq!(
            missing,
            "No box has the name or id `no-such-box` on host local0. \
             Run `min box list --all` to see the boxes on this host."
        );
        // With several hosts, the box can be on another VM, so the
        // refusal names `--vm`.
        let several = not_found_remedy("dev.local-minvmd0", true);
        let elsewhere = find_listed_box(&listing, "no-such-box", "dev.local-minvmd0", &several)
            .unwrap_err()
            .to_string();
        assert_eq!(
            elsewhere,
            "No box has the name or id `no-such-box` on host dev.local-minvmd0. \
             Run `min box list --all` to see the boxes on every host. \
             For a box on host <name>.local-minvmd0, run `min box show` again with `--vm <name>`."
        );
        // A start that runs past the first dash matches without the dash,
        // and a name matches ignoring case.
        assert_eq!(find("0199e0b00000").unwrap(), restarted.box_id);
        assert_eq!(find("KEPT-session").unwrap(), stopped.box_id);
        // A name that several boxes held resolves to the running box that
        // holds it, else to the most recent creation.
        let reused = |id: &str, state: &str| entry(id, Some("reused"), "session", state);
        let older = reused("0199e0d0-0000-7000-8000-000000000006", "stopped");
        let newer = reused("0199e0d0-0000-7000-8000-000000000007", "exited");
        let live = reused("0199e0d0-0000-7000-8000-000000000008", "running");
        let latest = reused("0199e0d0-0000-7000-8000-000000000009", "stopped");
        let ended = [older.clone(), newer.clone()];
        assert_eq!(
            find_listed_box(&ended, "reused", "local0", &remedy).unwrap(),
            newer.box_id
        );
        let with_live = [older, live.clone(), latest];
        assert_eq!(
            find_listed_box(&with_live, "reused", "local0", &remedy).unwrap(),
            live.box_id
        );
        // The daemon treats names that differ only in case as one name, so
        // a running `Dev` holds the name `dev` over a stopped `dev`.
        let stopped_dev = entry(
            "0199e0e0-0000-7000-8000-00000000000a",
            Some("dev"),
            "session",
            "stopped",
        );
        let running_dev = entry(
            "0199e0e0-0000-7000-8000-00000000000b",
            Some("Dev"),
            "session",
            "running",
        );
        let cased = [running_dev.clone(), stopped_dev];
        assert_eq!(
            find_listed_box(&cased, "dev", "local0", &remedy).unwrap(),
            running_dev.box_id
        );
        // An id that is not listed still goes to the daemon, which answers
        // for it.
        let unlisted = "0199e0ff-0000-7000-8000-000000000009";
        assert_eq!(
            find(unlisted).unwrap(),
            boxes::SessionId::parse_str(unlisted).unwrap()
        );
    }

    /// BCLI-001, BCLI-051: the listing prints the id, name, type, state,
    /// provider and host of each box, from every host. `-o json` writes
    /// only the `min/v1/box` objects. A host that does not answer gets one
    /// stderr line, and the other hosts still list.
    #[test]
    fn box_list_prints_columns_and_schema() {
        let mut task = entry(
            "0199e0a0-0000-7000-8000-000000000002",
            Some("build"),
            "task",
            "exited",
        );
        task.reason = Some("exit".to_string());
        task.exit_code = Some(0);
        let listed = vec![
            ListedBox {
                provider: "local-minvmd".to_string(),
                host: "local-minvmd0".to_string(),
                record: entry(
                    "0199e0a0-0000-7000-8000-000000000001",
                    Some("dev"),
                    "session",
                    "running",
                ),
            },
            ListedBox {
                provider: "local-minvmd".to_string(),
                host: "alpha.local-minvmd0".to_string(),
                record: task,
            },
        ];

        let mut out = Vec::new();
        render_box_list(&mut out, &listed, true).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\
ID                                    NAME   TYPE     PARENT  PROJECT         STATE            PROVIDER      HOST
0199e0a0-0000-7000-8000-000000000001  dev    session  -       /home/dev/proj  running          local-minvmd  local-minvmd0
0199e0a0-0000-7000-8000-000000000002  build  task     -       /home/dev/proj  exited (exit 0)  local-minvmd  alpha.local-minvmd0
"
        );

        let mut out = Vec::new();
        render_box_list_json(&mut out, &listed).unwrap();
        let text = String::from_utf8(out).unwrap();
        let parsed: serde_json_lenient::Value = serde_json_lenient::from_str(&text).unwrap();
        let objects = parsed.as_array().expect("an array of box objects");
        assert_eq!(objects.len(), 2);
        for object in objects {
            assert_eq!(object["schema"], "min/v1/box");
        }
        assert_eq!(
            objects[1],
            serde_json_lenient::json!({
                "schema": "min/v1/box",
                "id": "0199e0a0-0000-7000-8000-000000000002",
                "name": "build",
                "type": "task",
                "state": "exited",
                "provider": "local-minvmd",
                "host": "alpha.local-minvmd0",
                "parent": null,
                "project": "/home/dev/proj",
                "reason": "exit",
                "exit_code": 0,
                "signal": null,
            })
        );

        // An empty listing under `-o json` is an empty array, and no line
        // for a person.
        let mut out = Vec::new();
        render_box_list_json(&mut out, &[]).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "[]\n");

        // The stderr line for a host the listing could not read.
        assert_eq!(
            unreachable_host_line("alpha.local-minvmd0"),
            "Could not reach host alpha.local-minvmd0; its boxes are not listed."
        );
    }

    /// BCLI-003: `min box show` renders the state as BOX-011 names it, how
    /// a stopped box ended, the identity the box runs under, and its
    /// provider and host.
    #[test]
    fn box_show_renders_state_and_identity() {
        let running = entry(
            "0199e0a0-0000-7000-8000-000000000001",
            Some("dev"),
            "session",
            "running",
        );
        let shown = ShowBoxResponse {
            record: running,
            identity: BoxIdentity::Unknown,
            live_execs: Vec::new(),
            disk_bytes: None,
        };
        let mut out = Vec::new();
        render_box_show(&mut out, &shown, "local-minvmd", "local-minvmd0").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\
ID:         0199e0a0-0000-7000-8000-000000000001
Name:       dev
Type:       session
Parent:     -
Project:    /home/dev/proj
State:      running
Identity:   unknown
Provider:   local-minvmd
Host:       local-minvmd0
"
        );

        let mut stopped = entry(
            "0199e0a0-0000-7000-8000-000000000002",
            None,
            "task",
            "stopped",
        );
        stopped.reason = Some("stopped".to_string());
        stopped.signal = Some(9);
        let shown = ShowBoxResponse {
            record: stopped,
            identity: BoxIdentity::None,
            live_execs: Vec::new(),
            disk_bytes: None,
        };
        let mut out = Vec::new();
        render_box_show(&mut out, &shown, "local", "local0").unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("State:      stopped\n"), "{text}");
        assert!(text.contains("Signal:     9\n"), "{text}");
        assert!(text.contains("Identity:   none\n"), "{text}");
        assert!(
            text.contains("Provider:   local\nHost:       local0\n"),
            "{text}"
        );
    }
}

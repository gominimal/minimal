//! `min box list`: the box records the daemon keeps for the current
//! project, or for the whole host with `--all`, in any state (BOX-158,
//! rendered as BCLI-001 pulls it forward into the first slice).

use super::*;

/// Lists the boxes of the current project with their state, one row for
/// each box. With `--all`, lists every box on this host.
pub async fn cmd_box_list(global: &GlobalArgs, args: BoxListArgs) -> Result<(), anyhow::Error> {
    let scope = if args.all {
        None
    } else {
        let cwd = crate::attach::cwd_host_path(global)?;
        Some(box_list_scope(cwd.as_ref())?)
    };
    ensure_daemon(global)?;
    let mut client = connect_daemon(global).await?;
    let scoped = scope.is_some();
    let boxes = list_box_records(&mut client, scope).await?;
    let mut out = std::io::stdout().lock();
    render_box_list(&mut out, &boxes, scoped)?;
    Ok(())
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
     Run `min box list --all` to list every box on this host.";

/// The line `min box list --all` prints when the host has no box.
pub(crate) const EMPTY_HOST_LIST: &str = "No boxes on this host.";

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
/// box in the order the daemon returned them. With no box, one line says
/// so: for the current project when `scoped`, else for the host.
pub(crate) fn render_box_list(
    out: &mut impl std::io::Write,
    boxes: &[minimald_rpc::BoxListingEntry],
    scoped: bool,
) -> std::io::Result<()> {
    if boxes.is_empty() {
        if scoped {
            return writeln!(out, "{EMPTY_PROJECT_LIST}");
        }
        return writeln!(out, "{EMPTY_HOST_LIST}");
    }
    let header = ["ID", "NAME", "TYPE", "PARENT", "PROJECT", "STATE"];
    let rows: Vec<[String; 6]> = boxes
        .iter()
        .map(|entry| {
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
            ]
        })
        .collect();
    let mut widths = header.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: [&str; 6]| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use minimald_rpc::{BoxIdentity, BoxListingEntry, ShowBoxResponse};

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

        let mut out = Vec::new();
        render_box_list(&mut out, &listing, true).unwrap();
        let text = String::from_utf8(out).unwrap();
        let expected = "\
ID                                    NAME          TYPE     PARENT                                PROJECT         STATE
0199e0a0-0000-7000-8000-000000000001  kept-session  session  -                                     /home/dev/proj  stopped (signal 15)
0199e0a0-0000-7000-8000-000000000002  -             task     0199e0a0-0000-7000-8000-000000000001  /home/dev/proj  exited (exit 0)
0199e0a0-0000-7000-8000-000000000003  big-build     task     -                                     /home/dev/proj  exited (oom, exit 137)
0199e0b0-0000-7000-8000-000000000004  left-task     task     -                                     /home/dev/proj  stopped
0199e0c0-0000-7000-8000-000000000005  live          session  -                                     -               running
";
        assert_eq!(text, expected);

        // An empty listing says so: for the project when scoped, and for
        // the host with `--all`.
        let mut out = Vec::new();
        render_box_list(&mut out, &[], true).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "This project has no boxes. \
             Run `min box list --all` to list every box on this host.\n"
        );
        let mut out = Vec::new();
        render_box_list(&mut out, &[], false).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "No boxes on this host.\n");

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
        };
        let mut out = Vec::new();
        render_box_show(&mut out, &shown).unwrap();
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
Identity:   none
"
        );

        // A read of a child task box that exited, with a live exec.
        let shown = ShowBoxResponse {
            record: task.clone(),
            identity: BoxIdentity::Unknown,
            live_execs: vec!["exec-1".to_string()],
        };
        let mut out = Vec::new();
        render_box_show(&mut out, &shown).unwrap();
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
Identity:   unknown
Live execs: exec-1
"
        );

        // The argument to `min box show` finds the box the listing prints.
        let find = |arg: &str| find_listed_box(&listing, arg);
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
            "No box has the name or id `no-such-box`. \
             Run `min box list` to see the boxes on this host."
        );
        // An id that is not listed still goes to the daemon, which answers
        // for it.
        let unlisted = "0199e0ff-0000-7000-8000-000000000009";
        assert_eq!(
            find(unlisted).unwrap(),
            boxes::SessionId::parse_str(unlisted).unwrap()
        );
    }
}

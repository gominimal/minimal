//! `min session create`: activating a new session, from the project file
//! checks to the start line.

use super::*;
use minimal_client::box_name::request_name;
use minimal_client::box_registration::{
    CleanupOutcome, register_box_for_activation, settle_lease_after_cleanup,
};

/// The session-start line for a box the activation registered with the VM
/// host daemon (T66): the one line the start output owes the registration,
/// naming the VM host daemon the row lives on and the switch address the box
/// was handed — the facts a bundle's CLI transcript then answers without
/// reaching for the daemon's log, and the one line the host that reaches the
/// VM host daemon with no provider flag at all (NET-081's macOS half) has to
/// show for its own boxes.
///
/// `vm` is the VM host the line names, by the same rule
/// [`hostname_proxy_vm`] names the proxy's: the selected VM on the VM
/// backend, `None` on a backend that hosts no VMs. A registered box only ever
/// exists on the former, so the `None` shape is the defensive one, mirroring
/// the sibling start line's.
#[must_use]
pub fn box_registered_start_line(
    vm: Option<&str>,
    name: &str,
    addresses: &boxes::BoxAddresses,
) -> String {
    match vm {
        Some(vm) => format!(
            "BOX REGISTRATION:  box '{name}' registered with the VM host daemon on VM '{vm}' · \
             switch address {}",
            addresses.switch_address
        ),
        None => format!(
            "BOX REGISTRATION:  box '{name}' registered with the VM host daemon · \
             switch address {}",
            addresses.switch_address
        ),
    }
}

/// The activation flow shared by [`cmd_activate`] and the bare-`min` router.
/// `offer_scaffold` gates the `minimal.toml` scaffold offer: `cmd_activate`
/// keeps it (its long-standing behavior, unchanged), while bare `min`
/// suppresses it — that path must land in a session, never in a config
/// prompt. Everything else, including the session id on stdout, is
/// identical for both callers.
/// Refuses a dynamic ingress declaration on a box that is not `own_ip`:
/// only an own-IP box has a published address a runtime publish could
/// apply to, so a stance or range on a `host_ip` or `none` box would be a
/// declaration `min session policy` shows and nothing ever honours. The
/// CLI reference documents the flags as requiring `--network own_ip`.
pub(crate) fn refuse_dynamic_ingress_off_own_ip(
    network: impl Into<boxes::NetworkMode>,
    mode: Option<boxes::DynamicIngress>,
    range: Option<(u16, u16)>,
) -> Result<(), anyhow::Error> {
    if network.into() != boxes::NetworkMode::OwnIp && (mode.is_some() || range.is_some()) {
        anyhow::bail!(
            "--dynamic-ingress and --dynamic-range need --network own_ip: only a box with \
             its own IP address can publish ports"
        );
    }
    Ok(())
}

/// Refuses a static ingress mapping on a box that is not `own_ip`: only an
/// own-IP box has a published address a static forwarder could apply to, so
/// a mapping on a `host_ip` or `none` box would be recorded and shown with
/// no publish surface to honour it. The CLI reference documents the flag as
/// requiring `--network own_ip`.
fn refuse_ingress_off_own_ip(
    network: crate::cli::CliNetworkMode,
    has_ingress: bool,
) -> Result<(), anyhow::Error> {
    if network != crate::cli::CliNetworkMode::OwnIp && has_ingress {
        anyhow::bail!(
            "--ingress needs --network own_ip: only a box with its own IP address can \
             publish ports"
        );
    }
    Ok(())
}

/// Refuses a `network.ingress` from `minimal.toml` on a box that is not
/// `own_ip`, as [`refuse_ingress_off_own_ip`] refuses `--ingress`. `layer`
/// is the table that declares the entry's `network` (#3238).
fn refuse_file_ingress_off_own_ip(
    network: crate::cli::CliNetworkMode,
    network_flagged: bool,
    has_ingress: bool,
    layer: Option<&str>,
) -> Result<(), anyhow::Error> {
    if network == crate::cli::CliNetworkMode::OwnIp || !has_ingress {
        return Ok(());
    }
    let mode = boxes::NetworkMode::from(network).word();
    let layer = layer.unwrap_or("[network]");
    let file = mfile::MFILE_NAME;
    if network_flagged {
        anyhow::bail!(
            "{layer} in {file} sets network.ingress, but --network {mode} gives the box no \
             own IP address, so it cannot publish ports. Run the command again with \
             --network own_ip."
        );
    }
    anyhow::bail!(
        "{layer} in {file} sets network.ingress, but the box is {mode}, so it cannot publish \
         ports. Set network.mode = \"own_ip\" in {layer}, or run the command again with \
         --network own_ip."
    )
}

/// The network mode and the static port mappings of a session box (#3238).
/// `--network` replaces the entry's `network.mode`. Each `--ingress`
/// (`flag_mappings`) adds a mapping to its `network.ingress`, as BCLI-024
/// says a list flag adds to the list. The refusals run
/// before anything is created: a dynamic or static ingress needs an
/// `own_ip` box.
///
/// # Errors
///
/// The refusal, when the box has ingress and is not `own_ip`.
pub(crate) fn session_box_network(
    args: &ActivateArgs,
    project: &mut ProjectEgress,
    flag_mappings: Vec<boxes::PortMapping>,
) -> anyhow::Result<(crate::cli::CliNetworkMode, Vec<boxes::PortMapping>)> {
    let file_ingress = project.ingress.take();
    let network_flagged = args.network.is_some();
    let network = args
        .network
        .or(project.mode.map(cli_network_mode))
        .unwrap_or_else(crate::cli::default_network_mode);
    // Every dynamic stance stands on a VM-backed host: an `ask` there is
    // answered by the human attached on the host (NET-045).
    refuse_dynamic_ingress_off_own_ip(network, args.dynamic_ingress, args.dynamic_range)?;
    // A static mapping needs an own-IP box too: only it has a published
    // address a static forwarder could apply to.
    refuse_ingress_off_own_ip(network, !args.ingress.is_empty())?;
    let Some(file_mappings) = file_ingress else {
        return Ok((network, flag_mappings));
    };
    refuse_file_ingress_off_own_ip(
        network,
        network_flagged,
        !file_mappings.is_empty(),
        project.layer.as_deref(),
    )?;
    tracing::debug!(
        network = boxes::NetworkMode::from(network).word(),
        file_mappings = file_mappings.len(),
        flag_mappings = flag_mappings.len(),
        layer = ?project.layer,
        "the session box takes the entry's network.ingress and the --ingress mappings"
    );
    Ok((network, union_ingress(file_mappings, flag_mappings)))
}

/// The entry's `network.ingress` mappings followed by the `--ingress`
/// mappings, as BOX-064 unions lists. A flag mapping equal to one the entry
/// already has is not added twice.
pub(crate) fn union_ingress(
    mut file_mappings: Vec<boxes::PortMapping>,
    flag_mappings: Vec<boxes::PortMapping>,
) -> Vec<boxes::PortMapping> {
    for mapping in flag_mappings {
        if !file_mappings.contains(&mapping) {
            file_mappings.push(mapping);
        }
    }
    file_mappings
}

/// The `--network` value of a `network.mode` that `minimal.toml` sets.
fn cli_network_mode(mode: boxes::NetworkMode) -> crate::cli::CliNetworkMode {
    crate::cli::parse_network_mode(mode.word())
        .unwrap_or_else(|_| crate::cli::default_network_mode())
}

/// A project `minimal.toml` that exists but does not load. The activation
/// refuses it before anything is created, and the run ends with exit 3
/// (`main.rs`), the architecture's code for an invalid `minimal.toml`.
#[derive(Debug)]
pub struct ProjectFileInvalid {
    /// Why the file did not load.
    pub error: mfile::Error,
}

impl std::fmt::Display for ProjectFileInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The cause is in this text and `source()` returns none, so `{}`
        // and the printer's `{:#}` each show it once. The mfile error's own
        // cause (the io error of `Error::IO`) is in its Display already.
        // A loadout file is not the project's file, so its refusal does not
        // say that the project's file does not load.
        if let mfile::Error::LoadoutSetsLoadoutMode { .. } = self.error {
            return write!(f, "Cannot start the box: {}", self.error);
        }
        write!(
            f,
            "Cannot start the box: the project's {name} does not load: {error}",
            name = mfile::MFILE_NAME,
            error = self.error,
        )
    }
}

impl std::error::Error for ProjectFileInvalid {}

/// The session entry of the project's `minimal.toml` that egress is read from
/// (NET-060): `[sessions.default]`, or `[boxes.default]` with
/// `type = "session"`, else the only session entry, else the implicit
/// default session entry. Every other case refuses the start, before the
/// create request.
fn pick_session_entry(
    entries: &[mfile::entry::BoxEntry],
) -> Result<mfile::entry::BoxEntry, SessionEntryUndecided> {
    let candidates: Vec<&mfile::entry::BoxEntry> = entries
        .iter()
        .filter(|entry| entry.box_type.as_deref() == Some(boxes::SESSION_BOX_TYPE))
        .collect();
    if let Some(entry) = candidates
        .iter()
        .find(|entry| entry.name == mfile::entry::DEFAULT_ENTRY_NAME)
    {
        return Ok((*entry).clone());
    }
    // An entry whose type is not built in has a session root that only
    // mfile can resolve, so the client cannot tell whether it is a session.
    // gominimal/minimal#3140 tracks resolving a project Box Type's session
    // root here. The refusal stays until then.
    if let Some(entry) = entries.iter().find(|entry| {
        entry
            .box_type
            .as_deref()
            .is_none_or(|t| !mfile::expand::BUILTIN_BOX_TYPES.contains(&t))
    }) {
        return Err(SessionEntryUndecided::TypeUnresolved {
            name: entry.name.clone(),
            box_type: entry.box_type.clone(),
        });
    }
    match candidates.as_slice() {
        [only] => Ok((*only).clone()),
        [] => mfile::entry::implicit_default_entry(entries, |t| {
            mfile::expand::BUILTIN_BOX_TYPES
                .into_iter()
                .find(|builtin| *builtin == t)
        })
        .ok_or_else(|| SessionEntryUndecided::DefaultNotSession {
            box_type: entries
                .iter()
                .find(|entry| entry.name == mfile::entry::DEFAULT_ENTRY_NAME)
                .and_then(|entry| entry.box_type.clone()),
        }),
        several => Err(SessionEntryUndecided::NoDefault {
            candidates: several.iter().map(|entry| entry.name.clone()).collect(),
        }),
    }
}

/// A project `minimal.toml` whose session entry the start cannot pick. The
/// activation refuses it before the create request, and the run ends with
/// exit 2 (`main.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEntryUndecided {
    /// Two or more session entries, and none is named `default`.
    NoDefault {
        /// The names of the session entries, in the order the file is read.
        candidates: Vec<String>,
    },
    /// No session entry, and an entry named `default` that is not a
    /// session, so no implicit default session entry applies.
    DefaultNotSession {
        /// The type of the `default` entry, when the file gives one.
        box_type: Option<String>,
    },
    /// No session entry named `default`, and an entry whose type is not a
    /// built-in Box Type, so the client cannot tell whether it is a session.
    TypeUnresolved {
        /// The name of the entry.
        name: String,
        /// The type of the entry, when the file gives one.
        box_type: Option<String>,
    },
}

impl std::fmt::Display for SessionEntryUndecided {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let file = mfile::MFILE_NAME;
        match self {
            SessionEntryUndecided::NoDefault { candidates } => write!(
                f,
                "Cannot start the box: the project's {file} declares the session entries \
                 {names}. None of them is named \"default\", so the start cannot pick one. \
                 Rename the entry to start to \"default\" in {file}.",
                names = candidates.join(", "),
            ),
            SessionEntryUndecided::DefaultNotSession { box_type } => {
                let kind = box_type.as_deref().map_or_else(
                    || "no type".to_owned(),
                    |t| format!("the type \"{}\"", printable(t)),
                );
                write!(
                    f,
                    "Cannot start the box: the project's {file} declares no session entry. \
                     Its entry \"default\" has {kind}, so the start has no session entry \
                     to use. Add a [sessions.<name>] entry to {file}."
                )
            }
            SessionEntryUndecided::TypeUnresolved { name, box_type } => {
                let kind = box_type.as_deref().map_or_else(
                    || "no type".to_owned(),
                    |t| format!("the type \"{}\"", printable(t)),
                );
                write!(
                    f,
                    "Cannot start the box: the project's {file} declares the entry \"{name}\" \
                     with {kind}, so the start cannot tell whether it is a session entry. "
                )?;
                // An entry already holds the name `default`, so no other
                // entry can take it.
                if name == mfile::entry::DEFAULT_ENTRY_NAME {
                    write!(
                        f,
                        "Set type = \"session\" in the entry \"{name}\", or rename that entry \
                         and add a [sessions.default] entry to {file}."
                    )
                } else {
                    write!(
                        f,
                        "If \"{name}\" is the session to start, set type = \"session\" in it. \
                         Otherwise, name the session entry to start \"default\", or add a \
                         [sessions.default] entry to {file}."
                    )
                }
            }
        }
    }
}

impl std::error::Error for SessionEntryUndecided {}

impl SessionEntryUndecided {
    /// The exit code of the refused start.
    pub const EXIT_CODE: u8 = 2;
}

/// The verb a start came from: `min box start` or `min session start`.
/// Both share one start path ([`start_entry`]). The verb decides which
/// entries the start counts, and it names the command in the refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartVerb {
    Box,
    Session,
}

impl StartVerb {
    /// The command, as the person types it.
    #[must_use]
    pub fn command(self) -> &'static str {
        match self {
            Self::Box => "min box start",
            Self::Session => "min session start",
        }
    }
}

/// What a start creates its box from, whichever verb typed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartEntry {
    pub verb: StartVerb,
    /// The entry the person typed, when they typed one.
    pub entry: Option<String>,
    /// `--name`: the box's `[box] name` (BCLI-069).
    pub name: Option<String>,
    /// `--new`: a fresh instance (BCLI-070).
    pub new: bool,
    /// `--detach`: print the id and return, never attach.
    pub detach: bool,
    /// The override flags: `--network`, `--ingress`, the egress flags and
    /// `--loadout` (BCLI-024, BCLI-073).
    pub overrides: crate::StartOverrideArgs,
}

impl From<BoxStartArgs> for StartEntry {
    fn from(args: BoxStartArgs) -> Self {
        Self {
            verb: StartVerb::Box,
            entry: args.entry,
            name: args.name,
            new: args.new,
            detach: args.detach,
            overrides: args.overrides,
        }
    }
}

impl From<SessionStartArgs> for StartEntry {
    fn from(args: SessionStartArgs) -> Self {
        Self {
            verb: StartVerb::Session,
            entry: args.entry,
            name: args.name,
            new: args.new,
            detach: args.detach,
            overrides: args.overrides,
        }
    }
}

/// The built-in root of a Box Type, for a built-in type. The client cannot
/// resolve a project Box Type, so it has none here.
fn builtin_root(box_type: &str) -> Option<&'static str> {
    mfile::expand::BUILTIN_BOX_TYPES
        .into_iter()
        .find(|builtin| *builtin == box_type)
}

/// Whether the client cannot resolve `entry`'s type to a built-in root. Such
/// an entry can be a session.
/// <https://github.com/gominimal/minimal/issues/3140> tracks resolving a
/// project Box Type's root here.
pub(crate) fn type_unresolved(entry: &mfile::entry::BoxEntry) -> bool {
    entry.box_type.as_deref().and_then(builtin_root).is_none()
}

/// The refusal for `entry`, whose type the client cannot resolve.
pub(crate) fn type_unresolved_refusal(entry: &mfile::entry::BoxEntry) -> SessionEntryUndecided {
    SessionEntryUndecided::TypeUnresolved {
        name: entry.name.clone(),
        box_type: entry.box_type.clone(),
    }
}

/// The entries a refusal lists: the [`start_candidates`], else the
/// project's own entries when a type is unresolved.
pub(crate) fn listed_entries(entries: &[mfile::entry::BoxEntry]) -> Vec<mfile::entry::BoxEntry> {
    start_candidates(entries).unwrap_or_else(|_| entries.to_vec())
}

/// The entries a start counts: the project's entries, and the implicit
/// `default` session entry when the project needs one (BOX-165). A picker
/// calls this only after its lookups of an explicit entry, when the pick
/// depends on the implicit `default` or on the count.
///
/// # Errors
///
/// [`SessionEntryUndecided::TypeUnresolved`] when an entry's type does not
/// resolve to a built-in root. Such an entry can be a session, so the start
/// can tell neither which entries are sessions nor whether the implicit
/// `default` applies. <https://github.com/gominimal/minimal/issues/3140>
/// tracks resolving a project Box Type's root here. Remove this refusal
/// when the client resolves that root.
pub(crate) fn start_candidates(
    entries: &[mfile::entry::BoxEntry],
) -> Result<Vec<mfile::entry::BoxEntry>, SessionEntryUndecided> {
    if let Some(entry) = entries.iter().find(|entry| type_unresolved(entry)) {
        return Err(type_unresolved_refusal(entry));
    }
    let mut candidates = entries.to_vec();
    if let Some(implicit) = mfile::entry::implicit_default_entry(entries, builtin_root) {
        candidates.push(implicit);
    }
    Ok(candidates)
}

/// Whether `entry` is a session entry.
pub(crate) fn is_session_entry(entry: &mfile::entry::BoxEntry) -> bool {
    entry.box_type.as_deref() == Some(boxes::SESSION_BOX_TYPE)
}

/// The entry `min box start` starts (BCLI-072): the typed entry, else the
/// entry named `default` of any type, else the project's only entry. The
/// count includes the implicit `default` entry.
///
/// A typed project entry, and with no entry typed a project entry named
/// `default`, is picked whatever its type. [`plan_start`] refuses a type
/// that the start cannot serve.
///
/// # Errors
///
/// [`SessionEntryUndecided::TypeUnresolved`] from [`start_candidates`],
/// only when the pick depends on the implicit `default` or on the count.
/// Else a [`StartEntryRefusal`] when no entry can be picked.
pub(crate) fn pick_box_start_entry(
    entries: &[mfile::entry::BoxEntry],
    typed: Option<&str>,
) -> Result<mfile::entry::BoxEntry, anyhow::Error> {
    let wanted = typed.unwrap_or(mfile::entry::DEFAULT_ENTRY_NAME);
    if let Some(entry) = entries.iter().find(|entry| entry.name == wanted) {
        return Ok(entry.clone());
    }
    let unknown = |typed: &str| StartEntryRefusal::Unknown {
        verb: StartVerb::Box,
        entry: typed.to_string(),
        entries: listed_entries(entries)
            .into_iter()
            .map(|entry| entry.name)
            .collect(),
    };
    if let Some(typed) = typed.filter(|typed| *typed != mfile::entry::DEFAULT_ENTRY_NAME) {
        return Err(unknown(typed).into());
    }
    // Only the implicit `default` or the count is left to decide the pick.
    let candidates = start_candidates(entries)?;
    let names = || candidates.iter().map(|entry| entry.name.clone()).collect();
    if let Some(default) = candidates
        .iter()
        .find(|entry| entry.name == mfile::entry::DEFAULT_ENTRY_NAME)
    {
        return Ok(default.clone());
    }
    if let Some(typed) = typed {
        return Err(unknown(typed).into());
    }
    match candidates.as_slice() {
        [only] => Ok(only.clone()),
        _ => Err(StartEntryRefusal::Several {
            verb: StartVerb::Box,
            entries: names(),
        }
        .into()),
    }
}

/// A start the project's `minimal.toml` cannot serve: the start cannot pick
/// an entry, or the entry it names cannot start this way. The start refuses
/// it before it creates anything, and the run ends with
/// [`StartEntryRefusal::exit_code`] (`main.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartEntryRefusal {
    /// No entry was typed, several entries count, and none is `default`.
    Several {
        verb: StartVerb,
        /// The entries the start counted, in the order the file is read.
        entries: Vec<String>,
    },
    /// The typed entry is not one the start counts.
    Unknown {
        verb: StartVerb,
        entry: String,
        /// The entries the start counted, in the order the file is read.
        entries: Vec<String>,
    },
    /// `min session start` found no session entry, and the entry named
    /// `default` has another type, so no implicit `default` applies.
    DefaultBlocked {
        /// The type of the `default` entry, when the file gives one.
        box_type: Option<String>,
    },
    /// `min session start` named an entry that is not a session entry.
    NotSession {
        entry: String,
        box_type: Option<String>,
    },
    /// `--name` for a task entry: its box runs through the run path, which
    /// generates the box's name and takes no `--name`. This refusal is an
    /// interim. <https://github.com/gominimal/minimal/issues/3196> tracks a
    /// box name for `RunEntry`. Remove this refusal when `RunEntry` takes a
    /// name.
    NameUnsupported { entry: String },
    /// `--ingress` or `--loadout` for a task entry: its box runs through the
    /// run path, which takes neither flag. `flag` is the flag as typed.
    /// This refusal is an interim, like [`Self::NameUnsupported`]. Remove
    /// it for a flag when `RunEntry` takes that flag
    /// (<https://github.com/gominimal/minimal/issues/3163> for `--ingress`,
    /// <https://github.com/gominimal/minimal/issues/3237> for `--loadout`).
    FlagUnsupported { entry: String, flag: &'static str },
    /// A task entry declared as `[boxes.<name>]` with `type = "task"`: the
    /// run path finds its task in `[tasks]` only. This refusal is an
    /// interim. <https://github.com/gominimal/minimal/issues/3213> tracks
    /// those entries. Remove this refusal when `declared_task` reads the
    /// task entries of `[boxes]`.
    TaskNotInTasks { entry: String },
    /// `min box start` named an entry of a type it cannot start yet: an
    /// agent, service or user-defined type. This refusal is an interim.
    /// <https://github.com/gominimal/minimal/issues/3197> tracks the start
    /// of those entries.
    UnsupportedType {
        entry: String,
        box_type: Option<String>,
    },
    /// A typed session entry not named `default`. The box's spec would name
    /// the entry, but its body still comes from the project's `[session]`
    /// table, not from the entry (see [`stamp_session_spec_as`]). This
    /// refusal is an interim.
    /// <https://github.com/gominimal/minimal/issues/3204> tracks the entry's
    /// own body. Remove this refusal when the start expands the typed
    /// entry's body into its spec.
    NamedSessionUnsupported { verb: StartVerb, entry: String },
}

impl StartEntryRefusal {
    /// The exit code of the refused start, from the architecture's
    /// exit-code table: 4, not found, for an entry the start does not find.
    /// `min session start` searches only the session entries, so an entry
    /// that is not a session is not found too. Every other refusal is a
    /// usage refusal, 2.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Unknown { .. } | Self::NotSession { .. } => 4,
            Self::Several { .. }
            | Self::DefaultBlocked { .. }
            | Self::NameUnsupported { .. }
            | Self::FlagUnsupported { .. }
            | Self::TaskNotInTasks { .. }
            | Self::UnsupportedType { .. }
            | Self::NamedSessionUnsupported { .. } => 2,
        }
    }
}

/// The entry names of a refusal, each with its control characters escaped.
fn printable_list(names: &[String]) -> String {
    names
        .iter()
        .map(|name| printable(name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The type of an entry, as a refusal names it.
fn entry_kind(box_type: Option<&str>) -> String {
    box_type.map_or_else(
        || "no type".to_owned(),
        |t| format!("the type \"{}\"", printable(t)),
    )
}

impl std::fmt::Display for StartEntryRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let file = mfile::MFILE_NAME;
        let noun = |verb: &StartVerb| match verb {
            StartVerb::Box => "entries",
            StartVerb::Session => "session entries",
        };
        match self {
            Self::Several { verb, entries } => write!(
                f,
                "Cannot pick an entry to start. The project's {file} declares the {noun} \
                 {names}, and none of them is named \"default\". Run {command} <entry> \
                 with one of them.",
                noun = noun(verb),
                names = printable_list(entries),
                command = verb.command(),
            ),
            Self::Unknown {
                verb,
                entry,
                entries,
            } => {
                let singular = match verb {
                    StartVerb::Box => "entry",
                    StartVerb::Session => "session entry",
                };
                write!(
                    f,
                    "Cannot start {entry}. The project's {file} declares no {singular} \
                     named \"{entry}\".",
                    entry = printable(entry),
                )?;
                if entries.is_empty() {
                    Ok(())
                } else {
                    write!(
                        f,
                        " Its {noun} are {names}. Run {command} <entry> with one of them.",
                        noun = noun(verb),
                        names = printable_list(entries),
                        command = verb.command(),
                    )
                }
            }
            Self::DefaultBlocked { box_type } => write!(
                f,
                "Cannot start a session. The project's {file} declares no session entry, \
                 and its entry \"default\" has {kind}. Add a [sessions.<name>] entry to \
                 {file}, or rename the entry \"default\".",
                kind = entry_kind(box_type.as_deref()),
            ),
            Self::NotSession { entry, box_type } => {
                write!(
                    f,
                    "Cannot start {entry} as a session. Its entry in {file} has {kind}.",
                    entry = printable(entry),
                    kind = entry_kind(box_type.as_deref()),
                )?;
                if box_type.as_deref() == Some(boxes::TASK_BOX_TYPE) {
                    write!(f, " Run min box start {} to start it.", printable(entry))?;
                }
                Ok(())
            }
            Self::NameUnsupported { entry } => write!(
                f,
                "Cannot start {entry} with --name. A box from a task entry gets a \
                 generated name. Run min box start {entry} without --name.",
                entry = printable(entry),
            ),
            Self::FlagUnsupported { entry, flag } => write!(
                f,
                "Cannot start {entry} with {flag}. A box from a task entry does not \
                 take {flag}. Run min box start {entry} without {flag}.",
                entry = printable(entry),
            ),
            Self::TaskNotInTasks { entry } => write!(
                f,
                "Cannot start {entry}. min box start runs only the tasks declared as \
                 [tasks.<name>] in {file}, and {entry} is declared as [boxes.{entry}]. \
                 Declare it as [tasks.{entry}] to start it.",
                entry = printable(entry),
            ),
            Self::UnsupportedType { entry, box_type } => write!(
                f,
                "Cannot start {entry}. Its entry in {file} has {kind}, and min box start \
                 starts session and task entries only.",
                entry = printable(entry),
                kind = entry_kind(box_type.as_deref()),
            ),
            Self::NamedSessionUnsupported { verb, entry } => write!(
                f,
                "Cannot start {entry}. {command} cannot start a session entry by name \
                 yet, except the entry named \"default\". Rename {entry} to \"default\" \
                 in {file}, then run {command}.",
                entry = printable(entry),
                command = verb.command(),
            ),
        }
    }
}

impl std::error::Error for StartEntryRefusal {}

/// The refusal of a start off a terminal for an entry whose box has a
/// terminal, without `--detach` (BCLI-029). The start refuses it before it
/// creates anything, and `main.rs` ends the command with [`Self::EXIT_CODE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartNeedsTerminal {
    entry: String,
}

impl StartNeedsTerminal {
    /// The usage-refusal code of the architecture's exit-code table.
    pub const EXIT_CODE: u8 = 2;

    #[must_use]
    pub fn new(entry: &str) -> Self {
        Self {
            entry: entry.to_string(),
        }
    }
}

impl std::fmt::Display for StartNeedsTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} needs a terminal. Run it from a terminal, or pass --detach.",
            printable(&self.entry)
        )
    }
}

impl std::error::Error for StartNeedsTerminal {}

/// The refusal of a start whose box name a running box on the host holds
/// (BCLI-069, BOX-163). It names the holder, and the two flags that create
/// the box anyway. `main.rs` ends the command with [`Self::EXIT_CODE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartNameHeld {
    pub verb: StartVerb,
    pub entry: String,
    pub refusal: minimald_rpc::HeldNameRefusal,
}

impl StartNameHeld {
    /// The exit code of the held-name refusal.
    pub const EXIT_CODE: u8 = minimald_rpc::HeldNameRefusal::EXIT_CODE;
}

impl std::fmt::Display for StartNameHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let minimald_rpc::HeldNameRefusal {
            name,
            holder,
            holder_name,
        } = &self.refusal;
        let entry = printable(&self.entry);
        let name = printable(name);
        let holder_name = printable(holder_name);
        match holder {
            Some(holder) => write!(
                f,
                "Cannot start {entry}. The running box {holder_name} ({holder}) holds the \
                 name {name}.",
            )?,
            None => write!(
                f,
                "Cannot start {entry}. The running box {holder_name} holds the name {name}.",
            )?,
        }
        write!(
            f,
            " Run {command} --new {entry} to create another box from the entry, or \
             pass --name <name> to give the box another name.",
            command = self.verb.command(),
        )
    }
}

impl std::error::Error for StartNameHeld {}

/// The one stderr hint of a start that returns without attaching to a box
/// that has no terminal (BCLI-029). The box's stdin is already closed.
/// `box_id` is the id of the box the start created.
#[must_use]
pub fn unattached_start_hint(entry: &str, box_id: impl std::fmt::Display) -> String {
    format!(
        "{entry} started with no input. Run min box run {entry} to connect this \
         terminal's input and output to a new box. Run min box logs {box_id} for its \
         output, and min box wait {box_id} for its exit code."
    )
}

/// How a start creates its box.
#[derive(Debug)]
pub(crate) enum StartPlan {
    /// A session entry: the activation, which attaches unless `--detach`.
    Session {
        entry: String,
        args: ActivateArgs,
        options: ActivationOptions,
    },
    /// An entry whose box has no terminal: a detached run, which closes the
    /// box's stdin and prints its id.
    Detached {
        entry: String,
        run: crate::task::RunEntry,
    },
}

impl StartPlan {
    /// The entry the start picked.
    #[must_use]
    pub fn entry(&self) -> &str {
        match self {
            Self::Session { entry, .. } | Self::Detached { entry, .. } => entry,
        }
    }
}

/// Decides how `start` creates its box, from the project's `entries`, before
/// anything is created. `has_terminal` says whether this command runs on a
/// terminal that an attach can use.
///
/// # Errors
///
/// [`StartEntryRefusal`] when no entry can be picked or the entry cannot
/// start, and [`StartNeedsTerminal`] for an entry whose box has a terminal,
/// off a terminal, without `--detach`.
pub(crate) fn plan_start(
    start: &StartEntry,
    entries: &[mfile::entry::BoxEntry],
    has_terminal: bool,
) -> Result<StartPlan, anyhow::Error> {
    let entry = match start.verb {
        StartVerb::Box => pick_box_start_entry(entries, start.entry.as_deref())?,
        StartVerb::Session => {
            crate::cmd::session::pick_session_start_entry(entries, start.entry.as_deref())?
        }
    };
    match entry.box_type.as_deref() {
        // A typed session entry other than `default` would get the body of
        // the `[session]` table under its own name. That refusal is the
        // #3204 interim: remove it when the start expands the entry's body.
        // A bare start that picks the only session entry still starts it,
        // as BCLI-071 requires.
        Some(boxes::SESSION_BOX_TYPE)
            if start.entry.is_some() && entry.name != mfile::entry::DEFAULT_ENTRY_NAME =>
        {
            Err(StartEntryRefusal::NamedSessionUnsupported {
                verb: start.verb,
                entry: entry.name,
            }
            .into())
        }
        // A session box has a terminal: its spec sets `pty_enabled`
        // (`BoxSpec::for_session`).
        Some(boxes::SESSION_BOX_TYPE) => {
            if !start.detach && !has_terminal {
                return Err(StartNeedsTerminal::new(&entry.name).into());
            }
            let mut args = ActivateArgs::unflagged();
            args.name.clone_from(&start.name);
            args.attach = !start.detach;
            // BCLI-024, BCLI-073: the override flags reach the activation's
            // command-line layer. Each flag changes only its own key, so a
            // flag that is not given leaves the activation's value in place.
            let overrides = &start.overrides;
            args.network = overrides.network;
            args.ingress.clone_from(&overrides.ingress);
            args.egress.clone_from(&overrides.egress);
            args.loadout.clone_from(&overrides.loadout);
            // BCLI-075, BCLI-076: the rest of activate's override flags.
            let other = &overrides.other;
            args.dynamic_ingress = other.dynamic_ingress;
            args.dynamic_range = other.dynamic_range;
            args.credentialed_upstream = other.credentialed_upstream;
            args.no_loadouts = other.no_loadouts;
            args.no_hooks = other.no_hooks;
            Ok(StartPlan::Session {
                options: ActivationOptions {
                    offer_scaffold: false,
                    entry: Some(entry.name.clone()),
                    box_name: start.name.clone(),
                    fresh_instance: start.new,
                    quic443: other.quic443,
                    vpn_network_names: other.vpn_network_names.clone(),
                },
                entry: entry.name,
                args,
            })
        }
        // A task box never has a terminal (BOX-054), so the start detaches.
        // `run_entry` calls `request_fresh_instance`, and the daemon names
        // the box `<entry>-<n>` (BOX-163). So a task-entry start is always a
        // fresh instance, and `--new` changes nothing for it. A plain start
        // does not refuse a held name until gominimal/minimal#3196 lands.
        // The run path takes no `--name`, so the start refuses that flag
        // rather than drop it. That refusal is the #3196 interim: remove it
        // when `RunEntry` takes a name.
        //
        // The run path finds its task in `[tasks]` only, so a `[boxes]`
        // task entry is refused first. That refusal is the #3213 interim:
        // remove it when `declared_task` reads the task entries of `[boxes]`.
        Some(boxes::TASK_BOX_TYPE) if entry.table != mfile::entry::EntryTable::Tasks => {
            Err(StartEntryRefusal::TaskNotInTasks { entry: entry.name }.into())
        }
        Some(boxes::TASK_BOX_TYPE) if start.name.is_some() => {
            Err(StartEntryRefusal::NameUnsupported { entry: entry.name }.into())
        }
        // The run path takes `--network` and the egress flags, as `min box
        // run` does, but neither `--ingress` (#3163) nor `--loadout`
        // (#3237). The start refuses those two rather than drop them.
        // Remove the `--loadout` refusal when `RunEntry` takes the flag.
        Some(boxes::TASK_BOX_TYPE) if !start.overrides.ingress.is_empty() => {
            Err(StartEntryRefusal::FlagUnsupported {
                entry: entry.name,
                flag: "--ingress",
            }
            .into())
        }
        Some(boxes::TASK_BOX_TYPE) if !start.overrides.loadout.is_empty() => {
            Err(StartEntryRefusal::FlagUnsupported {
                entry: entry.name,
                flag: "--loadout",
            }
            .into())
        }
        Some(boxes::TASK_BOX_TYPE) => Ok(StartPlan::Detached {
            run: crate::task::RunEntry {
                verb: crate::task::RunVerb::Box,
                entry: entry.name.clone(),
                path: None,
                detach: true,
                args: Vec::new(),
                network: start.overrides.network,
                egress: start.overrides.egress.clone(),
                other: start.overrides.other.clone(),
            },
            entry: entry.name,
        }),
        // Agent, service and user-defined-type entries: an interim refusal
        // until gominimal/minimal#3197 lets `min box start` start them.
        box_type => Err(StartEntryRefusal::UnsupportedType {
            box_type: box_type.map(str::to_owned),
            entry: entry.name,
        }
        .into()),
    }
}

/// The project directory of a command: `-C`/`--repo-dir`, else the current
/// working directory.
fn command_project_dir(global: &GlobalArgs) -> Result<camino::Utf8PathBuf, anyhow::Error> {
    let effective_path = global
        .repo_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let project_path = std::fs::canonicalize(&effective_path)
        .with_context(|| format!("Cannot resolve project path '{}'", effective_path.display()))?;
    camino::Utf8PathBuf::from_path_buf(project_path)
        .map_err(|_| anyhow::anyhow!("Project path is not valid UTF-8"))
}

/// The bytes of the project's `minimal.toml` for `project`, or `None` when
/// the project has none.
fn project_file_bytes(project: &camino::Utf8Path) -> anyhow::Result<Option<Vec<u8>>> {
    let file = match mfile::File::from_dir_recursive(project.as_std_path()) {
        Ok(file) => file,
        Err(mfile::Error::NotFound) => return Ok(None),
        Err(error) => return Err(ProjectFileInvalid { error }.into()),
    };
    let Some(root) = file.repo_path() else {
        return Ok(None);
    };
    let Some(path) = [
        root.join(mfile::MFILE_NAME),
        root.join(".minimal").join(mfile::MFILE_NAME),
    ]
    .into_iter()
    .find(|path| path.is_file()) else {
        return Ok(None);
    };
    let bytes = std::fs::read(&path).map_err(|e| ProjectFileInvalid {
        error: mfile::Error::IO("minimal file", path.clone(), e),
    })?;
    Ok(Some(bytes))
}

/// The entries the project's `minimal.toml` declares. A project with no
/// `minimal.toml` declares none.
fn project_entries(project: &camino::Utf8Path) -> anyhow::Result<Vec<mfile::entry::BoxEntry>> {
    match project_file_bytes(project)? {
        Some(bytes) => {
            mfile::entry::read_entries(&bytes).map_err(|error| ProjectFileInvalid { error }.into())
        }
        None => Ok(Vec::new()),
    }
}

/// `min box start [<entry>]`: create a box from an entry and attach this
/// terminal to it, or print its id and return.
pub async fn cmd_box_start(global: &GlobalArgs, args: BoxStartArgs) -> Result<(), anyhow::Error> {
    start_entry(global, args.into()).await
}

/// The one start path of `min box start` and `min session start` (BCLI-029,
/// BCLI-069, BCLI-070, BCLI-071, BCLI-072): pick the entry, refuse what
/// cannot start before anything is created, then create the box. A box with
/// a terminal attaches unless `--detach`. Any other box starts with its
/// stdin closed, and the start prints one hint.
pub async fn start_entry(global: &GlobalArgs, start: StartEntry) -> Result<(), anyhow::Error> {
    let project = command_project_dir(global)?;
    let entries = project_entries(&project)?;
    let has_terminal = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let plan = plan_start(&start, &entries, has_terminal).inspect_err(|error| {
        tracing::info!(verb = start.verb.command(), %error, "the start was refused before it created a box");
    })?;
    tracing::info!(
        verb = start.verb.command(),
        entry = %plan.entry(),
        typed_entry = ?start.entry,
        name = ?start.name,
        fresh_instance = start.new,
        detach = start.detach,
        network = ?start.overrides.network,
        ingress = ?start.overrides.ingress,
        egress = ?start.overrides.egress,
        loadouts = ?start.overrides.loadout,
        other_overrides = ?start.overrides.other,
        "starting a box from the entry"
    );
    match plan {
        StartPlan::Session {
            entry,
            args,
            options,
        } => activate_box(global, args, options)
            .await
            .map_err(|error| start_refusal(error, start.verb, &entry)),
        StartPlan::Detached { entry, run } => {
            let id = crate::task::run_entry(global, run).await?;
            crate::output::record_box_id(&id.to_string());
            eprintln!("{}", unattached_start_hint(&entry, id));
            Ok(())
        }
    }
}

/// The error a start ends with, the same for `min box start` and `min
/// session start`: a held name becomes [`StartNameHeld`], with its hint to
/// `--new` and `--name`. A host port in use becomes the refusal's own text,
/// with the port and its holder (NET-144). Any other error passes through.
pub(crate) fn start_refusal(error: anyhow::Error, verb: StartVerb, entry: &str) -> anyhow::Error {
    match error.downcast::<minimald_rpc::HeldNameRefusal>() {
        Ok(refusal) => anyhow::Error::new(StartNameHeld {
            verb,
            entry: entry.to_string(),
            refusal,
        }),
        Err(error) => crate::cmd::session::activate_refusal(error),
    }
}

/// Settings of an activation that no `min session activate` flag carries.
/// A `bool` converts to these settings with only the scaffold offer set, so
/// a caller that passes `offer_scaffold` alone keeps its meaning.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActivationOptions {
    /// Offer to write a `minimal.toml` when the project has none.
    pub offer_scaffold: bool,
    /// The session entry the box is created from, when it is not `default`.
    pub entry: Option<String>,
    /// The `[box] name` of the box's spec (BCLI-069).
    pub box_name: Option<String>,
    /// Ask for a fresh instance, `<name>-<n>` (BCLI-070).
    pub fresh_instance: bool,
    /// The `--quic443` of a start (BCLI-024). `min session activate` does
    /// not take the flag.
    pub quic443: Option<boxes::core::bep::Quic443>,
    /// The `--vpn-network-names` of a start (BCLI-024). `min session
    /// activate` does not take the flag.
    pub vpn_network_names: Vec<String>,
}

impl From<bool> for ActivationOptions {
    fn from(offer_scaffold: bool) -> Self {
        Self {
            offer_scaffold,
            ..Self::default()
        }
    }
}

/// A grant the box cannot receive: a GitHub grant whose value cannot land
/// in its environment (BEP-007), or a store reference that no rule admits
/// (BEP-035). The creation is refused with exit 3, before the box exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantNotDelivered {
    /// The grant's name is not a POSIX environment variable name, so it
    /// cannot name a variable in the box.
    InvalidName {
        /// The grant's name, as the project file declares it.
        grant: String,
    },
    /// The mint gave the grant no sealed value, so its variable would be
    /// empty in the box.
    NotSealed {
        /// The grant's name.
        grant: String,
    },
    /// No `[secret-store-rules]` rule names the item a store reference
    /// reads, so nothing says where its value may go.
    NoStoreRule {
        /// The grant's name.
        grant: String,
        /// The reference, `<store>:<id>` or `<id>`.
        item: String,
    },
    /// The item's rule sets `action = "deny"`.
    StoreReferenceDenied {
        /// The grant's name.
        grant: String,
        /// The reference, `<store>:<id>` or `<id>`.
        item: String,
    },
    /// The item's rule sets `action = "ask"`, and the command cannot ask
    /// (BEP-035).
    AskWithoutTerminal {
        /// The grant's name.
        grant: String,
        /// The reference, `<store>:<id>` or `<id>`.
        item: String,
    },
    /// The item's rule sets `action = "ask"`, and the person answered no.
    StoreReferenceDeclined {
        /// The grant's name.
        grant: String,
        /// The reference, `<store>:<id>` or `<id>`.
        item: String,
    },
}

impl std::fmt::Display for GrantNotDelivered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName { grant } => write!(
                f,
                "Cannot create the box: the secret {grant:?} in [defaults.session.secrets] \
                 in {name} is not a valid environment variable name. A name uses only \
                 capital letters, digits and underscores, and does not start with a \
                 digit. Rename the secret, then create the box again.",
                name = mfile::MFILE_NAME,
            ),
            Self::NotSealed { grant } => write!(
                f,
                "Cannot create the box: no sealed value was made for the secret \
                 {grant}, so {grant} would be empty in the box. No box was created."
            ),
            Self::NoStoreRule { grant, item } => write!(
                f,
                "Cannot create the box: the secret {grant} in [defaults.session.secrets] \
                 in {name} \
                 reads the item {item} from the host's secret store, and no rule in \
                 [secret-store-rules] in your config.toml names that item. Add a rule for \
                 it, or remove the secret from {name}. Run `min dirs` to find config.toml.",
                name = mfile::MFILE_NAME,
            ),
            Self::StoreReferenceDenied { grant, item } => write!(
                f,
                "Cannot create the box: the secret {grant} in [defaults.session.secrets] \
                 in {name} \
                 reads the item {item} from the host's secret store, and the rule for that \
                 item in [secret-store-rules] denies it. Remove the secret from {name}.",
                name = mfile::MFILE_NAME,
            ),
            Self::AskWithoutTerminal { grant, item } => write!(
                f,
                "Cannot create the box: the secret {grant} reads the item {item} from the \
                 host's secret store. The rule for that item in [secret-store-rules] sets \
                 action = \"ask\", and this command cannot ask: it has no terminal, or \
                 --no-input is set. The secret was denied. Run the command in a terminal \
                 without --no-input, or remove the secret from {name}.",
                name = mfile::MFILE_NAME,
            ),
            Self::StoreReferenceDeclined { grant, item } => write!(
                f,
                "Cannot create the box: you did not allow the secret {grant} to read the \
                 item {item} from the host's secret store. No box was created."
            ),
        }
    }
}

impl std::error::Error for GrantNotDelivered {}

/// The project's `[session.network.bep]` settings, `[session.secrets]`
/// grants, the box spec's own variable names and the `[session.network]
/// quic443` stance. Only a missing project file reads as empty. A file that
/// exists but does not load refuses the activation, so a broken file can
/// never skip the grant checks (BEP-008).
fn project_bep_and_grants(
    project: &camino::Utf8Path,
) -> Result<
    (
        boxes::core::bep::BepSettings,
        boxes::core::bep::SecretGrants,
        Vec<String>,
        Option<boxes::core::bep::Quic443>,
    ),
    ProjectFileInvalid,
> {
    let session = match mfile::File::from_dir_recursive(project.as_std_path()) {
        Ok(file) => file.session,
        Err(mfile::Error::NotFound) => None,
        Err(error) => {
            tracing::debug!(
                rule = "BEP-008",
                project = %project,
                error = %error,
                "activation refused: the project file does not load"
            );
            return Err(ProjectFileInvalid { error });
        }
    };
    Ok(session.map_or_else(Default::default, |session| {
        // BEP-011: the names of the variables the box spec's own
        // environment sets, so the activation can warn for a trust variable.
        let spec_env = session
            .vars
            .keys()
            .map(|name| name.as_ref().to_string())
            .chain(
                session
                    .vars_lenient
                    .iter()
                    .map(|entry| entry.name().as_ref().to_string()),
            )
            .collect();
        let (bep, quic443) = session
            .network
            .map_or_else(Default::default, |n| (n.bep.unwrap_or_default(), n.quic443));
        (bep, session.secrets, spec_env, quic443)
    }))
}

/// Where one field of a box's effective egress came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EgressSource {
    /// The project's `minimal.toml`.
    ProjectFile,
    /// A flag of the creating command.
    Flag,
}

/// A box's effective egress (NET-060): the policy, and the source of each
/// field that one of them set, by the field's spec name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EffectiveEgress {
    pub(crate) policy: Option<boxes::EgressPolicy>,
    pub(crate) sources: Vec<(&'static str, EgressSource)>,
}

/// The `network.egress` table that the project's `minimal.toml` declares for
/// a session box or a task box (NET-060), with the hint for each legacy
/// spelling that the file uses.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ProjectEgress {
    pub(crate) policy: Option<boxes::EgressPolicy>,
    pub(crate) hints: Vec<String>,
    /// The `network.mode` of the expanded entry, when a layer sets one.
    /// Every box-creating command reads it when `--network` is not given.
    pub(crate) mode: Option<boxes::NetworkMode>,
    /// The `network.ingress` port mappings of the expanded entry, when a
    /// layer sets the key. A session box takes them, and each `--ingress`
    /// adds one mapping after them (#3238).
    pub(crate) ingress: Option<Vec<boxes::PortMapping>>,
    /// The table whose `network` the expanded entry holds, as the file
    /// names it: `[defaults]`, `[defaults.<type>]` or the entry's own, such
    /// as `[tasks.build]`. A later layer replaces the whole `network` table
    /// of an earlier one, so one table holds all of it. `None` when no
    /// layer declares `network`.
    pub(crate) layer: Option<String>,
}

/// The loadout mode of the session box a start creates, from the project
/// at `project`: the entry the start names, else the entry
/// [`pick_session_entry`] picks, as [`session_box_entry`] picks it. With
/// no project file, the bare session entry applies. `named` is the start's
/// `--loadout` list.
///
/// # Errors
///
/// Exit 2 ([`SessionEntryUndecided`]) when the pick is undecided, and exit
/// 3 ([`ProjectFileInvalid`]) for the refusals of
/// [`loadouts::entry_loadout_gate`], each before any loadout file is read.
pub(crate) fn session_loadout_mode(
    project: &camino::Utf8Path,
    entry: Option<&str>,
    named: &[String],
) -> anyhow::Result<mfile::expand::LoadoutMode> {
    let bytes = project_file_bytes(project)?;
    let entry = match &bytes {
        Some(bytes) => {
            let entries =
                mfile::entry::read_entries(bytes).map_err(|error| ProjectFileInvalid { error })?;
            let typed = entry.and_then(|name| entries.iter().find(|e| e.name == name));
            match typed {
                Some(entry) => entry.clone(),
                // An undecided pick refuses the start here, as
                // `session_box_entry` does, before any loadout is read.
                None => pick_session_entry(&entries)?,
            }
        }
        None => bare_entry(
            entry.unwrap_or(mfile::entry::DEFAULT_ENTRY_NAME),
            mfile::entry::EntryTable::Sessions,
            boxes::SESSION_BOX_TYPE,
        ),
    };
    loadouts::entry_loadout_gate(bytes.as_deref(), &entry, named)
        .map_err(|error| ProjectFileInvalid { error }.into())
}

/// The loadout mode of the box `min task run` creates for task `task` in
/// the project at `project`: its `[tasks.<task>]` entry, or the bare task
/// entry when the project declares none. A task takes no `--loadout`.
///
/// # Errors
///
/// As [`session_loadout_mode`].
pub(crate) fn task_loadout_mode(
    project: &camino::Utf8Path,
    task: &str,
) -> anyhow::Result<mfile::expand::LoadoutMode> {
    let bytes = project_file_bytes(project)?;
    let declared = match &bytes {
        Some(bytes) => mfile::entry::read_entries(bytes)
            .map_err(|error| ProjectFileInvalid { error })?
            .into_iter()
            .find(|e| e.name == task && e.box_type.as_deref() == Some(boxes::TASK_BOX_TYPE)),
        None => None,
    };
    let entry = declared
        .unwrap_or_else(|| bare_entry(task, mfile::entry::EntryTable::Tasks, boxes::TASK_BOX_TYPE));
    loadouts::entry_loadout_gate(bytes.as_deref(), &entry, &[])
        .map_err(|error| ProjectFileInvalid { error }.into())
}

/// An entry the file does not declare: `[<table>.<name>]` of `box_type`,
/// with no keys of its own.
fn bare_entry(
    name: &str,
    table: mfile::entry::EntryTable,
    box_type: &str,
) -> mfile::entry::BoxEntry {
    mfile::entry::BoxEntry {
        name: name.to_owned(),
        table,
        box_type: Some(box_type.to_owned()),
        body: toml::Table::new(),
        implicit: true,
    }
}

/// The project's [`ProjectEgress`]. The layers are `[defaults]`,
/// `[defaults.session]` and the session entry, and a later layer replaces an
/// earlier one. The entry is `[sessions.default]` when the file declares it,
/// or else the one `[sessions.<name>]` entry when the file declares exactly
/// one. With no session entry, the implicit default entry applies. Only the
/// `network` keys of the layers are read, so a key this read does not own
/// never refuses an activation. The policy is `None` when there is no
/// project file or no layer declares egress. A start passes the `entry` it
/// picked, and that entry is the session entry here.
pub(crate) fn project_egress(
    project: &camino::Utf8Path,
    entry: Option<&str>,
) -> anyhow::Result<ProjectEgress> {
    match project_file_bytes(project)? {
        Some(bytes) => project_egress_from(&bytes, entry),
        None => Ok(ProjectEgress::default()),
    }
}

/// The [`ProjectEgress`] of task `task` in the project: as
/// [`project_egress`] reads it for a session, with the layers `[defaults]`,
/// `[defaults.task]` and the task's entry. The policy is `None` when there
/// is no project file, the file declares no entry of type `task` named
/// `task`, or no layer declares egress.
pub(crate) fn task_project_egress(
    project: &camino::Utf8Path,
    task: &str,
) -> anyhow::Result<ProjectEgress> {
    match project_file_bytes(project)? {
        Some(bytes) => task_egress_from(&bytes, task),
        None => Ok(ProjectEgress::default()),
    }
}

/// Whether a `network` key appears in a layer that a session start can
/// read: `[defaults]`, `[defaults.session]`, a session entry, or a project
/// Box Type's entry, `[defaults.<name>]` or `[box_types.<name>.defaults]`,
/// whose root the client cannot resolve (#3140). A key in a task entry or in `[defaults.task]`
/// never reaches a session, so it never refuses a session start.
fn declares_network(file: &toml::Table, entries: &[mfile::entry::BoxEntry]) -> bool {
    let defaults = file.get("defaults").and_then(toml::Value::as_table);
    // `[defaults.<name>]` reaches every entry of type `<name>`. A built-in
    // type other than `session` is never a session's type, so only its
    // table is skipped, by the same rule as `can_be_session` below.
    let in_defaults = defaults.is_some_and(|defaults| {
        defaults.contains_key("network")
            || defaults.iter().any(|(name, value)| {
                (name == boxes::SESSION_BOX_TYPE
                    || !mfile::expand::BUILTIN_BOX_TYPES.contains(&name.as_str()))
                    && value
                        .as_table()
                        .is_some_and(|table| table.contains_key("network"))
            })
    });
    let in_type_defaults = file
        .get("box_types")
        .and_then(toml::Value::as_table)
        .is_some_and(|types| {
            types
                .values()
                .filter_map(toml::Value::as_table)
                .filter_map(|box_type| box_type.get("defaults").and_then(toml::Value::as_table))
                .any(|defaults| defaults.contains_key("network"))
        });
    // A built-in type other than `session` is never a session's entry.
    let can_be_session = |entry: &mfile::entry::BoxEntry| match entry.box_type.as_deref() {
        Some(t) if t == boxes::SESSION_BOX_TYPE => true,
        Some(t) => !mfile::expand::BUILTIN_BOX_TYPES.contains(&t),
        None => true,
    };
    in_defaults
        || in_type_defaults
        || entries
            .iter()
            .filter(|entry| can_be_session(entry))
            .any(|entry| entry.body.contains_key("network"))
}

/// [`project_egress`] over the bytes of a `minimal.toml`. A start that names
/// its `entry` reads the egress of that entry (BCLI-069). The start already
/// picked it, so no default is picked here. With no `entry`, or with a name
/// that only the implicit default entry answers, the pick applies.
fn project_egress_from(bytes: &[u8], entry: Option<&str>) -> anyhow::Result<ProjectEgress> {
    let file: toml::Table = toml::from_slice(bytes).map_err(|e| ProjectFileInvalid {
        error: mfile::Error::Format(e),
    })?;
    let entries =
        mfile::entry::read_entries(bytes).map_err(|error| ProjectFileInvalid { error })?;
    let typed = entry.and_then(|name| entries.iter().find(|entry| entry.name == name));
    let picked = match typed {
        Some(entry) => Ok(entry.clone()),
        None => pick_session_entry(&entries),
    };
    let entry = match picked {
        Ok(entry) => entry,
        // A file that declares no egress does not need a session entry for
        // it, so an undecided pick does not refuse its start.
        Err(_) if !declares_network(&file, &entries) => return Ok(ProjectEgress::default()),
        Err(undecided) => return Err(undecided.into()),
    };
    entry_egress(&file, entry)
}

/// [`task_project_egress`] over the bytes of a `minimal.toml`.
fn task_egress_from(bytes: &[u8], task: &str) -> anyhow::Result<ProjectEgress> {
    let file: toml::Table = toml::from_slice(bytes).map_err(|e| ProjectFileInvalid {
        error: mfile::Error::Format(e),
    })?;
    let entries =
        mfile::entry::read_entries(bytes).map_err(|error| ProjectFileInvalid { error })?;
    let Some(entry) = entries.into_iter().find(|entry| {
        entry.name == task && entry.box_type.as_deref() == Some(boxes::TASK_BOX_TYPE)
    }) else {
        return Ok(ProjectEgress::default());
    };
    entry_egress(&file, entry)
}

/// The egress of `entry` in the parsed `file`: its `[defaults]`,
/// `[defaults.<type>]` and entry layers, read as [`project_egress`] says.
fn entry_egress(
    file: &toml::Table,
    entry: mfile::entry::BoxEntry,
) -> anyhow::Result<ProjectEgress> {
    let network_of = |table: &toml::Table| -> toml::Table {
        table
            .get("network")
            .map(|network| toml::Table::from_iter([("network".to_owned(), network.clone())]))
            .unwrap_or_default()
    };
    let defaults = file
        .get("defaults")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    let mut layers = mfile::expand::Layers::default().with_file_defaults(
        &defaults,
        entry.box_type.as_deref(),
        &std::collections::BTreeSet::new(),
    );
    layers.defaults = network_of(&layers.defaults);
    layers.defaults_type = network_of(&layers.defaults_type);
    let entry = mfile::entry::BoxEntry {
        body: network_of(&entry.body),
        ..entry
    };
    // The merge replaces a table whole, so the last layer that declares
    // `network` holds the expanded entry's `network` table.
    let layer = if !entry.body.is_empty() {
        format!("[{}.{}]", entry.table.key(), entry.name)
    } else if !layers.defaults_type.is_empty() {
        format!(
            "[defaults.{}]",
            entry.box_type.as_deref().unwrap_or_default()
        )
    } else if !layers.defaults.is_empty() {
        "[defaults]".to_owned()
    } else {
        return Ok(ProjectEgress::default());
    };
    let mut expansion =
        mfile::expand::expand(&entry, &layers).map_err(|error| ProjectFileInvalid { error })?;
    // The network module's own read: a malformed egress table refuses the
    // start with exit 3, as every invalid `minimal.toml` does.
    let hints = mfile::network::canonicalize(&mut expansion.spec)
        .map_err(|error| network_key_invalid(&expansion.spec, error))?;
    let network = expansion.spec.get("network");
    // `canonicalize` has rewritten a legacy spelling and refused a value
    // that is not a mode, so the word is a current one.
    let mode = match network
        .and_then(|network| network.get("mode"))
        .and_then(toml::Value::as_str)
    {
        Some("none") => Some(boxes::NetworkMode::NoNet),
        Some("host_ip") => Some(boxes::NetworkMode::HostNet),
        Some("own_ip") => Some(boxes::NetworkMode::OwnIp),
        _ => None,
    };
    let ingress = network
        .and_then(|network| network.get("ingress"))
        .map(file_port_mappings)
        .transpose()?;
    let Some(egress) = network.and_then(|network| network.get("egress")) else {
        return Ok(ProjectEgress {
            policy: None,
            hints,
            mode,
            ingress,
            layer: Some(layer),
        });
    };
    let mut egress: boxes::EgressPolicy =
        egress
            .clone()
            .try_into()
            .map_err(|error| ProjectFileInvalid {
                error: mfile::Error::Format(error),
            })?;
    egress.allow_subnets = egress.allow_subnets.as_deref().map(normalize_subnets);
    egress.deny_subnets = egress.deny_subnets.as_deref().map(normalize_subnets);
    Ok(ProjectEgress {
        policy: Some(egress),
        hints,
        mode,
        ingress,
        layer: Some(layer),
    })
}

/// One `network.ingress` item of a `minimal.toml`, as `box.toml` writes it:
/// `{ proto = "tcp", port = 8080 }` publishes host port 8080 on the box's
/// port 8080. `external_port` and `internal_port` in place of `port` map two
/// different ports. `proto` is `tcp` or `udp`, and `tcp` when it is absent.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIngressItem {
    proto: Option<String>,
    port: Option<u16>,
    external_port: Option<u16>,
    internal_port: Option<u16>,
}

/// The port mappings of a `network.ingress` list (#3238). `canonicalize`
/// already refused an `ingress` that is not a list.
///
/// # Errors
///
/// Exit 3 ([`ProjectFileInvalid`]) for an item that is not a port mapping.
fn file_port_mappings(ingress: &toml::Value) -> anyhow::Result<Vec<boxes::PortMapping>> {
    let invalid = || ProjectFileInvalid {
        error: mfile::Error::InvalidSpecKey {
            key: "network.ingress".to_owned(),
            layer: mfile::MFILE_NAME.to_owned(),
            problem: mfile::SpecKeyProblem::WrongShape {
                expected: "a list of port mappings, such as `{ port = 8080 }` or \
                           `{ external_port = 8080, internal_port = 80, proto = \"tcp\" }`",
                found: "a list with an item that is not a port mapping",
            },
        },
    };
    let items: Vec<FileIngressItem> = ingress.clone().try_into().map_err(|_| invalid())?;
    let mut mappings = Vec::with_capacity(items.len());
    for item in items {
        let (external_port, internal_port) =
            match (item.port, item.external_port, item.internal_port) {
                (Some(port), None, None) => (port, port),
                (None, Some(external), Some(internal)) => (external, internal),
                _ => return Err(invalid().into()),
            };
        // The same spellings `--ingress` takes, in any case.
        let proto = match item.proto.as_deref() {
            None => boxes::IpProto::Tcp,
            Some(proto) => crate::cli::parse_ingress_proto(proto).map_err(|_| invalid())?,
        };
        if internal_port == 0 {
            return Err(invalid().into());
        }
        mappings.push(boxes::PortMapping {
            external_port,
            internal_port,
            proto,
        });
    }
    Ok(mappings)
}

/// The expanded session entry of the project at `project`, for the daemon
/// to compose the box from (BOX-068). `entry` names the entry. With no
/// name, the session entry pick applies, and the implicit `default` entry
/// answers a project that declares none (BOX-165).
///
/// `None` for a project with no `minimal.toml`. The daemon then composes
/// from what it reads itself, as it did before entries.
///
/// # Errors
///
/// Fails with exit 3 on a `minimal.toml` whose entry does not expand.
/// Fails with [`SessionEntryUndecided`] (exit 2) when no single session
/// entry can be picked.
pub(crate) fn session_box_entry(
    project: &camino::Utf8Path,
    entry: Option<&str>,
    hooks_enabled: bool,
) -> anyhow::Result<Option<boxes::wire::request::WireBoxEntry>> {
    let Some(bytes) = project_file_bytes(project)? else {
        return Ok(None);
    };
    let entries =
        mfile::entry::read_entries(&bytes).map_err(|error| ProjectFileInvalid { error })?;
    let typed = entry.and_then(|name| entries.iter().find(|entry| entry.name == name));
    let picked = match typed {
        Some(entry) => entry.clone(),
        // An undecided pick refuses the start. It never falls back to the
        // project's `[session]` table.
        None => pick_session_entry(&entries)?,
    };
    box_entry(project, &bytes, picked, hooks_enabled).map(Some)
}

/// The expanded `[tasks.<task>]` entry of the project at `project`, for the
/// daemon to compose the task box from (BOX-068). `None` when the project
/// declares no such entry.
///
/// # Errors
///
/// Fails with exit 3 on a `minimal.toml` whose entry does not expand.
pub(crate) fn task_box_entry(
    project: &camino::Utf8Path,
    task: &str,
    hooks_enabled: bool,
) -> anyhow::Result<Option<boxes::wire::request::WireBoxEntry>> {
    let Some(bytes) = project_file_bytes(project)? else {
        return Ok(None);
    };
    let entries =
        mfile::entry::read_entries(&bytes).map_err(|error| ProjectFileInvalid { error })?;
    let Some(entry) = entries.into_iter().find(|entry| {
        entry.name == task && entry.box_type.as_deref() == Some(boxes::TASK_BOX_TYPE)
    }) else {
        return Ok(None);
    };
    box_entry(project, &bytes, entry, hooks_enabled).map(Some)
}

/// Expands `entry` of the `minimal.toml` in `bytes` over `[defaults]` and
/// `[defaults.<type>]` (BOX-048, BOX-064), with a legacy `[session]` table
/// read as `[defaults.session]` (BOX-050), and takes the lists the daemon
/// composes from the expanded spec.
///
/// A list the spec has no key for stays `None`. A task entry sends only
/// `packages` and `lifecycle_hooks`. It sends no `vars`, `vars_lenient` or
/// `patches`. `min task run` reads only the `[tasks.<name>]` table, so those
/// keys from `[defaults]` and `[defaults.task]` do not reach a task box.
/// gominimal/minimal#3266 tracks that gap. With hooks off (`--no-hooks`), no
/// `lifecycle_hooks` list is sent.
fn box_entry(
    project: &camino::Utf8Path,
    bytes: &[u8],
    entry: mfile::entry::BoxEntry,
    hooks_enabled: bool,
) -> anyhow::Result<boxes::wire::request::WireBoxEntry> {
    let format_error = |error| ProjectFileInvalid {
        error: mfile::Error::Format(error),
    };
    let mut doc: toml::Table = toml::from_slice(bytes).map_err(format_error)?;
    // The hint for a legacy table is printed when the file loads
    // (`mfile::File`), so the hints this rewrite returns are not printed
    // again.
    mfile::legacy::canonicalize(&mut doc, mfile::legacy::this_release())
        .map_err(|error| ProjectFileInvalid { error })?;
    let defaults = doc
        .get("defaults")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    let project_types: std::collections::BTreeSet<String> = doc
        .get("box_types")
        .and_then(toml::Value::as_table)
        .map(|types| types.keys().cloned().collect())
        .unwrap_or_default();
    let mut layers = mfile::expand::Layers::default().with_file_defaults(
        &defaults,
        entry.box_type.as_deref(),
        &project_types,
    );
    // BOX-183, BOX-184: the merge compares resolved values, so each
    // `inherit` name takes this process's value. A name it does not set
    // stays out, and the merge falls back to the `default`.
    // Gap (BOX-183, residual of T125, issue #3302): `layers.loadouts` stays
    // empty here. So the loadout var conflict refusal in `merge_vars` does
    // not run before `min box create`, `min session start` or `min task run`
    // creates the box.
    layers.host_vars = mfile::expand::inherited_var_names(&entry, &layers)
        .into_iter()
        .filter_map(|name| std::env::var(&name).ok().map(|value| (name, value)))
        .collect();
    let expansion =
        mfile::expand::expand(&entry, &layers).map_err(|error| ProjectFileInvalid { error })?;
    let spec = &expansion.spec;
    fn list<T: serde::de::DeserializeOwned>(
        spec: &toml::Table,
        key: &str,
    ) -> Result<Option<T>, toml::de::Error> {
        spec.get(key)
            .cloned()
            .map(toml::Value::try_into)
            .transpose()
    }
    let box_type = entry
        .box_type
        .clone()
        .unwrap_or_else(|| boxes::SESSION_BOX_TYPE.to_owned());
    let project_path = paths::HostAbsPath::try_new(project.to_path_buf())
        .context("Invalid project root")?
        .into();
    let mut wire = boxes::wire::request::WireBoxEntry::new(&entry.name, &box_type, project_path);
    wire.packages = list(spec, "packages").map_err(format_error)?;
    if hooks_enabled {
        wire.lifecycle_hooks = list(spec, "lifecycle_hooks").map_err(format_error)?;
    }
    // A task entry sends no `vars`, `vars_lenient` or `patches`, so the
    // `[defaults]` and `[defaults.task]` values for them do not reach the
    // task box. gominimal/minimal#3266 tracks that gap.
    if box_type != boxes::TASK_BOX_TYPE {
        wire.vars = list(spec, "vars").map_err(format_error)?;
        wire.vars_lenient = list(spec, "vars_lenient").map_err(format_error)?;
        wire.patches = list(spec, "patches").map_err(format_error)?;
    }
    tracing::info!(
        entry = %wire.name,
        box_type = %wire.box_type,
        implicit = entry.implicit,
        packages = ?wire.packages,
        "expanded the box's entry"
    );
    Ok(wire)
}

/// The refusal for a `[network]` key that the network module cannot read:
/// an invalid spec key of `minimal.toml`, named by its dotted path.
fn network_key_invalid(
    spec: &toml::Table,
    error: mfile::network::NetworkError,
) -> ProjectFileInvalid {
    use mfile::network::NetworkError;
    // What the value at a dotted `key` of the spec is, as the message names it.
    let found_at = |key: &str| -> &'static str {
        let mut parts = key.split('.');
        let first = parts.next().and_then(|part| spec.get(part));
        match parts.try_fold(first, |value, part| Some(value?.get(part))) {
            Some(Some(toml::Value::String(_))) => "a string",
            Some(Some(toml::Value::Integer(_))) => "a whole number",
            Some(Some(toml::Value::Float(_))) => "a decimal number",
            Some(Some(toml::Value::Boolean(_))) => "a true or false value",
            Some(Some(toml::Value::Datetime(_))) => "a date or time",
            Some(Some(toml::Value::Array(_))) => "a list",
            Some(Some(toml::Value::Table(_))) => "a table",
            _ => "another kind of value",
        }
    };
    const MODES: &str = "\"none\", \"host_ip\" or \"own_ip\"";
    let (key, expected, found) = match error {
        NetworkError::UnknownMode(_) => (
            "network.mode".to_owned(),
            MODES,
            "a value that is not a network mode",
        ),
        NetworkError::ModeNotString => ("network.mode".to_owned(), MODES, found_at("network.mode")),
        NetworkError::WrongShape { key, expected } => {
            let found = found_at(&key);
            (key, expected, found)
        }
        NetworkError::ModeNoneWithEgress { key } => {
            (key, "no value while `network.mode` is \"none\"", "a value")
        }
    };
    ProjectFileInvalid {
        error: mfile::Error::InvalidSpecKey {
            key,
            layer: mfile::MFILE_NAME.to_owned(),
            problem: mfile::SpecKeyProblem::WrongShape { expected, found },
        },
    }
}

/// A session start's effective egress: the project's egress with the
/// egress flags applied, as [`effective_egress`] says. A `none` box with
/// egress is refused here, before the create request, and the refusal names
/// the minimal.toml table the egress came from (NET-065), as `min task run`
/// does.
///
/// # Errors
///
/// The refusal, when `network` is `none` and the box has egress.
fn session_effective_egress(
    project: ProjectEgress,
    flags: Option<boxes::EgressPolicy>,
    network: boxes::NetworkMode,
    args: &crate::EgressArgs,
) -> anyhow::Result<EffectiveEgress> {
    let file_layer = project.layer.filter(|_| project.policy.is_some());
    let egress = effective_egress(project.policy, flags, args.deny_all_egress);
    // A session's own_ip box is available on every host kind.
    crate::task::refuse_egress_on_none(
        network,
        egress.policy.is_some(),
        args,
        file_layer.as_deref(),
        true,
    )?;
    Ok(egress)
}

/// The box's effective egress (arch#166): the project's declaration with
/// the egress flags applied. `--allow-subnets`, `--allow-dns-hosts` and
/// `--deny-subnets` add their values to the file's list, the file's values
/// first and each value once. `--allow-protocols` replaces the file's list.
/// `--deny-all-egress`, which never comes with an allow flag (the parse
/// refuses the pair), can only narrow: it empties the file's
/// `allow_subnets` and `allow_dns_hosts` and leaves the rest of the file's
/// section in place (arch:1234). With no `allow_protocols` from the file or
/// a flag, the section is [`boxes::EgressPolicy::deny_all`] (NET-140). The
/// file's `deny_subnets` stay, and `--deny-subnets` adds to them.
pub(crate) fn effective_egress(
    project: Option<boxes::EgressPolicy>,
    flags: Option<boxes::EgressPolicy>,
    deny_all_flag: bool,
) -> EffectiveEgress {
    const FIELDS: [&str; 4] = [
        "allow_subnets",
        "allow_dns_hosts",
        "allow_protocols",
        "deny_subnets",
    ];
    if project.is_none() && flags.is_none() && !deny_all_flag {
        return EffectiveEgress::default();
    }
    let project = project.unwrap_or_default();
    let flags = flags.unwrap_or_default();
    let mut sources = Vec::new();
    // A list key: the file's values, then each flag value not already
    // there.
    let mut add = |field: &'static str,
                   file: Option<Vec<String>>,
                   flag: Option<Vec<String>>|
     -> Option<Vec<String>> {
        if file.is_some() {
            sources.push((field, EgressSource::ProjectFile));
        }
        let Some(flag) = flag else {
            return file;
        };
        sources.push((field, EgressSource::Flag));
        let mut list = file.unwrap_or_default();
        for value in flag {
            if !list.contains(&value) {
                list.push(value);
            }
        }
        Some(list)
    };
    let (allow_subnets, allow_dns_hosts) = if deny_all_flag {
        (Some(Vec::new()), Some(Vec::new()))
    } else {
        (
            add(FIELDS[0], project.allow_subnets, flags.allow_subnets),
            add(FIELDS[1], project.allow_dns_hosts, flags.allow_dns_hosts),
        )
    };
    let deny_subnets = add(FIELDS[3], project.deny_subnets, flags.deny_subnets);
    // `--deny-all-egress` leaves the file's `allow_protocols` in place
    // (arch:1234). With none from the file or a flag, the section is
    // `deny_all()`, every allow list present and empty (NET-140).
    let allow_protocols = if flags.allow_protocols.is_some() {
        sources.push((FIELDS[2], EgressSource::Flag));
        flags.allow_protocols
    } else if project.allow_protocols.is_some() {
        sources.push((FIELDS[2], EgressSource::ProjectFile));
        project.allow_protocols
    } else if deny_all_flag {
        sources.push((FIELDS[2], EgressSource::Flag));
        Some(Vec::new())
    } else {
        None
    };
    if deny_all_flag {
        sources.push((FIELDS[0], EgressSource::Flag));
        sources.push((FIELDS[1], EgressSource::Flag));
    }
    sources.sort_by_key(|(field, _)| FIELDS.iter().position(|f| f == field));
    EffectiveEgress {
        policy: Some(boxes::EgressPolicy {
            allow_subnets,
            allow_dns_hosts,
            allow_protocols,
            deny_subnets,
        }),
        sources,
    }
}

/// The box's credentialed-upstream declaration: the `--credentialed-upstream`
/// flag, or a `[session.secrets]` grant whose source is the broker or a
/// store (NET-134, BEP-016, BEP-032). The set is derived from those grants. A `[session.network.bep]`
/// setting or a `client_env` grant alone declares nothing. The settings
/// ride the declaration. The declared `quic443` stance does not: it rides
/// the policy of every box (BEP-018).
fn credentialed_upstream_for(
    flag: bool,
    bep: &boxes::core::bep::BepSettings,
    secrets: &boxes::core::bep::SecretGrants,
) -> Option<boxes::CredentialedUpstream> {
    let declared = flag
        || secrets
            .values()
            .any(boxes::core::bep::SecretGrant::is_credentialed);
    declared.then(|| boxes::CredentialedUpstream {
        bep: bep.clone(),
        secrets: secrets.clone(),
        // Filled once the store references are accepted (BEP-062).
        store_upstreams: Vec::new(),
    })
}

/// Puts the upstream authorities of each rule in `accepted` into the
/// declaration of `policy`, beside its grants, once each, in order (BEP-062).
/// A policy with no declaration, or no accepted rule, is left as it is, so
/// a box with no store reference carries no authorities.
fn put_store_upstreams(policy: &mut boxes::BoxPolicy, accepted: &boxes::core::bep::StoreRules) {
    let Some(declaration) = policy.credentialed_upstream.as_mut() else {
        return;
    };
    for authority in accepted.values().flat_map(|rule| rule.upstream.iter()) {
        if !declaration.store_upstreams.contains(authority) {
            declaration.store_upstreams.push(authority.clone());
        }
    }
}

/// Refuses a box spec whose grants the box or this host cannot honour, and
/// prints and returns the warnings of one it accepts. `spec_env` is the names
/// of the variables the box spec's own environment sets. It checks the project's settings
/// whether or not they declare a credentialed upstream, so a contradiction
/// in `[session.network.bep]` alone is still refused. The refusal ends the
/// run with exit 3 (`main.rs`). Every host today is un-enrolled.
/// `box_zone_resolver` is [`host_resolves_box_names`] for this host and
/// box (BEP-017).
fn refuse_unhonourable_grants(
    network: boxes::NetworkMode,
    egress: Option<&boxes::EgressPolicy>,
    settings: &boxes::core::bep::BepSettings,
    secrets: &boxes::core::bep::SecretGrants,
    full_breadth_acknowledged: bool,
    box_zone_resolver: bool,
    spec_env: &[String],
) -> Result<Vec<boxes::core::bep::BepWarning>, anyhow::Error> {
    use boxes::core::bep::{ActivationSpec, BepTables, HostFacts, check_activation};
    let hosts: Vec<&str> = bep::module::GITHUB
        .hosts
        .iter()
        .map(|authority| authority.host)
        .collect();
    let spec = ActivationSpec {
        network,
        egress,
        bep: settings,
        secrets,
        // `min box start` reads the grants and the proxy settings from
        // `[defaults.session]`, so its refusals name those tables.
        tables: BepTables::SESSION,
    };
    // BEP-057: the client configuration's acknowledgement, the same one
    // `min box spec` reads, so the preview and the start agree.
    let host = HostFacts {
        full_breadth_acknowledged,
        box_zone_resolver,
        ..HostFacts::LOCAL
    };
    let checked = check_activation(&spec, host, &hosts);
    tracing::info!(
        box_zone_resolver = host.box_zone_resolver,
        steering = settings.resolved_steering().word(),
        accepted = checked.is_ok(),
        "checked the box spec's grants against this host"
    );
    let mut plan = checked?;
    // BEP-011: a spec that sets a trust variable keeps its value, and says so.
    plan.warn_spec_trust_env(spec_env.iter().map(String::as_str));
    for warning in &plan.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(plan.warnings)
}

/// Whether the activation holds the box's name on the VM host daemon once
/// the box is active. A `host_ip` box holds it for the zone (NET-128). A
/// `none` box holds it so the host can name the box by its id when the
/// in-VM daemon reports an expose decision (NET-046). An own-address box
/// has a row, and a native host has no VM host daemon.
pub(crate) fn holds_name_with_vm_host(kind: paths::HostKind, network: boxes::NetworkMode) -> bool {
    kind == paths::HostKind::Minvmd
        && matches!(
            network,
            boxes::NetworkMode::HostNet | boxes::NetworkMode::NoNet
        )
}

/// Whether a box with `network` on a host of `kind` has its lookups go
/// through a resolver that steers the credential module's names (BEP-017,
/// BEP-062, BEP-081). This is a host fact and does not read the steering.
/// On the VM host, an own-address box's lookups go through the VM host's
/// switch, whose DNS gate steers them. A host-address box there resolves
/// through a steering answerer of its own in the guest (BEP-086). Both
/// answer a steered name with the proxy's address while the proxy's
/// listener is live, and SERVFAIL while it is down. A native host has no
/// proxy, so a steered name there always fails closed, and a `none` box
/// has no steered lookups of its own. `min box spec` reads it for the
/// network its `--network` flag names. Where this is true, a `dns`-steered
/// box opens TLS to the proxy's address on port 443, and the proxy routes
/// it by its SNI (BEP-080).
pub(crate) fn host_resolves_box_names(kind: paths::HostKind, network: boxes::NetworkMode) -> bool {
    kind == paths::HostKind::Minvmd
        && matches!(
            network,
            boxes::NetworkMode::OwnIp | boxes::NetworkMode::HostNet
        )
}

/// The network and the host fact a creation reads, for a host of `kind`:
/// the box's `--network` mode, and whether the switch resolves that box's
/// names. `min box spec` reads the same fact for the same mode.
pub(crate) fn creation_host(
    kind: paths::HostKind,
    args: &crate::cli::ActivateArgs,
) -> (boxes::NetworkMode, bool) {
    let network: boxes::NetworkMode = args.network_mode().into();
    (network, host_resolves_box_names(kind, network))
}

/// Checks the box spec's store references at creation, and gives the rules
/// it accepts, by item. Does nothing, and reads no configuration, for a box
/// with no store reference. Otherwise it reads the rules through
/// [`crate::config::read_client_config_and_store_rules`], which fails
/// closed. `can_ask` says whether the command can ask the person.
///
/// # Errors
///
/// [`boxes::core::bep::ActivationRefused`] for a reference to the GitHub
/// sign-in item or a rule upstream outside the egress (BEP-034, BEP-036),
/// and [`GrantNotDelivered`] for a reference with no rule or one its rule
/// denies (BEP-035). Each ends the run with exit 3.
fn check_store_grants(
    global: &GlobalArgs,
    secrets: &boxes::core::bep::SecretGrants,
    egress: Option<&boxes::EgressPolicy>,
    can_ask: bool,
) -> Result<boxes::core::bep::StoreRules, anyhow::Error> {
    if boxes::core::bep::store_references(secrets).next().is_none() {
        return Ok(boxes::core::bep::StoreRules::new());
    }
    let (_, rules) = crate::config::read_client_config_and_store_rules(global)?;
    accept_store_references(secrets, egress, &rules, can_ask, &mut |question| {
        crate::cmd::confirm(question, false)
    })
}

/// Judges each store reference in `secrets` against `rules`, and gives the
/// rules of the references it accepts, by item. First every reference is
/// checked against the deny set and the egress (BEP-034, BEP-036). Then a
/// reference with no rule, a `deny` rule, or an `ask` rule without
/// `can_ask` is refused (BEP-035). Only when no reference is refused does
/// it call `ask`, once per distinct item that an `ask` rule names. Logs one
/// info line naming each reference checked and its outcome.
///
/// # Errors
///
/// As [`check_store_grants`] says. `ask`'s own error ends the check.
fn accept_store_references(
    secrets: &boxes::core::bep::SecretGrants,
    egress: Option<&boxes::EgressPolicy>,
    rules: &boxes::core::bep::StoreRules,
    can_ask: bool,
    ask: &mut dyn FnMut(&str) -> Result<bool, anyhow::Error>,
) -> Result<boxes::core::bep::StoreRules, anyhow::Error> {
    use boxes::core::bep::{StoreConsent, check_store_references, store_consent, store_references};
    let module_hosts = crate::config::store_module_hosts();
    let deny = crate::config::store_deny_set(&module_hosts);
    let mut checked: Vec<String> = Vec::new();
    let outcome = (|| {
        if let Err(refused) = check_store_references(secrets, egress, rules, deny) {
            checked.extend(
                refused
                    .refusals
                    .iter()
                    .map(|refusal| format!("refused: {refusal}")),
            );
            return Err(anyhow::Error::from(refused));
        }
        // Every refusal that needs no answer comes first, so the person is
        // never asked about a creation that a later reference refuses.
        let mut to_ask: Vec<(String, Vec<String>, &boxes::core::bep::StoreRuleConfig)> = Vec::new();
        let mut allowed: Vec<(String, &str, &boxes::core::bep::StoreRuleConfig)> = Vec::new();
        for reference in store_references(secrets) {
            let item = reference.item();
            let grant = reference.grant.to_owned();
            let Some(rule) = reference.rule(rules) else {
                checked.push(format!("{item}: no rule"));
                return Err(GrantNotDelivered::NoStoreRule { grant, item }.into());
            };
            match store_consent(rule, can_ask) {
                StoreConsent::Allow => {}
                StoreConsent::Deny if rule.action == Some(boxes::core::bep::StoreAction::Ask) => {
                    checked.push(format!("{item}: denied, no terminal to ask"));
                    return Err(GrantNotDelivered::AskWithoutTerminal { grant, item }.into());
                }
                StoreConsent::Deny => {
                    checked.push(format!("{item}: denied by its rule"));
                    return Err(GrantNotDelivered::StoreReferenceDenied { grant, item }.into());
                }
                // One question per distinct item, naming every grant that reads it.
                StoreConsent::Ask => match to_ask.iter_mut().find(|(seen, ..)| *seen == item) {
                    Some((_, grants, _)) => grants.push(grant),
                    None => to_ask.push((item.clone(), vec![grant], rule)),
                },
            }
            allowed.push((item, reference.id, rule));
        }
        for (item, grants, rule) in &to_ask {
            let upstream: Vec<String> = rule.upstream.iter().map(|host| printable(host)).collect();
            let names: Vec<String> = grants.iter().map(|grant| printable(grant)).collect();
            let (subject, verbs) = if names.len() == 1 {
                (format!("The secret {}", names[0]), ("reads", "sends"))
            } else {
                (
                    format!("The secrets {}", names.join(", ")),
                    ("read", "send"),
                )
            };
            let question = format!(
                "{subject} {} the item {} from the host's secret store and {} it to {}. \
                 Allow it for this box?",
                verbs.0,
                printable(item),
                verbs.1,
                upstream.join(", ")
            );
            if !ask(&question)? {
                checked.push(format!("{item}: declined"));
                return Err(GrantNotDelivered::StoreReferenceDeclined {
                    grant: grants[0].clone(),
                    item: item.clone(),
                }
                .into());
            }
        }
        let mut accepted = boxes::core::bep::StoreRules::new();
        for (item, id, rule) in allowed {
            checked.push(format!("{item}: allowed"));
            accepted.insert(id.to_owned(), rule.clone());
        }
        Ok(accepted)
    })();
    tracing::info!(
        references = ?checked,
        accepted = outcome.is_ok(),
        "checked the box's store references"
    );
    outcome
}

/// `text` with each control character escaped, so a name from an
/// untrusted `minimal.toml` cannot move the cursor or fake a line in the
/// question the person answers.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// The names of the project's GitHub grants, in name order.
fn github_grant_names(secrets: &boxes::core::bep::SecretGrants) -> Vec<String> {
    secrets
        .iter()
        .filter(|(_, grant)| grant.is_github())
        .map(|(name, _)| name.clone())
        .collect()
}

/// Whether the host keychain holds a GitHub sign-in. Reads the item's
/// metadata only, which carries no token and asks for nothing.
fn sign_in_held(keychain: &dyn bep::signin::Keychain) -> Result<bool, anyhow::Error> {
    keychain
        .metadata()
        .map(|held| held.is_some())
        .map_err(|error| crate::mint::MintError::SignIn(error).into())
}

/// The proxy's name for the box's address stance. A box with no network
/// has none, and the activation refuses it a grant (BEP-009). The enum is
/// non-exhaustive, and a mode added later has no stance until it says one.
fn proxy_stance(network: boxes::NetworkMode) -> Option<bep::boxes::Stance> {
    match network {
        boxes::NetworkMode::OwnIp => Some(bep::boxes::Stance::OwnIp),
        boxes::NetworkMode::HostNet => Some(bep::boxes::Stance::HostIp),
        _ => None,
    }
}

/// Whether a node-local Box Egress Proxy serves boxes on this host: the
/// proxy published its identity at `identity`, and its control socket is
/// at `control`. A missing home directory gives neither path.
pub(crate) fn proxy_present(
    identity: Option<&std::path::Path>,
    control: Option<&std::path::Path>,
) -> bool {
    identity.is_some_and(std::path::Path::exists) && control.is_some_and(std::path::Path::exists)
}

/// Why no node-local proxy serves boxes on this host, or `None` when one
/// does ([`proxy_present`]). `binary` is the proxy program the host daemon
/// starts, by `bep::store::proxy_binary_path`, and `log` is the file that
/// daemon writes the proxy's output to, kept only when it exists. A
/// program that does not exist is
/// not installed. One that exists and published nothing does not answer.
/// A relative `MINVMD_BEP_BIN` is its own cause, not a missing program.
pub(crate) fn proxy_absence(
    identity: Option<&std::path::Path>,
    control: Option<&std::path::Path>,
    binary: Result<std::path::PathBuf, bep::store::ProxyLookupError>,
    log: Option<std::path::PathBuf>,
) -> Option<boxes::core::bep::ProxyAbsence> {
    use bep::store::ProxyLookupError;
    use boxes::core::bep::ProxyAbsence;
    if proxy_present(identity, control) {
        return None;
    }
    let absence = match binary {
        // The text names the log only when the host daemon wrote it.
        Ok(path) if path.exists() => ProxyAbsence::NotAnswering {
            path,
            log: log.filter(|log| log.exists()),
        },
        Ok(path) => ProxyAbsence::NotInstalled { path: Some(path) },
        Err(ProxyLookupError::RelativeEnv(path)) => ProxyAbsence::RelativePath { path },
        Err(ProxyLookupError::NoMinvmd) => ProxyAbsence::NotInstalled { path: None },
    };
    tracing::debug!(?absence, "no node-local proxy serves boxes");
    Some(absence)
}

/// The file the host daemon writes the proxy's output to: `bep.log` in its
/// host directory, beside the proxy's listener socket.
fn proxy_log_path(minimal_dir: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    minimal_client::resolve_host_dir(minimal_dir, true)
        .ok()
        .map(|dir| dir.join("bep.log"))
}

/// Checks a box spec's GitHub grants at creation, and gives their names.
///
/// Where no node-local proxy serves boxes, a GitHub grant is refused with
/// `gatehouse_unenrolled_node` (Gatehouse §6.2). Only on a host that has
/// one is a grant with no held sign-in refused with
/// `github_sign_in_required` (BEP-003). Only the sign-in item's metadata
/// is read, and nothing asks for a sign-in.
pub(crate) fn check_github_grants(
    secrets: &boxes::core::bep::SecretGrants,
    proxy_absence: Option<boxes::core::bep::ProxyAbsence>,
    keychain: &dyn bep::signin::Keychain,
) -> Result<Vec<String>, anyhow::Error> {
    let grants = github_grant_names(secrets);
    if grants.is_empty() {
        return Ok(grants);
    }
    // BEP-007: each grant's name becomes a variable in the box's
    // environment, so a name that is not one is refused before anything
    // is created.
    if let Some(grant) = grants
        .iter()
        .find(|grant| boxes::core::primitives::StrictVarName::try_new(grant.as_str()).is_err())
    {
        return Err(GrantNotDelivered::InvalidName {
            grant: grant.clone(),
        }
        .into());
    }
    boxes::core::bep::require_proxy(secrets, proxy_absence)?;
    let signed_in = sign_in_held(keychain)?;
    boxes::core::bep::require_sign_in(secrets, signed_in)?;
    Ok(grants)
}

/// The facts a GitHub grant box is registered with the proxy under: its
/// box id and its address stance. A native host and a daemon that predates
/// box ids give no id, and no proxy serves those boxes. A grant there is
/// refused with `gatehouse_unenrolled_node`, and never resolves to nothing.
#[cfg(test)]
pub(crate) fn grant_box_facts(
    grants: &[String],
    box_id: Option<String>,
    network: boxes::NetworkMode,
) -> Result<Option<(String, bep::boxes::Stance)>, boxes::core::bep::ActivationRefused> {
    proxy_box_facts(grants, &[], box_id, network)
}

/// `grant_box_facts` for a box with the GitHub grants `github_grants` and
/// the store references `stores`. A refusal names every one of them, and
/// names them as secrets, not as GitHub grants, when any is a store
/// reference.
fn proxy_box_facts(
    github_grants: &[String],
    stores: &[crate::mint::StoreGrant],
    box_id: Option<String>,
    network: boxes::NetworkMode,
) -> Result<Option<(String, bep::boxes::Stance)>, boxes::core::bep::ActivationRefused> {
    let grants = proxy_grant_names(github_grants, stores);
    if grants.is_empty() {
        return Ok(None);
    }
    match (box_id, proxy_stance(network)) {
        (Some(box_id), Some(stance)) => Ok(Some((box_id, stance))),
        _ => Err(boxes::core::bep::unenrolled_node(
            grants,
            !stores.is_empty(),
            boxes::core::bep::ProxyAbsence::NotServed,
        )),
    }
}

/// The root certificate a GitHub grant box trusts: the PEM that the
/// proxy's published identity carries (BEP-011, BEP-072). An identity that
/// carries none, one that is not a PEM certificate, or one whose subject
/// key is not the published root key is refused, so no grant box starts
/// without the root it needs, and none trusts a stale or foreign root.
#[cfg(test)]
pub(crate) fn grant_root_certificate(
    identity: &bep::publish::Identity,
) -> Result<String, anyhow::Error> {
    root_certificate_for(identity, false)
}

/// `grant_root_certificate` for a box whose only proxy-served secrets are
/// store references when `stored` is true, so its refusal names no GitHub
/// grant.
fn root_certificate_for(
    identity: &bep::publish::Identity,
    stored: bool,
) -> Result<String, anyhow::Error> {
    let refuse = || no_root_certificate(stored);
    let der = identity.root_certificate_der().map_err(|error| {
        tracing::debug!(%error, "the published identity carries no usable root certificate");
        refuse()
    })?;
    let root = identity
        .key(bep::keys::Role::Root)
        .map_err(|error| {
            tracing::debug!(%error, "the published identity carries no usable root key");
            refuse()
        })?
        .to_sec1_bytes();
    if !certificate_carries_key(&der, &root) {
        tracing::debug!("the published root certificate does not carry the published root key");
        return Err(refuse());
    }
    identity.root_certificate.clone().ok_or_else(refuse)
}

/// Whether `der`, a DER X.509 certificate, carries `point`, an uncompressed
/// SEC1 P-256 point, as its subject public key. It reads only the
/// structure up to the SubjectPublicKeyInfo. The name constraints and the
/// signature are the proxy's to issue and the box's TLS stack to check.
fn certificate_carries_key(der: &[u8], point: &[u8]) -> bool {
    // AlgorithmIdentifier content: id-ecPublicKey, prime256v1.
    const P256_ALGORITHM: &[u8] = &[
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x03, 0x01, 0x07,
    ];
    let spki = (|| {
        let (certificate, _) = der_element(der, 0x30)?;
        let (tbs, _) = der_element(certificate, 0x30)?;
        // The version is explicit and optional.
        let mut fields = der_element(tbs, 0xa0).map_or(tbs, |(_, rest)| rest);
        // serialNumber, signature, issuer, validity, subject.
        for tag in [0x02, 0x30, 0x30, 0x30, 0x30] {
            fields = der_element(fields, tag)?.1;
        }
        der_element(fields, 0x30).map(|(spki, _)| spki)
    })();
    let Some(spki) = spki else {
        return false;
    };
    let Some((algorithm, rest)) = der_element(spki, 0x30) else {
        return false;
    };
    let Some((key, rest)) = der_element(rest, 0x03) else {
        return false;
    };
    algorithm == P256_ALGORITHM && rest.is_empty() && key.split_first() == Some((&0, point))
}

/// The content of the DER element at the start of `input` when its tag is
/// `tag`, and the bytes after it.
fn der_element(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&found, input) = input.split_first()?;
    if found != tag {
        return None;
    }
    let (&first, input) = input.split_first()?;
    let (len, input) = if first < 0x80 {
        (usize::from(first), input)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || input.len() < count {
            return None;
        }
        let (bytes, input) = input.split_at(count);
        let len = bytes
            .iter()
            .fold(0usize, |len, &byte| (len << 8) | usize::from(byte));
        (len, input)
    };
    (input.len() >= len).then(|| input.split_at(len))
}

/// The refusal of a box whose proxy publishes no root certificate.
/// `stored` says the box's only proxy-served secrets are store references.
fn no_root_certificate(stored: bool) -> anyhow::Error {
    let declares = if stored {
        "a secret from the host's secret store"
    } else {
        "a GitHub grant"
    };
    anyhow::anyhow!(
        "Cannot start the box: it declares {declares}, and the Box Egress Proxy has \
         published no root certificate for the box to trust. Run `bep` to publish it, then \
         create the box again."
    )
}

/// What the grant mint hands to the create request: each grant's sealed
/// value, the proxy's root certificate, and the box's registration with
/// the proxy.
pub(crate) struct MintedGrants {
    /// Each grant's sealed value.
    pub minted: Vec<crate::mint::Minted>,
    /// The proxy's root certificate, PEM.
    pub root_certificate: Option<String>,
    /// The box's registration with the proxy.
    pub registration: Option<crate::mint::ProxyRegistration>,
}

/// Puts what the mint gave on the create request: one sealed delivery for
/// each grant (BEP-007) and the proxy's root certificate for the box to
/// trust (BEP-072). `grants` names every grant the proxy serves: the
/// GitHub grants, then the store references. A box with neither gets
/// neither a delivery nor a root.
#[cfg(test)]
pub(crate) fn hand_grants(
    request: &mut minimald_rpc::CreateSessionRequest,
    grants: &[String],
    minted: &[crate::mint::Minted],
    root_certificate: Option<String>,
) -> Result<(), anyhow::Error> {
    hand_minted(request, grants, false, minted, root_certificate)
}

/// `hand_grants`, where `stored` says the box's only proxy-served secrets
/// are store references, so a refusal names no GitHub grant.
fn hand_minted(
    request: &mut minimald_rpc::CreateSessionRequest,
    grants: &[String],
    stored: bool,
    minted: &[crate::mint::Minted],
    root_certificate: Option<String>,
) -> Result<(), anyhow::Error> {
    let deliveries = sealed_deliveries(grants, minted)?;
    let root_certificate = if grants.is_empty() {
        None
    } else {
        // A grant box with no root is refused before the mint, and this
        // keeps the refusal on every path to the request.
        Some(root_certificate.ok_or_else(|| no_root_certificate(stored))?)
    };
    request.config.sealed_deliveries = deliveries;
    request.config.root_certificate = root_certificate;
    Ok(())
}

/// Mints each GitHub grant's sign-in reference for the box `box_id`, and
/// registers the box's declared egress and stance with the Box Egress
/// Proxy (BEP-005). Then it mints a store handle for each of `stores`, and
/// seals each one as a `store` member (BEP-032). A box with store
/// references only registers with no sign-in. Does nothing for a box with
/// neither, and
/// refuses a grant box with no id or no stance, or one whose proxy
/// publishes no root certificate. It blocks on the control socket, so the
/// activation runs it on a blocking thread. The registration it gives
/// forgets the box at the proxy when it is dropped before the creation
/// finishes.
fn mint_grants(
    grants: Vec<String>,
    stores: &[crate::mint::StoreGrant],
    config_dir: Option<&std::path::Path>,
    box_id: Option<String>,
    egress: Vec<String>,
    network: boxes::NetworkMode,
) -> Result<MintedGrants, anyhow::Error> {
    use crate::mint::{
        ControlClient, GrantBox, HostClientKeyStore, MintError, ProxyRegistration,
        StoreOnlyMintError, local_client_key, mint_and_register, mint_store_members,
    };
    let Some((box_id, stance)) = proxy_box_facts(&grants, stores, box_id, network)? else {
        return Ok(MintedGrants {
            minted: Vec::new(),
            root_certificate: None,
            registration: None,
        });
    };
    let stored = grants.is_empty();
    let declares = if stored {
        "a secret from the host's secret store"
    } else {
        "a GitHub grant"
    };
    // A box with store references only is told about its secrets, not
    // about a GitHub grant it does not declare.
    let mint_error = |error: MintError| -> anyhow::Error {
        if stored {
            StoreOnlyMintError(error).into()
        } else {
            error.into()
        }
    };
    let (Some(identity_path), Some(control_path)) =
        (crate::mint::identity_path(), crate::mint::control_path())
    else {
        bail!(
            "Cannot start the box: it declares {declares}, and no home directory was found, \
             which holds the Box Egress Proxy's keys."
        );
    };
    let identity = bep::publish::Identity::read(&identity_path).map_err(|error| {
        mint_error(MintError::Identity {
            path: identity_path.clone(),
            error,
        })
    })?;
    // BEP-072: refused before the box registers, so a refusal leaves nothing
    // at the proxy.
    let root_certificate = root_certificate_for(&identity, stored)?;
    let mut control = ControlClient::connect(&control_path).map_err(mint_error)?;
    // BEP-063: every creation signs under the client's one kept key, so the
    // proxy holds one registration for this client, not one for each box. A
    // key the keychain refuses this program is replaced here, and the mint
    // registers the replacement before any handle leaves this process.
    let key = local_client_key(&HostClientKeyStore).map_err(mint_error)?;
    // A clock before the epoch gives no issue time, so the mint stops
    // rather than signing handles issued at zero.
    let Ok(since) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        bail!(
            "Cannot start the box: it declares {declares}, and the system clock reads a \
             time before 1970. Set the system clock, then create the box again."
        );
    };
    let now = since.as_secs();
    let mut minted = if grants.is_empty() {
        // A box with store references only needs no sign-in: it registers
        // its egress and stance here, as the GitHub mint does.
        let box_hex = crate::mint::box_id_hex(&box_id).map_err(mint_error)?;
        if let Err(error) = control.register_box(&box_hex, &egress, stance) {
            if !matches!(error, MintError::NotRunning { .. }) {
                drop(ProxyRegistration::new(control_path.clone(), &box_id).map_err(mint_error)?);
            }
            return Err(mint_error(error));
        }
        Vec::new()
    } else {
        let grant_box = GrantBox {
            box_id: box_id.clone(),
            grants,
            egress,
            stance,
        };
        mint_and_register(
            &bep::signin::HostKeychain,
            &identity,
            &identity_path,
            &mut control,
            &key,
            &grant_box,
            now,
        )?
    };
    // Held from here, so a failed store mint forgets the box at the proxy.
    let registration = ProxyRegistration::new(control_path, &box_id).map_err(mint_error)?;
    // BEP-032, BEP-063: one store handle for each accepted rule, sealed as a
    // `store` member under the grant's variable.
    minted.extend(
        mint_store_members(
            &identity,
            &identity_path,
            &mut control,
            &key,
            &box_id,
            stores,
            config_dir,
            now,
        )
        .map_err(mint_error)?,
    );
    Ok(MintedGrants {
        minted,
        root_certificate: Some(root_certificate),
        registration: Some(registration),
    })
}

/// The names of the grants the proxy serves: the GitHub grants, then the
/// store references, each the variable its sealed value lands in.
fn proxy_grant_names(
    github_grants: &[String],
    store_grants: &[crate::mint::StoreGrant],
) -> Vec<String> {
    github_grants
        .iter()
        .cloned()
        .chain(store_grants.iter().map(|store| store.grant.clone()))
        .collect()
}

/// The store grants of `secrets` under the rules `accepted` gives them, in
/// the proxy's form (BEP-032). A reference with no accepted rule, or with a
/// rule that has no single injection form, is refused by name, so a box
/// never starts with that grant's variable empty.
fn store_grants(
    secrets: &boxes::core::bep::SecretGrants,
    accepted: &boxes::core::bep::StoreRules,
) -> Result<Vec<crate::mint::StoreGrant>, anyhow::Error> {
    boxes::core::bep::store_references(secrets)
        .map(|reference| {
            reference
                .rule(accepted)
                .and_then(|rule| bep::handle::StoreRule::from_config(reference.id, rule))
                .map(|rule| crate::mint::StoreGrant {
                    grant: reference.grant.to_owned(),
                    rule,
                })
                .ok_or_else(|| {
                    GrantNotDelivered::NotSealed {
                        grant: reference.grant.to_owned(),
                    }
                    .into()
                })
        })
        .collect()
}

/// The authorities to register with the proxy as the box's declared egress
/// (BEP-022). A box whose egress admits every name lists none, so a GitHub
/// grant registers the module's hosts for it, or the proxy would refuse them.
fn proxy_egress(
    egress: Option<&boxes::EgressPolicy>,
    network: boxes::NetworkMode,
    github_grant: bool,
) -> Vec<String> {
    if github_grant && boxes::core::bep::egress_admits_every_name(network, egress) {
        return bep::module::GITHUB
            .hosts
            .iter()
            .map(|authority| authority.host.to_string())
            .collect();
    }
    egress
        .and_then(|egress| egress.allow_dns_hosts.clone())
        .unwrap_or_default()
}

/// Mints the box's GitHub grants and its accepted store references for the
/// box id `box_id` the registration handed back, and puts each grant's
/// sealed value on the request for the box's launches to place (BEP-005,
/// BEP-007, BEP-032), with the proxy's root certificate (BEP-072). Does
/// nothing for a box with neither. `config_dir` is the `min --config-dir`
/// override, which the store mint checks `bep serve` agrees with. No box
/// exists yet, so a failure only withdraws the row the box's registration
/// bought (T66). `box_name` is the name that row was registered under. A
/// box with no `--name` has none on the request (BOX-163).
async fn mint_into_request(
    request: &mut minimald_rpc::CreateSessionRequest,
    box_name: Option<&str>,
    registered_id: Option<minimald_rpc::BoxId>,
    github_grants: &[String],
    store_grants: &[crate::mint::StoreGrant],
    config_dir: Option<std::path::PathBuf>,
    control_sock: Option<std::path::PathBuf>,
) -> Result<Option<crate::mint::ProxyRegistration>, anyhow::Error> {
    let grants = github_grants.to_vec();
    let stores = store_grants.to_vec();
    let delivered = proxy_grant_names(github_grants, store_grants);
    let stored = github_grants.is_empty();
    let box_id = registered_id.map(|box_id| box_id.to_string());
    let network = request.config.network;
    let egress = proxy_egress(
        request.config.policy.egress.as_ref(),
        network,
        !github_grants.is_empty(),
    );
    // The mint blocks on the proxy's control socket and the host keychain,
    // so it runs off the runtime's workers.
    let minted = tokio::task::spawn_blocking(move || {
        mint_grants(
            grants,
            &stores,
            config_dir.as_deref(),
            box_id,
            egress,
            network,
        )
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|minted| minted)
    .and_then(|minted| {
        hand_minted(
            request,
            &delivered,
            stored,
            &minted.minted,
            minted.root_certificate,
        )?;
        Ok(minted.registration)
    });
    match minted {
        Ok(registration) => Ok(registration),
        Err(error) => {
            withdraw_box_row(
                control_sock,
                box_name,
                request.config.box_addresses,
                registered_id,
            )
            .await;
            Err(error)
        }
    }
}

/// The create request's sealed deliveries: one for each GitHub grant, in
/// the grants' order, each holding the value the mint sealed for it
/// (BEP-007). A grant the mint gave no sealed value is refused by name, so
/// a box never starts with that grant's variable empty.
fn sealed_deliveries(
    grants: &[String],
    minted: &[crate::mint::Minted],
) -> Result<Vec<boxes::SealedDelivery>, anyhow::Error> {
    grants
        .iter()
        .map(|grant| {
            let Some(minted) = minted.iter().find(|minted| &minted.grant == grant) else {
                return Err(GrantNotDelivered::NotSealed {
                    grant: grant.clone(),
                }
                .into());
            };
            Ok(boxes::SealedDelivery {
                variable: grant.clone(),
                sealed: minted.sealed.to_string(),
            })
        })
        .collect()
}

/// One named step of [`activate_box`], in the order the activation runs
/// them. Each step runs inside its own `activation_step` span, so a log read
/// under `RUST_LOG=info` shows where an activation spent its time and which
/// step ended it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActivationStep {
    /// The flags alone: ingress and egress declarations and the project path.
    CheckArguments,
    /// The project file's grants, refused before anything is created.
    CheckProject,
    /// The daemon is started if it is not already running.
    StartDaemon,
    /// Loadouts, hooks and the user contribution, composed on this machine.
    ResolveLoadouts,
    /// The upload root and whether the upload is skipped.
    PlanUpload,
    /// The daemon connection and the duplicate-session advisory.
    ConnectDaemon,
    /// The box's registration with the VM host daemon.
    RegisterBox,
    /// The GitHub grants' sign-in references, sealed onto the create
    /// request, and the box's registration with the Box Egress Proxy.
    MintGrants,
    /// The `CreateSession` call and its version gate.
    CreateSession,
    /// The session-start lines printed once the session exists.
    ReportStart,
    /// The project file upload into the session workspace.
    UploadFiles,
    /// The loadout composition and its gating.
    ComposeLoadout,
    /// The patch upload and the finalize that makes the session active.
    Finalize,
    /// The `host_ip` name hold on the VM host daemon.
    HoldName,
}

impl ActivationStep {
    /// Every step, in the order [`activate_box`] runs them.
    #[cfg(test)]
    pub(crate) const ORDER: [Self; 14] = [
        Self::CheckArguments,
        Self::CheckProject,
        Self::StartDaemon,
        Self::ResolveLoadouts,
        Self::PlanUpload,
        Self::ConnectDaemon,
        Self::RegisterBox,
        Self::MintGrants,
        Self::CreateSession,
        Self::ReportStart,
        Self::UploadFiles,
        Self::ComposeLoadout,
        Self::Finalize,
        Self::HoldName,
    ];

    /// The step's name in its span and in the failure record.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::CheckArguments => "check_arguments",
            Self::CheckProject => "check_project",
            Self::StartDaemon => "start_daemon",
            Self::ResolveLoadouts => "resolve_loadouts",
            Self::PlanUpload => "plan_upload",
            Self::ConnectDaemon => "connect_daemon",
            Self::RegisterBox => "register_box",
            Self::CreateSession => "create_session",
            Self::MintGrants => "mint_grants",
            Self::ReportStart => "report_start",
            Self::UploadFiles => "upload_files",
            Self::ComposeLoadout => "compose_loadout",
            Self::Finalize => "finalize",
            Self::HoldName => "hold_name",
        }
    }

    /// Runs `work` inside this step's span. A failure is logged with the
    /// step's name and returned unchanged: the error the person sees, and
    /// the exit code `main.rs` downcasts it to, stay the step's own.
    pub(crate) async fn run<T>(
        self,
        work: impl std::future::Future<Output = Result<T, anyhow::Error>>,
    ) -> Result<T, anyhow::Error> {
        use tracing::Instrument as _;
        let span = tracing::info_span!(
            "activation_step",
            step = self.name(),
            otel.status_code = tracing::field::Empty
        );
        let result = work.instrument(span.clone()).await;
        if let Err(error) = &result {
            // The status, so a trace query for failed steps finds them; the
            // event stays at INFO, since a failed step is often expected.
            span.record("otel.status_code", "ERROR");
            span.in_scope(|| {
                tracing::info!(
                    step = self.name(),
                    error = %format!("{error:#}"),
                    "activation step failed"
                );
            });
        }
        result
    }
}

/// Puts the root of the project at `dir` on the create request: the
/// directory that holds the project's `minimal.toml`, found the way the
/// upload finds it. The daemon records it as the box's project root
/// (BOX-001).
///
/// # Errors
///
/// Fails on a broken `minimal.toml` in `dir` or a parent of it.
pub(crate) fn stamp_project_root(
    request: &mut minimald_rpc::CreateSessionRequest,
    dir: &camino::Utf8Path,
) -> Result<(), anyhow::Error> {
    let root = resolve_upload_root(dir)?;
    set_project_root(request, root)
}

/// Puts `root` on the create request as the box's project root (BOX-001).
fn set_project_root(
    request: &mut minimald_rpc::CreateSessionRequest,
    root: camino::Utf8PathBuf,
) -> Result<(), anyhow::Error> {
    request.config.project_root =
        Some(paths::HostAbsPath::try_new(root).context("Invalid project root")?);
    Ok(())
}

/// The spec flags of the create request: the network mode, the policy and
/// the hooks choice that the command's flags and the project resolved.
pub(crate) fn spec_flags(request: &minimald_rpc::CreateSessionRequest) -> mfile::spec::SpecFlags {
    mfile::spec::SpecFlags {
        network: request.config.network,
        policy: request.config.policy.clone(),
        hooks_enabled: request.config.hooks_enabled,
    }
}

/// Puts `spec` on the create request, for the daemon to store with the
/// box's record (BOX-068).
///
/// # Errors
///
/// Fails if the spec cannot be encoded as JSON.
pub(crate) fn put_spec(
    request: &mut minimald_rpc::CreateSessionRequest,
    spec: &mfile::spec::BoxSpec,
) -> Result<(), anyhow::Error> {
    request.spec = Some(serde_json_lenient::to_value(spec).context("Cannot encode the box spec")?);
    Ok(())
}

/// Adds each `--vpn-network-names` value to the `network.vpn_network_names`
/// list of the spec on `request` (BCLI-024). A name the list already holds
/// is not added again. The daemon stores the list with the box's spec, and
/// does not enforce it (BOX-076). Nothing changes when `names` is empty.
///
/// # Errors
///
/// Fails when `names` is not empty and the request carries no spec, so a
/// name is never dropped without a word. Fails too when the spec on
/// `request` has a `network` that is not a table, or a
/// `network.vpn_network_names` that is not a list.
pub(crate) fn add_vpn_network_names(
    request: &mut minimald_rpc::CreateSessionRequest,
    names: &[String],
) -> Result<(), anyhow::Error> {
    use serde_json_lenient::Value;
    if names.is_empty() {
        return Ok(());
    }
    let Some(spec) = request.spec.as_mut() else {
        anyhow::bail!(
            "Cannot use --vpn-network-names here: this box does not store a `[network]` \
             section. Run the command again without --vpn-network-names."
        );
    };
    let network = spec
        .as_object_mut()
        .context("The box spec is not a table")?
        .entry("network")
        .or_insert_with(|| Value::Object(serde_json_lenient::Map::new()))
        .as_object_mut()
        .context("The box spec's network is not a table")?;
    let list = network
        .entry("vpn_network_names")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .context("The box spec's network.vpn_network_names is not a list")?;
    for name in names {
        let value = Value::String(name.clone());
        if !list.contains(&value) {
            list.push(value);
        }
    }
    Ok(())
}

/// Marks `request` as a fresh instance (BCLI-070, BOX-163). The daemon
/// names the box `<name>-<n>`, with the smallest `n` no retained box uses,
/// and never refuses it for a held name. The client invents no name, so the
/// request carries none. `min task run` and `min box run` create every box
/// this way.
pub(crate) fn request_fresh_instance(request: &mut minimald_rpc::CreateSessionRequest) {
    request.config.name = None;
    request.fresh_instance = true;
}

/// The name the daemon gives the box `request` creates, when the create
/// is not a fresh instance (BOX-163): the spec's `[box] name`, else the
/// request's name, else the spec's entry as the daemon cleans it
/// ([`boxes::box_name::entry_box_name`]). `None` for a request with no spec
/// and no name.
pub(crate) fn created_box_name(request: &minimald_rpc::CreateSessionRequest) -> Option<String> {
    let spec = request.spec.as_ref().and_then(|value| {
        serde_json_lenient::from_value::<mfile::spec::BoxSpec>(value.clone()).ok()
    });
    if let Some(name) = spec.as_ref().and_then(|spec| spec.name.clone()) {
        return Some(name);
    }
    if let Some(name) = request.config.name.clone() {
        return Some(name);
    }
    // Only the entry is cleaned, as the daemon cleans it, so the VM host
    // row and the box carry one name. A `[box] name` or `--name` is sent
    // unchanged above.
    spec.map(|spec| boxes::box_name::entry_box_name(&spec.entry))
}

/// The creation key a fresh-instance `host_ip` grant box registers under
/// with the VM host daemon (BEP-082): `<base>~<random hex>`. The daemon
/// names a fresh instance `<base>-<n>` only after the registration, so the
/// box cannot register under that name. No box name can spell `~`, so the
/// key never meets a box's name, and two fresh instances of one entry
/// register at once under keys of their own. `None` for a create that is
/// not a fresh instance, or for a box that is not a `host_ip` grant box:
/// those register under [`created_box_name`].
///
/// # Errors
///
/// Fails if the system gives no random bytes for the key.
pub(crate) fn host_ip_registration_key(
    request: &minimald_rpc::CreateSessionRequest,
    base: Option<&str>,
) -> Result<Option<String>, anyhow::Error> {
    let grant_box = matches!(request.config.network, boxes::NetworkMode::HostNet)
        && request.config.box_addresses.is_none()
        && request.config.policy.credentialed_upstream.is_some();
    let Some(base) = base.filter(|_| request.fresh_instance && grant_box) else {
        return Ok(None);
    };
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("Cannot make a registration key for the box: {error}"))?;
    Ok(Some(format!("{base}~{}", hex::encode(bytes))))
}

/// The name the daemon gave box `id`, read off its record. `None` when the
/// read fails or the box has no name: the caller keeps the name it had.
pub(crate) async fn daemon_box_name(
    client: &mut minimal_client::Client,
    id: boxes::SessionId,
) -> Option<String> {
    match client
        .oneshot_rpc::<minimald_rpc::GetSessionRecord>(minimald_rpc::GetSessionRecordRequest::Id(
            id,
        ))
        .await
    {
        Ok(reply) => reply.record.and_then(|record| record.name),
        Err(error) => {
            tracing::warn!(session_id = %id, %error, "could not read the name the daemon gave the box");
            None
        }
    }
}

/// The error a refused create ends the command with. A held name ends it
/// with exit 2, naming the holder (BOX-163). Any other refusal is the
/// daemon's text as it is.
pub(crate) fn create_refusal(error: String) -> anyhow::Error {
    match minimal_client::box_name::held_name_refusal(&error) {
        Some(refusal) => {
            tracing::info!(
                name = %refusal.name,
                holder = ?refusal.holder,
                holder_name = %refusal.holder_name,
                exit_code = minimald_rpc::HeldNameRefusal::EXIT_CODE,
                "the create was refused: a running box holds the name"
            );
            anyhow::Error::new(refusal)
        }
        None => anyhow::anyhow!("{error}"),
    }
}

/// The id and name of the box that holds `held`, read from the daemon by
/// name. `None` when the read fails or finds no box.
async fn held_name_holder(
    client: &mut minimal_client::Client,
    held: &str,
) -> Option<(boxes::SessionId, Option<String>)> {
    match client
        .oneshot_rpc::<minimald_rpc::GetSessionRecord>(minimald_rpc::GetSessionRecordRequest::Name(
            held.to_string(),
        ))
        .await
    {
        Ok(reply) => reply.record.map(|record| (record.id, record.name)),
        Err(error) => {
            tracing::warn!(held_name = %held, %error, "could not read the box that holds the name");
            None
        }
    }
}

/// The error an own-address create ends with when the VM host refused its
/// registration because a live row holds `held` (BOX-163). It is the
/// held-name refusal a daemon create sends, so `min` exits 2. It names the
/// holder's id when `holder` gives its id and name, and the held spelling
/// alone when the holder could not be read.
pub(crate) fn registration_held_name_refusal(
    name: &str,
    held: &str,
    holder: Option<(boxes::SessionId, Option<String>)>,
) -> anyhow::Error {
    let (holder, holder_name) = match holder {
        Some((id, name)) => (Some(id), name),
        None => (None, None),
    };
    let refusal = minimald_rpc::HeldNameRefusal {
        name: name.to_string(),
        holder,
        holder_name: holder_name.unwrap_or_else(|| held.to_string()),
    };
    tracing::info!(
        name = %refusal.name,
        holder = ?refusal.holder,
        holder_name = %refusal.holder_name,
        exit_code = minimald_rpc::HeldNameRefusal::EXIT_CODE,
        "the box registration was refused: a running box holds the name"
    );
    anyhow::Error::new(refusal)
}

/// Puts the spec of a session box from `dir` on the create request
/// (BOX-068): the project's `[session]` table, with the request's network
/// mode, policy and hooks choice as the flags. A project with no
/// `minimal.toml` has no `[session]` table.
///
/// Known gap: the dashboard's activation in `crates/minimal/src/dash/rpc.rs`
/// builds its own `CreateSessionRequest` and does not call this yet, so a
/// session box created from `min dash` has no stored spec. That file is
/// outside this change. A follow-up must call this function there.
///
/// # Errors
///
/// Fails on a `minimal.toml` in `dir` or a parent of it that does not load.
#[cfg(test)]
pub(crate) fn stamp_session_spec(
    request: &mut minimald_rpc::CreateSessionRequest,
    dir: &camino::Utf8Path,
) -> Result<(), anyhow::Error> {
    stamp_session_spec_as(request, dir, None, None)
}

/// [`stamp_session_spec`] for the session entry `entry`, when it is not
/// `default`, with `name` as the spec's `[box] name` (BCLI-069).
///
/// The spec names the typed entry, but its body still comes from the
/// project's `[session]` table through `BoxSpec::for_session`. The body of
/// `[sessions.<entry>]` is not applied yet. That is the interim of
/// gominimal/minimal#3204, and until then `plan_start` refuses a typed
/// session entry other than `default`
/// ([`StartEntryRefusal::NamedSessionUnsupported`]). A bare start of the
/// only session entry still reaches this function with that entry's name.
/// Flip it when box creation reads entries
/// (gominimal/minimal#2418): then expand the typed entry's body into the
/// spec through BOX-064's layers.
///
/// # Errors
///
/// Fails on a `minimal.toml` in `dir` or a parent of it that does not load.
pub(crate) fn stamp_session_spec_as(
    request: &mut minimald_rpc::CreateSessionRequest,
    dir: &camino::Utf8Path,
    entry: Option<&str>,
    name: Option<&str>,
) -> Result<(), anyhow::Error> {
    let session = match mfile::File::from_dir_recursive(dir.as_std_path()) {
        Ok(file) => file.session,
        Err(mfile::Error::NotFound) => None,
        Err(error) => return Err(ProjectFileInvalid { error }.into()),
    };
    let mut spec = mfile::spec::BoxSpec::for_session(session.as_ref(), spec_flags(request));
    if let Some(entry) = entry {
        spec.entry = entry.to_string();
    }
    if let Some(name) = name {
        spec.name = Some(name.to_string());
    }
    put_spec(request, &spec)
}

/// The project root to record for an activation from `dir`. Tarball sync
/// already resolved it as `upload_root`, so it is reused. Otherwise the root
/// is resolved here. `CheckProject` already refuses a `minimal.toml` that does
/// not load under every `--sync` mode, before `PlanUpload` runs, so an error
/// here is not expected and propagates.
///
/// # Errors
///
/// Fails on a broken `minimal.toml` in `dir` or a parent of it.
fn activation_project_root(
    upload_root: Option<&camino::Utf8Path>,
    dir: &camino::Utf8Path,
) -> Result<camino::Utf8PathBuf, anyhow::Error> {
    match upload_root {
        Some(root) => Ok(root.to_path_buf()),
        None => resolve_upload_root(dir),
    }
}

/// The workspace upload a create planned, so the upload step holds one value
/// instead of a root and a decision that are only meaningful together.
enum UploadPlan {
    /// `--sync none`: the daemon composes against an empty workspace.
    Skip,
    /// The tree to stream, and what the upload gate decided about it.
    Workspace {
        root: camino::Utf8PathBuf,
        decision: UploadDecision,
    },
}

/// The refusal when the VM gave a `host_ip` grant box an id other than the
/// one its registration minted (BEP-082).
const REGISTERED_ID_MISMATCH: &str = "No session was created. The VM gave the new session \
     an id other than the one reserved for it. Run the command again.";

/// Checks that the box the daemon created carries the id a `host_ip`
/// registration minted, byte for byte (BEP-082). A box with no `host_ip`
/// registration, or a registration with no id, has nothing to check.
fn ensure_registered_id(
    registered: Option<&minimal_client::box_registration::RegisteredWithVmHost>,
    created: boxes::SessionId,
) -> anyhow::Result<()> {
    let Some(minted) = registered
        .filter(|registration| registration.host_ip)
        .and_then(|registration| registration.box_id)
    else {
        return Ok(());
    };
    if minted.to_bytes() == created.to_bytes() {
        return Ok(());
    }
    tracing::warn!(
        registered_box_id = %minted,
        created_box_id = %created,
        "refused a host_ip box whose record id is not its registration's id"
    );
    Err(anyhow::anyhow!(REGISTERED_ID_MISMATCH))
}

/// The egress section the egress flags declare, or `None` when no egress
/// flag is given. `min session activate` and `min task run` both read their
/// flags through it.
///
/// # Errors
///
/// An `--allow-protocols` value that is not a protocol.
pub(crate) fn flag_egress(
    args: &crate::EgressArgs,
) -> Result<Option<boxes::EgressPolicy>, anyhow::Error> {
    let mut allow_protocols = Vec::with_capacity(args.allow_protocols.len());
    for spec in &args.allow_protocols {
        allow_protocols.push(parse_egress_proto(spec)?);
    }
    // Any rule flag makes the declaration; a field with no values stays
    // `None` — its allow-all/none-denied default — so `--deny-subnets` alone
    // records an allow-all policy that denies one range. `--deny-all-egress`
    // is not a rule: [`effective_egress`] applies it to the file's lists.
    let has_egress = !args.allow_subnets.is_empty()
        || !allow_protocols.is_empty()
        || !args.allow_dns_hosts.is_empty()
        || !args.deny_subnets.is_empty();
    Ok(has_egress.then_some(boxes::EgressPolicy {
        allow_subnets: (!args.allow_subnets.is_empty())
            .then(|| normalize_subnets(&args.allow_subnets)),
        allow_dns_hosts: (!args.allow_dns_hosts.is_empty()).then(|| args.allow_dns_hosts.clone()),
        allow_protocols: (!allow_protocols.is_empty()).then_some(allow_protocols),
        deny_subnets: (!args.deny_subnets.is_empty())
            .then(|| normalize_subnets(&args.deny_subnets)),
    }))
}

/// The line naming the masked network for each subnet flag that carries
/// host bits, e.g. `--deny-subnets 10.0.0.1/8 is read as 10.0.0.0/8`.
/// `min session activate`, `min task run` and `min box run` print them.
pub(crate) fn subnet_notices(args: &crate::EgressArgs) -> Vec<String> {
    let notices = |flag: &str, entries: &[String]| -> Vec<String> {
        entries
            .iter()
            .filter_map(|entry| {
                boxes::normalized_cidr(entry)
                    .map(|normalized| format!("{flag} {entry} is read as {normalized}"))
            })
            .collect()
    };
    let mut lines = notices("--allow-subnets", &args.allow_subnets);
    lines.extend(notices("--deny-subnets", &args.deny_subnets));
    lines
}

/// The `--ingress` mappings and the egress flags of an activation, parsed
/// (BCLI-024). Each flag overrides only its own key of the entry's
/// `[network]` table.
///
/// # Errors
///
/// Fails when an `--ingress` mapping or an egress flag does not parse.
pub(crate) fn flag_network_overrides(
    args: &ActivateArgs,
) -> Result<(Vec<boxes::PortMapping>, Option<boxes::EgressPolicy>), anyhow::Error> {
    let mut port_mappings = Vec::with_capacity(args.ingress.len());
    for spec in &args.ingress {
        port_mappings.push(parse_ingress_mapping(spec)?);
    }
    let egress = flag_egress(&args.egress)?;
    Ok((port_mappings, egress))
}

/// The egress and ingress half of an activation's create policy: the
/// effective `egress` and the parsed `--ingress` mappings (BCLI-024). The
/// other fields keep their defaults, for the caller to set.
///
/// NET-043: any dynamic declaration makes the ingress policy too. A stance
/// alone (with no range, no static mapping) still names how dynamic
/// requests are decided. Nothing set keeps `None`: the deny-all default,
/// which the policy module evaluates the same as an explicit deny.
pub(crate) fn network_override_policy(
    args: &ActivateArgs,
    port_mappings: Vec<boxes::PortMapping>,
    egress: Option<boxes::EgressPolicy>,
) -> boxes::BoxPolicy {
    let has_ingress =
        !port_mappings.is_empty() || args.dynamic_ingress.is_some() || args.dynamic_range.is_some();
    boxes::BoxPolicy {
        egress,
        ingress: has_ingress.then_some(boxes::IngressPolicy {
            port_mappings,
            dynamic_allowed_range: args.dynamic_range,
            dynamic_ingress: args.dynamic_ingress,
        }),
        ..boxes::BoxPolicy::default()
    }
}

/// The loadouts an activation resolves (BCLI-073): each `--loadout` in
/// place of the client config's `default_loadouts`, or none under
/// `--no-loadouts`. The stored spec does not record the selected loadouts
/// yet: <https://github.com/gominimal/minimal/issues/3236>.
pub(crate) fn start_loadout_selection(args: &ActivateArgs) -> loadouts::LoadoutSelection {
    loadouts::LoadoutSelection::from_flags(&args.loadout, args.no_loadouts)
}

pub(crate) async fn activate_box(
    global: &GlobalArgs,
    mut args: ActivateArgs,
    options: impl Into<ActivationOptions>,
) -> Result<(), anyhow::Error> {
    let options: ActivationOptions = options.into();
    let offer_scaffold = options.offer_scaffold;
    let (utf8_path, abs_path, port_mappings, egress) = ActivationStep::CheckArguments
        .run(async {
            let effective_path = match (&args.path, &global.repo_dir) {
                (Some(p), _) => std::path::PathBuf::from(p),
                (None, Some(dir)) => dir.clone(),
                (None, None) => std::path::PathBuf::from("."),
            };

            let project_path = std::fs::canonicalize(&effective_path).with_context(|| {
                format!("Cannot resolve project path '{}'", effective_path.display())
            })?;

            let utf8_path = camino::Utf8PathBuf::from_path_buf(project_path)
                .map_err(|_| anyhow::anyhow!("Project path is not valid UTF-8"))?;
            let abs_path =
                paths::HostAbsPath::try_new(utf8_path.clone()).context("Invalid project path")?;

            let (port_mappings, egress) = flag_network_overrides(&args)?;
            Ok::<_, anyhow::Error>((utf8_path, abs_path, port_mappings, egress))
        })
        .await?;
    let (policy, github_grants, store_grants) = ActivationStep::CheckProject
        .run(async {
            let (project_bep, project_secrets, project_env, project_quic443) =
                project_bep_and_grants(&utf8_path)?;
            // NET-060: the project's egress, with each field a flag names
            // replaced by the flag.
            let mut project_egress = project_egress(&utf8_path, options.entry.as_deref())?;
            let (network, port_mappings) =
                session_box_network(&args, &mut project_egress, port_mappings)?;
            // Every later read of `args.network` sees the box's mode.
            args.network = Some(network);
            // A legacy key spelling still loads. A start with no terminal
            // prints its hint, and an interactive start logs it, so no line
            // prints before the box shell.
            let headless = args.no_prompt || global.no_input || !can_prompt_interactively();
            for hint in &project_egress.hints {
                if headless {
                    eprintln!("{hint}");
                } else {
                    tracing::warn!(hint = %hint, "the project's network keys use a legacy spelling");
                }
            }
            let egress =
                session_effective_egress(project_egress, egress, network.into(), &args.egress)?;
            tracing::debug!(
                egress = ?egress.policy,
                sources = ?egress.sources,
                "the create request's effective egress"
            );
            let mut policy = boxes::BoxPolicy {
                // NET-134: the lane is the box's own declaration, never a default —
                // a box that did not ask for a credentialed upstream keeps every
                // frame it sends to the proxy's address refused at the host-side
                // gate, whatever its egress rules say.
                credentialed_upstream: credentialed_upstream_for(
                    args.credentialed_upstream,
                    &project_bep,
                    &project_secrets,
                ),
                // BEP-018: the declared stance is a setting of every box, lane
                // or not, so a declared `block` reaches the gate of a box with
                // no credentialed upstream.
                // BCLI-024: `--quic443` replaces the declared stance.
                quic443: options.quic443.or(project_quic443),
                ..network_override_policy(&args, port_mappings, egress.policy)
            };

            // BEP-008/009/010/017/056: a box spec with a grant it cannot honour is
            // refused here, before the daemon starts and before anything is created.
            // BEP-057: the client configuration is read only when a grant needs the
            // acknowledgement, so a box with no narrow grant never depends on it.
            let full_breadth_acknowledged = project_secrets
                .values()
                .any(boxes::core::bep::SecretGrant::is_narrower_than_full)
                && crate::config::full_breadth_acknowledged(global)?;
            let (network, box_zone_resolver) = creation_host(daemon_host_kind(global), &args);
            refuse_unhonourable_grants(
                network,
                policy.egress.as_ref(),
                &project_bep,
                &project_secrets,
                full_breadth_acknowledged,
                box_zone_resolver,
                &project_env,
            )?;
            // BEP-034/035/036: each store reference needs a rule that admits
            // it, inside the box's egress, before anything is created.
            let can_ask = !global.no_input && crate::can_prompt_interactively();
            // BEP-032: each accepted reference gets a store handle, sealed
            // as a `store` member at the mint below.
            let accepted_store_rules =
                check_store_grants(global, &project_secrets, policy.egress.as_ref(), can_ask)?;
            let store_grants = store_grants(&project_secrets, &accepted_store_rules)?;
            // BEP-062: a `dns` or `both` box resolves each accepted rule's
            // upstream to the proxy, so the gate needs the authorities.
            put_store_upstreams(&mut policy, &accepted_store_rules);
            // Gatehouse §6.2, BEP-003: a GitHub grant needs a node-local
            // proxy, and then a held sign-in. Only the item's metadata is
            // read, and nothing asks for a sign-in.
            let identity = crate::mint::identity_path();
            let control = crate::mint::control_path();
            // The proxy program is the one `min secret` names: `bep` beside
            // the `minvmd` on PATH, unless MINVMD_BEP_BIN gives it.
            let binary = bep::store::proxy_binary_on_path(
                std::env::var_os(bep::store::PROXY_BIN_ENV).as_deref(),
                std::env::var_os("PATH").as_deref(),
            );
            let github_grants = check_github_grants(
                &project_secrets,
                proxy_absence(
                    identity.as_deref(),
                    control.as_deref(),
                    binary,
                    proxy_log_path(global.minimal_dir.as_deref()),
                ),
                &bep::signin::HostKeychain,
            )?;
            Ok::<_, anyhow::Error>((policy, github_grants, store_grants))
        })
        .await?;
    ActivationStep::StartDaemon
        .run(async { ensure_daemon(global) })
        .await?;

    // BOX-163: the request carries a name only for `--name`. With none,
    // the daemon names the box from its spec's entry. A held name, the
    // entry's or a `--name`, is refused below: the command ends with exit
    // 2, naming the holder. The client invents no name.

    let network: boxes::NetworkMode = args.network_mode().into();

    // The daemon sources `username` from the authenticated SSH
    // connection context; the client doesn't send it. `box_addresses`
    // lands just before the create (T66): the registration is the last
    // fallible client-side step, so a loadout, policy, or hook failure
    // between here and there never strands a row on the host.
    let mut request =
        minimald_rpc::CreateSessionRequest::new(String::new(), abs_path.clone(), network, policy);
    request.config.name = request_name(args.name.as_deref());
    // BCLI-070: `--new` asks for a fresh instance, `<name>-<n>`. The
    // spec's `[box] name`, when `--name` gives one, is the base of the name.
    if options.fresh_instance {
        request_fresh_instance(&mut request);
    }
    request.config.hooks_enabled = !args.no_hooks;
    request.config.creating_verb = minimald_rpc::CreatingVerb::Session;
    // The version gate: a daemon of another build refuses the create
    // outright, before it allocates anything to tear down. `None` under the
    // skew override, which is what lets an operator proceed.
    request.must_match_version = version_assertion();

    // `--sync` defaults to tarball; `sync_explicit` records whether the
    // user actually typed the flag, which distinguishes a deliberate
    // `--sync tarball` (the escape hatch that force-uploads an empty dir
    // or `$HOME`) from the implicit default.
    let sync_explicit = args.sync.is_some();

    // Resolve the upload root before opening the daemon connection: a
    // malformed mfile in an ancestor should fail loudly before we create a
    // session on the daemon, so we don't leak a draft session. Resolved
    // before the loadout prep, which checks the project's own hooks and sizes
    // the finalize budget against the project root — not the directory the
    // command was invoked from. Only needed for tarball sync, the default:
    // `--sync none` skips the upload entirely (#770).
    let upload_root = match args.sync.unwrap_or(SyncMode::Tarball) {
        SyncMode::None => None,
        SyncMode::Tarball => Some(resolve_upload_root(&utf8_path)?),
    };
    // The record's project root (BOX-001), set on the request below under
    // every `--sync` mode, `none` included.
    let project_root = activation_project_root(upload_root.as_deref(), &utf8_path)?;

    let (
        policy_path,
        initial_policy,
        compose_options,
        hook_scripts,
        finalize_hook_budget,
        contribution,
        user_policy,
    ) = ActivationStep::ResolveLoadouts
        .run(async {
            // Resolve and compose the loadouts BEFORE opening the daemon
            // connection: a missing loadout file or a malformed one should
            // fail loudly on the client side without ever touching the
            // daemon. The same sequence stages the loadout hook scripts and
            // sizes the finalize hook budget, so `min session activate`,
            // `min task run`, and the dashboard share it.
            let policy_path = config::user_policy_path(global);
            // BOX-173, BOX-175, BOX-181: the box's loadout mode, read before
            // any loadout file. A sealed box selects none and prints nothing
            // about its skipped defaults (BOX-171).
            let mode =
                session_loadout_mode(&project_root, options.entry.as_deref(), &args.loadout)?;
            let selection = loadouts::gate_selection(start_loadout_selection(&args), mode);
            // The project root the upload will carry, so the project's own
            // hooks are checked and its `[session]` timeouts size the finalize
            // budget; a subdirectory invocation must not look empty.
            let hooks = if args.no_hooks {
                loadouts::HookPrep::Disabled
            } else {
                loadouts::HookPrep::Enforce
            };
            let inputs =
                loadouts::prepare_activation_inputs(global, &project_root, selection, hooks, None)?;

            // Scaffold-offer a missing `minimal.toml` only after the loadouts
            // resolve and compose: a bad `--loadout` must error before anything
            // prints, so the user is never told the session is proceeding and
            // then that it is not. `--sync none` never sends a `minimal.toml`,
            // so offering to create one there would only write a file the
            // session then ignores.
            if offer_scaffold && !matches!(args.sync, Some(SyncMode::None)) {
                offer_mfile_scaffold(
                    &utf8_path,
                    global,
                    Some(
                        "Continuing without one; the session gets a default environment. \
                 Run 'min init' to give the project its own config.",
                    ),
                )?;
            }

            inputs.announce_loadouts();

            // The contribution carries the banner's loadout display list as a
            // first-class orientation field (the daemon seeds MINIMAL_LOADOUTS
            // from it in the launcher baseline). The banner's other dynamic
            // clause — blueprint presence — is a session-filesystem fact,
            // tested by the templates in-shell when they print.
            Ok::<_, anyhow::Error>((
                policy_path,
                inputs.initial_policy,
                inputs.compose_options,
                inputs.hook_scripts,
                inputs.hook_budget,
                inputs.contribution,
                inputs.user_policy,
            ))
        })
        .await?;

    // BOX-068: the box's expanded entry rides on the contribution, and the
    // daemon composes the project's part of the box from it. One span
    // covers the expansion and the compose call that sends it.
    use tracing::Instrument as _;
    let entry_span = tracing::info_span!("box_entry", box_type = boxes::SESSION_BOX_TYPE);
    let mut contribution = contribution;
    contribution.entry = entry_span
        .in_scope(|| session_box_entry(&project_root, options.entry.as_deref(), !args.no_hooks))?
        .map(Box::new);

    // The upload decision needs no TTY — the interactive `Confirm` is answered
    // at the upload step, once the session exists — so it is resolved here,
    // still before the create. A `$HOME` whose lifecycle hooks a skip would
    // drop refuses here rather than after a session and its row exist.
    let upload_plan = ActivationStep::PlanUpload
        .run(async {
            set_project_root(&mut request, project_root)?;
            // BOX-068: the box's spec, after every flag and the project's
            // policy are on the request.
            stamp_session_spec_as(
                &mut request,
                &utf8_path,
                options.entry.as_deref(),
                options.box_name.as_deref(),
            )?;
            add_vpn_network_names(&mut request, &options.vpn_network_names)?;

            let Some(root) = upload_root else {
                return Ok::<_, anyhow::Error>(UploadPlan::Skip);
            };
            let headless = args.no_prompt || global.no_input || !can_prompt_interactively();
            let decision = decide_workspace_upload(
                &root,
                sync_explicit,
                headless,
                std::env::home_dir().as_deref(),
            );
            // Only a hooks-enabled activation refuses: `--no-hooks` already
            // disabled the project's hooks, so it cannot drop any by surprise.
            if !args.no_hooks {
                refuse_dropped_hooks_before_create(decision, &root, CLI_DROPPED_HOOKS_REMEDY)?;
            }
            Ok(UploadPlan::Workspace { root, decision })
        })
        .await?;

    // Deliberately not `connect_daemon`: this path's version gate travels on
    // the `CreateSession` below rather than on a `GetVersion` sent ahead of it.
    // Activation is the hot path #1251's gate landed on, and it must not pay a
    // round trip for a check its own first RPC can make.
    let mut client = ActivationStep::ConnectDaemon
        .run(async {
            let mut client = connect_daemon_unchecked(global).await?;

            // Warn before minting a second session for a path that already has one:
            // the duplicate leaves bare `min` from this directory ambiguous between
            // them. Advisory only — a listing failure (ordinary transport or
            // daemon-side error) must not block activation, so the duplicate check is
            // skipped on error. But `oneshot_rpc` reuses one `russh` handle, and a
            // transport-level listing failure can close the shared connection, which
            // would then break the `CreateSession` channel below; so on any listing
            // error, reconnect before creation. A benign daemon-side error leaves the
            // old connection usable and the reconnect is merely a no-op cost on the
            // rare failure path — the happy path still pays no extra round trip. The
            // hard version gate is unaffected: `CreateSession` below carries its own
            // `must_match_version`, so a version-skewed daemon is still refused there
            // even when this enumeration is skipped.
            match list_sessions_version_gated(&mut client).await {
                Ok(existing_sessions) => {
                    if let Some(warning) = duplicate_session_warning(
                        &existing_sessions.sessions,
                        &request.config.project_path,
                    ) {
                        eprintln!("{warning}");
                    }
                }
                Err(_) => {
                    // The listing failed. A transport-level closure can leave the
                    // shared `russh` handle unusable, which would then break the
                    // `CreateSession` channel below, so try to reconnect. But a
                    // daemon-side listing error closes only the RPC channel and leaves
                    // the SSH connection intact — so if the reconnect itself fails,
                    // keep the original client and let `CreateSession` proceed on it
                    // rather than aborting activation outright. `CreateSession` carries
                    // its own hard version gate and surfaces a clear error if the
                    // connection really is dead, so retaining the original client can
                    // only help the daemon-side-error case and never regresses the
                    // transport-closure case.
                    if let Ok(reconnected) = connect_daemon_unchecked(global).await {
                        client = reconnected;
                    }
                }
            }
            Ok::<_, anyhow::Error>(client)
        })
        .await?;

    // T66: an own-address box on a VM-backed host registers with the VM host
    // daemon just before the create — the host allocates the box's switch
    // and loopback addresses into the table its egress gate decides by and
    // hands them back, and the create request carries them so the in-VM
    // daemon attaches with the handed switch address instead of drawing its
    // own. A `host_ip` box shares the node's own row, so it registers no
    // row of its own — its name is held in the zone instead (NODATA) once
    // the session is active, below — and a `none` box, or a native daemon
    // with no box table, registers nothing and attaches as it always has.
    // A `host_ip` box that declares a credentialed upstream registers for
    // its box id alone (BEP-082): the host mints the id and hands it no
    // address, and the proxy serves the box's grants under that id.
    // A registration that cannot be made ends the activation here, with its
    // cause: no session exists yet to clean up, and a box that went on to
    // create unregistered would run with no host-side row to decide its
    // egress by, so this is the one failure that never falls back. Past
    // here, the row exists and every later failure owes it its creator's
    // withdrawal (T66): the sites below send it. The control socket is
    // resolved once, here, and the withdrawals ride on it.
    let kind = daemon_host_kind(global);
    let control_sock = vm_host_control_sock(kind, global.minimal_dir.as_deref());
    // The row is registered under the name the daemon will give the box
    // (BOX-163): `--name`, else the spec's. A live row that holds it
    // refuses the registration, and the refusal ends the activation.
    let mut box_name = created_box_name(&request);
    tracing::info!(
        requested_name = ?request.config.name,
        box_name = ?box_name,
        name_source = if request.config.name.is_some() { "--name" } else { "entry" },
        "creating the box under the name the daemon gives it"
    );
    // BEP-082: a fresh-instance `host_ip` grant box registers under a
    // creation key of its own, and the create carries the key so the
    // in-VM daemon's id mint finds the registration after it names the
    // box `<base>-<n>`. Every withdrawal before and after the create names
    // the row by the name it registered under.
    let host_ip_registration = host_ip_registration_key(&request, box_name.as_deref())?;
    if let Some(key) = &host_ip_registration {
        tracing::info!(
            box_name = ?box_name,
            host_ip_registration = %key,
            "registering the fresh host_ip box under a creation key of its own"
        );
    }
    let mut registered = ActivationStep::RegisterBox
        .run(async {
            let registration_name = host_ip_registration.as_deref().or(box_name.as_deref());
            let registered = match registration_name {
                Some(name) => {
                    match register_box_for_activation(
                        kind,
                        global.minimal_dir.as_deref(),
                        request.config.network,
                        name,
                        &request.config.policy,
                    )
                    .await
                    {
                        Ok(registered) => registered,
                        // BOX-163: a live row holds the name. The refusal
                        // names the box that holds it and exits 2.
                        Err(error) => {
                            let Some(held) = error
                                .downcast_ref::<minimal_client::box_registration::NameAlreadyHeld>()
                                .map(|refused| refused.held.clone())
                            else {
                                return Err(error);
                            };
                            let holder = held_name_holder(&mut client, &held).await;
                            return Err(registration_held_name_refusal(name, &held, holder));
                        }
                    }
                }
                None => None,
            };
            // The registration is the client's record of the box: the addresses
            // the create carries, and the id the host minted for it (NET-133).
            // The id stays here: the create relays none (BOX-002).
            // A `host_ip` registration has an id and no row, so it carries
            // no addresses onto the create.
            carry_registration(
                &mut request.config,
                registered
                    .as_ref()
                    .filter(|registration| !registration.host_ip),
            );
            // Only a `host_ip` registration carries its key: a box that
            // registered nothing has no registration to find.
            request.config.host_ip_registration = host_ip_registration
                .clone()
                .filter(|_| registered.as_ref().is_some_and(|r| r.host_ip));
            Ok::<_, anyhow::Error>(registered)
        })
        .await?;
    // Gatehouse §6.2: a GitHub grant box with no box id or no stance has no
    // proxy to serve its grant. It is refused before the create, and the
    // row the registration bought is withdrawn (T66).
    let registered_id = registered
        .as_ref()
        .and_then(|registration| registration.box_id);
    if let Err(refused) = proxy_box_facts(
        &github_grants,
        &store_grants,
        registered_id.map(|box_id| box_id.to_string()),
        request.config.network,
    ) {
        withdraw_box_row(
            control_sock.clone(),
            host_ip_registration.as_deref().or(box_name.as_deref()),
            request.config.box_addresses,
            registered_id,
        )
        .await;
        return Err(refused.into());
    }

    // BEP-005/007: each GitHub grant's sign-in reference is minted for the
    // id the registration handed, before the create, so the create request
    // carries each sealed value for every launch of the box to place in its
    // grant's environment variable. A failure withdraws the row the
    // registration bought (T66).
    // The proxy's hold on the box: dropped by a later step's failure, it
    // forgets the box's declared egress there. It is kept once the session
    // is active. A Ctrl-C exits the process with no drop, so it leaves the
    // box at the proxy until the box's destroy forgets it (#2277).
    let proxy_registration = ActivationStep::MintGrants
        .run(mint_into_request(
            &mut request,
            host_ip_registration.as_deref().or(box_name.as_deref()),
            registered_id,
            &github_grants,
            &store_grants,
            global.config_dir.clone(),
            control_sock.clone(),
        ))
        .await?;

    use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, CreateSession};
    // BOX-163: a box the person did not name takes its entry's name. A
    // create under a name that a running box holds, the entry's name or a
    // `--name`, is refused: the command ends with exit 2, naming the
    // holder. Only a run (`min task run`, `min box run`) asks for a fresh
    // instance, `<name>-<n>` ([`request_fresh_instance`]).
    let created = ActivationStep::CreateSession
        .run(async {
            let created = {
                // The id the VM host daemon minted stays with this client. The
                // create request carries none (BOX-002).
                tracing::info!(
                    registered_box_id = ?registered
                        .as_ref()
                        .and_then(|registration| registration.box_id),
                    requested_name = ?request.config.name,
                    fresh_instance = request.fresh_instance,
                    "creating the box with no box id on the request; the client keeps the registered id"
                );
                let resp = client.oneshot_rpc::<CreateSession>(request.clone()).await;
                let resp = match resp {
                    Ok(resp) => resp,
                    // A transport failure abandons the activation and the row its
                    // registration bought: the create never happened, so no session
                    // holds the pair (T66).
                    Err(error) => {
                        withdraw_box_row(
                            control_sock.clone(),
                            host_ip_registration.as_deref().or(box_name.as_deref()),
                            request.config.box_addresses,
                            registered
                                .as_ref()
                                .and_then(|registration| registration.box_id),
                        )
                        .await;
                        return Err(session_rpc_failed(crate::SessionRpc::CreateSession, error));
                    }
                };
                match resp {
                    minimald_rpc::Errorable::Ok(r) => r,
                    minimald_rpc::Errorable::Err { error } => {
                        // Any other create failure abandons the activation and
                        // its row the same way. A held name is one of them: it
                        // ends the command with exit 2, naming the holder.
                        withdraw_box_row(
                            control_sock.clone(),
                            host_ip_registration.as_deref().or(box_name.as_deref()),
                            request.config.box_addresses,
                            registered
                                .as_ref()
                                .and_then(|registration| registration.box_id),
                        )
                        .await;
                        return Err(create_refusal(error));
                    }
                }
            };
            // The other half of the gate: a daemon old enough to predate
            // `must_match_version` ignored the assertion instead of answering it, and
            // says so by echoing no version at all. Being older than the field is
            // itself proof of a skew, so refuse here — still before the upload, the
            // loadout, and the finalize that #1251 died at, and with the session left
            // unfinalized for the daemon to reap when this connection drops.
            if let Err(error) = ensure_version_reported(created.daemon_version.as_deref()) {
                // A skewed daemon's refusal abandons the unfinalized session and its
                // row; the withdrawal rides out with the error (T66).
                withdraw_box_row(
                    control_sock.clone(),
                    host_ip_registration.as_deref().or(box_name.as_deref()),
                    request.config.box_addresses,
                    registered
                        .as_ref()
                        .and_then(|registration| registration.box_id),
                )
                .await;
                return Err(error);
            }
            // BEP-082: a `host_ip` grant box's grants are sealed under the id
            // its registration minted. A record under another id is a box
            // the proxy cannot serve, so the activation ends fail-closed, as
            // the version check above does.
            if let Err(error) = ensure_registered_id(registered.as_ref(), created.id) {
                withdraw_box_row(
                    control_sock.clone(),
                    host_ip_registration.as_deref().or(box_name.as_deref()),
                    request.config.box_addresses,
                    registered
                        .as_ref()
                        .and_then(|registration| registration.box_id),
                )
                .await;
                return Err(error);
            }
            Ok::<_, anyhow::Error>(created)
        })
        .await?;
    let id = created.id;
    // BOX-163: the daemon named the box. Read the name back for the start
    // lines, the name hold and the cleanup below.
    if let Some(name) = daemon_box_name(&mut client, id).await {
        tracing::info!(
            session_id = %id,
            box_name = %name,
            fresh_instance = request.fresh_instance,
            "the daemon named the box"
        );
        box_name = Some(name);
    }
    // A `host_ip` box's egress, admitted on the VM host daemon before the
    // box runs anything (NET-085): the host gate decides every frame the box
    // sends from the node's own address by the admitted policies, and drops
    // a box's frames that none admits. The guard retires it unless the
    // session outlives this activation. The admit carries the box's lane
    // declaration (BEP-083), so a grant box reaches the proxy's listener
    // from its first process on.
    let mut host_ip_residency = HostIpResidency::admit_declaring(
        control_sock.clone(),
        id,
        request.config.network,
        request.config.policy.egress.as_ref(),
        request.config.policy.credentialed_upstream.is_some(),
    )
    .await;
    ActivationStep::ReportStart
        .run(async {
            // The registration's own half of the session-start output (T66): one line
            // naming the VM host daemon the box's row lives on and the switch address
            // it was handed, beside the `tracing::info!` line the same registration
            // writes. The line is the one a bundle reads off the CLI transcript to say
            // whether this box has a host row — which is the question the host that
            // reaches the VM host daemon with no provider flag at all (NET-081's macOS
            // half) otherwise answers nowhere in its own output. A box that registered
            // nothing — a native host, a host-ip box sharing the node's own row, a
            // `none` box with no switch address — prints nothing: it has no row to
            // name. Keyed on the host kind the registration itself keyed on, never
            // on `use_minvmd()`, so the flagless VM-backed host prints it too.
            if let Some(addresses) = request.config.box_addresses.as_ref() {
                eprintln!(
                    "{}",
                    box_registered_start_line(
                        hostname_proxy_vm(kind),
                        box_name.as_deref().unwrap_or("-"),
                        addresses,
                    )
                );
            }
            // NET-020: no warning line of its own. The `names:` line below
            // carries the cause in place of its resolution clause, once.
            // NET-122/NET-123/NET-138: the naming lines, printed once per session
            // start — after the create, and re-surfaced when the daemon reports this
            // session at the 127.0.0.1 interim because its session-start bind
            // probe found the reserved range absent. The advisory only ever names
            // the command that points the host's resolver at the answerer; running
            // it (and any privilege prompt it carries) is the user's act, never the
            // session start's. One read of this host's resolver state decides the
            // advisory and the surface verdict below it, so the two lines cannot
            // disagree about one host.
            //
            // On a VM-backed host the answerer is the VM host daemon's (NET-138):
            // the in-VM daemon starts none, so the port and the bound proof come
            // from the host — the state read over minvmd's control socket (never
            // through the in-VM daemon, because a guest relaying a host fact is
            // forgeable from inside the escape boundary) and this CLI's own A
            // query for the host's row at the port that read named, the proof the
            // answerer is live rather than merely reported held. A native host
            // keeps the daemon's own report. `held_no_channel` is the machine fact
            // that ends the question: a port held by a process no channel reaches
            // means this VM's names are not answered on the host whatever this
            // host's hook and range say, so neither is read and the warning says
            // the fact instead of the advisory.
            let (vm_answerer, answerer_port, answerer_bound, held_no_channel, proxy_down) =
                match vm_host_answerer_status(global).await {
                    Some(reply) => {
                        let read = crate::resolver::host_answerer_read(reply.clone()).await;
                        (
                            Some(reply),
                            read.port,
                            read.answerer_bound,
                            read.held_no_channel,
                            read.proxy_down,
                        )
                    }
                    None => (
                        None,
                        created.zone_answerer_port,
                        created.answerer_bound,
                        false,
                        None,
                    ),
                };
            // The host line below never names the reported port as serving while
            // the reply carries a proxy-down sibling, and the cause — the sibling's,
            // or a native daemon's own report — prints exactly once, in place of
            // the line's resolution half whatever the verdict (NET-020), never
            // beside a `via 127.0.0.1:<port>` and never as a line of its own.
            let proxy_down_sibling = vm_answerer
                .as_ref()
                .and_then(|reply| reply.proxy_down.as_ref());
            let proxy_cause = crate::resolver::host_line_proxy_cause(
                proxy_down_sibling,
                created.hostname_routing_unavailable.as_deref(),
            );
            // The port this daemon's hostnames route through (NET-026's discovery on
            // this surface) is the `via 127.0.0.1:<port>` of the one host line
            // below: a VM whose host port the host already held walked to one of
            // its own (NET-059), a native daemon whose default was busy asked the OS
            // for a free one (NET-025), so a walked port is never a log line alone.
            // Absent while the proxy is still coming up, or from a daemon that
            // predates the field, and beside a proxy-down sibling, whose cause
            // names itself in the line instead.
            //
            // A proxy whose held port freed after the VM started (NET-022)
            // publishes on the VM host daemon only, so the guest reported no
            // port for it. The line then reads the ports the VM host daemon
            // serves on, as `min ls` does (`reported_proxy_port`). The read
            // runs only on a VM-backed host whose guest reported no port.
            let vm_served_ports = if created.hostname_proxy_port.is_none() && vm_answerer.is_some()
            {
                crate::cmd::session::vm_host_proxy_ports_at(control_sock.clone()).await
            } else {
                Vec::new()
            };
            let serving_proxy_port = crate::resolver::serving_proxy_port(
                crate::cmd::list::reported_proxy_port(
                    created.hostname_proxy_port,
                    &vm_served_ports,
                ),
                proxy_down_sibling,
            );
            // The interim itself, named at every session start on a VM-backed host
            // — TTY and non-TTY, ahead of the warning, the advisory and the verdict
            // below — because who answers the zone is the machine fact the names
            // this session is about to rely on rest on, and a holder another VM's
            // minvmd took is otherwise discoverable only from `min ls`. The
            // pre-acquisition state prints nothing: nothing is held yet to name.
            // The reply's two facts are two lines: the answerer's state renders
            // from the answerer field — even while the proxy is down or its
            // publish unconfirmed, because the sibling cause no longer displaces
            // the state — and the proxy's publish outcome, when the reply carries
            // one, names itself once below, with the surface verdict.
            if let Some(reply) = &vm_answerer
                && let Some(line) = vm_host_answerer_start_line(reply.answerer.clone())
            {
                eprintln!("{line}");
            }
            // NET-018: the one host line, naming the box, at the moment the user is
            // about to rely on the names. Its surface half is decided in the one
            // function both verbs share (`resolver`) and its install clause lists
            // this host's missing finalize-install items — names while the surface
            // is not native, the classifier while a native daemon's host says so
            // (`host_install_for_this_host`, the same scoping `min finalize-install`
            // applies) — so the two verbs print the same words (NET-122's pointer
            // is the line's tail). Host DNS is opt-in: the start never prints the
            // privileged step, only the command that runs it. The host's items are
            // probed only once a line is going to print: a start with no surface to
            // name has no clause to end it with.
            let surface = if held_no_channel && let Some(answerer_port) = answerer_port {
                // NET-138's warning, at every session start — TTY and non-TTY: it
                // rides stderr unconditionally, because the first lookup that
                // fails is the one it explains, and a piped activate is as owed
                // the fact as an interactive one.
                eprintln!(
                    "{}",
                    crate::resolver::port_held_no_channel_warning(answerer_port)
                );
                // The verdict is the proxy's by the status's own word, without
                // reading the hook or the range: both could only misreport native
                // for a port no daemon answers, and the arm that cannot strand the
                // user is the proxy's (NET-019 keeps it serving). Logged as the
                // same session-start record the native arm logs, with the fact
                // that decided it.
                let surface = crate::resolver::LiveSurface::Proxy;
                tracing::info!(
                    surface = ?surface,
                    held_no_channel = true,
                    answerer_bound = false,
                    answerer_port = answerer_port,
                    hostname_proxy_down = ?proxy_down,
                    "session start decided the live name surface for this host"
                );
                Some(surface)
            } else if answerer_port.is_none() && proxy_down.is_some() {
                // T93: the VM host daemon's own verdict on the hostname proxy's
                // publication — a terminal publish failure, named with the port it
                // is about and its cause instead of a bare "not serving" — printed
                // at every session start, TTY and non-TTY alike, because the names
                // this session is about to rely on are the ones the line says
                // cannot resolve. No host read runs in this arm — no detection, no
                // liveness query, no range probe — because the status is the VM
                // host daemon's answer on the proxy's publication, and no host
                // probe can move it. Reached only when the answerer is not
                // decidable — the pre-acquisition state, or the old daemon's
                // substituting state — because a reply that carries both an
                // answerer verdict and the sibling cause has its surface decided
                // by the answerer arm below: the cause has already named the
                // proxy's half on the line of its own above, and the answerer's
                // half is the detection's to read. The verdict is the proxy's; the
                // cause rides the host line in place of its resolution half.
                let surface = crate::resolver::LiveSurface::Proxy;
                tracing::info!(
                    surface = ?surface,
                    hostname_proxy_down = ?proxy_down,
                    "session start decided the live name surface for this host"
                );
                Some(surface)
            } else if let Some(answerer_port) = answerer_port {
                // The surface half, decided from this host's detection: its hook
                // (and the stub-bypass blocker that says whether its lookups
                // consult what the hook configures), the answerer-bound proof this
                // start holds — the daemon's report on a native host, this CLI's
                // own query on a VM-backed one — and the reserved range on this
                // host's own loopback. `None` — the answerer not bound — is the
                // proxy's surface: there is no native surface to name. A
                // proxy-down cause never moves the verdict — it replaces the host
                // line's resolution half beside whichever verdict this read
                // decides. The proxy keeps serving beside native DNS (NET-019): the
                // `HTTP(S)_PROXY` recipes this activation prints keep working, so
                // nothing already captured goes stale.
                let detection = crate::resolver::session_detection().await;
                let surface_verdict = crate::resolver::live_name_surface_with_range_at(
                    &detection,
                    Some(answerer_port),
                    answerer_bound,
                )
                .await;
                // With no verdict the proxy is the live surface.
                let unbound_surface = crate::resolver::LiveSurface::Proxy;
                match surface_verdict {
                    Some(verdict) => {
                        // The host-side record of that verdict, the half the
                        // daemon's own log cannot make: a daemon can name only the
                        // answerer *it* binds (see the daemon's
                        // `log_live_name_surface`), so the surface this host's own
                        // reads decided — and the three facts behind it, with the
                        // range as the one fact only this read holds — is logged
                        // here, at the start that printed it, beside the daemon's
                        // line. `min` filters at `warn` unless `RUST_LOG` is set, so
                        // the line is visible under `RUST_LOG=info`. Logged, never
                        // printed: the line below is the user's. `min ls` does not
                        // log its verdict — a list re-reads the host every run, and
                        // the record that matters is the one at the starts that
                        // rely on the names.
                        tracing::info!(
                            surface = ?verdict.surface,
                            hook_routes = detection.0.routes(answerer_port),
                            blocker = ?detection.1,
                            answerer_bound = answerer_bound,
                            range_present = ?verdict.range_present,
                            range_unit_state = ?detection.2.state,
                            range_unit_check = ?detection.2.failed_check,
                            hostname_proxy_down = ?proxy_down,
                            "session start decided the live name surface for this host, \
                             with the range unit's state beside it"
                        );
                        Some(verdict.surface)
                    }
                    None => {
                        // The answerer is reported but not bound yet: no native
                        // surface to name, so the proxy is the live one.
                        tracing::info!(
                            surface = ?unbound_surface,
                            answerer_bound = false,
                            answerer_port = answerer_port,
                            hostname_proxy_down = ?proxy_down,
                            "session start decided the live name surface for this host"
                        );
                        Some(unbound_surface)
                    }
                }
            } else {
                // No answerer reported and no VM sibling — a daemon that predates
                // the field, or the VM-backed pre-acquisition state: the proxy is
                // the surface the names route through while it serves, or the
                // daemon's own report says why it does not, and nothing is said
                // while nothing serves yet and nothing is reported.
                (serving_proxy_port.is_some() || proxy_cause.is_some())
                    .then_some(crate::resolver::LiveSurface::Proxy)
            };
            if let Some(surface) = surface {
                let host_install = crate::cmd::finalize_install::host_install_for_this_host(global);
                let box_name = box_name.as_deref().unwrap_or("-");
                // T110: the box's ports answer at its own address unless the
                // daemon put it on the `127.0.0.1` interim. That holds for a
                // host-address box too: on a VM node before the range lands,
                // it is not mirrored onto `127.0.0.1` and only the proxy
                // reaches it, which `min ls` reads as the fallback as well.
                let at_own_address = !created.interim_loopback;
                if proxy_cause.is_some() {
                    tracing::debug!(
                        surface = "min session activate names: line",
                        "printed the hostname-routing cause"
                    );
                }
                eprintln!(
                    "{}",
                    crate::resolver::host_line_beside(
                        box_name,
                        &surface,
                        serving_proxy_port,
                        host_install,
                        proxy_cause.as_deref(),
                        at_own_address,
                    )
                );
            }

            // NET-079: the host's verdict on whether it can decide a host-address
            // box's egress per box, spelled by the daemon — the side that read the
            // host — and printed verbatim, so the terminal, the daemon's log line
            // for this same create, and the start all say the same thing. The
            // advisory names the cause, the state it leaves the box in, and, when
            // the missing privileged step is the cause, the exact command that
            // installs it; it is never a prompt, and never load-bearing for the
            // start either (see [`print_classifier_advisory`]). Printed after the
            // session exists and before the work on it, like the notice below it,
            // so a host that cannot decide per box is named at the start that
            // runs there and not only in a log the person was not reading.
            print_classifier_advisory(&mut std::io::stderr(), &created);

            // The in-force note (NET-074): one line naming the default an
            // own-address session that declared no egress now has, and how to
            // declare reach. Scoped to the box the default binds — an own-address
            // session with no egress section — on a daemon that has not opted out
            // (NET-077): the opt-out is the daemon's own fact, so it is read off the
            // create reply above, and an opted-out daemon's box keeps allow-all and
            // needs no note. Printed after the session exists and before the work
            // on it, so it is not lost above a failed activate's output.
            if request.config.network == minimald_rpc::NetworkMode::OwnIp
                && request.config.policy.egress.is_none()
                && created.deny_all_opt_out != Some(true)
                && let Some(note) = deny_all_default_notice(boxes::EGRESS_DEFAULT_PHASE)
            {
                eprintln!("{note}");
            }

            // When a subnet flag carries host bits (e.g. `--deny-subnets 10.0.0.1/8`),
            // the enforcement layer reads it as the masked network (`10.0.0.0/8`).
            // Print a one-line notice naming the normalized form so the user knows
            // how their entry is read, rather than discovering it through a mismatch.
            // The notice is computed from the original flags, not the stored policy:
            // the policy now holds the normalized form, so reading it back would
            // print nothing.
            for line in subnet_notices(&args.egress) {
                eprintln!("{line}");
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?;

    // From here the session exists on the daemon in an unfinalized state.
    // Arm a Ctrl-C guard so an interrupt during the (blocking) gating
    // prompt tears it down instead of orphaning it in `Pending` — see
    // [`ActivationInterrupt`]. Disarmed once the session is `Active`.
    let interrupt_guard = arm_activation_interrupt(global, id);
    // A `host_ip` box has no pair on its record, so a Ctrl-C withdraws its
    // name by the id its registration handed back (BEP-082).
    if let Some(box_id) = registered
        .as_ref()
        .filter(|registration| registration.host_ip)
        .and_then(|registration| registration.box_id)
    {
        interrupt_guard.withdraw_host_ip_name_as(box_id);
    }

    // Upload the project directory to the daemon so the session
    // workspace holds the user's files — `ConfigureLoadout`'s compose
    // reads the mfile (and any local `packages/`, `stacks/`,
    // `profiles/` used by graph resolution) off that workspace, so it
    // has to run before `ConfigureLoadout`. `--sync none` opts out;
    // the daemon then composes against an empty workspace and the
    // caller is on their own for getting files there.
    ActivationStep::UploadFiles
        .run(async {
            match upload_plan {
                UploadPlan::Skip => {
                    // `--sync none` skips the upload, so the daemon composes against
                    // an empty workspace and the project's `minimal.toml` — packages,
                    // vars, patches, hooks — is silently dropped. Say so when there
                    // is a config to lose, so the default-config session is not a
                    // surprise.
                    if let Some(notice) = sync_none_notice(&utf8_path) {
                        eprintln!("{notice}");
                    }
                }
                UploadPlan::Workspace { root, decision } => {
                    // `--no-hooks` already disabled the project's hooks, so a
                    // skip cannot drop anything by surprise and says nothing
                    // about them.
                    let dropped_hooks = if args.no_hooks {
                        DroppedHooksPolicy::Ignore
                    } else {
                        DroppedHooksPolicy::Refuse
                    };
                    if let Err(error) = cli_workspace_upload(
                        &mut client,
                        id,
                        &utf8_path,
                        &root,
                        decision,
                        dropped_hooks,
                    )
                    .await
                    {
                        // The upload failed: the activation is abandoned, and
                        // the row its registration bought goes with it (T66).
                        withdraw_box_row(
                            control_sock.clone(),
                            host_ip_registration.as_deref().or(box_name.as_deref()),
                            request.config.box_addresses,
                            registered
                                .as_ref()
                                .and_then(|registration| registration.box_id),
                        )
                        .await;
                        return Err(error);
                    }
                }
            };
            Ok::<_, anyhow::Error>(())
        })
        .await?;

    // Collect the client-side patches (from loadouts, already gated
    // in Phase 1) *before* the wire contribution moves into the
    // ConfigureLoadout RPC. These land in the final Composition
    // whether the response is `Materialized` or `Pending`, so the
    // client is authoritative for them. Any daemon-side patches
    // that come back through a `Pending` response's `SubmitVerdict`
    // get appended below.
    let mut collected_patches = ActivationStep::ComposeLoadout
        .run(async {
            let mut collected_patches = minimal_client::contribution_patch_uploads(&contribution);

            // The session exists but has no loadout yet; composing it is a
            // second round-trip because the daemon's composer reads the
            // project config out of the session's workspace, not from a path
            // on this machine.
            let configured = client
                .oneshot_rpc::<ConfigureLoadout>(ConfigureLoadoutRequest {
                    session_id: id,
                    contribution,
                })
                .instrument(entry_span.clone())
                .await;
            let configured = match configured {
                // A transport failure abandons the activation and its row (T66).
                Err(error) => {
                    withdraw_box_row(
                        control_sock.clone(),
                        host_ip_registration.as_deref().or(box_name.as_deref()),
                        request.config.box_addresses,
                        registered
                            .as_ref()
                            .and_then(|registration| registration.box_id),
                    )
                    .await;
                    return Err(session_rpc_failed(
                        crate::SessionRpc::ConfigureLoadout,
                        error,
                    ));
                }
                Ok(configured) => configured,
            };
            let configured = match configured {
                minimald_rpc::Errorable::Ok(r) => r,
                // Bails before the `println!("{id}")` below: a session that cannot
                // compose never puts an id on stdout for a script to capture.
                minimald_rpc::Errorable::Err { error } => {
                    // The session cannot compose and is abandoned with its row (T66).
                    withdraw_box_row(
                        control_sock.clone(),
                        host_ip_registration.as_deref().or(box_name.as_deref()),
                        request.config.box_addresses,
                        registered
                            .as_ref()
                            .and_then(|registration| registration.box_id),
                    )
                    .await;
                    bail!(composition_failure_message(&utf8_path, &error));
                }
            };
            // The daemon may finalize immediately (`Ready`) or ask the
            // client to gate items first (`Pending`). On the pending path
            // we run the user-policy prompt loop; on ready there's nothing
            // to gate.
            //
            // Decide up front whether we can prompt: `--no-prompt` forces
            // the abort path, and a non-TTY stderr triggers it implicitly
            // (a script or CI run should never expect to read a keypress).
            // Both fall through to `NoPromptHook`, which accumulates every
            // item it would have prompted for so we can print a
            // `user_policy.toml` snippet on the error path.
            if let minimald_rpc::ConfigureLoadoutResponse::Pending { response } = configured {
                let non_interactive =
                    args.no_prompt || global.no_input || !can_prompt_interactively();
                if non_interactive {
                    // NoPromptHook fake-approves every unapproved item so
                    // handle_response finishes both the var and patch gates
                    // and records everything in `summary`. If anything was
                    // recorded, we abort *before* actually shipping the
                    // verdict — the daemon must not see those fake
                    // approvals. Only when `summary` is empty (every daemon-
                    // sent item was already handled by the user's policy)
                    // do we submit and let the session go Active.
                    let session_id = response.session_id;
                    let hooks = prompt::NoPromptHook::new();
                    let verdict =
                        match compute_verdict(response, user_policy, compose_options, &hooks) {
                            Ok((verdict, _final_policy)) => verdict,
                            Err(e) => {
                                send_abort(&mut client, session_id).await;
                                // The session is aborted and its row withdrawn (T66):
                                // the path failed after registering.
                                withdraw_box_row(
                                    control_sock.clone(),
                                    host_ip_registration.as_deref().or(box_name.as_deref()),
                                    request.config.box_addresses,
                                    registered
                                        .as_ref()
                                        .and_then(|registration| registration.box_id),
                                )
                                .await;
                                // The route an activation actually reaches today: the
                                // daemon routes project config back for gating, so a
                                // project it cannot compose surfaces here rather than as
                                // the `Errorable::Err` above.
                                bail!(composition_failure_message(&utf8_path, &e.to_string()));
                            }
                        };
                    let summary = hooks.into_summary();
                    if summary.count() > 0 {
                        send_abort(&mut client, session_id).await;
                        // The session is aborted and its row withdrawn (T66): the
                        // path failed after registering.
                        withdraw_box_row(
                            control_sock.clone(),
                            host_ip_registration.as_deref().or(box_name.as_deref()),
                            request.config.box_addresses,
                            registered
                                .as_ref()
                                .and_then(|registration| registration.box_id),
                        )
                        .await;
                        let count = summary.count();
                        let snippet = summary.as_toml_snippet();
                        bail!(
                            "{count} item{s} would require interactive approval, but \
                     --no-prompt was set (or stdin/stderr is not a terminal).\n\n\
                     Add the following to {}:\n\n{snippet}\n\
                     Then re-run this command.",
                            policy_path.display(),
                            s = if count == 1 { "" } else { "s" },
                        );
                    }
                    collected_patches.extend(approved_patches_from_verdict(&verdict));
                    let submitted = submit_verdict_and_wait(&mut client, session_id, verdict).await;
                    if let Err(error) = submitted {
                        // The verdict never landed: the activation is abandoned with
                        // its row (T66).
                        withdraw_box_row(
                            control_sock.clone(),
                            host_ip_registration.as_deref().or(box_name.as_deref()),
                            request.config.box_addresses,
                            registered
                                .as_ref()
                                .and_then(|registration| registration.box_id),
                        )
                        .await;
                        return Err(error);
                    }
                } else {
                    // The hook stashes policy mutations in interior
                    // `RefCell`s so a `DenyPermanent` (which returns
                    // `HookResult::Abort` and can't pipe an
                    // `updated_policy` back through the composer) still
                    // survives to `into_final_policy`. We save
                    // unconditionally before propagating the result, so a
                    // deny-and-abort still writes the rule.
                    let hooks = prompt::InteractivePrompt::new(&policy_path, user_policy.clone());
                    let result = drive_pending_to_active(
                        &mut client,
                        response,
                        user_policy,
                        compose_options,
                        &hooks,
                        &utf8_path,
                    )
                    .await;
                    if let Ok((_, _, ref approved)) = result {
                        collected_patches.extend(approved.iter().cloned());
                    }
                    let final_policy = hooks.into_final_policy();
                    if final_policy != initial_policy {
                        // A `save_user_policy` failure is reported to
                        // stderr and *doesn't* propagate: if the activation
                        // itself also failed (`DenyPermanent` returns Err
                        // and still wants its rule saved; a real
                        // composition fault), `result?` below is what the
                        // operator needs to see. Blindly `?`ing the save
                        // would clobber that error with a spurious
                        // "updating user_policy.toml" message that hides
                        // the true failure.
                        match prompt::save_user_policy(&policy_path, &final_policy) {
                            Ok(()) => eprintln!("Updated {}", policy_path.display()),
                            Err(e) => eprintln!(
                                "warning: failed to update {}: {e}",
                                policy_path.display()
                            ),
                        }
                    }
                    if result.is_err() {
                        // The activation failed after registering: its row is
                        // withdrawn with it (T66).
                        withdraw_box_row(
                            control_sock.clone(),
                            host_ip_registration.as_deref().or(box_name.as_deref()),
                            request.config.box_addresses,
                            registered
                                .as_ref()
                                .and_then(|registration| registration.box_id),
                        )
                        .await;
                    }
                    result?;
                }
            }

            // On the Ready path (loadouts auto-decided; no prompt fired)
            // `initial_policy` is only referenced inside the Pending branch
            // above, so it appears unused to the compiler. Explicit `_` to
            // squash the lint without dropping the useful name.
            let _ = initial_policy;
            Ok::<_, anyhow::Error>(collected_patches)
        })
        .await?;

    // Upload composition patches and finalize the session. This
    // has to happen before attach is allowed — a Materializing
    // session isn't attachable, and the launcher reads patches
    // from `<workspace>/patches/`. Dedup by sandbox destination:
    // the composer's post-gate check guarantees any duplicates
    // are exact matches (same source), so collapsing is safe.
    // A Ctrl-C during the finalize tears the activation down. The cleanup
    // after a finalize that failed settles the session and its row itself
    // and handles a Ctrl-C of its own (`cleanup_after_failed_finalize`), so
    // the activation's interrupt handler is disarmed before it: left armed,
    // it would withdraw the row whatever the cleanup found, a live box's
    // included.
    let mut interrupt_guard = Some(interrupt_guard);
    ActivationStep::Finalize
        .run(async {
            minimal_client::dedup_patch_uploads(&mut collected_patches);
            // The registration's lease is held across the finalize and, when
            // that fails, across the cleanup destroy too: only the destroy's
            // answer says whether a box is live behind the row (inbox#690).
            // Until the lease is committed, an activation that dies leaves
            // the VM host daemon to withdraw the row on the lease's close.
            let lease = registered
                .as_mut()
                .and_then(|registration| registration.lease.take());
            if let Err(e) = upload_and_finalize(
                &mut client,
                id,
                &collected_patches,
                &hook_scripts,
                finalize_hook_budget,
            )
            .await
            {
                drop(interrupt_guard.take());
                // Best-effort teardown: the session is stuck in
                // Materializing on the daemon. Destroy it so the operator's
                // `min ls` doesn't fill with half-finalized sessions, and
                // withdraw the row the registration bought with it (T66),
                // unless the session finished first and was kept, or may
                // have been.
                let outcome = best_effort_destroy(&mut client, id, true).await;
                // A session that is kept, or may be, keeps its egress: its
                // destroy retires it.
                if outcome != CleanupOutcome::Destroyed
                    && let Some(residency) = host_ip_residency.as_mut()
                {
                    residency.keep();
                }
                if !settle_lease_after_cleanup(lease, outcome).await {
                    withdraw_box_row(
                        control_sock.clone(),
                        host_ip_registration.as_deref().or(box_name.as_deref()),
                        request.config.box_addresses,
                        registered
                            .as_ref()
                            .and_then(|registration| registration.box_id),
                    )
                    .await;
                }
                // A kept session is active: it gets the `host_ip` name hold
                // an activation that succeeded makes below.
                if outcome == CleanupOutcome::Kept
                    && holds_name_with_vm_host(kind, request.config.network)
                    && let Some(name) = box_name.as_deref()
                {
                    hold_box_name_with_vm_host(control_sock.clone(), name, Some(id), true).await;
                }
                return Err(e);
            }
            if let Some(lease) = lease {
                lease.commit().await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?;

    // The session is `Active` now — a Ctrl-C must no longer tear it down
    // (the attach hand-off below and the user's own session are fair game
    // for interrupts, but not this cleanup).
    drop(interrupt_guard.take());
    if let Some(registration) = proxy_registration {
        registration.keep();
    }
    if let Some(residency) = host_ip_residency.as_mut() {
        residency.keep();
    }

    // The `host_ip` interim: the box shares the node's own row, so its name
    // is held in the zone with no row behind it and answers NODATA instead
    // of NXDOMAIN (best-effort, warned within the helper). Held only now
    // the session is active, so an activation that dies or fails earlier
    // — its unfinalized session reaped with the connection — leaves no
    // hold behind; the destroy releases it ([`release_held_box_name`]).
    // Only this activate/destroy pair holds on the client's own account:
    // `min task run` (task.rs) mints an ephemeral, auto-generated host_ip
    // session through raw `CreateSession`/`DestroySession` RPCs and never
    // passes through here, so its run neither holds nor releases its name
    // — a task box's name is not meant to be reached, and widening the
    // interim to that path is a design ruling for the name-registry work,
    // not a change a review pass may make in passing. The re-hold before
    // an attach or exec ([`rehold_held_name_before_attach`]) does not tell
    // a task session apart, though: it holds the name of any named host_ip
    // session without a box row that a client attaches to or execs into.
    // A task run releases such a hold by its session's id once it removes
    // or destroys its box (`release_task_name_hold`). A box the run keeps
    // holds it until its reap releases it. A run whose
    // client is killed outright releases nothing, and that hold is
    // dropped after the VM host daemon's next restart, when nothing
    // re-makes it.
    //
    // Every hold is made by a client over the host's control socket, as
    // this one and that re-hold are; the in-VM daemon makes none. So
    // after a VM host daemon restart, the hold of a session nobody
    // attaches to or execs into is dropped once the daemon's reconfirm
    // bound passes, and the name answers NXDOMAIN until the session's
    // next attach or exec.
    //
    // A `none` box on a VM host takes the same hold (NET-046): it has no
    // switch row, so the hold is the host's one record of its box id, and
    // the in-VM daemon's expose decision report names the box by that id.
    // Its name answers NODATA, as a `host_ip` box's does while it is not
    // resident. `min session destroy` and the dashboard's destroy release
    // it, `min session rename` moves it, and an attach or exec re-holds it
    // after a VM host daemon restart, because `holds_name` (vm_host.rs) is
    // true for a `none` box as for a `host_ip` box. An unnamed `none` box
    // holds nothing, and the host refuses its report.
    ActivationStep::HoldName
        .run(async {
            if holds_name_with_vm_host(kind, request.config.network)
                && let Some(name) = box_name.as_deref()
            {
                hold_box_name_with_vm_host(control_sock.clone(), name, Some(id), true).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?;

    println!("{id}");
    crate::output::record_box_id(&id.to_string());

    // T126 (NET-138): a `host_ip` box on a VM host names each of its
    // mirrored ports that another program on the host holds. Printed only
    // when the activation does not attach, so no line is lost under the
    // shell's first paint.
    if !args.attach
        && kind == paths::HostKind::Minvmd
        && request.config.network == boxes::NetworkMode::HostNet
    {
        crate::resolver::print_mirror_collisions(control_sock.clone()).await;
    }

    if args.attach {
        // Chain into attach. Announce the freshly created session first: the
        // bare id printed to stdout above is the scripting contract, while this
        // stderr line tells an interactive operator which session they just
        // created and are entering.
        if should_announce_box(global) {
            eprintln!(
                "Created session {}",
                box_announce_label(&id, box_name.as_deref())
            );
        }
        let attach_args = AttachArgs {
            session: Some(id.to_string()),
        };
        return cmd_attach(global, attach_args).await;
    }

    Ok(())
}

/// The normalized form of each subnet flag entry, so the stored policy
/// holds the masked network the enforcement layer reads (`10.0.0.1/8` →
/// `10.0.0.0/8`). Entries that are already normalized, invalid, or IPv6 are
/// kept verbatim: `normalized_cidr` yields `None` for those, and the
/// enforcement layer's own reading of them is unchanged.
fn normalize_subnets(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| boxes::normalized_cidr(entry).unwrap_or_else(|| entry.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use boxes::DynamicIngress;

    /// A start refusal escapes the control characters of every entry name
    /// it prints, so a name from `minimal.toml` cannot move the cursor.
    #[test]
    fn start_refusals_escape_entry_names() {
        let bad = "dev\u{1b}[2K\n".to_owned();
        let refusals = [
            StartEntryRefusal::Several {
                verb: StartVerb::Box,
                entries: vec![bad.clone(), "ok".to_owned()],
            },
            StartEntryRefusal::Unknown {
                verb: StartVerb::Session,
                entry: bad.clone(),
                entries: vec![bad.clone()],
            },
            StartEntryRefusal::NotSession {
                entry: bad.clone(),
                box_type: Some(boxes::TASK_BOX_TYPE.to_owned()),
            },
            StartEntryRefusal::NameUnsupported { entry: bad.clone() },
            StartEntryRefusal::TaskNotInTasks { entry: bad.clone() },
            StartEntryRefusal::UnsupportedType {
                entry: bad.clone(),
                box_type: Some("agent".to_owned()),
            },
            StartEntryRefusal::NamedSessionUnsupported {
                verb: StartVerb::Session,
                entry: bad.clone(),
            },
        ];
        let mut texts: Vec<String> = refusals.iter().map(ToString::to_string).collect();
        texts.push(StartNeedsTerminal::new(&bad).to_string());
        for holder in [
            None,
            Some(boxes::SessionId::parse_str("0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b").unwrap()),
        ] {
            texts.push(
                StartNameHeld {
                    verb: StartVerb::Box,
                    entry: bad.clone(),
                    refusal: minimald_rpc::HeldNameRefusal {
                        name: bad.clone(),
                        holder,
                        holder_name: bad.clone(),
                    },
                }
                .to_string(),
            );
        }
        for text in texts {
            assert!(!text.contains('\u{1b}'), "{text:?}");
            assert!(!text.contains('\n'), "{text:?}");
            assert!(text.contains("dev\\u{1b}[2K\\n"), "{text:?}");
        }
    }

    /// BOX-001: a create from `<root>/sub` sends `<root>`, the directory
    /// that holds `minimal.toml`, as the project root.
    #[test]
    fn create_from_a_subdirectory_sends_the_project_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(mfile::MFILE_NAME),
            "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
        )
        .unwrap();
        let root = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let mut request = minimald_rpc::CreateSessionRequest::new(
            "rooted",
            paths::HostAbsPath::try_new(sub.clone()).unwrap(),
            boxes::NetworkMode::HostNet,
            boxes::BoxPolicy::default(),
        );

        stamp_project_root(&mut request, &sub).unwrap();

        assert_eq!(
            request.config.project_root,
            Some(paths::HostAbsPath::try_new(root.to_path_buf()).unwrap())
        );
        assert_eq!(request.config.project_path.as_str(), sub.as_str());
    }

    /// BOX-068: the create request carries the box's spec: the project's
    /// `[session]` table with the request's flags for an activation, and
    /// the declared task for `min task run`.
    #[test]
    fn activation_puts_the_spec_on_the_create_request() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(mfile::MFILE_NAME),
            "[session]\npackages = [\"git\"]\n\n[tasks.lint]\nexec = [\"true\"]\npackages = [\"rust\"]\n",
        )
        .unwrap();
        let root = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
        let policy = boxes::BoxPolicy {
            egress: Some(boxes::EgressPolicy::deny_all()),
            ..Default::default()
        };
        let mut request = minimald_rpc::CreateSessionRequest::new(
            "specced",
            paths::HostAbsPath::try_new(root.to_path_buf()).unwrap(),
            boxes::NetworkMode::OwnIp,
            policy.clone(),
        );
        request.config.hooks_enabled = false;
        assert_eq!(request.spec, None);

        stamp_session_spec(&mut request, root).unwrap();

        let wire = request.spec.clone().expect("the spec is on the request");
        // The request carries the `box.toml` tables and the mode's spec word.
        assert_eq!(wire["v"], mfile::spec::BOX_SPEC_VERSION);
        assert_eq!(wire["box"]["type"], boxes::SESSION_BOX_TYPE);
        assert_eq!(wire["io"]["pty_enabled"], true);
        assert_eq!(
            wire["install"]["packages"],
            serde_json_lenient::json!(["git"])
        );
        assert_eq!(wire["network"]["mode"], "own_ip");
        assert_eq!(
            wire["network"]["egress"]["allow_subnets"],
            serde_json_lenient::json!([])
        );
        assert!(wire.get("type").is_none() && wire.get("packages").is_none());
        let sent: mfile::spec::BoxSpec = serde_json_lenient::from_value(wire).unwrap();
        assert_eq!(sent.v, mfile::spec::BOX_SPEC_VERSION);
        assert_eq!(sent.box_type, boxes::SESSION_BOX_TYPE);
        assert_eq!(sent.packages, vec!["git".to_string()]);
        assert!(!sent.hooks_enabled, "--no-hooks reaches the spec");
        assert_eq!(sent.network.mode, boxes::NetworkMode::OwnIp);
        assert_eq!(sent.network.policy, policy);

        // The task path: the declared task's spec, through the same helper.
        let file = mfile::File::from_dir_recursive(dir.path()).unwrap();
        let task =
            mfile::spec::BoxSpec::for_task("lint", &file.tasks["lint"], spec_flags(&request))
                .expect("a task that is not interactive has a spec");
        put_spec(&mut request, &task).unwrap();
        let wire = request.spec.clone().unwrap();
        assert_eq!(wire["box"]["type"], boxes::TASK_BOX_TYPE);
        assert_eq!(wire["io"]["pty_enabled"], false);
        assert_eq!(
            wire["install"]["packages"],
            serde_json_lenient::json!(["rust"])
        );
        let sent: mfile::spec::BoxSpec = serde_json_lenient::from_value(wire).unwrap();
        assert_eq!(sent, task);

        std::fs::write(dir.path().join(mfile::MFILE_NAME), "not valid toml = =").unwrap();
        assert!(stamp_session_spec(&mut request, root).is_err());
    }

    /// BOX-001: with no tarball upload root, a subdirectory resolves to the
    /// directory that holds `minimal.toml`, and a `minimal.toml` that does
    /// not load is an error. A resolved upload root is reused as it is.
    #[test]
    fn activation_project_root_resolves_the_root_and_refuses_a_broken_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(mfile::MFILE_NAME),
            "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
        )
        .unwrap();
        let root = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).unwrap();

        assert_eq!(
            activation_project_root(None, &sub).unwrap(),
            root.to_path_buf()
        );

        let resolved = camino::Utf8Path::new("/resolved/root");
        assert_eq!(
            activation_project_root(Some(resolved), &sub).unwrap(),
            resolved.to_path_buf()
        );

        std::fs::write(dir.path().join(mfile::MFILE_NAME), "not valid toml = =").unwrap();
        assert!(activation_project_root(None, &sub).is_err());
    }

    #[test]
    fn normalize_subnets_masks_host_bits_and_keeps_the_rest() {
        assert_eq!(
            normalize_subnets(&["10.0.0.1/8".to_string(), "192.168.1.5/24".to_string()]),
            vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()]
        );
        assert_eq!(
            normalize_subnets(&[
                "10.0.0.0/8".to_string(),
                "fd00::1/8".to_string(),
                "not-a-cidr".to_string(),
            ]),
            vec![
                "10.0.0.0/8".to_string(),
                "fd00::1/8".to_string(),
                "not-a-cidr".to_string()
            ]
        );
    }

    #[test]
    fn dynamic_ingress_needs_own_ip() {
        use crate::cli::CliNetworkMode::{HostNet, NoNet, OwnIp};
        for network in [HostNet, NoNet] {
            for (mode, range) in [
                (Some(DynamicIngress::Allow), Some((8000, 8443))),
                (Some(DynamicIngress::Deny), None),
                (None, Some((8000, 8443))),
            ] {
                let error = refuse_dynamic_ingress_off_own_ip(network, mode, range)
                    .expect_err("a dynamic declaration off own_ip is refused");
                assert!(
                    error.to_string().contains("need --network own_ip"),
                    "{error}"
                );
            }
            refuse_dynamic_ingress_off_own_ip(network, None, None)
                .expect("no dynamic declaration is never refused");
        }
        refuse_dynamic_ingress_off_own_ip(OwnIp, Some(DynamicIngress::Allow), Some((8000, 8443)))
            .expect("an own-IP box keeps its dynamic declaration");
    }

    /// BEP-007: each grant's sealed value goes on the create request under
    /// the grant's variable, and a grant left with no sealed value is
    /// refused by name.
    #[test]
    fn sealed_deliveries_follow_the_grants_and_refuse_a_missing_one() {
        let minted = |grant: &str, sealed: &str| crate::mint::Minted {
            grant: grant.to_string(),
            sealed: zeroize::Zeroizing::new(sealed.to_string()),
            expiry: 0,
        };
        let grants = vec!["GH_TOKEN".to_string(), "GITHUB_TOKEN".to_string()];
        let deliveries = sealed_deliveries(
            &grants,
            &[
                minted("GITHUB_TOKEN", "sealed-two"),
                minted("GH_TOKEN", "sealed-one"),
            ],
        )
        .unwrap();
        assert_eq!(
            deliveries,
            [
                boxes::SealedDelivery {
                    variable: "GH_TOKEN".to_string(),
                    sealed: "sealed-one".to_string(),
                },
                boxes::SealedDelivery {
                    variable: "GITHUB_TOKEN".to_string(),
                    sealed: "sealed-two".to_string(),
                },
            ]
        );

        let error = sealed_deliveries(&grants, &[minted("GH_TOKEN", "sealed-one")])
            .expect_err("a grant with no sealed value is refused");
        assert_eq!(
            error.downcast_ref::<GrantNotDelivered>(),
            Some(&GrantNotDelivered::NotSealed {
                grant: "GITHUB_TOKEN".to_string(),
            })
        );
        assert_eq!(
            error.to_string(),
            "Cannot create the box: no sealed value was made for the secret \
             GITHUB_TOKEN, so GITHUB_TOKEN would be empty in the box. No box was created."
        );
    }

    /// BEP-007: a GitHub grant's name becomes a variable in the box's
    /// environment, so a name that is not a POSIX variable name is refused
    /// before the proxy or the sign-in is checked.
    #[test]
    fn a_grant_whose_name_is_not_a_variable_name_is_refused() {
        use boxes::core::bep::ProxyAbsence;
        let grant: boxes::core::bep::SecretGrant =
            toml::from_str("source = \"broker\"\nscopes = [\"github:user-token\"]").unwrap();
        let keychain = bep::signin::MemoryKeychain::default();
        for name in ["X=1; touch /tmp/owned #", "gh_token", "1TOKEN"] {
            let secrets = boxes::core::bep::SecretGrants::from([(name.to_string(), grant.clone())]);
            let error = check_github_grants(&secrets, Some(ProxyAbsence::NotServed), &keychain)
                .expect_err("a name that is not a variable name is refused");
            assert_eq!(
                error.downcast_ref::<GrantNotDelivered>(),
                Some(&GrantNotDelivered::InvalidName {
                    grant: name.to_string(),
                }),
                "{name}"
            );
        }
        let secrets = boxes::core::bep::SecretGrants::from([("X=1; cmd #".to_string(), grant)]);
        assert_eq!(
            check_github_grants(&secrets, Some(ProxyAbsence::NotServed), &keychain)
                .unwrap_err()
                .to_string(),
            "Cannot create the box: the secret \"X=1; cmd #\" in [defaults.session.secrets] \
             in minimal.toml is not a valid environment variable name. A name uses only \
             capital letters, digits and underscores, and does not start with a digit. \
             Rename the secret, then create the box again."
        );
    }

    #[test]
    fn ingress_needs_own_ip() {
        use crate::cli::CliNetworkMode::{HostNet, NoNet, OwnIp};
        for network in [HostNet, NoNet] {
            refuse_ingress_off_own_ip(network, true)
                .expect_err("an ingress mapping off own_ip is refused");
            refuse_ingress_off_own_ip(network, false).expect("no ingress mapping is never refused");
        }
        refuse_ingress_off_own_ip(OwnIp, true).expect("an own-IP box keeps its ingress mapping");
    }

    /// BEP-008/009/017: a project whose `minimal.toml` declares a GitHub
    /// grant the box cannot honour is refused with exit 3 before the create.
    /// The activation stops before it starts the daemon: the state
    /// directory stays empty, so nothing was spawned or created. The
    /// refusal names each GitHub host the egress omits.
    #[tokio::test]
    async fn activation_refuses_grant_before_create_with_exit_3() {
        let project = tempfile::tempdir().expect("project dir");
        std::fs::write(
            project.path().join(mfile::MFILE_NAME),
            "[session.network.bep]\nsteering = \"proxy_env\"\n\n\
             [session.secrets.GH_TOKEN]\nsource = \"broker\"\n\
             scopes = [\"github:user-token\"]\n",
        )
        .expect("write minimal.toml");
        let state = tempfile::tempdir().expect("state dir");
        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = ActivateArgs {
            name: Some("grant-box".into()),
            path: Some(project.path().to_string_lossy().into_owned()),
            sync: None,
            network: Some(CliNetworkMode::OwnIp),
            ingress: Vec::new(),
            dynamic_ingress: None,
            dynamic_range: None,
            egress: crate::EgressArgs {
                allow_dns_hosts: vec!["github.com".into(), "api.github.com".into()],
                ..crate::EgressArgs::default()
            },
            credentialed_upstream: false,
            loadout: Vec::new(),
            no_loadouts: true,
            no_hooks: true,
            no_prompt: true,
            attach: false,
        };
        let err = activate_box(&global, args, false)
            .await
            .expect_err("the grant box is refused");
        let refused = err
            .downcast_ref::<boxes::core::bep::ActivationRefused>()
            .expect("the refusal is the box spec refusal");
        assert_eq!(refused.exit_code(), 3);
        assert_eq!(
            refused.to_string(),
            "This box declares a GitHub grant, but its egress does not allow: \
             uploads.github.com, codeload.github.com. Add them to egress.allow_dns_hosts."
        );
        assert!(
            std::fs::read_dir(state.path())
                .expect("state dir")
                .next()
                .is_none(),
            "nothing was spawned or created before the refusal"
        );
    }

    /// T66, BOX-163: an activation with no `--name` registers its row under
    /// the entry's name, and the request carries no name. When the grant
    /// mint fails, the row that registration bought is withdrawn under the
    /// registered name. The mint fails here before it reads the home
    /// directory: the request's network mode gives the proxy no stance.
    #[tokio::test]
    async fn unnamed_activation_withdraws_its_row_when_the_grant_mint_fails() {
        use minimal_client::box_registration::register_box_for_activation;

        let dir = tempfile::TempDir::new().unwrap();
        let host_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&host_dir).unwrap();
        let sock_path = host_dir.join("control.sock");
        let attachments = minvmd::bep_attach::Attachments::new();
        let registry = minvmd::box_registry::BoxRegistry::new(switch::SwitchSubnet::default())
            .feeding_proxy_attachments(attachments.clone());
        let _server = minvmd::control::spawn(
            sock_path.clone(),
            registry.clone(),
            minvmd::net::answerer::AnswererStatus::allocating_for_tests("unnamed-mint-node"),
            minvmd::control::ProxyPublishStatus::default(),
        )
        .expect("the control server binds its socket");

        let mut registered = register_box_for_activation(
            paths::HostKind::Minvmd,
            Some(dir.path()),
            boxes::NetworkMode::OwnIp,
            "web",
            &boxes::BoxPolicy::default(),
        )
        .await
        .expect("the control server answers the registration")
        .expect("an own-address box on a VM-backed host registers");
        // Commit the lease, as an activation does, so only the withdrawal
        // under test can remove the row.
        if let Some(lease) = registered.lease.take() {
            lease.commit().await;
        }
        let id = registered.box_id.expect("the host minted an id");
        let source = registered.addresses.switch_address.octets();
        assert!(
            registry.table().by_source(source).is_some(),
            "the registration published the row"
        );

        let mut request = minimald_rpc::CreateSessionRequest::new(
            "web",
            paths::HostAbsPath::try_new(camino::Utf8PathBuf::from("/tmp/project")).unwrap(),
            boxes::NetworkMode::NoNet,
            boxes::BoxPolicy::default(),
        );
        // No `--name`: the request names no box (BOX-163).
        request.config.name = None;
        request.config.box_addresses = Some(registered.addresses);

        let result = mint_into_request(
            &mut request,
            Some("web"),
            Some(id),
            &["GH_TOKEN".to_owned()],
            &[],
            None,
            Some(sock_path.clone()),
        )
        .await;
        assert!(result.is_err(), "the grant mint fails");
        assert!(
            registry.table().by_source(source).is_none(),
            "the failed mint withdrew the row registered under the entry's name"
        );
        assert!(
            !attachments.holds_id(id.to_bytes()),
            "the withdrawn box's id is held by no attachment"
        );
    }

    /// BEP-082: a fresh-instance `host_ip` grant box registers under a
    /// creation key, `<base>~<random hex>`, and each create gets a key of
    /// its own. Two such keys for one base register at once, each for its
    /// own id, and a failed create withdraws by its key. A create that is
    /// not a fresh instance, or a box that is not a `host_ip` grant box,
    /// has no key and registers under its created name: a second
    /// registration of that fixed name is still refused.
    #[tokio::test]
    async fn fresh_instance_grant_box_registers_under_a_creation_key() {
        use minimal_client::box_registration::{
            NameAlreadyHeld, register_box_for_activation, withdraw_box_row,
        };

        let grant_policy = boxes::BoxPolicy {
            credentialed_upstream: Some(boxes::CredentialedUpstream::default()),
            ..boxes::BoxPolicy::default()
        };
        let request = |network, policy: &boxes::BoxPolicy, fresh| {
            let mut request = minimald_rpc::CreateSessionRequest::new(
                "dev",
                paths::HostAbsPath::try_new(camino::Utf8PathBuf::from("/tmp/project")).unwrap(),
                network,
                policy.clone(),
            );
            request.fresh_instance = fresh;
            request
        };
        let fresh_grant = request(boxes::NetworkMode::HostNet, &grant_policy, true);
        let base = created_box_name(&fresh_grant);
        assert_eq!(base.as_deref(), Some("dev"));
        let key = || {
            host_ip_registration_key(&fresh_grant, base.as_deref())
                .expect("random bytes")
                .expect("a fresh grant box has a key")
        };
        let (first_key, second_key) = (key(), key());
        for key in [&first_key, &second_key] {
            let hex = key
                .strip_prefix("dev~")
                .expect("the key starts with the base");
            assert_eq!(hex.len(), 32, "{key}");
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "{key}");
        }
        assert_ne!(first_key, second_key, "each create gets its own key");
        for (no_key, why) in [
            (
                request(boxes::NetworkMode::HostNet, &grant_policy, false),
                "not a fresh instance",
            ),
            (
                request(boxes::NetworkMode::OwnIp, &grant_policy, true),
                "an own-address box",
            ),
            (
                request(
                    boxes::NetworkMode::HostNet,
                    &boxes::BoxPolicy::default(),
                    true,
                ),
                "a host_ip box with no grant",
            ),
        ] {
            assert_eq!(
                host_ip_registration_key(&no_key, Some("dev")).unwrap(),
                None,
                "{why} has no key"
            );
        }

        let dir = tempfile::TempDir::new().unwrap();
        let host_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&host_dir).unwrap();
        let sock_path = host_dir.join("control.sock");
        let registry = minvmd::box_registry::BoxRegistry::new(switch::SwitchSubnet::default());
        let _server = minvmd::control::spawn(
            sock_path.clone(),
            registry.clone(),
            minvmd::net::answerer::AnswererStatus::allocating_for_tests("fresh-grant-node"),
            minvmd::control::ProxyPublishStatus::default(),
        )
        .expect("the control server binds its socket");
        let register = |name: String| {
            let dir = dir.path().to_path_buf();
            let policy = grant_policy.clone();
            async move {
                register_box_for_activation(
                    paths::HostKind::Minvmd,
                    Some(&dir),
                    boxes::NetworkMode::HostNet,
                    &name,
                    &policy,
                )
                .await
            }
        };

        // Two fresh instances register at once, under their own keys.
        let (first, second) =
            tokio::join!(register(first_key.clone()), register(second_key.clone()));
        let first = first.expect("answered").expect("registered");
        let second = second.expect("answered").expect("registered");
        assert!(first.host_ip && second.host_ip);
        let (first_id, second_id) = (first.box_id.unwrap(), second.box_id.unwrap());
        assert_ne!(first_id, second_id, "each fresh instance gets its own id");
        assert_eq!(
            registry.host_ip_id_for(&first_key),
            Some(first_id.to_bytes())
        );
        assert_eq!(
            registry.host_ip_id_for(&second_key),
            Some(second_id.to_bytes())
        );

        // A failed create withdraws its registration by its key.
        withdraw_box_row(
            Some(sock_path.clone()),
            Some(&first_key),
            None,
            Some(first_id),
        )
        .await;
        assert_eq!(registry.host_ip_id_for(&first_key), None);
        assert_eq!(
            registry.host_ip_id_for(&second_key),
            Some(second_id.to_bytes())
        );

        // A create under the fixed name is not a fresh instance: a second
        // registration of the name a live registration holds is refused.
        register("dev".to_string())
            .await
            .expect("answered")
            .expect("registered");
        let refused = register("dev".to_string())
            .await
            .expect_err("a held fixed name is refused");
        assert_eq!(
            refused
                .downcast_ref::<NameAlreadyHeld>()
                .map(|refused| refused.held.as_str()),
            Some("dev")
        );
    }

    /// BEP-022: a `host_ip` box with no `egress` section registers the GitHub
    /// hosts for its grant. A box with a section registers what it lists.
    #[test]
    fn host_ip_grant_box_with_no_egress_section_registers_the_github_hosts() {
        let hosts: Vec<String> = bep::module::GITHUB
            .hosts
            .iter()
            .map(|authority| authority.host.to_string())
            .collect();
        assert_eq!(proxy_egress(None, boxes::NetworkMode::HostNet, true), hosts);
        assert!(proxy_egress(None, boxes::NetworkMode::HostNet, false).is_empty());
        assert!(proxy_egress(None, boxes::NetworkMode::OwnIp, true).is_empty());

        let listed = boxes::EgressPolicy {
            allow_dns_hosts: Some(vec!["github.com".to_string()]),
            ..boxes::EgressPolicy::default()
        };
        assert_eq!(
            proxy_egress(Some(&listed), boxes::NetworkMode::HostNet, true),
            ["github.com"]
        );
    }

    /// BEP-082: a `host_ip` grant box whose record takes another id than
    /// its registration's is refused with this text. A matching id, a box
    /// with no `host_ip` registration, and a registration with no id pass.
    #[test]
    fn host_ip_grant_box_with_another_id_is_refused() {
        let minted = minimald_rpc::BoxId::from_bytes(*b"0123456789abcdef");
        let registration =
            |host_ip: bool, box_id| minimal_client::box_registration::RegisteredWithVmHost {
                addresses: boxes::BoxAddresses {
                    switch_address: std::net::Ipv4Addr::UNSPECIFIED,
                    loopback_address: std::net::Ipv4Addr::UNSPECIFIED,
                },
                host_ip,
                box_id,
                task_addresses: Vec::new(),
                lease: None,
            };
        let same = boxes::SessionId::from_bytes(minted.to_bytes());
        let other = boxes::SessionId::from_bytes(*b"fedcba9876543210");
        let host_ip = registration(true, Some(minted));
        assert!(ensure_registered_id(Some(&host_ip), same).is_ok());
        let refused = ensure_registered_id(Some(&host_ip), other)
            .expect_err("another id ends the activation");
        assert_eq!(
            refused.to_string(),
            "No session was created. The VM gave the new session an id other than the \
             one reserved for it. Run the command again."
        );
        assert!(ensure_registered_id(None, other).is_ok());
        assert!(ensure_registered_id(Some(&registration(true, None)), other).is_ok());
        assert!(ensure_registered_id(Some(&registration(false, Some(minted))), other).is_ok());
    }

    /// BEP-082: a GitHub grant box with `--network host_ip` on a VM host
    /// registers for a box id, with no address and no row in the host's
    /// address table. With that id the proxy serves it, so the grant check
    /// gives its id and its `host_ip` stance, not the refusal that says no
    /// proxy serves boxes on this machine. A `host_ip` box that declares no
    /// credentialed upstream registers nothing.
    #[tokio::test]
    async fn host_ip_grant_box_on_vm_host_is_not_refused_as_unserved() {
        use minimal_client::box_registration::register_box_for_activation;

        let dir = tempfile::TempDir::new().unwrap();
        let host_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&host_dir).unwrap();
        let sock_path = host_dir.join("control.sock");
        let registry = minvmd::box_registry::BoxRegistry::new(switch::SwitchSubnet::default());
        let _server = minvmd::control::spawn(
            sock_path.clone(),
            registry.clone(),
            minvmd::net::answerer::AnswererStatus::allocating_for_tests("host-ip-grant-node"),
            minvmd::control::ProxyPublishStatus::default(),
        )
        .expect("the control server binds its socket");

        let grant_policy = boxes::BoxPolicy {
            credentialed_upstream: Some(boxes::CredentialedUpstream::default()),
            ..boxes::BoxPolicy::default()
        };
        let registered = register_box_for_activation(
            paths::HostKind::Minvmd,
            Some(dir.path()),
            boxes::NetworkMode::HostNet,
            "agent",
            &grant_policy,
        )
        .await
        .expect("the control server answers the registration")
        .expect("a host_ip grant box on a VM host registers");
        assert!(registered.host_ip);
        assert_eq!(registered.row_addresses(), None, "the box has no row");
        assert!(registered.lease.is_none(), "no row, so no lease to hold");
        let id = registered.box_id.expect("the host minted an id");
        assert!(registry.holds_host_ip_id(id.to_bytes()));
        assert!(
            registry.table().rows().is_empty(),
            "the registration put no row in the address table"
        );

        let facts = proxy_box_facts(
            &["GH_TOKEN".to_owned()],
            &[],
            Some(id.to_string()),
            boxes::NetworkMode::HostNet,
        )
        .expect("a host_ip grant box with an id is served");
        assert_eq!(
            facts,
            Some((id.to_string(), bep::boxes::Stance::HostIp)),
            "the grant is served under the minted id and the host_ip stance"
        );

        // A host_ip box that declares no upstream needs no id.
        assert!(
            register_box_for_activation(
                paths::HostKind::Minvmd,
                Some(dir.path()),
                boxes::NetworkMode::HostNet,
                "plain",
                &boxes::BoxPolicy::default(),
            )
            .await
            .expect("nothing to register is no failure")
            .is_none()
        );
        // With no id, the refusal still prints: no proxy serves the box.
        let refused = proxy_box_facts(
            &["GH_TOKEN".to_owned()],
            &[],
            None,
            boxes::NetworkMode::HostNet,
        )
        .expect_err("no box id, so no proxy serves the box");
        assert!(
            refused
                .to_string()
                .starts_with("Cannot create the box: it declares the GitHub grant GH_TOKEN, and "),
            "{refused}"
        );
    }

    /// BEP-008: a project file that exists but does not load refuses the
    /// activation before the create. It never reads as "no grants
    /// declared", so a broken file cannot skip the grant checks.
    #[tokio::test]
    async fn activation_refuses_unloadable_project_file_before_create() {
        let project = tempfile::tempdir().expect("project dir");
        std::fs::write(
            project.path().join(mfile::MFILE_NAME),
            "[session.secrets.GH_TOKEN\nsource = \"broker\"\n",
        )
        .expect("write minimal.toml");
        let state = tempfile::tempdir().expect("state dir");
        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = ActivateArgs {
            name: Some("broken-box".into()),
            path: Some(project.path().to_string_lossy().into_owned()),
            sync: None,
            network: Some(CliNetworkMode::OwnIp),
            ingress: Vec::new(),
            dynamic_ingress: None,
            dynamic_range: None,
            egress: crate::EgressArgs::default(),
            credentialed_upstream: false,
            loadout: Vec::new(),
            no_loadouts: true,
            no_hooks: true,
            no_prompt: true,
            attach: false,
        };
        let err = activate_box(&global, args, false)
            .await
            .expect_err("the broken project file is refused");
        assert!(
            err.downcast_ref::<ProjectFileInvalid>().is_some(),
            "the refusal is typed: {err}"
        );
        assert!(
            err.to_string()
                .starts_with("Cannot start the box: the project's minimal.toml does not load"),
            "unexpected error: {err}"
        );
        assert!(
            std::fs::read_dir(state.path())
                .expect("state dir")
                .next()
                .is_none(),
            "nothing was spawned or created before the refusal"
        );
    }

    /// BEP-057: the start path honours the client configuration's
    /// full-breadth acknowledgement, the same as `min box spec` does.
    #[test]
    fn start_honours_full_breadth_acknowledgement() {
        let project = tempfile::tempdir().expect("project dir");
        std::fs::write(
            project.path().join(mfile::MFILE_NAME),
            "[session.network.bep]\nsteering = \"proxy_env\"\n\
             [session.secrets.GH_TOKEN]\nsource = \"broker\"\n\
             scopes = [\"github:repo:read\"]\n",
        )
        .expect("write minimal.toml");
        let path = camino::Utf8Path::from_path(project.path()).expect("utf-8 path");
        let (bep, secrets, spec_env, _) = project_bep_and_grants(path).expect("loads");
        // The egress here is unset, so both runs refuse for that too. Only
        // the narrow-scope refusal depends on the acknowledgement.
        let narrow = |acknowledged: bool| {
            let err = refuse_unhonourable_grants(
                boxes::NetworkMode::OwnIp,
                None,
                &bep,
                &secrets,
                acknowledged,
                false,
                &spec_env,
            )
            .expect_err("refused for the egress");
            let refused = err
                .downcast_ref::<boxes::core::bep::ActivationRefused>()
                .expect("an activation refusal");
            refused.refusals.iter().any(|refusal| {
                matches!(
                    refusal,
                    boxes::core::bep::BepRefusal::NarrowScopesUnenrolled { .. }
                )
            })
        };
        assert!(narrow(false), "refused without the acknowledgement");
        assert!(!narrow(true), "accepted with the acknowledgement");
    }

    /// BEP-011: a box spec with a GitHub grant that sets `SSL_CERT_FILE` in
    /// its own environment gets the warning on stderr. The same spec
    /// without the variable gets none.
    #[test]
    fn spec_trust_env_warns_at_activation() {
        let warnings = |vars: &str| {
            let project = tempfile::tempdir().expect("project dir");
            std::fs::write(
                project.path().join(mfile::MFILE_NAME),
                format!(
                    "[session]\n{vars}\
                     [session.network.bep]\nsteering = \"proxy_env\"\n\
                     [session.secrets.GH_TOKEN]\nsource = \"broker\"\n\
                     scopes = [\"github:user-token\"]\n"
                ),
            )
            .expect("write minimal.toml");
            let path = camino::Utf8Path::from_path(project.path()).expect("utf-8 path");
            let (bep, secrets, spec_env, _) = project_bep_and_grants(path).expect("loads");
            let egress = boxes::EgressPolicy {
                allow_dns_hosts: Some(
                    bep::module::GITHUB
                        .hosts
                        .iter()
                        .map(|authority| authority.host.to_string())
                        .collect(),
                ),
                ..boxes::EgressPolicy::default()
            };
            refuse_unhonourable_grants(
                boxes::NetworkMode::OwnIp,
                Some(&egress),
                &bep,
                &secrets,
                false,
                false,
                &spec_env,
            )
            .expect("accepted")
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
        };
        assert_eq!(
            warnings("vars = { SSL_CERT_FILE = \"/etc/my-ca.pem\" }\n"),
            vec![
                "This box sets SSL_CERT_FILE itself, so tools that read it will not \
                 trust the proxy's certificate."
                    .to_string()
            ]
        );
        assert!(warnings("").is_empty(), "no trust variable, no warning");
    }

    /// BEP-016: a `[session.network.bep]` setting alone declares no
    /// credentialed upstream. The set is derived from broker grants.
    #[test]
    fn bep_settings_alone_activate_without_credentialed_upstream() {
        let project = tempfile::tempdir().expect("project dir");
        std::fs::write(
            project.path().join(mfile::MFILE_NAME),
            "[session.network.bep]\nsteering = \"proxy_env\"\n",
        )
        .expect("write minimal.toml");
        let path = camino::Utf8Path::from_path(project.path()).expect("utf-8 path");
        let (bep, secrets, spec_env, _) = project_bep_and_grants(path).expect("loads");
        assert_eq!(bep.steering, Some(boxes::core::bep::Steering::ProxyEnv));
        assert!(credentialed_upstream_for(false, &bep, &secrets).is_none());
        refuse_unhonourable_grants(
            boxes::NetworkMode::OwnIp,
            None,
            &bep,
            &secrets,
            false,
            false,
            &spec_env,
        )
        .expect("accepted");
    }

    /// A `client_env` grant alone declares no credentialed upstream. A
    /// broker grant, or the flag, does.
    #[test]
    fn only_broker_grants_declare_credentialed_upstream() {
        use boxes::core::bep::{BepSettings, GrantSource, SecretGrant, SecretGrants};
        let bep = BepSettings::default();
        let grant = |source| SecretGrant {
            source,
            scopes: Vec::new(),
            mode: None,
        };
        let client = SecretGrants::from([("NPM_TOKEN".into(), grant(GrantSource::ClientEnv))]);
        assert!(credentialed_upstream_for(false, &bep, &client).is_none());
        assert!(credentialed_upstream_for(true, &bep, &client).is_some());
        let broker = SecretGrants::from([("GH_TOKEN".into(), grant(GrantSource::Broker))]);
        assert!(credentialed_upstream_for(false, &bep, &broker).is_some());
    }

    /// A store reference as a box spec writes it: `source = "store"` with
    /// `store` and `id`.
    fn store_reference(id: &str) -> boxes::core::bep::SecretGrant {
        toml::from_str(&format!(
            "source = \"store\"\nstore = \"keychain\"\nid = \"{id}\""
        ))
        .expect("a store reference parses")
    }

    /// One store grant `OPENAI_KEY` that reads the item `openai-key`.
    fn store_grant() -> boxes::core::bep::SecretGrants {
        boxes::core::bep::SecretGrants::from([("OPENAI_KEY".into(), store_reference("openai-key"))])
    }

    /// A rule for `openai-key` that sends it to `api.openai.com`.
    fn store_rule(action: Option<boxes::core::bep::StoreAction>) -> boxes::core::bep::StoreRules {
        boxes::core::bep::StoreRules::from([(
            "openai-key".into(),
            boxes::core::bep::StoreRuleConfig {
                store: None,
                upstream: vec!["api.openai.com".into()],
                header: Some("Authorization".into()),
                prefix: Some("Bearer ".into()),
                basic_auth: None,
                action,
            },
        )])
    }

    fn egress_of(hosts: &[&str]) -> boxes::EgressPolicy {
        boxes::EgressPolicy {
            allow_dns_hosts: Some(hosts.iter().map(|h| (*h).to_owned()).collect()),
            ..boxes::EgressPolicy::default()
        }
    }

    fn never_ask(question: &str) -> Result<bool, anyhow::Error> {
        panic!("asked with no terminal: {question}")
    }

    // BEP-062: the upstream of each store rule the creation accepts rides
    // the box's policy beside its grants, so a `dns` box's gate can steer
    // it. A box with no store reference carries none, and serializes as it
    // did before the field existed.
    #[test]
    fn accepted_store_rule_authorities_reach_the_box_policy() {
        let secrets = store_grant();
        let egress = egress_of(&["api.openai.com"]);
        let accepted = accept_store_references(
            &secrets,
            Some(&egress),
            &store_rule(None),
            false,
            &mut never_ask,
        )
        .expect("the rule accepts the reference");
        let mut policy = boxes::BoxPolicy {
            egress: Some(egress),
            credentialed_upstream: credentialed_upstream_for(
                false,
                &boxes::core::bep::BepSettings::default(),
                &secrets,
            ),
            ..boxes::BoxPolicy::default()
        };
        put_store_upstreams(&mut policy, &accepted);
        let declaration = policy
            .credentialed_upstream
            .as_ref()
            .expect("a store reference declares the lane");
        assert_eq!(declaration.store_upstreams, ["api.openai.com"]);
        assert_eq!(declaration.secrets, secrets, "beside its grants");
        let json = serde_json_lenient::to_value(&policy).expect("the policy serializes");
        assert_eq!(
            json["credentialed_upstream"]["store_upstreams"],
            serde_json_lenient::json!(["api.openai.com"])
        );

        // A second accepted rule that names the same authority adds it once.
        let mut twice = store_rule(None);
        let mut other = twice["openai-key"].clone();
        other.upstream = vec!["api.openai.com".into(), "api.example.com:8443".into()];
        twice.insert("other-key".into(), other);
        put_store_upstreams(&mut policy, &twice);
        assert_eq!(
            policy
                .credentialed_upstream
                .as_ref()
                .map(|d| d.store_upstreams.clone()),
            Some(vec![
                "api.openai.com".to_owned(),
                "api.example.com:8443".to_owned()
            ])
        );

        // No store reference: no rule is accepted and no field is written.
        let mut plain = boxes::BoxPolicy {
            credentialed_upstream: credentialed_upstream_for(
                true,
                &boxes::core::bep::BepSettings::default(),
                &boxes::core::bep::SecretGrants::new(),
            ),
            ..boxes::BoxPolicy::default()
        };
        put_store_upstreams(&mut plain, &boxes::core::bep::StoreRules::new());
        let json = serde_json_lenient::to_value(&plain).expect("the policy serializes");
        assert_eq!(json["credentialed_upstream"], serde_json_lenient::json!({}));
    }

    // BEP-032, BEP-063: each store reference that a rule accepts gets its
    // own store handle, sealed as a `store` member under its variable. The
    // proxy opens each value and reads its handle under the rule that
    // admitted it, so it redeems the value that rule names.
    #[test]
    fn box_creation_seals_a_store_member_per_accepted_rule() {
        use std::sync::Arc;

        use base64::Engine as _;
        use bep::boxes::{BoxRegistry, Stance};
        use bep::control::{Control, Registry};
        use bep::publish::{Identity, PublishedKey};
        use bep::seal::{Binding, MemberKind, ProxyKey, ProxyPublicKey};

        const BOX_ID: &str = "0192f0c1-7a2b-7c3d-8e4f-a0b1c2d3e4f5";
        const BOX_HEX: &str = "0192f0c17a2b7c3d8e4fa0b1c2d3e4f5";
        const NOW: u64 = 1_800_000_000;
        const ROOT_END: u64 = 2_000_000_000;

        // Two grants read the one accepted item, so the box carries two.
        let egress = egress_of(&["api.openai.com"]);
        let mut secrets = store_grant();
        secrets.insert("ZZ_KEY".into(), store_reference("openai-key"));
        let accepted = accept_store_references(
            &secrets,
            Some(&egress),
            &store_rule(None),
            false,
            &mut never_ask,
        )
        .expect("the rule accepts both references");
        let stores = store_grants(&secrets, &accepted).expect("each rule has a form");
        let rule =
            bep::handle::StoreRule::from_config("openai-key", &store_rule(None)["openai-key"])
                .expect("the rule's proxy form");
        assert_eq!(
            stores,
            [
                crate::mint::StoreGrant {
                    grant: "OPENAI_KEY".into(),
                    rule: rule.clone(),
                },
                crate::mint::StoreGrant {
                    grant: "ZZ_KEY".into(),
                    rule: rule.clone(),
                },
            ]
        );
        // A reference that no accepted rule names is refused by name.
        let err = store_grants(&secrets, &boxes::core::bep::StoreRules::new())
            .expect_err("no accepted rule");
        assert_eq!(
            err.downcast_ref::<GrantNotDelivered>(),
            Some(&GrantNotDelivered::NotSealed {
                grant: "OPENAI_KEY".into()
            })
        );

        // The proxy's control socket, and its published identity.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let clients = Registry::default();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let control = runtime
            .block_on(async { Control::bind(&path, Arc::clone(&clients), BoxRegistry::default()) })
            .unwrap();
        runtime.spawn(control.run());
        let published = |key: &ProxyPublicKey| PublishedKey {
            public: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.to_sec1_bytes()),
            kid: key.kid(),
        };
        let sealing = ProxyKey::generate().unwrap();
        let identity = Identity {
            sealing: Some(published(&sealing.public())),
            root: Some(published(&ProxyKey::generate().unwrap().public())),
            signing: Some(published(&ProxyKey::generate().unwrap().public())),
            root_not_after: Some(ROOT_END),
            root_certificate: None,
        };

        // The mint as `mint_grants` runs it for a box with store references
        // only: the box registers, then each handle is minted and sealed.
        let key = crate::mint::ClientKey::generate().unwrap();
        let mut client = crate::mint::ControlClient::connect(&path).unwrap();
        client
            .register_box(BOX_HEX, &["api.openai.com".into()], Stance::OwnIp)
            .unwrap();
        let minted = crate::mint::mint_store_members(
            &identity,
            std::path::Path::new("identity.json"),
            &mut client,
            &key,
            BOX_ID,
            &stores,
            None,
            NOW,
        )
        .unwrap();
        assert!(clients.read().unwrap().contains(&key.kid()));

        // The create request carries one sealed delivery for each grant.
        let deliveries = sealed_deliveries(&proxy_grant_names(&[], &stores), &minted).unwrap();
        assert_eq!(
            deliveries
                .iter()
                .map(|delivery| delivery.variable.as_str())
                .collect::<Vec<_>>(),
            ["OPENAI_KEY", "ZZ_KEY"]
        );

        let mut jtis = Vec::new();
        for delivery in &deliveries {
            let opened = bep::seal::open(
                &sealing,
                &delivery.sealed,
                &Binding {
                    box_id: BOX_HEX.into(),
                    host: sealing.public().kid(),
                    module: bep::module::GITHUB.id.into(),
                    now: NOW + 1,
                },
            )
            .expect("the proxy opens the sealed value");
            assert_eq!(opened.member.kind, MemberKind::Store);
            assert_eq!(opened.member.exp, Some(ROOT_END));
            let read = bep::handle::read_opened(
                &opened,
                &clients.read().unwrap(),
                &vec![rule.clone()],
                &bep::module::GITHUB,
                NOW + 1,
            );
            assert_eq!(read.identifier.as_deref(), Some("keychain:openai-key"));
            read.handle
                .check(NOW + 1)
                .expect("the handle is valid under the rule that admitted it");
            assert_eq!(read.handle.inject.as_ref(), Some(&rule.inject));
            jtis.push(read.jti.expect("the handle has a jti"));
        }
        assert_ne!(jtis[0], jtis[1], "each member is its own handle");
    }

    /// BEP-035: a store reference that no rule names is refused at
    /// creation, through the reader creation uses, with exit 3. A box with
    /// no store reference reads no configuration and passes.
    #[test]
    fn store_reference_without_rule_is_refused_at_creation() {
        let config_dir = tempfile::tempdir().expect("config dir");
        let global = crate::cli::GlobalArgs {
            config_dir: Some(config_dir.path().to_path_buf()),
            ..crate::cli::GlobalArgs::default()
        };
        let egress = egress_of(&["api.openai.com"]);
        let err = check_store_grants(&global, &store_grant(), Some(&egress), false)
            .expect_err("a reference with no rule is refused");
        let refused = err
            .downcast_ref::<GrantNotDelivered>()
            .expect("a refusal main.rs ends with exit 3");
        assert_eq!(
            refused,
            &GrantNotDelivered::NoStoreRule {
                grant: "OPENAI_KEY".into(),
                item: "openai-key".into(),
            }
        );
        let text = refused.to_string();
        assert!(
            text.contains("OPENAI_KEY") && text.contains("openai-key"),
            "{text}"
        );
        assert!(text.contains("[secret-store-rules]"), "{text}");

        let none = check_store_grants(&global, &boxes::core::bep::SecretGrants::new(), None, false)
            .expect("no store reference, nothing to refuse");
        assert!(none.is_empty());

        // A rule in another store does not name the reference.
        let mut other = store_rule(None);
        other.get_mut("openai-key").expect("rule").store = Some("vault".into());
        let err =
            accept_store_references(&store_grant(), Some(&egress), &other, true, &mut never_ask)
                .expect_err("a rule in another store is no rule");
        assert!(matches!(
            err.downcast_ref::<GrantNotDelivered>(),
            Some(GrantNotDelivered::NoStoreRule { .. })
        ));

        let accepted = accept_store_references(
            &store_grant(),
            Some(&egress),
            &store_rule(None),
            false,
            &mut never_ask,
        )
        .expect("a matching rule inside the egress is accepted");
        assert_eq!(accepted, store_rule(None));
    }

    /// BEP-036: a rule whose upstream the box's egress does not admit
    /// refuses the creation with exit 3, naming the missing host.
    #[test]
    fn store_rule_outside_egress_exits_3() {
        for egress in [None, Some(egress_of(&["example.com"]))] {
            let err = accept_store_references(
                &store_grant(),
                egress.as_ref(),
                &store_rule(None),
                true,
                &mut never_ask,
            )
            .expect_err("an upstream outside the egress is refused");
            let refused = err
                .downcast_ref::<boxes::core::bep::ActivationRefused>()
                .expect("an activation refusal");
            assert_eq!(refused.exit_code(), 3);
            assert_eq!(
                refused.refusals,
                [boxes::core::bep::BepRefusal::StoreHostsOutsideEgress {
                    grant: "OPENAI_KEY".into(),
                    missing: vec!["api.openai.com".into()],
                }]
            );
            assert!(err.to_string().contains("api.openai.com"), "{err}");
        }
    }

    /// BEP-035: an `ask` rule with no terminal denies the reference, and
    /// asks nothing. With a terminal it asks, and the answer decides.
    #[test]
    fn ask_rule_without_a_terminal_denies() {
        let egress = egress_of(&["api.openai.com"]);
        let ask = store_rule(Some(boxes::core::bep::StoreAction::Ask));
        let err =
            accept_store_references(&store_grant(), Some(&egress), &ask, false, &mut never_ask)
                .expect_err("no terminal denies");
        let refused = err.downcast_ref::<GrantNotDelivered>().expect("exit 3");
        assert_eq!(
            refused,
            &GrantNotDelivered::AskWithoutTerminal {
                grant: "OPENAI_KEY".into(),
                item: "openai-key".into(),
            }
        );
        assert!(refused.to_string().contains("--no-input"), "{refused}");

        let mut questions = Vec::new();
        let accepted =
            accept_store_references(&store_grant(), Some(&egress), &ask, true, &mut |q| {
                questions.push(q.to_owned());
                Ok(true)
            })
            .expect("a yes accepts");
        assert_eq!(accepted, ask);
        assert_eq!(questions.len(), 1);
        assert!(questions[0].contains("api.openai.com"), "{}", questions[0]);
        assert_eq!(
            printable("KEY\u{1b}[2K\nAllow? y"),
            "KEY\\u{1b}[2K\\nAllow? y"
        );

        let err = accept_store_references(&store_grant(), Some(&egress), &ask, true, &mut |_| {
            Ok(false)
        })
        .expect_err("a no refuses");
        assert!(matches!(
            err.downcast_ref::<GrantNotDelivered>(),
            Some(GrantNotDelivered::StoreReferenceDeclined { .. })
        ));

        let deny = store_rule(Some(boxes::core::bep::StoreAction::Deny));
        let err =
            accept_store_references(&store_grant(), Some(&egress), &deny, true, &mut never_ask)
                .expect_err("a deny rule refuses");
        assert!(matches!(
            err.downcast_ref::<GrantNotDelivered>(),
            Some(GrantNotDelivered::StoreReferenceDenied { .. })
        ));

        // A deny after an ask asks nothing: every refusal comes first.
        let mut two = store_grant();
        two.insert("ZZ_TOKEN".into(), store_reference("other-key"));
        let mut ask_then_deny = ask.clone();
        let mut denied = deny["openai-key"].clone();
        denied.upstream = vec!["api.openai.com".into()];
        ask_then_deny.insert("other-key".into(), denied);
        let err =
            accept_store_references(&two, Some(&egress), &ask_then_deny, true, &mut never_ask)
                .expect_err("the deny refuses before any question");
        assert!(matches!(
            err.downcast_ref::<GrantNotDelivered>(),
            Some(GrantNotDelivered::StoreReferenceDenied { .. })
        ));

        // One item under two grants is asked once, and names both grants.
        let mut shared = store_grant();
        shared.insert("ZZ_TOKEN".into(), store_reference("openai-key"));
        let mut questions = Vec::new();
        let accepted = accept_store_references(&shared, Some(&egress), &ask, true, &mut |q| {
            questions.push(q.to_owned());
            Ok(true)
        })
        .expect("a yes accepts both grants");
        assert_eq!(accepted, ask);
        assert_eq!(questions.len(), 1, "{questions:?}");
        assert!(
            questions[0].contains("OPENAI_KEY") && questions[0].contains("ZZ_TOKEN"),
            "{}",
            questions[0]
        );
    }

    /// BEP-010: `steering = "off"` with `proxy_env = true` is refused with
    /// exit 3 even when no grant declares a credentialed upstream.
    #[test]
    fn steering_off_with_proxy_env_is_refused_without_a_grant() {
        let bep = boxes::core::bep::BepSettings {
            steering: Some(boxes::core::bep::Steering::Off),
            proxy_env: true,
            ..Default::default()
        };
        let secrets = boxes::core::bep::SecretGrants::new();
        assert!(credentialed_upstream_for(false, &bep, &secrets).is_none());
        let err = refuse_unhonourable_grants(
            boxes::NetworkMode::OwnIp,
            None,
            &bep,
            &secrets,
            false,
            false,
            &[],
        )
        .expect_err("refused");
        let refused = err
            .downcast_ref::<boxes::core::bep::ActivationRefused>()
            .expect("the refusal is the box spec refusal");
        assert_eq!(refused.exit_code(), 3);
    }

    /// NET-046: a `none` box on a VM host holds its name with the host, as
    /// a `host_ip` box does, so the host can name it by its box id.
    #[test]
    fn none_box_holds_its_name_with_the_vm_host() {
        use boxes::NetworkMode;
        use paths::HostKind;
        assert!(holds_name_with_vm_host(
            HostKind::Minvmd,
            NetworkMode::NoNet
        ));
        assert!(holds_name_with_vm_host(
            HostKind::Minvmd,
            NetworkMode::HostNet
        ));
        assert!(!holds_name_with_vm_host(
            HostKind::Minvmd,
            NetworkMode::OwnIp
        ));
        assert!(!holds_name_with_vm_host(
            HostKind::Minimald,
            NetworkMode::NoNet
        ));
    }

    /// BEP-017, BEP-062, BEP-080, BEP-081: a GitHub grant box with `dns`
    /// steering, declared or by default, or with `both`, is created on the
    /// VM host for `own_ip` and `host_ip`, and `min box spec` shows it. On
    /// a native host, and for a `none` box, both are refused for the
    /// missing resolver. For every case, `min box spec` refuses exactly
    /// when creation does, with the same text.
    #[test]
    fn vm_host_admits_dns_and_both_for_own_ip_and_host_ip() {
        use boxes::core::bep::Steering;
        use paths::HostKind;
        // The host fact does not read the steering.
        assert!(host_resolves_box_names(
            HostKind::Minvmd,
            boxes::NetworkMode::OwnIp
        ));
        assert!(!host_resolves_box_names(
            HostKind::Minimald,
            boxes::NetworkMode::OwnIp
        ));
        assert!(host_resolves_box_names(
            HostKind::Minvmd,
            boxes::NetworkMode::HostNet
        ));
        assert!(!host_resolves_box_names(
            HostKind::Minimald,
            boxes::NetworkMode::HostNet
        ));
        assert!(!host_resolves_box_names(
            HostKind::Minvmd,
            boxes::NetworkMode::NoNet
        ));
        let github_hosts: Vec<&str> = bep::module::GITHUB
            .hosts
            .iter()
            .map(|authority| authority.host)
            .collect();
        let egress = boxes::EgressPolicy {
            allow_dns_hosts: Some(github_hosts.iter().map(|h| (*h).to_string()).collect()),
            ..boxes::EgressPolicy::default()
        };
        // No steering declared resolves to `dns`.
        for (declared, word) in [
            ("", "dns"),
            ("steering = \"dns\"\n", "dns"),
            ("steering = \"both\"\n", "both"),
        ] {
            let project = tempfile::tempdir().expect("project dir");
            std::fs::write(
                project.path().join(mfile::MFILE_NAME),
                format!(
                    "[session.network.bep]\n{declared}\
                     [session.secrets.GH_TOKEN]\nsource = \"broker\"\n\
                     scopes = [\"github:user-token\"]\n"
                ),
            )
            .expect("write minimal.toml");
            let path = camino::Utf8Path::from_path(project.path()).expect("utf-8 path");
            let (bep, secrets, spec_env, _) = project_bep_and_grants(path).expect("loads");
            assert!(credentialed_upstream_for(false, &bep, &secrets).is_some());
            assert_eq!(bep.resolved_steering().word(), word);
            assert_eq!(bep.resolved_steering() == Steering::Both, word == "both");
            let no_resolver = format!(
                "This box declares a secret with steering = \"{word}\", but this host \
                 has no box DNS resolver. Set steering = \"proxy_env\" in \
                 [defaults.session.network.bep] in minimal.toml."
            );

            for (kind, network) in [
                (HostKind::Minvmd, boxes::NetworkMode::OwnIp),
                (HostKind::Minimald, boxes::NetworkMode::OwnIp),
                (HostKind::Minvmd, boxes::NetworkMode::HostNet),
                (HostKind::Minimald, boxes::NetworkMode::HostNet),
            ] {
                let resolver = host_resolves_box_names(kind, network);
                let accepted = resolver;
                let refusal = no_resolver.as_str();
                let case = format!("{word} {kind:?} {network:?}");

                let created = refuse_unhonourable_grants(
                    network,
                    Some(&egress),
                    &bep,
                    &secrets,
                    false,
                    resolver,
                    &spec_env,
                );
                // `min box spec` reads the same fact for this host.
                let rules = boxes::core::bep::StoreRules::new();
                let mut out = Vec::new();
                let previewed = crate::cmd::box_spec::render(
                    &crate::cmd::box_spec::SpecInputs {
                        root_fingerprint: None,
                        bep: &bep,
                        quic443: None,
                        secrets: &secrets,
                        acknowledged: false,
                        network,
                        box_zone_resolver: resolver,
                        github_hosts: &github_hosts,
                        store_rules: &rules,
                        tables: boxes::core::bep::BepTables::SESSION,
                    },
                    &mut out,
                );
                assert_eq!(
                    created.is_ok(),
                    previewed.is_ok(),
                    "{case}: min box spec and creation agree"
                );

                if accepted {
                    let warnings = created.unwrap_or_else(|err| panic!("{case}: accepted: {err}"));
                    assert!(warnings.is_empty(), "{case}: no warning: {warnings:?}");
                    let text = String::from_utf8(out).expect("utf-8");
                    assert!(
                        text.contains(&format!("steering  {word}\n")),
                        "{case}: {text}"
                    );
                    continue;
                }
                for err in [
                    created.expect_err("creation refuses"),
                    previewed.expect_err("min box spec refuses"),
                ] {
                    let refused = err
                        .downcast_ref::<boxes::core::bep::ActivationRefused>()
                        .expect("the refusal is the box spec refusal");
                    assert_eq!(refused.exit_code(), 3, "{case}");
                    assert_eq!(refused.to_string(), refusal, "{case}");
                }
            }

            // `min box spec --network <mode>` and `min session activate
            // --network <mode>`, parsed as the command line gives them, read
            // the same network and host fact, so they give the same refusal
            // for every mode on both host kinds. With no flag, both are of a
            // `host_ip` box.
            for flag in [None, Some("none"), Some("host_ip"), Some("own_ip")] {
                for kind in [HostKind::Minvmd, HostKind::Minimald] {
                    let mut activate = vec!["min", "session", "activate"];
                    let mut spec = vec!["min", "box", "spec"];
                    if let Some(mode) = flag {
                        activate.extend(["--network", mode]);
                        spec.extend(["--network", mode]);
                    }
                    let activate_args = parsed_activate_args(&activate);
                    let spec_args = parsed_box_spec_args(&spec);
                    let (network, resolver) = creation_host(kind, &activate_args);
                    let (spec_network, spec_resolver) =
                        crate::cmd::box_spec::preview_host(kind, &spec_args);
                    let case = format!("{word} {kind:?} --network {flag:?}");
                    assert_eq!(network, spec_network, "{case}: same network");
                    assert_eq!(resolver, spec_resolver, "{case}: same host fact");

                    let created = refuse_unhonourable_grants(
                        network,
                        Some(&egress),
                        &bep,
                        &secrets,
                        false,
                        resolver,
                        &spec_env,
                    );
                    let rules = boxes::core::bep::StoreRules::new();
                    let mut out = Vec::new();
                    let previewed = crate::cmd::box_spec::render(
                        &crate::cmd::box_spec::SpecInputs {
                            root_fingerprint: None,
                            bep: &bep,
                            quic443: None,
                            secrets: &secrets,
                            acknowledged: false,
                            network: spec_network,
                            box_zone_resolver: spec_resolver,
                            github_hosts: &github_hosts,
                            store_rules: &rules,
                            tables: boxes::core::bep::BepTables::SESSION,
                        },
                        &mut out,
                    );
                    let created = created.map(|_| ()).map_err(|err| err.to_string());
                    let previewed = previewed.map_err(|err| err.to_string());
                    assert_eq!(created, previewed, "{case}: same refusal");

                    // With no flag the box is a `host_ip` box.
                    let admitted_on_vm_host = kind == HostKind::Minvmd
                        && matches!(flag, None | Some("host_ip") | Some("own_ip"));
                    if admitted_on_vm_host {
                        // On the VM host, `min box spec --network own_ip`
                        // and `--network host_ip` admit a `dns` or `both`
                        // spec with a credentialed upstream (BEP-081).
                        assert_eq!(previewed, Ok(()), "{case}: admitted");
                        let text = String::from_utf8(out).expect("utf-8");
                        assert!(
                            text.contains(&format!("steering  {word}\n")),
                            "{case}: {text}"
                        );
                    } else {
                        // A native host, and a `none` box, have no
                        // steered lookups, so the spec is refused for the
                        // missing resolver. A `none` box is also refused
                        // for its missing network.
                        let refused = previewed.expect_err("min box spec refuses");
                        assert!(refused.ends_with(no_resolver.as_str()), "{case}: {refused}");
                        if flag == Some("none") {
                            assert!(refused.contains("has no network"), "{case}: {refused}");
                        } else {
                            assert_eq!(refused, no_resolver, "{case}");
                        }
                    }
                }
            }
        }
    }

    /// The `min session activate` arguments for `argv`, from the real clap
    /// parse.
    fn parsed_activate_args(argv: &[&str]) -> ActivateArgs {
        use clap::Parser as _;
        match crate::Cli::try_parse_from(argv).expect("parses").command {
            Some(crate::Command::Session(crate::SessionArgs {
                command: crate::SessionCommand::Activate(args),
            })) => args,
            _ => panic!("expected min session activate for {argv:?}"),
        }
    }

    /// The `min box spec` arguments for `argv`, from the real clap parse.
    fn parsed_box_spec_args(argv: &[&str]) -> crate::BoxSpecArgs {
        use clap::Parser as _;
        match crate::Cli::try_parse_from(argv).expect("parses").command {
            Some(crate::Command::Box(crate::BoxArgs {
                command: crate::BoxCommand::Spec(args),
            })) => args,
            _ => panic!("expected min box spec for {argv:?}"),
        }
    }

    // BEP-032: a box whose only proxy-served secrets are store references
    // is refused in words that name no GitHub grant. A GitHub grant box
    // keeps the GitHub wording.
    #[test]
    fn a_store_only_box_is_refused_without_naming_a_github_grant() {
        use crate::mint::{MintError, StoreOnlyMintError};

        let not_running = || MintError::NotRunning {
            path: "/home/me/.minimal/bep/control.sock".into(),
            error: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
        };
        let store = StoreOnlyMintError(not_running()).to_string();
        assert!(
            store.starts_with(
                "Cannot start the box: it declares a secret from the host's secret store, \
                 and the Box Egress Proxy does not answer on \
                 /home/me/.minimal/bep/control.sock: "
            ),
            "{store}"
        );
        assert!(!store.contains("GitHub"), "{store}");
        let github = not_running().to_string();
        assert!(
            github.starts_with(
                "Cannot start the box: it declares a GitHub grant, and the Box Egress Proxy \
                 does not answer on /home/me/.minimal/bep/control.sock: "
            ),
            "{github}"
        );
        let random = StoreOnlyMintError(MintError::Random).to_string();
        assert!(!random.contains("GitHub"), "{random}");
        assert!(!no_root_certificate(true).to_string().contains("GitHub"));
        assert!(
            no_root_certificate(false)
                .to_string()
                .contains("it declares a GitHub grant")
        );

        // Where no proxy serves boxes, the refusal names the store
        // reference as a secret.
        let mut secrets = store_grant();
        secrets.insert("ZZ_KEY".into(), store_reference("openai-key"));
        let accepted = accept_store_references(
            &secrets,
            Some(&egress_of(&["api.openai.com"])),
            &store_rule(None),
            false,
            &mut never_ask,
        )
        .expect("the rule accepts both references");
        let stores = store_grants(&secrets, &accepted).expect("each rule has a form");
        let refused = proxy_box_facts(&[], &stores, None, boxes::NetworkMode::OwnIp)
            .expect_err("no box id, so no proxy serves the box")
            .to_string();
        assert!(
            refused.starts_with(
                "Cannot create the box: it declares the secret OPENAI_KEY, ZZ_KEY, and "
            ),
            "{refused}"
        );
        assert!(!refused.contains("GitHub"), "{refused}");
        let refused = proxy_box_facts(&["GH_TOKEN".into()], &[], None, boxes::NetworkMode::OwnIp)
            .expect_err("no box id, so no proxy serves the box")
            .to_string();
        assert!(
            refused
                .starts_with("Cannot create the box: it declares the GitHub grant GH_TOKEN, and "),
            "{refused}"
        );
    }

    /// A `network` key in a task entry never reaches a session, so two
    /// session entries with no default still start when only a task
    /// declares `network`. The same key in a session layer still refuses.
    #[test]
    fn network_key_only_in_task_does_not_refuse_session_pick() {
        let sessions = "[sessions.a]\npackages = [\"git\"]\n\n\
                        [sessions.b]\npackages = [\"git\"]\n\n\
                        [tasks.build]\nexec = 'true'\n\n";
        let only_task =
            format!("{sessions}[tasks.build.network.egress]\nallow_dns_hosts = [\"github.com\"]\n");
        let project = project_egress_from(only_task.as_bytes(), None)
            .expect("a network key only in a task does not refuse the session start");
        assert_eq!(project, ProjectEgress::default());
        let task_defaults = format!(
            "{sessions}[defaults.task.network.egress]\nallow_dns_hosts = [\"github.com\"]\n"
        );
        assert_eq!(
            project_egress_from(task_defaults.as_bytes(), None)
                .expect("[defaults.task] does not refuse the session start"),
            ProjectEgress::default()
        );
        for layer in [
            "[defaults.network.egress]",
            "[defaults.session.network.egress]",
            "[sessions.a.network.egress]",
        ] {
            let body = format!("{sessions}{layer}\nallow_dns_hosts = [\"github.com\"]\n");
            let error = project_egress_from(body.as_bytes(), None)
                .expect_err("a session layer's network key needs a picked entry");
            assert!(
                error.downcast_ref::<SessionEntryUndecided>().is_some(),
                "{layer}: {error}"
            );
        }
        // `[defaults.<name>]` of a project Box Type reaches a possible
        // session, so its network key still refuses the undecided pick.
        let project_type = "[boxes.dev]\ntype = \"mydev\"\n\n\
                            [defaults.mydev.network.egress]\n\
                            allow_dns_hosts = [\"github.com\"]\n";
        let error = project_egress_from(project_type.as_bytes(), None)
            .expect_err("[defaults.mydev] needs a resolved type");
        assert!(
            matches!(
                error.downcast_ref::<SessionEntryUndecided>(),
                Some(SessionEntryUndecided::TypeUnresolved { name, .. }) if name == "dev"
            ),
            "{error}"
        );
    }

    /// NET-065: a session start with project egress and `--network none`
    /// refuses before the create request, and names the minimal.toml table
    /// the egress came from.
    #[test]
    fn session_network_none_refusal_names_minimal_toml() {
        let daemon = "egress rules need network mode own_ip or host_ip (this box is none): a \
                      none box has no network to apply them to.";
        let none = boxes::NetworkMode::NoNet;
        for (body, layer) in [
            (
                "[defaults.network.egress]\nallow_dns_hosts = [\"github.com\"]\n",
                "[defaults]",
            ),
            (
                "[defaults.session.network.egress]\nallow_dns_hosts = [\"github.com\"]\n",
                "[defaults.session]",
            ),
            (
                "[sessions.default]\npackages = [\"git\"]\n\n\
                 [sessions.default.network.egress]\nallow_dns_hosts = [\"github.com\"]\n",
                "[sessions.default]",
            ),
        ] {
            let project = project_egress_from(body.as_bytes(), None).expect("the file loads");
            let refusal =
                session_effective_egress(project, None, none, &crate::EgressArgs::default())
                    .expect_err("--network none refuses the project's egress")
                    .to_string();
            assert_eq!(
                refusal,
                format!(
                    "{daemon} The box's egress rules come from {layer} in minimal.toml. Run it \
                     with --network host_ip or --network own_ip."
                )
            );
        }
        // A flag alone names the flag and offers to drop it.
        let flags = crate::EgressArgs {
            deny_all_egress: true,
            ..crate::EgressArgs::default()
        };
        let refusal = session_effective_egress(
            ProjectEgress::default(),
            flag_egress(&flags).expect("the flags parse"),
            none,
            &flags,
        )
        .expect_err("--network none refuses --deny-all-egress")
        .to_string();
        assert_eq!(
            refusal,
            format!(
                "{daemon} The box's egress rules come from --deny-all-egress. Run it with \
                 --network host_ip or --network own_ip, or without --deny-all-egress."
            )
        );
        // With no egress, or on another mode, the start goes on.
        session_effective_egress(
            ProjectEgress::default(),
            None,
            none,
            &crate::EgressArgs::default(),
        )
        .expect("a none box with no egress starts");
        let project = project_egress_from(
            b"[defaults.network.egress]\nallow_dns_hosts = [\"github.com\"]\n",
            None,
        )
        .expect("the file loads");
        session_effective_egress(
            project,
            None,
            boxes::NetworkMode::HostNet,
            &crate::EgressArgs::default(),
        )
        .expect("a host_ip box keeps its egress");
    }

    /// NET-060: the egress keys a project's `minimal.toml` declares become
    /// the box policy's egress, and each field names the file as its source.
    #[test]
    fn project_egress_table_reaches_box_policy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(mfile::MFILE_NAME),
            "[session]\npackages = [\"git\"]\n\n\
             [defaults.network.egress]\n\
             allow_subnets = [\"10.0.0.1/8\"]\n\
             allow_protocols = [\"tcp\", \"udp\"]\n\
             allow_dns_hosts = [\"github.com\"]\n\
             deny_subnets = [\"169.254.169.254/32\"]\n",
        )
        .unwrap();
        let root = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).unwrap();

        let project = project_egress(&sub, None)
            .expect("the project file loads")
            .policy;
        let effective = effective_egress(project, None, false);
        let expected = boxes::EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".into()]),
            allow_dns_hosts: Some(vec!["github.com".into()]),
            allow_protocols: Some(vec![boxes::IpProto::Tcp, boxes::IpProto::Udp]),
            deny_subnets: Some(vec!["169.254.169.254/32".into()]),
        };
        assert_eq!(effective.policy.as_ref(), Some(&expected));
        assert_eq!(
            effective.sources,
            [
                ("allow_subnets", EgressSource::ProjectFile),
                ("allow_dns_hosts", EgressSource::ProjectFile),
                ("allow_protocols", EgressSource::ProjectFile),
                ("deny_subnets", EgressSource::ProjectFile),
            ]
        );

        // The box spec records the policy that the create request carries.
        let flags = mfile::spec::SpecFlags {
            network: boxes::NetworkMode::OwnIp,
            policy: boxes::BoxPolicy::new(effective.policy, None),
            hooks_enabled: true,
        };
        let spec = mfile::spec::BoxSpec::for_session(None, flags);
        assert_eq!(spec.network.policy.egress, Some(expected));

        // `[sessions.default]` replaces `[defaults]`, and the flat legacy key
        // reads as its nested key.
        let layered = project_egress_from(
            b"[defaults.network.egress]\nallow_dns_hosts = [\"a.example\"]\n\n\
              [sessions.default.network]\negress_allow_dns = [\"b.example\"]\n",
            None,
        )
        .expect("the file loads");
        assert_eq!(
            layered.hints.len(),
            1,
            "the flat legacy key gives one hint: {:?}",
            layered.hints
        );
        let layered = layered.policy.expect("egress is declared");
        assert_eq!(layered.allow_dns_hosts, Some(vec!["b.example".to_owned()]));

        // A file whose one session entry is `[sessions.dev]` gives that
        // entry's egress, and `[sessions.default]` wins over another entry.
        let only_dev = project_egress_from(
            b"[sessions.dev.network.egress]\nallow_dns_hosts = [\"dev.example\"]\n",
            None,
        )
        .unwrap()
        .policy
        .expect("the one entry declares egress");
        assert_eq!(
            only_dev.allow_dns_hosts,
            Some(vec!["dev.example".to_owned()])
        );
        let with_default = project_egress_from(
            b"[sessions.dev.network.egress]\nallow_dns_hosts = [\"dev.example\"]\n\n\
              [sessions.default.network.egress]\nallow_dns_hosts = [\"d.example\"]\n",
            None,
        )
        .unwrap()
        .policy
        .expect("the default entry declares egress");
        assert_eq!(
            with_default.allow_dns_hosts,
            Some(vec!["d.example".to_owned()])
        );

        // A `[boxes.<name>]` entry with `type = "session"` is a session entry,
        // the same as `[sessions.<name>]`.
        let boxes_dev = project_egress_from(
            b"[boxes.dev]\ntype = \"session\"\n\n\
              [boxes.dev.network.egress]\nallow_dns_hosts = [\"box.example\"]\n",
            None,
        )
        .unwrap()
        .policy
        .expect("the boxes entry declares egress");
        assert_eq!(
            boxes_dev.allow_dns_hosts,
            Some(vec!["box.example".to_owned()])
        );

        // Two session entries and none named `default`: the start cannot
        // pick one, and refuses with exit 2 before the create request.
        let refusal = project_egress_from(
            b"[sessions.dev.network.egress]\nallow_dns_hosts = [\"dev.example\"]\n\n\
              [boxes.web]\ntype = \"session\"\n",
            None,
        )
        .expect_err("two session entries and no default refuse the start");
        let undecided = refusal
            .downcast_ref::<SessionEntryUndecided>()
            .expect("the refusal is an undecided session entry");
        assert_eq!(SessionEntryUndecided::EXIT_CODE, 2);
        assert_eq!(
            undecided.to_string(),
            "Cannot start the box: the project's minimal.toml declares the session entries \
             web, dev. None of them is named \"default\", so the start cannot pick one. \
             Rename the entry to start to \"default\" in minimal.toml."
        );

        // No session entry, and a `default` entry of another type: no
        // implicit default session entry applies, so the start refuses.
        let refusal = project_egress_from(
            b"[defaults.network.egress]\nallow_dns_hosts = [\"a.example\"]\n\n\
              [tasks.default]\ncommand = \"true\"\n",
            None,
        )
        .expect_err("a task named default blocks the implicit session entry");
        let undecided = refusal
            .downcast_ref::<SessionEntryUndecided>()
            .expect("the refusal is an undecided session entry");
        assert_eq!(
            undecided.to_string(),
            "Cannot start the box: the project's minimal.toml declares no session entry. \
             Its entry \"default\" has the type \"task\", so the start has no session entry \
             to use. Add a [sessions.<name>] entry to minimal.toml."
        );

        // An entry whose type is not built in: the client cannot resolve its
        // session root, so the start refuses rather than skip the entry.
        let refusal = project_egress_from(
            b"[boxes.dev]\ntype = \"devbox\"\n\n\
              [boxes.dev.network.egress]\nallow_dns_hosts = [\"dev.example\"]\n",
            None,
        )
        .expect_err("an entry of an unresolved type refuses the start");
        let undecided = refusal
            .downcast_ref::<SessionEntryUndecided>()
            .expect("the refusal is an undecided session entry");
        assert_eq!(
            undecided.to_string(),
            "Cannot start the box: the project's minimal.toml declares the entry \"dev\" \
             with the type \"devbox\", so the start cannot tell whether it is a session entry. \
             If \"dev\" is the session to start, set type = \"session\" in it. \
             Otherwise, name the session entry to start \"default\", or add a \
             [sessions.default] entry to minimal.toml."
        );
        let refusal = project_egress_from(
            b"[defaults.network.egress]\nallow_dns_hosts = [\"a.example\"]\n\n\
              [boxes.default]\ntype = \"devbox\"\n",
            None,
        )
        .expect_err("a default entry of an unresolved type refuses the start");
        let undecided = refusal
            .downcast_ref::<SessionEntryUndecided>()
            .expect("the refusal is an undecided session entry");
        assert_eq!(
            undecided.to_string(),
            "Cannot start the box: the project's minimal.toml declares the entry \"default\" \
             with the type \"devbox\", so the start cannot tell whether it is a session entry. \
             Set type = \"session\" in the entry \"default\", or rename that entry \
             and add a [sessions.default] entry to minimal.toml."
        );

        // The fix the refusal names works: a `[sessions.default]` entry
        // beside the unresolved entry is picked, and gives the egress.
        let fixed = project_egress_from(
            b"[defaults.network.egress]\nallow_dns_hosts = [\"a.example\"]\n\n\
              [boxes.dev]\ntype = \"devbox\"\n\n\
              [sessions.default]\npackages = [\"git\"]\n",
            None,
        )
        .expect("a [sessions.default] entry is picked over an unresolved entry")
        .policy
        .expect("the defaults layer declares egress");
        assert_eq!(fixed.allow_dns_hosts, Some(vec!["a.example".to_owned()]));

        // Egress only in a project Box Type's defaults is still egress: an
        // undecided pick refuses the start rather than drop it.
        let refusal = project_egress_from(
            b"[box_types.devbox]\nextends = \"session\"\n\n\
              [box_types.devbox.defaults.network.egress]\nallow_dns_hosts = [\"t.example\"]\n\n\
              [boxes.dev]\ntype = \"devbox\"\n",
            None,
        )
        .expect_err("egress in a type's defaults refuses an undecided start");
        assert!(
            matches!(
                refusal.downcast_ref::<SessionEntryUndecided>(),
                Some(SessionEntryUndecided::TypeUnresolved { name, .. }) if name == "dev"
            ),
            "{refusal:#}"
        );

        // The entry's type is any TOML string, so the refusal escapes it: a
        // hostile file cannot write a terminal escape sequence to stderr.
        let refusal = SessionEntryUndecided::TypeUnresolved {
            name: "dev".to_owned(),
            box_type: Some("dev\u{1b}[31mbox".to_owned()),
        }
        .to_string();
        assert!(!refusal.contains('\u{1b}'), "{refusal:?}");
        assert!(
            refusal.contains("the type \"dev\\u{1b}[31mbox\""),
            "{refusal:?}"
        );

        // A file that declares no egress starts with no project egress, even
        // when its session entry cannot be picked.
        let no_egress = project_egress_from(
            b"[sessions.dev]\npackages = [\"git\"]\n\n[sessions.web]\npackages = [\"git\"]\n",
            None,
        )
        .expect("a file without egress keys does not refuse the start");
        assert_eq!(no_egress.policy, None);

        // A bad egress value is an invalid `minimal.toml`: the refusal is a
        // `ProjectFileInvalid`, which `main.rs` ends with exit 3.
        let refusal = project_egress_from(
            b"[defaults.network.egress]\nallow_protocols = [\"carrier-pigeon\"]\n",
            None,
        )
        .expect_err("an unknown protocol refuses the start");
        assert!(
            matches!(
                refusal.downcast_ref::<ProjectFileInvalid>(),
                Some(ProjectFileInvalid {
                    error: mfile::Error::Format(_)
                })
            ),
            "{refusal:?}"
        );
        let refusal = project_egress_from(
            b"[defaults.network]\nmode = \"none\"\n\n\
              [defaults.network.egress]\nallow_dns_hosts = [\"a.example\"]\n",
            None,
        )
        .expect_err("egress with mode none refuses the start");
        let refusal = refusal
            .downcast_ref::<ProjectFileInvalid>()
            .expect("the refusal is an invalid project file");
        assert!(
            matches!(
                &refusal.error,
                mfile::Error::InvalidSpecKey { key, .. } if key.starts_with("network.egress.")
            ),
            "{refusal:?}"
        );

        // No egress keys, and no project file, declare nothing.
        assert_eq!(
            project_egress_from(b"[session]\npackages = [\"git\"]\n", None).unwrap(),
            ProjectEgress::default()
        );
        assert_eq!(
            effective_egress(None, None, false),
            EffectiveEgress::default()
        );
    }

    /// NET-060, arch#166: a list flag adds to the project file's list, the
    /// file's values first and each value once, `--allow-protocols`
    /// replaces the file's list, and the fields no flag names stay as the
    /// file declares them. This is `min session activate`'s rule and the
    /// run verbs'.
    #[test]
    fn egress_flag_adds_to_the_project_list() {
        let project = project_egress_from(
            b"[defaults.network.egress]\n\
              allow_subnets = [\"10.0.0.0/8\"]\n\
              allow_dns_hosts = [\"github.com\"]\n\
              allow_protocols = [\"udp\"]\n\
              deny_subnets = [\"169.254.169.254/32\"]\n",
            None,
        )
        .unwrap()
        .policy;
        let flags = boxes::EgressPolicy {
            allow_subnets: Some(vec!["192.168.0.0/16".into(), "10.0.0.0/8".into()]),
            allow_protocols: Some(vec![boxes::IpProto::Tcp]),
            deny_subnets: Some(vec!["172.16.0.0/12".into()]),
            ..boxes::EgressPolicy::default()
        };
        let effective = effective_egress(project.clone(), Some(flags), false);
        assert_eq!(
            effective.policy,
            Some(boxes::EgressPolicy {
                allow_subnets: Some(vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()]),
                allow_dns_hosts: Some(vec!["github.com".into()]),
                allow_protocols: Some(vec![boxes::IpProto::Tcp]),
                deny_subnets: Some(vec!["169.254.169.254/32".into(), "172.16.0.0/12".into()]),
            })
        );
        assert_eq!(
            effective.sources,
            [
                ("allow_subnets", EgressSource::ProjectFile),
                ("allow_subnets", EgressSource::Flag),
                ("allow_dns_hosts", EgressSource::ProjectFile),
                ("allow_protocols", EgressSource::Flag),
                ("deny_subnets", EgressSource::ProjectFile),
                ("deny_subnets", EgressSource::Flag),
            ]
        );

        // `--deny-all-egress` alone empties the two destination lists and
        // sets no deny range, so the file's `allow_protocols` and
        // `deny_subnets` stay, under the file (arch:1234).
        let denied = effective_egress(project.clone(), None, true);
        assert_eq!(
            denied.policy,
            Some(boxes::EgressPolicy {
                allow_subnets: Some(vec![]),
                allow_dns_hosts: Some(vec![]),
                allow_protocols: Some(vec![boxes::IpProto::Udp]),
                deny_subnets: Some(vec!["169.254.169.254/32".into()]),
            })
        );
        assert_eq!(
            denied.sources,
            [
                ("allow_subnets", EgressSource::Flag),
                ("allow_dns_hosts", EgressSource::Flag),
                ("allow_protocols", EgressSource::ProjectFile),
                ("deny_subnets", EgressSource::ProjectFile),
            ]
        );
        // With no file it is the deny-all section (NET-140).
        assert_eq!(
            effective_egress(None, None, true).policy,
            Some(boxes::EgressPolicy::deny_all())
        );

        // `--deny-all-egress` only narrows: it empties the file's allow
        // lists, `--allow-protocols` replaces the protocols, and
        // `--deny-subnets` adds to the file's denies.
        let narrowed = effective_egress(
            project,
            Some(boxes::EgressPolicy {
                allow_protocols: Some(vec![boxes::IpProto::Tcp]),
                deny_subnets: Some(vec!["10.0.0.0/8".into()]),
                ..boxes::EgressPolicy::default()
            }),
            true,
        );
        assert_eq!(
            narrowed.policy,
            Some(boxes::EgressPolicy {
                allow_subnets: Some(vec![]),
                allow_dns_hosts: Some(vec![]),
                allow_protocols: Some(vec![boxes::IpProto::Tcp]),
                deny_subnets: Some(vec!["169.254.169.254/32".into(), "10.0.0.0/8".into()]),
            })
        );
    }
}

#[cfg(test)]
mod activation_step_tests {
    use super::ActivationStep;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt as _;

    /// What the capture layer saw: each `activation_step` span's step, in
    /// creation order, each failure record's step and error, and the step
    /// of each span that recorded an ERROR status.
    #[derive(Default)]
    struct Seen {
        spans: Vec<String>,
        failures: Vec<(String, String)>,
        errored: Vec<String>,
        /// The step of each open `activation_step` span, by span id.
        by_id: std::collections::HashMap<u64, String>,
    }

    #[derive(Default)]
    struct Fields {
        step: Option<String>,
        error: Option<String>,
        message: Option<String>,
        status: Option<String>,
    }

    impl tracing::field::Visit for Fields {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            match field.name() {
                "step" => self.step = Some(value.to_owned()),
                "error" => self.error = Some(value.to_owned()),
                "message" => self.message = Some(value.to_owned()),
                "otel.status_code" => self.status = Some(value.to_owned()),
                _ => {}
            }
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.record_str(field, &format!("{value:?}"));
        }
    }

    struct Capture(Arc<Mutex<Seen>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if attrs.metadata().name() == "activation_step" {
                let mut fields = Fields::default();
                attrs.record(&mut fields);
                let step = fields.step.unwrap_or_default();
                let mut seen = self.0.lock().unwrap();
                seen.by_id.insert(id.into_u64(), step.clone());
                seen.spans.push(step);
            }
        }

        fn on_record(
            &self,
            id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut fields = Fields::default();
            values.record(&mut fields);
            let mut seen = self.0.lock().unwrap();
            if fields.status.as_deref() == Some("ERROR")
                && let Some(step) = seen.by_id.get(&id.into_u64()).cloned()
            {
                seen.errored.push(step);
            }
        }

        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            if fields.message.as_deref() == Some("activation step failed") {
                self.0.lock().unwrap().failures.push((
                    fields.step.unwrap_or_default(),
                    fields.error.unwrap_or_default(),
                ));
            }
        }
    }

    /// The step names [`super::activate_box`] runs, in source order.
    fn steps_in_activate_box() -> Vec<String> {
        let text = include_str!("create.rs");
        let start = text
            .find("pub(crate) async fn activate_box(")
            .expect("create.rs defines activate_box");
        let body = &text[start..];
        let end = body
            .find("\nfn normalize_subnets(")
            .expect("normalize_subnets follows activate_box");
        // Comment lines name steps too; only code runs them.
        let body: String = body[..end]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let body = body.as_str();
        let needle = concat!("ActivationStep", "::");
        body.match_indices(needle)
            .filter_map(|(at, _)| {
                let rest = &body[at + needle.len()..];
                let variant: String = rest
                    .chars()
                    .take_while(char::is_ascii_alphanumeric)
                    .collect();
                rest[variant.len()..]
                    .trim_start()
                    .starts_with(".run(")
                    .then_some(variant)
            })
            .collect()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn activation_steps_run_in_order_and_name_the_failing_step() {
        // The activation runs every step once, in the declared order.
        let declared: Vec<String> = ActivationStep::ORDER
            .iter()
            .map(|step| format!("{step:?}"))
            .collect();
        assert_eq!(steps_in_activate_box(), declared);

        // Each step opens its own span, and the failing step names itself
        // while its error passes through unchanged.
        let seen = Arc::new(Mutex::new(Seen::default()));
        let subscriber = tracing_subscriber::registry().with(Capture(seen.clone()));
        let _guard = tracing::subscriber::set_default(subscriber);

        let failing = ActivationStep::UploadFiles;
        let mut ran = Vec::new();
        let mut outcome = Ok(());
        for step in ActivationStep::ORDER {
            outcome = step
                .run(async {
                    ran.push(step);
                    if step == failing {
                        anyhow::bail!("Failed to upload project files");
                    }
                    Ok(())
                })
                .await;
            if outcome.is_err() {
                break;
            }
        }

        let error = outcome.expect_err("the failing step ends the run");
        assert_eq!(error.to_string(), "Failed to upload project files");
        let through = ActivationStep::ORDER
            .iter()
            .position(|step| *step == failing)
            .expect("the failing step is in the order");
        assert_eq!(ran, ActivationStep::ORDER[..=through]);

        let seen = seen.lock().unwrap();
        let names: Vec<&str> = ActivationStep::ORDER[..=through]
            .iter()
            .map(|step| step.name())
            .collect();
        assert_eq!(seen.spans, names);
        assert_eq!(
            seen.failures,
            [(
                "upload_files".to_owned(),
                "Failed to upload project files".to_owned()
            )]
        );
        // Only the failing step's span carries the ERROR status.
        assert_eq!(seen.errored, ["upload_files"]);
    }

    #[derive(clap::Parser)]
    struct ActivateCli {
        #[command(flatten)]
        args: crate::cli::ActivateArgs,
    }

    #[tokio::test(flavor = "current_thread")]
    async fn activation_steps_run_in_order_and_name_the_failing_step_in_activate_box() {
        use clap::Parser as _;
        // A project path that does not exist ends the real activation in its
        // first step, before any daemon is started or contacted.
        let missing = tempfile::tempdir().unwrap().path().join("no-such-project");
        let cli = ActivateCli::try_parse_from(["activate", missing.to_str().unwrap()]).unwrap();

        let seen = Arc::new(Mutex::new(Seen::default()));
        let subscriber = tracing_subscriber::registry().with(Capture(seen.clone()));
        let _guard = tracing::subscriber::set_default(subscriber);

        let error = super::activate_box(&crate::cli::GlobalArgs::default(), cli.args, false)
            .await
            .expect_err("a missing project path ends the activation");
        let expected = format!("Cannot resolve project path '{}'", missing.display());
        assert_eq!(error.to_string(), expected);

        let seen = seen.lock().unwrap();
        assert_eq!(seen.spans, ["check_arguments"]);
        assert_eq!(seen.failures.len(), 1);
        assert_eq!(seen.failures[0].0, "check_arguments");
        assert!(
            seen.failures[0].1.starts_with(&expected),
            "failure record: {:?}",
            seen.failures[0].1
        );
        assert_eq!(seen.errored, ["check_arguments"]);
    }
}

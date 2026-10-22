//! `min session create`: activating a new session, from the project file
//! checks to the start line.

use super::*;
use minimal_client::box_registration::{finalize_holding_lease, register_box_reminting_autogen};

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
pub(super) fn refuse_dynamic_ingress_off_own_ip(
    network: crate::cli::CliNetworkMode,
    mode: Option<boxes::DynamicIngress>,
    range: Option<(u16, u16)>,
) -> Result<(), anyhow::Error> {
    if network != crate::cli::CliNetworkMode::OwnIp && (mode.is_some() || range.is_some()) {
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
        write!(
            f,
            "Cannot start the box: the project's {name} does not load: {error}",
            name = mfile::MFILE_NAME,
            error = self.error,
        )
    }
}

impl std::error::Error for ProjectFileInvalid {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// A GitHub grant the box cannot receive in its environment (BEP-007). The
/// creation is refused with exit 3, before the box exists.
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
}

impl std::fmt::Display for GrantNotDelivered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName { grant } => write!(
                f,
                "Cannot create the box: the secret {grant:?} in [session.secrets] in \
                 {name} is not a valid environment variable name. A name uses only \
                 capital letters, digits and underscores, and does not start with a \
                 digit. Rename the secret, then create the box again.",
                name = mfile::MFILE_NAME,
            ),
            Self::NotSealed { grant } => write!(
                f,
                "Cannot create the box: no sealed value was made for its GitHub grant \
                 {grant}, so {grant} would be empty in the box. No box was created."
            ),
        }
    }
}

impl std::error::Error for GrantNotDelivered {}

/// The project's `[session.network.bep]` settings and `[session.secrets]`
/// grants. Only a missing project file reads as empty. A file that exists
/// but does not load refuses the activation, so a broken file can never
/// skip the grant checks (BEP-008).
fn project_bep_and_grants(
    project: &camino::Utf8Path,
) -> Result<
    (
        boxes::core::bep::BepSettings,
        boxes::core::bep::SecretGrants,
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
        (
            session.network.and_then(|n| n.bep).unwrap_or_default(),
            session.secrets,
        )
    }))
}

/// The box's credentialed-upstream declaration: the `--credentialed-upstream`
/// flag, or a `[session.secrets]` grant whose source is the broker (NET-134,
/// BEP-016). The set is derived from broker grants. A `[session.network.bep]`
/// setting or a `client_env` grant alone declares nothing. The settings
/// ride the declaration.
fn credentialed_upstream_for(
    flag: bool,
    bep: &boxes::core::bep::BepSettings,
    secrets: &boxes::core::bep::SecretGrants,
) -> Option<boxes::CredentialedUpstream> {
    let declared = flag
        || secrets
            .values()
            .any(|grant| grant.source == boxes::core::bep::GrantSource::Broker);
    declared.then(|| boxes::CredentialedUpstream {
        bep: bep.clone(),
        secrets: secrets.clone(),
    })
}

/// Refuses a box spec whose grants the box or this host cannot honour, and
/// prints the warnings of one it accepts. It checks the project's settings
/// whether or not they declare a credentialed upstream, so a contradiction
/// in `[session.network.bep]` alone is still refused. The refusal ends the
/// run with exit 3 (`main.rs`). Every host today is un-enrolled and has no
/// box-zone resolver.
fn refuse_unhonourable_grants(
    network: boxes::NetworkMode,
    egress: Option<&boxes::EgressPolicy>,
    settings: &boxes::core::bep::BepSettings,
    secrets: &boxes::core::bep::SecretGrants,
    full_breadth_acknowledged: bool,
) -> Result<(), anyhow::Error> {
    use boxes::core::bep::{ActivationSpec, HostFacts, check_activation};
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
    };
    // BEP-057: the client configuration's acknowledgement, the same one
    // `min box spec` reads, so the preview and the start agree.
    let host = HostFacts {
        full_breadth_acknowledged,
        ..HostFacts::LOCAL
    };
    let plan = check_activation(&spec, host, &hosts)?;
    for warning in &plan.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(())
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

/// Checks a box spec's GitHub grants at creation, and gives their names.
///
/// Where no node-local proxy serves boxes, a GitHub grant is refused with
/// `gatehouse_unenrolled_node` (Gatehouse §6.2). Only on a host that has
/// one is a grant with no held sign-in refused with
/// `github_sign_in_required` (BEP-003). Only the sign-in item's metadata
/// is read, and nothing asks for a sign-in.
pub(crate) fn check_github_grants(
    secrets: &boxes::core::bep::SecretGrants,
    proxy_present: bool,
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
    boxes::core::bep::require_proxy(secrets, proxy_present)?;
    let signed_in = sign_in_held(keychain)?;
    boxes::core::bep::require_sign_in(secrets, signed_in)?;
    Ok(grants)
}

/// The facts a GitHub grant box is registered with the proxy under: its
/// box id and its address stance. A native host and a daemon that predates
/// box ids give no id, and no proxy serves those boxes. A grant there is
/// refused with `gatehouse_unenrolled_node`, and never resolves to nothing.
pub(crate) fn grant_box_facts(
    grants: &[String],
    box_id: Option<String>,
    network: boxes::NetworkMode,
) -> Result<Option<(String, bep::boxes::Stance)>, boxes::core::bep::ActivationRefused> {
    if grants.is_empty() {
        return Ok(None);
    }
    match (box_id, proxy_stance(network)) {
        (Some(box_id), Some(stance)) => Ok(Some((box_id, stance))),
        _ => Err(boxes::core::bep::unenrolled_node(grants.to_vec())),
    }
}

/// Mints each GitHub grant's sign-in reference for the box `box_id`, and
/// registers the box's declared egress and stance with the Box Egress
/// Proxy (BEP-005). Does nothing for a box with no GitHub grant, and
/// refuses a grant box with no id or no stance. It blocks on the control
/// socket, so the activation runs it on a blocking thread. The
/// registration it gives forgets the box at the proxy when it is dropped
/// before the creation finishes.
fn mint_grants(
    grants: Vec<String>,
    box_id: Option<String>,
    egress: Vec<String>,
    network: boxes::NetworkMode,
) -> Result<
    (
        Vec<crate::mint::Minted>,
        Option<crate::mint::ProxyRegistration>,
    ),
    anyhow::Error,
> {
    use crate::mint::{
        ClientKey, ControlClient, GrantBox, MintError, ProxyRegistration, mint_and_register,
    };
    let Some((box_id, stance)) = grant_box_facts(&grants, box_id, network)? else {
        return Ok((Vec::new(), None));
    };
    let (Some(identity_path), Some(control_path)) =
        (crate::mint::identity_path(), crate::mint::control_path())
    else {
        bail!(
            "Cannot start the box: it declares a GitHub grant, and no home directory was found, \
             which holds the Box Egress Proxy's keys."
        );
    };
    let identity =
        bep::publish::Identity::read(&identity_path).map_err(|error| MintError::Identity {
            path: identity_path.clone(),
            error,
        })?;
    let mut control = ControlClient::connect(&control_path)?;
    let key = ClientKey::generate()?;
    let grant_box = GrantBox {
        box_id,
        grants,
        egress,
        stance,
    };
    // A clock before the epoch gives no issue time, so the mint stops
    // rather than signing handles issued at zero.
    let Ok(since) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        bail!(
            "Cannot start the box: it declares a GitHub grant, and the system clock reads a \
             time before 1970. Set the system clock, then create the box again."
        );
    };
    let minted = mint_and_register(
        &bep::signin::HostKeychain,
        &identity,
        &identity_path,
        &mut control,
        &key,
        &grant_box,
        since.as_secs(),
    )?;
    let registration = ProxyRegistration::new(control_path, &grant_box.box_id)?;
    Ok((minted, Some(registration)))
}

/// Mints the box's GitHub grants for the box id `request` carries, and puts
/// each grant's sealed value on the request for the box's launches to place
/// (BEP-005, BEP-007). Does nothing for a box with no GitHub grant. No box
/// exists yet, so a failure only withdraws the row the box's registration
/// bought (T66).
async fn mint_into_request(
    request: &mut minimald_rpc::CreateSessionRequest,
    github_grants: &[String],
    control_sock: Option<std::path::PathBuf>,
) -> Result<Option<crate::mint::ProxyRegistration>, anyhow::Error> {
    let grants = github_grants.to_vec();
    let box_id = request.config.box_id.map(|box_id| box_id.to_string());
    let egress = request
        .config
        .policy
        .egress
        .as_ref()
        .and_then(|egress| egress.allow_dns_hosts.clone())
        .unwrap_or_default();
    let network = request.config.network;
    // The mint blocks on the proxy's control socket and the host keychain,
    // so it runs off the runtime's workers.
    let minted = tokio::task::spawn_blocking(move || mint_grants(grants, box_id, egress, network))
        .await
        .map_err(anyhow::Error::from)
        .and_then(|minted| minted)
        .and_then(|(minted, registration)| {
            Ok((sealed_deliveries(github_grants, &minted)?, registration))
        });
    match minted {
        Ok((deliveries, registration)) => {
            request.config.sealed_deliveries = deliveries;
            Ok(registration)
        }
        Err(error) => {
            withdraw_box_row(
                control_sock,
                request.config.name.as_deref(),
                request.config.box_addresses,
                request.config.box_id,
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
        let span = tracing::info_span!("activation_step", step = self.name());
        let result = work.instrument(span.clone()).await;
        if let Err(error) = &result {
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

pub(crate) async fn activate_box(
    global: &GlobalArgs,
    args: ActivateArgs,
    offer_scaffold: bool,
) -> Result<(), anyhow::Error> {
    let (utf8_path, abs_path, port_mappings, egress) = ActivationStep::CheckArguments
        .run(async {
            // Before anything is created, and before the daemon is spawned (a cold
            // VM boot), since both are argument errors: a dynamic declaration needs
            // an own-IP box. Every stance stands on a VM-backed host: an `ask` there is
            // answered by the human attached on the host (NET-045).
            refuse_dynamic_ingress_off_own_ip(
                args.network,
                args.dynamic_ingress,
                args.dynamic_range,
            )?;
            // A static mapping needs an own-IP box too: only it has a published
            // address a static forwarder could apply to.
            refuse_ingress_off_own_ip(args.network, !args.ingress.is_empty())?;

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

            let mut port_mappings = Vec::with_capacity(args.ingress.len());
            for spec in &args.ingress {
                let mapping = parse_ingress_mapping(spec)?;
                port_mappings.push(mapping);
            }
            let mut allow_protocols = Vec::with_capacity(args.allow_protocols.len());
            for spec in &args.allow_protocols {
                allow_protocols.push(parse_egress_proto(spec)?);
            }
            // Any egress flag makes the declaration; a field with no values stays
            // `None` — its allow-all/none-denied default — so `--deny-subnets` alone
            // records an allow-all policy that denies one range. `--deny-all-egress`
            // is the whole declaration on its own: it maps to
            // `boxes::EgressPolicy::deny_all()`, every allow list present and
            // empty, rather than to four absent lists — a deny-all box declared by
            // flag must read in the record exactly like one declared by file, which
            // is the shape the host-address classifier decides its verdict on
            // (NET-079) and the one `min session policy` names `deny-all`. The parse
            // conflict (`cli.rs`) keeps it from combining with a rule flag, so the
            // arms cannot both run.
            let egress = if args.deny_all_egress {
                Some(boxes::EgressPolicy::deny_all())
            } else {
                let has_egress = !args.allow_subnets.is_empty()
                    || !allow_protocols.is_empty()
                    || !args.allow_dns_hosts.is_empty()
                    || !args.deny_subnets.is_empty();
                has_egress.then_some(boxes::EgressPolicy {
                    allow_subnets: (!args.allow_subnets.is_empty())
                        .then(|| normalize_subnets(&args.allow_subnets)),
                    allow_dns_hosts: (!args.allow_dns_hosts.is_empty())
                        .then(|| args.allow_dns_hosts.clone()),
                    allow_protocols: (!allow_protocols.is_empty()).then_some(allow_protocols),
                    deny_subnets: (!args.deny_subnets.is_empty())
                        .then(|| normalize_subnets(&args.deny_subnets)),
                })
            };
            Ok::<_, anyhow::Error>((utf8_path, abs_path, port_mappings, egress))
        })
        .await?;
    // NET-043: any dynamic declaration makes the ingress policy too — a
    // stance alone (with no range, no static mapping) still names how
    // dynamic requests are decided, and a range without a stance cannot
    // reach the create (the flag requires its mode). Nothing set keeps
    // `None`: the deny-all default, which the policy module evaluates the
    // same as an explicit deny.
    let (policy, github_grants) = ActivationStep::CheckProject
        .run(async {
            let has_ingress = !port_mappings.is_empty()
                || args.dynamic_ingress.is_some()
                || args.dynamic_range.is_some();
            let (project_bep, project_secrets) = project_bep_and_grants(&utf8_path)?;
            let policy = boxes::BoxPolicy {
                egress,
                ingress: has_ingress.then_some(boxes::IngressPolicy {
                    port_mappings,
                    dynamic_allowed_range: args.dynamic_range,
                    dynamic_ingress: args.dynamic_ingress,
                }),
                // NET-134: the lane is the box's own declaration, never a default —
                // a box that did not ask for a credentialed upstream keeps every
                // frame it sends to the proxy's address refused at the host-side
                // gate, whatever its egress rules say.
                credentialed_upstream: credentialed_upstream_for(
                    args.credentialed_upstream,
                    &project_bep,
                    &project_secrets,
                ),
            };

            // BEP-008/009/010/017/056: a box spec with a grant it cannot honour is
            // refused here, before the daemon starts and before anything is created.
            // BEP-057: the client configuration is read only when a grant needs the
            // acknowledgement, so a box with no narrow grant never depends on it.
            let full_breadth_acknowledged = project_secrets
                .values()
                .any(boxes::core::bep::SecretGrant::is_narrower_than_full)
                && crate::config::full_breadth_acknowledged(global)?;
            refuse_unhonourable_grants(
                args.network.into(),
                policy.egress.as_ref(),
                &project_bep,
                &project_secrets,
                full_breadth_acknowledged,
            )?;
            // Gatehouse §6.2, BEP-003: a GitHub grant needs a node-local
            // proxy, and then a held sign-in. Only the item's metadata is
            // read, and nothing asks for a sign-in.
            let identity = crate::mint::identity_path();
            let control = crate::mint::control_path();
            let github_grants = check_github_grants(
                &project_secrets,
                proxy_present(identity.as_deref(), control.as_deref()),
                &bep::signin::HostKeychain,
            )?;
            Ok::<_, anyhow::Error>((policy, github_grants))
        })
        .await?;
    ActivationStep::StartDaemon
        .run(async { ensure_daemon(global) })
        .await?;

    // A session with no `--name` still deserves a typable handle, so mint
    // `<dir-basename>-<4 hex>` client-side; without it `min ls`, the attach
    // picker, and the create announcement fall back to a bare short id. A
    // user-supplied name is passed through untouched — including a collision,
    // which must surface as an error rather than be silently suffixed.
    let autogen = args.name.is_none();
    let session_name = args
        .name
        .clone()
        .unwrap_or_else(|| autogen_session_name(&utf8_path, &random_hex4()));

    let network: boxes::NetworkMode = args.network.into();

    // The daemon sources `username` from the authenticated SSH
    // connection context; the client doesn't send it. `box_addresses`
    // lands just before the create (T66): the registration is the last
    // fallible client-side step, so a loadout, policy, or hook failure
    // between here and there never strands a row on the host.
    let mut request =
        minimald_rpc::CreateSessionRequest::new(session_name, abs_path.clone(), network, policy);
    request.config.hooks_enabled = !args.no_hooks;
    // The version gate: a daemon of another build refuses the create
    // outright, before it allocates anything to tear down. `None` under the
    // skew override, which is what lets an operator proceed.
    request.must_match_version = version_assertion();

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
            // daemon.
            let cfg = config::read_client_config(global)?;
            let policy_path = config::user_policy_path(global);
            let user_policy = config::read_user_policy(global)?;
            let initial_policy = user_policy.clone();
            let compose_options = loadouts::compose_options_from_config(&cfg);
            let selection = loadouts::LoadoutSelection::from_flags(&args.loadout, args.no_loadouts);
            let active = loadouts::resolve_active_loadouts(selection, &cfg, global)?;

            // Scaffold-offer a missing `minimal.toml` only after loadouts resolve:
            // a bad `--loadout` must error before anything prints, so the user is
            // never told the session is proceeding and then that it is not.
            // `--sync none` never sends a `minimal.toml`, so offering to create
            // one there would only write a file the session then ignores.
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

            if !active.loadouts.is_empty() {
                let names: Vec<&str> = active.loadouts.iter().map(|l| l.name().as_ref()).collect();
                eprintln!("Applying loadouts: {}", names.join(", "));
            }
            // The contribution carries the banner's loadout display list as a
            // first-class orientation field (the daemon seeds MINIMAL_LOADOUTS
            // from it in the launcher baseline). The banner's other dynamic
            // clause — blueprint presence — is a session-filesystem fact,
            // tested by the templates in-shell when they print.
            // Resolve the loadouts' external hook scripts before anything
            // touches the daemon: a mistyped path, a symlinked script, or a
            // missing loadout script directory should fail here, on this
            // machine, rather than after a session exists on the daemon.
            let hook_scripts =
                loadouts::stage_loadout_hook_scripts(&active, &abs_path, !args.no_hooks)?;

            // Same idea for the *project's* hooks, which the daemon composes from
            // the uploaded mfile and which therefore never pass through the
            // staging above. Nothing here is uploaded — the project tree carries
            // its own scripts — but the checks a staging pass would have made are
            // still worth making on this machine, before a session exists.
            if !args.no_hooks {
                loadouts::check_project_hooks(&abs_path)?;
            }

            // The daemon runs the composition's `on_activate` hooks inside
            // `FinalizeSession`; size that call's deadline to their summed declared
            // timeouts, computed here while the loadouts are still in hand.
            let finalize_hook_budget =
                loadouts::activate_hook_budget(&active, &utf8_path, !args.no_hooks);

            let (contribution, user_policy) = loadouts::compose_user_contribution(
                active,
                user_policy,
                compose_options,
                !args.no_hooks,
            )?;
            Ok::<_, anyhow::Error>((
                policy_path,
                initial_policy,
                compose_options,
                hook_scripts,
                finalize_hook_budget,
                contribution,
                user_policy,
            ))
        })
        .await?;

    // `--sync` defaults to tarball; `sync_explicit` records whether the
    // user actually typed the flag, which distinguishes a deliberate
    // `--sync tarball` (the escape hatch that force-uploads an empty dir
    // or `$HOME`) from the implicit default.
    let sync_explicit = args.sync.is_some();
    let sync_mode = args.sync.unwrap_or(SyncMode::Tarball);

    // Resolve the upload root before opening the daemon connection:
    // a malformed mfile in an ancestor should fail loudly before
    // we create a session on the daemon, so we don't leak a draft
    // session. Only needed for tarball sync — `--sync none` skips
    // the upload entirely (#770).
    let (upload_root, skip_empty_or_home) = ActivationStep::PlanUpload
        .run(async {
            let upload_root = match sync_mode {
                SyncMode::None => None,
                SyncMode::Tarball => Some(resolve_upload_root(&utf8_path)?),
            };

            // Skip the upload without prompting when the resolved root is an
            // empty directory or `$HOME` — unless the user asked for it with an
            // explicit `--sync tarball`, the escape hatch.
            let skip_empty_or_home = !sync_explicit
                && upload_root.as_ref().is_some_and(|root| {
                    file_upload::is_empty_or_home(
                        root.as_std_path(),
                        std::env::home_dir().as_deref(),
                    )
                });
            Ok::<_, anyhow::Error>((upload_root, skip_empty_or_home))
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
    // A registration that cannot be made ends the activation here, with its
    // cause: no session exists yet to clean up, and a box that went on to
    // create unregistered would run with no host-side row to decide its
    // egress by, so this is the one failure that never falls back. Past
    // here, the row exists and every later failure owes it its creator's
    // withdrawal (T66): the sites below send it. The control socket is
    // resolved once, here, and the withdrawals ride on it.
    let kind = daemon_provider_kind(global);
    let control_sock = vm_host_control_sock(kind, global.minimal_dir.as_deref());
    // An autogen name can collide with a live box's row the same way it
    // can with a session (the row stays live until its session's destroy):
    // the registration's refusal re-mints it within the same budget the
    // create's collision retry below spends.
    let mut attempts = 0u32;
    let mut registered = ActivationStep::RegisterBox
        .run(async {
            let registered = register_box_reminting_autogen(
                kind,
                global.minimal_dir.as_deref(),
                request.config.network,
                request
                    .config
                    .name
                    .as_mut()
                    .expect("the session name is minted before the create"),
                &request.config.policy,
                autogen,
                &mut attempts,
                || autogen_session_name(&utf8_path, &random_hex4()),
            )
            .await?;
            // The registration is the client's record of the box: the addresses
            // the create carries, and the id the host minted for it (NET-133).
            request.config.box_addresses = registered
                .as_ref()
                .map(|registration| registration.addresses);
            request.config.task_addresses = registered
                .as_ref()
                .map(|registration| registration.task_addresses.clone())
                .unwrap_or_default();
            request.config.box_id = registered
                .as_ref()
                .and_then(|registration| registration.box_id);
            Ok::<_, anyhow::Error>(registered)
        })
        .await?;
    // Gatehouse §6.2: a GitHub grant box with no box id or no stance has no
    // proxy to serve its grant. It is refused before the create, and the
    // row the registration bought is withdrawn (T66).
    if let Err(refused) = grant_box_facts(
        &github_grants,
        request.config.box_id.map(|box_id| box_id.to_string()),
        request.config.network,
    ) {
        withdraw_box_row(
            control_sock.clone(),
            request.config.name.as_deref(),
            request.config.box_addresses,
            request.config.box_id,
        )
        .await;
        return Err(refused.into());
    }

    // BEP-005/007: each GitHub grant's sign-in reference is minted for the
    // id the registration handed, before the create, so the create request
    // carries each sealed value for every launch of the box to place in its
    // grant's environment variable. A failure withdraws the row the
    // registration bought (T66). An autogen collision below re-registers
    // under a new id, and mints again for it.
    // The proxy's hold on the box: dropped by a later step's failure, it
    // forgets the box's declared egress there. It is kept once the session
    // is active. A Ctrl-C exits the process with no drop, so it leaves the
    // box at the proxy until the box's destroy forgets it (#2277).
    let mut proxy_registration = ActivationStep::MintGrants
        .run(mint_into_request(
            &mut request,
            &github_grants,
            control_sock.clone(),
        ))
        .await?;

    use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, CreateSession};
    // An autogen name can (rarely) collide with an existing session built
    // from the same directory; on the daemon's already-exists rejection,
    // re-mint the hex suffix and retry a bounded number of times. A
    // user-supplied name never retries — its collision, and any other failure
    // (e.g. a policy/network-mode validation error), surfaces unchanged.
    // `attempts` carries over from the registration's own collision retry.
    let created = ActivationStep::CreateSession
        .run(async {
            let created = loop {
                let resp = client.oneshot_rpc::<CreateSession>(request.clone()).await;
                let resp = match resp {
                    Ok(resp) => resp,
                    // A transport failure abandons the activation and the row its
                    // registration bought: the create never happened, so no session
                    // holds the pair (T66).
                    Err(error) => {
                        withdraw_box_row(
                            control_sock.clone(),
                            request.config.name.as_deref(),
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
                    minimald_rpc::Errorable::Ok(r) => break r,
                    minimald_rpc::Errorable::Err { error } => {
                        if should_retry_autogen(autogen, attempts, &error) {
                            attempts += 1;
                            // The row the first attempt bought is this attempt's to
                            // leave behind: its creator withdraws it before
                            // re-registering under the re-minted name (T66) — it was
                            // bought for a session this create never made.
                            withdraw_box_row(
                                control_sock.clone(),
                                request.config.name.as_deref(),
                                request.config.box_addresses,
                                registered
                                    .as_ref()
                                    .and_then(|registration| registration.box_id),
                            )
                            .await;
                            // The abandoned row's lease goes with it, uncommitted.
                            drop(registered.take());
                            request.config.name =
                                Some(autogen_session_name(&utf8_path, &random_hex4()));
                            // A registered box's row carries the name it was
                            // registered under (T66), so the re-mint re-registers;
                            // the abandoned row is withdrawn above, by its id, which
                            // returns its addresses to the host's hand-out books,
                            // and the retry leaves no row behind. The re-registration can itself fail —
                            // the plan can be exhausted by then — and that failure
                            // ends the retry loop the same way the first one would
                            // have, with its cause. The first registration's id is
                            // discarded with its row: ids are never freed or
                            // reused, so the re-registration is a new creation, and
                            // the host mints it a new id, which replaces the record
                            // (NET-133).
                            registered = register_box_reminting_autogen(
                                kind,
                                global.minimal_dir.as_deref(),
                                request.config.network,
                                request.config.name.as_mut().expect("just re-minted"),
                                &request.config.policy,
                                autogen,
                                &mut attempts,
                                || autogen_session_name(&utf8_path, &random_hex4()),
                            )
                            .await?;
                            request.config.box_addresses = registered
                                .as_ref()
                                .map(|registration| registration.addresses);
                            request.config.task_addresses = registered
                                .as_ref()
                                .map(|registration| registration.task_addresses.clone())
                                .unwrap_or_default();
                            request.config.box_id = registered
                                .as_ref()
                                .and_then(|registration| registration.box_id);
                            // The sealed values name the abandoned id, so the
                            // new one gets its own (BEP-007). The replaced
                            // registration forgets the old id at the proxy.
                            proxy_registration = mint_into_request(
                                &mut request,
                                &github_grants,
                                control_sock.clone(),
                            )
                            .await?;
                            continue;
                        }
                        // A create failure that is not a retryable autogen collision
                        // abandons the activation and its row the same way.
                        withdraw_box_row(
                            control_sock.clone(),
                            request.config.name.as_deref(),
                            request.config.box_addresses,
                            registered
                                .as_ref()
                                .and_then(|registration| registration.box_id),
                        )
                        .await;
                        bail!("{error}");
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
                    request.config.name.as_deref(),
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
            // name. Keyed on the provider kind the registration itself keyed on, never
            // on `use_minvmd()`, so the flagless VM-backed host prints it too.
            if let Some(addresses) = request.config.box_addresses.as_ref() {
                eprintln!(
                    "{}",
                    box_registered_start_line(
                        hostname_proxy_vm(kind),
                        request.config.name.as_deref().unwrap_or("-"),
                        addresses,
                    )
                );
            }
            warn_if_hostname_routing_down(
                created.hostname_routing_unavailable.as_deref(),
                "min session activate",
            );
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
            let serving_proxy_port = crate::resolver::serving_proxy_port(
                created.hostname_proxy_port,
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
                let box_name = request.config.name.as_deref().unwrap_or("-");
                eprintln!(
                    "{}",
                    crate::resolver::host_line_beside(
                        box_name,
                        &surface,
                        serving_proxy_port,
                        host_install,
                        proxy_cause.as_deref(),
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
            for entry in &args.allow_subnets {
                if let Some(normalized) = boxes::normalized_cidr(entry) {
                    eprintln!("--allow-subnets {entry} is read as {normalized}");
                }
            }
            for entry in &args.deny_subnets {
                if let Some(normalized) = boxes::normalized_cidr(entry) {
                    eprintln!("--deny-subnets {entry} is read as {normalized}");
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?;

    // From here the session exists on the daemon in an unfinalized state.
    // Arm a Ctrl-C guard so an interrupt during the (blocking) gating
    // prompt tears it down instead of orphaning it in `Pending` — see
    // [`ActivationInterrupt`]. Disarmed once the session is `Active`.
    let interrupt_guard = arm_activation_interrupt(global, id);

    // Upload the project directory to the daemon so the session
    // workspace holds the user's files — `ConfigureLoadout`'s compose
    // reads the mfile (and any local `packages/`, `stacks/`,
    // `profiles/` used by graph resolution) off that workspace, so it
    // has to run before `ConfigureLoadout`. `--sync none` opts out;
    // the daemon then composes against an empty workspace and the
    // caller is on their own for getting files there.
    ActivationStep::UploadFiles.run(async {
    match sync_mode {
        SyncMode::None => {
            // `--sync none` skips the upload, so the daemon composes against
            // an empty workspace and the project's `minimal.toml` — packages,
            // vars, patches, hooks — is silently dropped. Say so when there
            // is a config to lose, so the default-config session is not a
            // surprise.
            if let Some(notice) = sync_none_notice(&utf8_path) {
                eprintln!("{notice}");
            }
        }
        SyncMode::Tarball if skip_empty_or_home => {
            // An empty directory has nothing to sync, and `$HOME` is far
            // too much to ship on a stray confirmation keypress — and if
            // `$HOME` is itself a VCS root the old gate uploaded it with
            // no prompt at all. Skip both silently by default; a
            // deliberate `--sync tarball` (via `sync_explicit`) is the
            // escape hatch that still uploads them.
            eprintln!("Starting with an empty box (nothing here to sync)");
        }
        SyncMode::Tarball => {
            // Upload from the project root — the directory the mfile
            // lives in — rather than wherever the user invoked us. This
            // matches the CLI's config-discovery walk: a user running
            // `minimal activate ./subdir` still uploads the whole
            // project. Falls back to `utf8_path` when no mfile is found
            // anywhere up the tree (#770).
            let upload_root = upload_root.expect("upload_root is set for SyncMode::Tarball above");
            if upload_root != utf8_path {
                eprintln!("Uploading from project root {upload_root} (resolved from {utf8_path})");
            }
            // Guard against accidentally uploading a non-VCS directory
            // (e.g. `~`). A VCS root, or a directory carrying a
            // `minimal.toml` (a declared project), uploads unconditionally.
            // For an undeclared non-VCS root an interactive caller gets the
            // confirm (default No); a headless caller (CI, pipes, agents,
            // `--no-prompt`, `--no-input`) can't be asked, so it skips the
            // upload with a warning rather than silently shipping a directory
            // nobody confirmed — `--sync tarball` (via `sync_explicit`) is the
            // escape hatch that force-uploads it anyway (#770).
            let headless = args.no_prompt || global.no_input || !can_prompt_interactively();
            let should_upload = match file_upload::upload_gate(
                file_upload::is_vcs_root(upload_root.as_std_path()),
                sync_explicit,
                project_has_mfile(&upload_root),
                headless,
            ) {
                file_upload::UploadGate::Upload => true,
                file_upload::UploadGate::SkipHeadless => {
                    // Skipping the upload means the project's minimal.toml
                    // never reaches the daemon, so any lifecycle hooks it
                    // declares are discarded and never run. Refuse loudly
                    // instead of exiting 0 on a session silently missing
                    // them; the caller can force the upload or opt out on
                    // purpose.
                    let dropped_hooks = project_lifecycle_hook_count(&upload_root);
                    if dropped_hooks > 0 {
                        bail!(
                            "{upload_root} is not a version control repository root, so its \
                             file upload is being skipped — but its {name} declares \
                             {dropped_hooks} lifecycle hook(s) that reach the session only \
                             through that upload. They would be silently dropped and never \
                             run. Pass `--sync tarball` to upload the project (hooks \
                             included), or `--sync none` to start without them deliberately.",
                            name = mfile::MFILE_NAME,
                        );
                    }
                    eprintln!(
                        "{}",
                        file_upload::skipped_upload_warning(upload_root.as_std_path())
                    );
                    false
                }
                file_upload::UploadGate::Prompt => confirm(
                    &format!(
                        "{upload_root} is not a version control repository root. \
                         Upload all files from this directory?"
                    ),
                    false,
                )?,
            };
            if should_upload {
                let uploaded = client
                    .upload_workspace_files(id, upload_root.as_std_path())
                    .await;
                if let Err(error) = uploaded {
                    // The upload failed: the activation is abandoned, and the
                    // row its registration bought goes with it (T66).
                    withdraw_box_row(
                        control_sock.clone(),
                        request.config.name.as_deref(),
                        request.config.box_addresses,
                        registered
                            .as_ref()
                            .and_then(|registration| registration.box_id),
                    )
                    .await;
                    return Err(error.context("Failed to upload project files"));
                }
            } else if !headless {
                eprintln!(
                    "Skipping file upload; the session will start with an \
                     empty workspace."
                );
            }
        }
    };
    Ok::<_, anyhow::Error>(())
    }).await?;

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
                .await;
            let configured = match configured {
                // A transport failure abandons the activation and its row (T66).
                Err(error) => {
                    withdraw_box_row(
                        control_sock.clone(),
                        request.config.name.as_deref(),
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
                        request.config.name.as_deref(),
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
                                    request.config.name.as_deref(),
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
                            request.config.name.as_deref(),
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
                            request.config.name.as_deref(),
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
                            request.config.name.as_deref(),
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
    ActivationStep::Finalize
        .run(async {
            minimal_client::dedup_patch_uploads(&mut collected_patches);
            // The registration's lease is held across the finalize and committed
            // only once the session is active: until then an activation that dies
            // leaves the VM host daemon to withdraw the row on the lease's close.
            let lease = registered
                .as_mut()
                .and_then(|registration| registration.lease.take());
            if let Err(e) = finalize_holding_lease(
                lease,
                upload_and_finalize(
                    &mut client,
                    id,
                    &collected_patches,
                    &hook_scripts,
                    finalize_hook_budget,
                ),
            )
            .await
            {
                // Best-effort teardown: the session is stuck in
                // Materializing on the daemon. Destroy it so the operator's
                // `min ls` doesn't fill with half-finalized sessions, and
                // withdraw the row the registration bought with it (T66).
                best_effort_destroy(&mut client, id).await;
                withdraw_box_row(
                    control_sock.clone(),
                    request.config.name.as_deref(),
                    request.config.box_addresses,
                    registered
                        .as_ref()
                        .and_then(|registration| registration.box_id),
                )
                .await;
                return Err(e);
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?;

    // The session is `Active` now — a Ctrl-C must no longer tear it down
    // (the attach hand-off below and the user's own session are fair game
    // for interrupts, but not this cleanup).
    drop(interrupt_guard);
    if let Some(registration) = proxy_registration {
        registration.keep();
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
    // A task run releases such a hold by its session's id once the run
    // returns or is interrupted (`release_task_name_hold`); a run whose
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
    ActivationStep::HoldName
        .run(async {
            if kind == paths::ProviderKind::Minvmd
                && request.config.network == boxes::NetworkMode::HostNet
                && let Some(name) = request.config.name.as_deref()
            {
                hold_box_name_with_vm_host(control_sock.clone(), name, Some(id), true).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?;

    println!("{id}");

    if args.attach {
        // Chain into attach. Announce the freshly created session first: the
        // bare id printed to stdout above is the scripting contract, while this
        // stderr line tells an interactive operator which session they just
        // created and are entering.
        if should_announce_box(global) {
            eprintln!(
                "Created session {}",
                box_announce_label(&id, request.config.name.as_deref())
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
            "Cannot create the box: no sealed value was made for its GitHub grant \
             GITHUB_TOKEN, so GITHUB_TOKEN would be empty in the box. No box was created."
        );
    }

    /// BEP-007: a GitHub grant's name becomes a variable in the box's
    /// environment, so a name that is not a POSIX variable name is refused
    /// before the proxy or the sign-in is checked.
    #[test]
    fn a_grant_whose_name_is_not_a_variable_name_is_refused() {
        let grant: boxes::core::bep::SecretGrant =
            toml::from_str("source = \"broker\"\nscopes = [\"github:user-token\"]").unwrap();
        let keychain = bep::signin::MemoryKeychain::default();
        for name in ["X=1; touch /tmp/owned #", "gh_token", "1TOKEN"] {
            let secrets = boxes::core::bep::SecretGrants::from([(name.to_string(), grant.clone())]);
            let error = check_github_grants(&secrets, false, &keychain)
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
            check_github_grants(&secrets, false, &keychain)
                .unwrap_err()
                .to_string(),
            "Cannot create the box: the secret \"X=1; cmd #\" in [session.secrets] in \
             minimal.toml is not a valid environment variable name. A name uses only \
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
            network: CliNetworkMode::OwnIp,
            ingress: Vec::new(),
            dynamic_ingress: None,
            dynamic_range: None,
            allow_subnets: Vec::new(),
            allow_dns_hosts: vec!["github.com".into(), "api.github.com".into()],
            allow_protocols: Vec::new(),
            deny_subnets: Vec::new(),
            deny_all_egress: false,
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
            network: CliNetworkMode::OwnIp,
            ingress: Vec::new(),
            dynamic_ingress: None,
            dynamic_range: None,
            allow_subnets: Vec::new(),
            allow_dns_hosts: Vec::new(),
            allow_protocols: Vec::new(),
            deny_subnets: Vec::new(),
            deny_all_egress: false,
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
        let (bep, secrets) = project_bep_and_grants(path).expect("loads");
        // The egress here is unset, so both runs refuse for that too. Only
        // the narrow-scope refusal depends on the acknowledgement.
        let narrow = |acknowledged: bool| {
            let err = refuse_unhonourable_grants(
                boxes::NetworkMode::OwnIp,
                None,
                &bep,
                &secrets,
                acknowledged,
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
        let (bep, secrets) = project_bep_and_grants(path).expect("loads");
        assert_eq!(bep.steering, Some(boxes::core::bep::Steering::ProxyEnv));
        assert!(credentialed_upstream_for(false, &bep, &secrets).is_none());
        refuse_unhonourable_grants(boxes::NetworkMode::OwnIp, None, &bep, &secrets, false)
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
        let err =
            refuse_unhonourable_grants(boxes::NetworkMode::OwnIp, None, &bep, &secrets, false)
                .expect_err("refused");
        let refused = err
            .downcast_ref::<boxes::core::bep::ActivationRefused>()
            .expect("the refusal is the box spec refusal");
        assert_eq!(refused.exit_code(), 3);
    }
}

#[cfg(test)]
mod activation_step_tests {
    use super::ActivationStep;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt as _;

    /// What the capture layer saw: each `activation_step` span's step, in
    /// creation order, and each failure record's step and error.
    #[derive(Default)]
    struct Seen {
        spans: Vec<String>,
        failures: Vec<(String, String)>,
    }

    #[derive(Default)]
    struct Fields {
        step: Option<String>,
        error: Option<String>,
        message: Option<String>,
    }

    impl tracing::field::Visit for Fields {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            match field.name() {
                "step" => self.step = Some(value.to_owned()),
                "error" => self.error = Some(value.to_owned()),
                "message" => self.message = Some(value.to_owned()),
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
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if attrs.metadata().name() == "activation_step" {
                let mut fields = Fields::default();
                attrs.record(&mut fields);
                self.0
                    .lock()
                    .unwrap()
                    .spans
                    .push(fields.step.unwrap_or_default());
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
    }
}

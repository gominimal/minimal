//! `min box spec`: what a box is created from.
//!
//! With no argument it shows what a project's box gets from the local Box
//! Egress Proxy (BEP-038). It prints the proxy's root CA fingerprint, each
//! broker grant with its upstream hosts and the `full` marker, each store
//! reference, the resolved steering mode, and the `quic443` stance when it
//! lets HTTP/3 past the proxy. The rows come from [`render`], which is pure.
//!
//! With an argument that names an entry of the project, it shows the
//! entry's expanded spec, with the layer that set each value (BCLI-021).
//! Else the argument is a box address, and it shows the spec stored for
//! that box (BCLI-022). Every section of the spec shows, whether or not
//! the host enforces it (BCLI-023).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use boxes::core::bep::{
    ActivationRefused, ActivationSpec, BepRefusal, BepSettings, BepTables, BepWarning, HostFacts,
    Quic443, SecretGrant, SecretGrants, Steering, StoreAction, StoreRules, refusals,
    store_references,
};

use crate::output::ObjectType;
use crate::{BoxSpecArgs, BoxSpecOutputFormat, GlobalArgs};

/// What [`render`] reads.
pub(crate) struct SpecInputs<'a> {
    /// The SHA-256 fingerprint of the proxy's root certificate, as colon
    /// separated hex pairs, or `None` when the proxy has not published it.
    pub root_fingerprint: Option<&'a str>,
    /// `[session.network.bep]`.
    pub bep: &'a BepSettings,
    /// `[session.network] quic443`, `None` when not declared.
    pub quic443: Option<Quic443>,
    /// `[session.secrets]`.
    pub secrets: &'a SecretGrants,
    /// Whether the client configuration sets the full-breadth
    /// acknowledgement.
    pub acknowledged: bool,
    /// The box's network mode, from `min box spec --network`, the same
    /// mode `min session activate --network` gives the box it creates.
    pub network: boxes::NetworkMode,
    /// Whether this host resolves the box's steered names, the same host
    /// fact the box's creation reads (BEP-017, BEP-081):
    /// `host_resolves_box_names` for this host and [`Self::network`]. On a
    /// VM host it is true for `own_ip` and for `host_ip`.
    pub box_zone_resolver: bool,
    /// The GitHub module's upstream hosts.
    pub github_hosts: &'a [&'a str],
    /// The client's `[secret-store-rules]`, merged and with refused rules
    /// left out.
    pub store_rules: &'a StoreRules,
    /// The minimal.toml tables that set [`Self::secrets`] and
    /// [`Self::bep`], which a refusal names.
    pub tables: BepTables<'a>,
}

/// Writes the `min box spec` rows for `inputs`.
///
/// # Errors
///
/// [`ActivationRefused`] (exit 3) when a GitHub grant declares scopes
/// narrower than `full` and the client configuration does not acknowledge
/// full breadth (BEP-057), and the writer's error.
pub(crate) fn render(inputs: &SpecInputs<'_>, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
    let credentialed = inputs.secrets.values().any(SecretGrant::is_credentialed);
    if !credentialed {
        writeln!(
            out,
            "This project declares no broker secret, so its box does not use the proxy."
        )?;
        return Ok(());
    }

    // BEP-057: every host is un-enrolled today.
    // Interim: only BEP-057, BEP-009 (from `--network`) and BEP-017 are
    // previewed here; the full exit-3 set is gominimal/minimal#2445.
    // BEP-017: the resolver fact is the one creation reads, so the two
    // agree.
    let host = HostFacts {
        full_breadth_acknowledged: inputs.acknowledged,
        box_zone_resolver: inputs.box_zone_resolver,
        ..HostFacts::LOCAL
    };
    let egress = None;
    let spec = ActivationSpec {
        network: inputs.network,
        egress,
        bep: inputs.bep,
        secrets: inputs.secrets,
        tables: inputs.tables,
    };
    let narrow: Vec<BepRefusal> = refusals(&spec, host, inputs.github_hosts)
        .into_iter()
        .filter(|refusal| {
            matches!(
                refusal,
                BepRefusal::NarrowScopesUnenrolled { .. }
                    | BepRefusal::BrokerScopeNotGithub { .. }
                    | BepRefusal::NoNetworkWithGrant { .. }
                    | BepRefusal::NoResolver { .. }
            )
        })
        .collect();
    if !narrow.is_empty() {
        return Err(ActivationRefused { refusals: narrow }.into());
    }

    match inputs.root_fingerprint {
        // #2446: the fingerprint of the published root certificate, in the
        // form `openssl x509 -noout -fingerprint -sha256` prints for it.
        Some(fingerprint) => writeln!(out, "root CA  certificate SHA256:{fingerprint}")?,
        None => writeln!(
            out,
            "root CA  not published yet. The proxy publishes it when it starts."
        )?,
    }

    for (name, grant) in inputs.secrets {
        if !grant.is_credentialed() {
            continue;
        }
        if grant.is_github() {
            let scopes: Vec<&str> = grant
                .scopes
                .iter()
                .map(String::as_str)
                .filter(|scope| scope.starts_with("github:"))
                .collect();
            // An un-enrolled host mints every GitHub member `full` (BEP-005).
            writeln!(
                out,
                "grant  {}  full  {name}  hosts {}",
                scopes.join(", "),
                inputs.github_hosts.join(", ")
            )?;
            if grant.is_narrower_than_full() {
                writeln!(
                    out,
                    "  acknowledge_full_breadth_unenrolled is set in config.toml: \
                     for the life of this box, {name} reaches every repository your \
                     GitHub sign-in reaches, through the hosts above only."
                )?;
            }
        }
    }
    for reference in store_references(inputs.secrets) {
        // BEP-038, BEP-063: the authorities the matching rule registers
        // are the upstream the store handle carries.
        // A deny rule never redeems the reference, whatever upstream it
        // keeps, so the row says it is denied and lists no authorities.
        let item = reference.item();
        let name = reference.grant;
        match reference.rule(inputs.store_rules) {
            Some(rule) if rule.action == Some(StoreAction::Deny) => writeln!(
                out,
                "store  {item}  {name}  denied by its rule in [secret-store-rules] in config.toml"
            )?,
            Some(rule) if !rule.upstream.is_empty() => writeln!(
                out,
                "store  {item}  {name}  upstream {}",
                rule.upstream.join(", ")
            )?,
            Some(_) => writeln!(out, "store  {item}  {name}  no upstream registered")?,
            None => writeln!(
                out,
                "store  {item}  {name}  no rule in [secret-store-rules] in config.toml"
            )?,
        }
    }

    let steering = inputs.bep.resolved_steering();
    writeln!(out, "steering  {}", steering.word())?;
    // Networking §5.4: steering `off` with a GitHub grant is a warning, not
    // a refusal, so the exit stays 0.
    if steering == Steering::Off {
        let grants: Vec<String> = inputs
            .secrets
            .iter()
            .filter(|(_, grant)| grant.is_github())
            .map(|(name, _)| name.clone())
            .collect();
        if !grants.is_empty() {
            writeln!(
                out,
                "warning  {}",
                BepWarning::SteeringOffWithGrant { grants }
            )?;
        }
    }
    if !inputs.quic443.unwrap_or_default().blocks(true, steering) {
        writeln!(out, "quic443  allowed (HTTP/3 bypasses the proxy)")?;
    }
    Ok(())
}

/// `~/.minimal/bep/identity.json`, where the proxy publishes its keys.
fn identity_path() -> Option<PathBuf> {
    std::env::home_dir().map(|home| home.join(".minimal/bep/identity.json"))
}

/// The published root certificate's fingerprint, or `None` with a debug
/// line saying why.
pub(crate) fn root_fingerprint(path: Option<&Path>) -> Option<String> {
    let path = path?;
    match bep::publish::Identity::read(path)
        .and_then(|identity| identity.root_certificate_fingerprint())
    {
        Ok(fingerprint) => Some(fingerprint),
        Err(error) => {
            tracing::debug!(path = %path.display(), %error, "no published root CA");
            None
        }
    }
}

/// `min box spec [<entry>|<box>]`: with no argument, the Box Egress Proxy
/// rows of the project that `--repo-dir` names, else the current one
/// (BEP-038). With an argument, the expanded spec of that entry of the
/// project (BCLI-021), else the spec stored for the box it addresses
/// (BCLI-022). The argument is never read as a directory.
pub(crate) async fn cmd_box_spec(global: &GlobalArgs, args: BoxSpecArgs) -> anyhow::Result<()> {
    let mut out = Vec::new();
    box_spec_to(global, args, true, &mut out).await?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&out)
        .context("failed to write to stdout")?;
    stdout.flush().context("failed to write to stdout")
}

/// [`cmd_box_spec`], written to `out`. `spawn` says whether the box form
/// starts the local daemon when it does not run. Nothing is written when
/// the command fails.
pub(crate) async fn box_spec_to(
    global: &GlobalArgs,
    args: BoxSpecArgs,
    spawn: bool,
    out: &mut Vec<u8>,
) -> anyhow::Result<()> {
    let Some(target) = args.target.clone() else {
        // BCLI-021: the project form keeps only `--network`.
        if let Some(flag) = given_override_flags(&args, false).first() {
            return Err(spec_flag_refusal(flag, "the project's proxy rows", "min box spec").into());
        }
        return project_rows(global, &args, out);
    };
    let project = global
        .repo_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    let entries = project_file_bytes(&project).and_then(|bytes| match bytes {
        Some((_, bytes)) => mfile::entry::read_entries(&bytes)
            .map_err(|error| crate::ProjectFileInvalid { error }.into()),
        None => Ok(Vec::new()),
    });
    let entries = match entries {
        Ok(entries) => entries,
        // A project file that does not load blocks the entry form. Only a
        // target that cannot name an entry reads as a box address: a
        // qualified address, a full box id, or `self`. When no box answers
        // to it, the project file error is the useful one.
        Err(project_error) => {
            if !given_override_flags(&args, true).is_empty() {
                return Err(project_error);
            }
            let only_a_box = matches!(
                super::box_verbs::parse_box_address(&target),
                super::box_verbs::BoxAddress::Qualified { .. }
            ) || boxes::SessionId::parse_str(&target).is_ok()
                || target == "self";
            if !only_a_box {
                tracing::info!(verb = "box spec", target = %target, outcome = "project file invalid");
                return Err(project_error);
            }
            let format = args.output.unwrap_or_default();
            if spawn && crate::cmd::ensure_daemon(global).is_err() {
                return Err(project_error);
            }
            return match box_spec(global, &target, format, out).await {
                Err(error)
                    if !matches!(
                        error.downcast_ref::<super::box_verbs::BoxAddressRefusal>(),
                        Some(
                            super::box_verbs::BoxAddressRefusal::Ambiguous { .. }
                                | super::box_verbs::BoxAddressRefusal::AmbiguousIdStart { .. }
                        )
                    ) =>
                {
                    tracing::info!(verb = "box spec", target = %target, outcome = "project file invalid");
                    Err(project_error)
                }
                result => result,
            };
        }
    };
    // BCLI-022: an entry of the project first, else a box address.
    let is_entry = entries.iter().any(|entry| entry.name == target)
        || (target == mfile::entry::DEFAULT_ENTRY_NAME
            && super::box_verbs::pick_box_start_entry(&entries, Some(&target)).is_ok());
    if is_entry {
        let entry = super::box_verbs::pick_box_start_entry(&entries, Some(&target))?;
        tracing::info!(verb = "box spec", entry = %entry.name, "rendering an entry's spec");
        return entry_spec(global, &project, &entry, &args, out);
    }
    if let Some(flag) = given_override_flags(&args, true).first() {
        tracing::info!(verb = "box spec", target = %target, outcome = "refused", flag = %flag);
        return Err(spec_flag_refusal(
            flag,
            "a box's stored spec",
            &format!("min box spec {target}"),
        )
        .into());
    }
    if spawn {
        crate::cmd::ensure_daemon(global)?;
    }
    box_spec(global, &target, args.output.unwrap_or_default(), out).await
}

/// The override flags `args` gives, as the person typed them. `--network`
/// is left out unless `network` is set.
fn given_override_flags(args: &BoxSpecArgs, network: bool) -> Vec<&'static str> {
    let overrides = &args.overrides;
    let egress = &overrides.egress;
    [
        (network && overrides.network.is_some(), "--network"),
        (!overrides.ingress.is_empty(), "--ingress"),
        (!egress.allow_subnets.is_empty(), "--allow-subnets"),
        (!egress.deny_subnets.is_empty(), "--deny-subnets"),
        (!egress.allow_dns_hosts.is_empty(), "--allow-dns-hosts"),
        (!egress.allow_protocols.is_empty(), "--allow-protocols"),
        (egress.deny_all_egress, "--deny-all-egress"),
        (!overrides.loadout.is_empty(), "--loadout"),
    ]
    .into_iter()
    .filter_map(|(given, flag)| given.then_some(flag))
    .collect()
}

/// The exit-2 refusal of `flag` for a form of `min box spec` that takes
/// no override flag. `form` is what that form shows, and `remedy` the
/// command to run without the flag.
fn spec_flag_refusal(flag: &str, form: &str, remedy: &str) -> crate::InitRefusal {
    crate::InitRefusal {
        code: 2,
        message: format!(
            "min box spec does not take {flag} when it shows {form}. \
             Run {remedy} without {flag}."
        ),
    }
}

/// The project directory that holds the `minimal.toml` for `project`, and
/// the file's bytes. `None` when the project has no `minimal.toml`.
fn project_file_bytes(project: &Path) -> anyhow::Result<Option<(PathBuf, Vec<u8>)>> {
    let file = match mfile::File::from_dir_recursive(project) {
        Ok(file) => file,
        Err(mfile::Error::NotFound) => return Ok(None),
        Err(error) => return Err(crate::ProjectFileInvalid { error }.into()),
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
    let bytes = std::fs::read(&path).map_err(|e| crate::ProjectFileInvalid {
        error: mfile::Error::IO("minimal file", path.clone(), e),
    })?;
    Ok(Some((root.to_path_buf(), bytes)))
}

/// `min box spec` with no argument: the Box Egress Proxy rows of the
/// project (BEP-038).
fn project_rows(global: &GlobalArgs, args: &BoxSpecArgs, out: &mut Vec<u8>) -> anyhow::Result<()> {
    let project = global
        .repo_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    let session = match mfile::File::from_dir_recursive(&project) {
        Ok(file) => file.session,
        Err(mfile::Error::NotFound) => anyhow::bail!(
            "No {} found in {} or its parent directories.",
            mfile::MFILE_NAME,
            project.display()
        ),
        Err(error) => {
            return Err(crate::ProjectFileInvalid { error }.into());
        }
    };
    let (bep, quic443, secrets) = session.map_or_else(Default::default, |session| {
        let network = session.network.unwrap_or_default();
        (
            network.bep.unwrap_or_default(),
            network.quic443,
            session.secrets,
        )
    });
    tracing::debug!(project = %project.display(), "rendering min box spec");
    let (network, _) = preview_host(crate::daemon_host_kind(global), args);
    // This path reads `[defaults.session]`, as `min box start` does.
    proxy_rows(
        global,
        &bep,
        quic443,
        &secrets,
        network,
        BepTables::SESSION,
        out,
    )
}

/// Writes the Box Egress Proxy rows for `secrets` (BEP-038) to `out`, for
/// a box of `network` on this host.
fn proxy_rows(
    global: &GlobalArgs,
    bep: &BepSettings,
    quic443: Option<Quic443>,
    secrets: &SecretGrants,
    network: boxes::NetworkMode,
    tables: BepTables<'_>,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<()> {
    let acknowledged = crate::config::full_breadth_acknowledged(global)?;
    let store_rules = if boxes::core::bep::store_references(secrets).next().is_some() {
        crate::config::read_client_config_and_store_rules(global)?.1
    } else {
        StoreRules::new()
    };
    let root = root_fingerprint(identity_path().as_deref());
    tracing::debug!(root_found = root.is_some(), "rendering the proxy rows");
    let github_hosts: Vec<&str> = bep::module::GITHUB
        .hosts
        .iter()
        .map(|authority| authority.host)
        .collect();
    let box_zone_resolver =
        super::box_verbs::host_resolves_box_names(crate::daemon_host_kind(global), network);
    render(
        &SpecInputs {
            root_fingerprint: root.as_deref(),
            bep,
            quic443,
            secrets,
            acknowledged,
            network,
            box_zone_resolver,
            github_hosts: &github_hosts,
            store_rules: &store_rules,
            tables,
        },
        out,
    )
}

/// The network and the host fact the preview reads, for a host of `kind`:
/// the box's `--network` mode, and whether the host resolves that box's
/// steered names: the switch's DNS gate for `own_ip`, and the box's own
/// steering answerer for `host_ip` (BEP-081). Creation reads the same fact
/// for the same mode, so `min box spec --network <mode>` refuses what `min
/// session activate --network <mode>` refuses.
pub(crate) fn preview_host(
    kind: paths::HostKind,
    args: &BoxSpecArgs,
) -> (boxes::NetworkMode, bool) {
    let network: boxes::NetworkMode = args
        .overrides
        .network
        .unwrap_or_else(crate::cli::default_network_mode)
        .into();
    (
        network,
        super::box_verbs::host_resolves_box_names(kind, network),
    )
}

/// The label of the layer that `origin` names, in the words of
/// `minimal.toml`, for `entry`'s expansion.
fn origin_label(origin: &mfile::expand::Origin, entry: &mfile::entry::BoxEntry) -> String {
    use mfile::expand::Layer;
    match origin.layer {
        Layer::Upstream => "[upstream]".to_owned(),
        Layer::TypeDefaults => format!(
            "type {} defaults",
            origin.box_type.as_deref().unwrap_or("-")
        ),
        Layer::Defaults => "[defaults]".to_owned(),
        Layer::DefaultsType => format!("[defaults.{}]", entry.box_type.as_deref().unwrap_or("-")),
        Layer::Entry if entry.implicit => "the implicit default entry".to_owned(),
        Layer::Entry => format!("[{}.{}]", entry.table.key(), entry.name),
        Layer::Loadouts => "loadouts".to_owned(),
        Layer::Overrides => COMMAND_LINE.to_owned(),
    }
}

/// The minimal.toml table at `path` under the layer that set `key` of
/// `entry`'s expansion, for a refusal that names where to edit the value
/// (BCLI-021). A table replaces the one a lower layer sets, so a value
/// that no table of the file sets names the table where an edit takes
/// effect: the entry's own table, or `[defaults.<type>]` for the implicit
/// default entry.
fn setting_table(
    report: &mfile::expand::ExpansionReport,
    entry: &mfile::entry::BoxEntry,
    key: &str,
    path: &str,
) -> String {
    use mfile::expand::{Layer, ValueOrigin};
    let box_type = entry.box_type.as_deref().unwrap_or(boxes::SESSION_BOX_TYPE);
    let layer = match report.values.get(key) {
        Some(ValueOrigin::Value(origin)) => Some(origin.layer),
        _ => None,
    };
    match layer {
        Some(Layer::Defaults) => format!("[defaults.{path}]"),
        Some(Layer::DefaultsType) => format!("[defaults.{box_type}.{path}]"),
        _ if entry.implicit => format!("[defaults.{box_type}.{path}]"),
        _ => format!("[{}.{}.{path}]", entry.table.key(), entry.name),
    }
}

/// The source of a value that an override flag sets.
const COMMAND_LINE: &str = "the command line";
/// The source of a value that no layer sets: the creating command's
/// default.
const DEFAULT_SOURCE: &str = "the default";

/// The labels of the layers in `origin`, each once, in layer order.
fn origin_labels(
    origin: &mfile::expand::ValueOrigin,
    entry: &mfile::entry::BoxEntry,
) -> Vec<String> {
    let origins: Vec<&mfile::expand::Origin> = match origin {
        mfile::expand::ValueOrigin::Value(origin) => vec![origin],
        mfile::expand::ValueOrigin::List(items) => items.iter().collect(),
    };
    let mut labels: Vec<String> = Vec::new();
    for origin in origins {
        let label = origin_label(origin, entry);
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    labels
}

/// The keys of a `[secrets.<VAR>]` grant that name where its value comes
/// from. Every other key is left out of a render, so a secret shows as its
/// reference only.
const SECRET_REFERENCE_KEYS: [&str; 5] = ["source", "store", "id", "scopes", "mode"];

/// An entry's expanded spec, the source of each value, and the proxy rows
/// of an entry with a credentialed upstream.
struct EntrySpec {
    entry: String,
    box_type: String,
    spec: toml::Table,
    sources: std::collections::BTreeMap<String, Vec<String>>,
    proxy_rows: Vec<String>,
    /// The names of the loadouts `min box start` selects for the entry, in
    /// the order it applies them, for a task entry too. Empty for a sealed
    /// box, which selects no loadout.
    loadouts: Option<Vec<String>>,
}

/// `min box spec <entry>` (BCLI-021): the entry's expanded spec in the
/// `-o` format, with the layer that set each value.
fn entry_spec(
    global: &GlobalArgs,
    project: &Path,
    entry: &mfile::entry::BoxEntry,
    args: &BoxSpecArgs,
    out: &mut Vec<u8>,
) -> anyhow::Result<()> {
    let rendered = expand_entry(global, project, entry, args)?;
    let mut text = Vec::new();
    match args.output.unwrap_or_default() {
        BoxSpecOutputFormat::Toml => {
            writeln!(
                text,
                "# The spec of entry {} (type {}). The comment before each \
                 value names the layer that set it.",
                rendered.entry, rendered.box_type
            )?;
            if let Some(loadouts) = &rendered.loadouts {
                if loadouts.is_empty() {
                    writeln!(text, "# Loadouts: none.")?;
                } else {
                    writeln!(text, "# Loadouts: {}.", loadouts.join(", "))?;
                }
            }
            write_toml(&rendered.spec, &rendered.sources, &mut text)?;
            if !rendered.proxy_rows.is_empty() {
                writeln!(text, "\n# Box Egress Proxy:")?;
                for row in &rendered.proxy_rows {
                    writeln!(text, "# {row}")?;
                }
            }
        }
        format => {
            let mut doc = serde_json_lenient::Map::new();
            doc.insert("schema".to_owned(), ObjectType::Spec.schema().into());
            doc.insert("entry".to_owned(), rendered.entry.clone().into());
            doc.insert("type".to_owned(), rendered.box_type.clone().into());
            if let Some(loadouts) = &rendered.loadouts {
                doc.insert(
                    "loadouts".to_owned(),
                    serde_json_lenient::to_value(loadouts).context("Cannot encode the loadouts")?,
                );
            }
            doc.insert(
                "spec".to_owned(),
                serde_json_lenient::to_value(&rendered.spec).context("Cannot encode the spec")?,
            );
            doc.insert(
                "sources".to_owned(),
                serde_json_lenient::to_value(&rendered.sources)
                    .context("Cannot encode the sources")?,
            );
            if !rendered.proxy_rows.is_empty() {
                doc.insert(
                    "egress_proxy".to_owned(),
                    serde_json_lenient::to_value(&rendered.proxy_rows)
                        .context("Cannot encode the proxy rows")?,
                );
            }
            write_document(&serde_json_lenient::Value::Object(doc), format, &mut text)?;
        }
    }
    tracing::info!(verb = "box spec", entry = %rendered.entry, outcome = "ok");
    out.extend_from_slice(&text);
    Ok(())
}

/// Expands `entry` of the project at `project` as `min box start` does,
/// with the override flags of `args` applied to its `[network]` table.
fn expand_entry(
    global: &GlobalArgs,
    project: &Path,
    entry: &mfile::entry::BoxEntry,
    args: &BoxSpecArgs,
) -> anyhow::Result<EntrySpec> {
    let invalid = |error| crate::ProjectFileInvalid { error };
    let Some((root, bytes)) = project_file_bytes(project)? else {
        anyhow::bail!(
            "No {} found in {} or its parent directories.",
            mfile::MFILE_NAME,
            project.display()
        );
    };
    let root = camino::Utf8PathBuf::from_path_buf(root)
        .map_err(|_| anyhow::anyhow!("Project path is not valid UTF-8"))?;
    let mut doc: toml::Table =
        toml::from_slice(&bytes).map_err(|e| invalid(mfile::Error::Format(e)))?;
    mfile::legacy::canonicalize(&mut doc, mfile::legacy::this_release()).map_err(invalid)?;
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
    let layers = mfile::expand::Layers::default().with_file_defaults(
        &defaults,
        entry.box_type.as_deref(),
        &project_types,
    );
    let expansion = mfile::expand::expand(entry, &layers).map_err(invalid)?;
    let mut spec = expansion.spec;
    let mut sources = std::collections::BTreeMap::new();
    for (key, origin) in &expansion.report.values {
        sources.insert(key.clone(), origin_labels(origin, entry));
    }
    // The tables a refusal names: the layer that set `secrets`, and the
    // layer that set `network`, whose `bep` table the proxy reads.
    let secrets_table = setting_table(&expansion.report, entry, "secrets", "secrets");
    let bep_table = setting_table(&expansion.report, entry, "network", "network.bep");
    let box_type = entry
        .box_type
        .clone()
        .unwrap_or_else(|| boxes::SESSION_BOX_TYPE.to_owned());

    // BCLI-021: the network that `min box start` sends with the same
    // flags, from the functions it calls.
    let overrides = &args.overrides;
    let network_label = sources.get("network").cloned();
    if box_type == boxes::TASK_BOX_TYPE {
        // `min box start` refuses these two flags for a task entry, so the
        // spec refuses them the same way (`StartEntryRefusal::FlagUnsupported`).
        let unsupported = [
            (!overrides.ingress.is_empty(), "--ingress"),
            (!overrides.loadout.is_empty(), "--loadout"),
        ];
        if let Some((_, flag)) = unsupported.into_iter().find(|(given, _)| *given) {
            tracing::info!(verb = "box spec", entry = %entry.name, outcome = "refused", flag = %flag);
            return Err(crate::InitRefusal {
                code: 2,
                message: format!(
                    "min box spec does not take {flag} for {name}. A box from a task \
                     entry does not take {flag}. Run min box spec {name} without {flag}.",
                    name = entry.name
                ),
            }
            .into());
        }
    }
    // The loadouts `min box start` or `min task run` selects, read from
    // the same client config. A missing or malformed loadout fails here as
    // it fails the start. Folding their values into the spec is #3236.
    // The box's loadout mode, read before any loadout as the start reads
    // it, for a task entry too. A sealed box selects no loadout (BOX-171,
    // BOX-173).
    let loadout_mode = crate::loadouts::entry_loadout_gate(Some(&bytes), entry, &overrides.loadout)
        .map_err(invalid)?;
    let cfg = crate::config::read_client_config(global)?;
    let active = crate::loadouts::resolve_active_loadouts(
        crate::loadouts::gate_selection(
            crate::loadouts::LoadoutSelection::from_flags(&overrides.loadout, false),
            loadout_mode,
        ),
        &cfg,
        global,
    )?;
    // BOX-172: a loadout that sets `loadout_mode` fails the start, so it
    // fails the spec the same way.
    if let Some(loadout) = active.loadouts.iter().find(|l| l.sets_loadout_mode()) {
        return Err(invalid(mfile::Error::LoadoutSetsLoadoutMode {
            loadout: Some(loadout.name().as_ref().to_owned()),
        })
        .into());
    }
    let loadouts = Some(
        active
            .loadouts
            .iter()
            .map(|loadout| loadout.name().as_ref().to_owned())
            .collect(),
    );
    let mut ingress_sources = vec![COMMAND_LINE.to_owned()];
    let (mode, mode_source, egress, ingress) = if box_type == boxes::TASK_BOX_TYPE {
        let project_egress = super::box_verbs::task_project_egress(&root, &entry.name)?;
        let flags = super::box_verbs::flag_egress(&overrides.egress)?;
        let egress = super::box_verbs::effective_egress(
            project_egress.policy,
            flags,
            overrides.egress.deny_all_egress,
        );
        let (mode, source) = match (overrides.network, project_egress.mode) {
            (Some(flag), _) => (flag.into(), vec![COMMAND_LINE.to_owned()]),
            (None, Some(mode)) => (mode, network_label.clone().unwrap_or_default()),
            (None, None) => (
                crate::cli::default_network_mode().into(),
                vec![DEFAULT_SOURCE.to_owned()],
            ),
        };
        (mode, source, egress.policy, None)
    } else {
        let mut activate = crate::ActivateArgs::unflagged();
        activate.network = overrides.network;
        activate.ingress.clone_from(&overrides.ingress);
        activate.egress.clone_from(&overrides.egress);
        let (port_mappings, flags) = super::box_verbs::flag_network_overrides(&activate)?;
        let mut project_egress = super::box_verbs::project_egress(&root, Some(&entry.name))?;
        // #3238: as `min box start` sends them, the entry's `network.mode`
        // applies when no `--network` replaces it, and each `--ingress` adds
        // a mapping after the entry's `network.ingress`.
        let file_ingress = project_egress.ingress.take();
        let (mode, source) = match (overrides.network, project_egress.mode) {
            (Some(flag), _) => (flag.into(), vec![COMMAND_LINE.to_owned()]),
            (None, Some(mode)) => (mode, network_label.clone().unwrap_or_default()),
            (None, None) => (
                activate.network_mode().into(),
                vec![DEFAULT_SOURCE.to_owned()],
            ),
        };
        let mut ingress_source = Vec::new();
        if file_ingress.is_some() {
            ingress_source.extend(network_label.clone().unwrap_or_default());
        }
        if file_ingress.is_none() || !overrides.ingress.is_empty() {
            ingress_source.push(COMMAND_LINE.to_owned());
        }
        let port_mappings = match file_ingress {
            Some(file_mappings) => super::box_verbs::union_ingress(file_mappings, port_mappings),
            None => port_mappings,
        };
        let egress = super::box_verbs::effective_egress(
            project_egress.policy,
            flags,
            activate.egress.deny_all_egress,
        );
        let policy =
            super::box_verbs::network_override_policy(&activate, port_mappings, egress.policy);
        ingress_sources = ingress_source;
        (mode, source, policy.egress, policy.ingress)
    };
    let mut network = spec
        .get("network")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    network.insert("mode".to_owned(), mode.word().into());
    sources.insert("network.mode".to_owned(), mode_source);
    let egress_flagged = overrides.egress != crate::EgressArgs::default();
    match egress {
        Some(egress) => {
            let had = network.contains_key("egress");
            network.insert(
                "egress".to_owned(),
                toml::Value::try_from(&egress).context("Cannot encode the egress")?,
            );
            let mut source = if had {
                network_label.clone().unwrap_or_default()
            } else {
                Vec::new()
            };
            if egress_flagged {
                source.push(COMMAND_LINE.to_owned());
            }
            sources.insert("network.egress".to_owned(), source);
        }
        None => {
            network.remove("egress");
        }
    }
    if let Some(ingress) = ingress {
        network.insert(
            "ingress".to_owned(),
            toml::Value::try_from(&ingress).context("Cannot encode the ingress")?,
        );
        sources.insert("network.ingress".to_owned(), ingress_sources);
    }
    spec.insert("network".to_owned(), toml::Value::Table(network.clone()));
    if network_label.is_none() {
        sources.insert("network".to_owned(), sources["network.mode"].clone());
    }

    // A secret shows as its reference only, never a value.
    // The grants parse first, so a grant that `min box start` refuses is
    // refused here too.
    let mut grants = SecretGrants::new();
    if let Some(toml::Value::Table(secrets)) = spec.get_mut("secrets") {
        grants = toml::Value::Table(secrets.clone())
            .try_into()
            .map_err(|e| invalid(mfile::Error::Format(e)))?;
        for (_, grant) in secrets.iter_mut() {
            if let toml::Value::Table(fields) = grant {
                fields.retain(|key, _| SECRET_REFERENCE_KEYS.contains(&key));
            }
        }
    }
    let mut rows_text = Vec::new();
    if grants.values().any(SecretGrant::is_credentialed) {
        let bep: BepSettings = network
            .get("bep")
            .cloned()
            .map(toml::Value::try_into)
            .transpose()
            .map_err(|e| invalid(mfile::Error::Format(e)))?
            .unwrap_or_default();
        let quic443: Option<Quic443> = network
            .get("quic443")
            .cloned()
            .map(toml::Value::try_into)
            .transpose()
            .map_err(|e| invalid(mfile::Error::Format(e)))?;
        let mut rows = Vec::new();
        let tables = BepTables {
            secrets: &secrets_table,
            network_bep: &bep_table,
        };
        proxy_rows(global, &bep, quic443, &grants, mode, tables, &mut rows)?;
        rows_text = String::from_utf8_lossy(&rows)
            .lines()
            .map(str::to_owned)
            .collect();
    }
    Ok(EntrySpec {
        entry: entry.name.clone(),
        box_type,
        spec,
        sources,
        proxy_rows: rows_text,
        loadouts,
    })
}

/// `min box spec <box>` (BCLI-022): the spec stored for the box that
/// `target` addresses, in `format`.
async fn box_spec(
    global: &GlobalArgs,
    target: &str,
    format: BoxSpecOutputFormat,
    out: &mut Vec<u8>,
) -> anyhow::Result<()> {
    use minimald_rpc::{Errorable, GetBoxSpec, GetBoxSpecRequest};
    let super::box_verbs::ResolvedBox { host, box_id: id } =
        super::box_verbs::resolve_box_on_local_hosts(global, target, "box spec").await?;
    let mut client = super::box_verbs::box_host_client(&host).await?;
    let stored = match client
        .oneshot_rpc::<GetBoxSpec>(GetBoxSpecRequest { id })
        .await
        .context("GetBoxSpec RPC failed")?
    {
        Errorable::Ok(reply) => reply.spec,
        Errorable::Err { error } if error.starts_with(minimald_rpc::UNKNOWN_SESSION_ID_LEAD) => {
            // The box was removed after the address resolved.
            tracing::info!(verb = "box spec", box_id = %id, outcome = "not found");
            return Err(super::box_verbs::BoxAddressRefusal::NotFound {
                address: target.to_owned(),
            }
            .into());
        }
        Errorable::Err { error } => {
            tracing::info!(verb = "box spec", box_id = %id, outcome = "error", "{error}");
            anyhow::bail!("{error}")
        }
    };
    let Some(mut stored) = stored else {
        tracing::info!(verb = "box spec", box_id = %id, outcome = "no stored spec");
        anyhow::bail!(
            "Box {id} has no stored spec. Its host stores none for a box created \
             before boxes stored their spec."
        );
    };
    // A secret shows as its reference only, whatever the stored copy holds.
    if let Some(serde_json_lenient::Value::Object(secrets)) = stored.get_mut("secrets") {
        for grant in secrets.values_mut() {
            if let serde_json_lenient::Value::Object(fields) = grant {
                fields.retain(|key, _| SECRET_REFERENCE_KEYS.contains(&key.as_str()));
            }
        }
    }
    let mut text = Vec::new();
    match format {
        BoxSpecOutputFormat::Toml => {
            writeln!(text, "# The spec box {id} was created with.")?;
            let spec = match json_to_toml(&stored) {
                Some(toml::Value::Table(table)) => table,
                _ => anyhow::bail!("The stored spec of box {id} is not a table."),
            };
            write_toml(&spec, &std::collections::BTreeMap::new(), &mut text)?;
        }
        format => {
            let mut doc = serde_json_lenient::Map::new();
            doc.insert("schema".to_owned(), ObjectType::Spec.schema().into());
            doc.insert("box".to_owned(), id.to_string().into());
            doc.insert("spec".to_owned(), stored);
            write_document(&serde_json_lenient::Value::Object(doc), format, &mut text)?;
        }
    }
    tracing::info!(verb = "box spec", box_id = %id, outcome = "ok", host = %host.host);
    out.extend_from_slice(&text);
    Ok(())
}

/// `value` as TOML, with each `null` left out. `None` for a `null`.
fn json_to_toml(value: &serde_json_lenient::Value) -> Option<toml::Value> {
    use serde_json_lenient::Value;
    Some(match value {
        Value::Null => return None,
        Value::Bool(b) => toml::Value::Boolean(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => toml::Value::Integer(i),
            None => toml::Value::Float(n.as_f64().unwrap_or_default()),
        },
        Value::String(s) => toml::Value::String(s.clone()),
        Value::Array(items) => toml::Value::Array(items.iter().filter_map(json_to_toml).collect()),
        Value::Object(map) => toml::Value::Table(
            map.iter()
                .filter_map(|(k, v)| json_to_toml(v).map(|v| (k.clone(), v)))
                .collect(),
        ),
    })
}

/// Whether `value` writes as a TOML table or an array of tables, which
/// must follow every plain key of its parent.
fn is_table_like(value: &toml::Value) -> bool {
    match value {
        toml::Value::Table(_) => true,
        toml::Value::Array(items) => !items.is_empty() && items.iter().all(toml::Value::is_table),
        _ => false,
    }
}

/// Writes `spec` as TOML, each top-level key with a comment line before it
/// that names its sources from `sources`: the key itself, then each dotted
/// key below it.
fn write_toml(
    spec: &toml::Table,
    sources: &std::collections::BTreeMap<String, Vec<String>>,
    out: &mut Vec<u8>,
) -> anyhow::Result<()> {
    let (plain, tables): (Vec<_>, Vec<_>) = spec.iter().partition(|(_, v)| !is_table_like(v));
    for (key, value) in plain.into_iter().chain(tables) {
        let prefix = format!("{key}.");
        for (path, labels) in sources
            .iter()
            .filter(|(path, _)| *path == key || path.starts_with(&prefix))
        {
            writeln!(out, "# {path}: from {}", labels.join(", "))?;
        }
        let one = toml::Table::from_iter([(key.clone(), value.clone())]);
        let text = toml::to_string(&one).context("Cannot write the spec as TOML")?;
        out.extend_from_slice(text.as_bytes());
        if is_table_like(value) {
            writeln!(out)?;
        }
    }
    Ok(())
}

/// Writes `doc` as JSON or YAML.
fn write_document(
    doc: &serde_json_lenient::Value,
    format: BoxSpecOutputFormat,
    out: &mut Vec<u8>,
) -> anyhow::Result<()> {
    match format {
        BoxSpecOutputFormat::Json | BoxSpecOutputFormat::Toml => {
            serde_json_lenient::to_writer_pretty(&mut *out, doc)
                .context("Cannot write the spec as JSON")?;
            writeln!(out)?;
        }
        BoxSpecOutputFormat::Yaml => {
            let mut text = String::new();
            write_yaml(doc, 0, &mut text);
            out.extend_from_slice(text.as_bytes());
        }
    }
    Ok(())
}

/// A YAML scalar or key for `text`: plain when it is safe, else quoted.
fn yaml_string(text: &str) -> String {
    // Plain only in a narrow safe set: a letter, `_` or `/` first, so no
    // number, date, `-` or `.inf` reads as another type, and no word that
    // YAML 1.1 or 1.2 reads as a bool or null in any case.
    const TYPED_WORDS: [&str; 12] = [
        "true", "false", "null", "yes", "no", "on", "off", "y", "n", "nan", "inf", "infinity",
    ];
    let plain = text
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || matches!(c, '_' | '/'))
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
        && !TYPED_WORDS
            .iter()
            .any(|word| text.eq_ignore_ascii_case(word));
    if plain {
        text.to_owned()
    } else {
        serde_json_lenient::to_string(text).unwrap_or_else(|_| format!("{text:?}"))
    }
}

/// Writes `value` as block YAML at `indent` spaces into `out`.
fn write_yaml(value: &serde_json_lenient::Value, indent: usize, out: &mut String) {
    use serde_json_lenient::Value;
    let pad = " ".repeat(indent);
    let inline = |value: &Value| -> Option<String> {
        match value {
            Value::Null => Some("null".to_owned()),
            Value::Bool(b) => Some(b.to_string()),
            Value::Number(n) => Some(n.to_string()),
            Value::String(s) => Some(yaml_string(s)),
            Value::Array(items) if items.is_empty() => Some("[]".to_owned()),
            Value::Object(map) if map.is_empty() => Some("{}".to_owned()),
            _ => None,
        }
    };
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                match inline(value) {
                    Some(text) => out.push_str(&format!("{pad}{}: {text}\n", yaml_string(key))),
                    None => {
                        out.push_str(&format!("{pad}{}:\n", yaml_string(key)));
                        write_yaml(value, indent + 2, out);
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                match inline(item) {
                    Some(text) => out.push_str(&format!("{pad}- {text}\n")),
                    None => {
                        out.push_str(&format!("{pad}-\n"));
                        write_yaml(item, indent + 2, out);
                    }
                }
            }
        }
        scalar => {
            if let Some(text) = inline(scalar) {
                out.push_str(&format!("{pad}{text}\n"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boxes::core::bep::GrantSource;

    const HOSTS: &[&str] = &[
        "github.com",
        "api.github.com",
        "uploads.github.com",
        "codeload.github.com",
    ];

    #[test]
    fn yaml_string_quotes_text_that_reads_as_another_type() {
        for text in [
            "True",
            "NO",
            "Yes",
            "Null",
            "y",
            "-",
            "0x1F",
            "1_000",
            ".inf",
            "2026-11-11",
            "",
        ] {
            assert!(yaml_string(text).starts_with('"'), "{text}");
        }
        for text in ["client_env", "min/v1/spec", "own_ip", "api.github.com"] {
            assert_eq!(yaml_string(text), text);
        }
    }

    fn grant(scopes: &[&str]) -> SecretGrant {
        SecretGrant {
            source: GrantSource::Broker,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            mode: None,
        }
    }

    /// A store reference as a box spec writes it: `source = "store"` with
    /// `store` and `id`.
    fn store_grant(store: &str, id: &str) -> SecretGrant {
        toml::from_str(&format!(
            "source = \"store\"\nstore = \"{store}\"\nid = \"{id}\""
        ))
        .expect("a store reference parses")
    }

    fn proxy_env() -> BepSettings {
        BepSettings {
            steering: Some(Steering::ProxyEnv),
            ..BepSettings::default()
        }
    }

    fn rendered(
        secrets: &SecretGrants,
        bep: &BepSettings,
        quic443: Option<Quic443>,
        acknowledged: bool,
    ) -> anyhow::Result<String> {
        let mut out = Vec::new();
        render(
            &SpecInputs {
                root_fingerprint: Some("abc123"),
                bep,
                quic443,
                secrets,
                acknowledged,
                // An own-address box on the VM host, whose switch resolves
                // box names (BEP-017).
                network: boxes::NetworkMode::OwnIp,
                box_zone_resolver: true,
                github_hosts: HOSTS,
                store_rules: &StoreRules::new(),
                tables: BepTables::SESSION,
            },
            &mut out,
        )?;
        Ok(String::from_utf8(out).expect("utf-8"))
    }

    /// BEP-038, BEP-063: a store reference prints the authorities its
    /// matching rule registers, and only a rule for the same store matches.
    #[test]
    fn box_spec_lists_store_references_with_their_authorities() {
        let secrets =
            SecretGrants::from([("CLAUDE".to_string(), store_grant("keychain", "claude"))]);
        let rule = |store: &str| boxes::core::bep::StoreRuleConfig {
            store: Some(store.to_string()),
            upstream: vec![
                "api.anthropic.com".into(),
                "console.anthropic.com:8443".into(),
            ],
            header: Some("x-api-key".into()),
            prefix: None,
            basic_auth: None,
            action: None,
        };
        let render_with = |rules: &StoreRules| {
            let mut out = Vec::new();
            render(
                &SpecInputs {
                    root_fingerprint: Some("abc123"),
                    bep: &proxy_env(),
                    quic443: None,
                    secrets: &secrets,
                    acknowledged: false,
                    network: boxes::NetworkMode::OwnIp,
                    box_zone_resolver: false,
                    github_hosts: HOSTS,
                    store_rules: rules,
                    tables: BepTables::SESSION,
                },
                &mut out,
            )
            .expect("renders");
            String::from_utf8(out).expect("utf-8")
        };

        let rules = StoreRules::from([("claude".to_string(), rule("keychain"))]);
        let text = render_with(&rules);
        assert!(
            text.contains(
                "store  claude  CLAUDE  upstream api.anthropic.com, \
                 console.anthropic.com:8443\n"
            ),
            "{text}"
        );

        // A rule for another store does not match the reference.
        let other = StoreRules::from([("claude".to_string(), rule("vault"))]);
        let text = render_with(&other);
        assert!(
            text.contains(
                "store  claude  CLAUDE  no rule in [secret-store-rules] in config.toml\n"
            ),
            "{text}"
        );

        // A deny rule lists no authorities, even when it keeps an upstream.
        let mut denied = rule("keychain");
        denied.action = Some(StoreAction::Deny);
        let text = render_with(&StoreRules::from([("claude".to_string(), denied)]));
        assert!(
            text.contains(
                "store  claude  CLAUDE  denied by its rule in [secret-store-rules] in \
                 config.toml\n"
            ),
            "{text}"
        );
        assert!(!text.contains("api.anthropic.com"), "{text}");

        // A rule with no store is a rule for the keychain.
        let mut native = rule("keychain");
        native.store = None;
        let text = render_with(&StoreRules::from([("claude".to_string(), native)]));
        assert!(
            text.contains("store  claude  CLAUDE  upstream api.anthropic.com"),
            "{text}"
        );

        // A reference in another store names the store.
        let secrets = SecretGrants::from([("CLAUDE".to_string(), store_grant("vault", "claude"))]);
        let mut out = Vec::new();
        render(
            &SpecInputs {
                root_fingerprint: Some("abc123"),
                bep: &proxy_env(),
                quic443: None,
                secrets: &secrets,
                acknowledged: false,
                network: boxes::NetworkMode::OwnIp,
                box_zone_resolver: false,
                github_hosts: HOSTS,
                store_rules: &other,
                tables: BepTables::SESSION,
            },
            &mut out,
        )
        .expect("renders");
        let text = String::from_utf8(out).expect("utf-8");
        assert!(
            text.contains("store  vault:claude  CLAUDE  upstream api.anthropic.com"),
            "{text}"
        );

        // A broker scope is not a store reference. The preview refuses it,
        // as box creation does.
        let secrets = SecretGrants::from([
            ("CLAUDE".to_string(), store_grant("vault", "claude")),
            ("OLD".to_string(), grant(&["claude"])),
        ]);
        let mut out = Vec::new();
        let error = render(
            &SpecInputs {
                root_fingerprint: Some("abc123"),
                bep: &proxy_env(),
                quic443: None,
                secrets: &secrets,
                acknowledged: false,
                network: boxes::NetworkMode::OwnIp,
                box_zone_resolver: false,
                github_hosts: HOSTS,
                store_rules: &other,
                tables: BepTables::SESSION,
            },
            &mut out,
        )
        .expect_err("the old spelling is refused");
        let refused = error
            .downcast_ref::<ActivationRefused>()
            .expect("an activation refusal");
        assert_eq!(
            refused.refusals,
            vec![BepRefusal::BrokerScopeNotGithub {
                grant: "OLD".into(),
                scope: "claude".into(),
                table: "[defaults.session.secrets]".into(),
            }]
        );
        assert!(out.is_empty(), "no rows before the refusal");
    }

    /// BEP-038: the root fingerprint, the upstream hosts per grant, the
    /// steering mode and each store reference.
    #[test]
    fn box_spec_renders_ca_upstreams_steering_and_references() {
        let secrets = SecretGrants::from([
            ("GH_TOKEN".to_string(), grant(&["github:user-token"])),
            ("NPM_TOKEN".to_string(), store_grant("keychain", "npm")),
        ]);
        let text = rendered(&secrets, &proxy_env(), None, false).expect("renders");
        assert_eq!(
            text,
            "root CA  certificate SHA256:abc123\n\
             grant  github:user-token  full  GH_TOKEN  hosts github.com, api.github.com, \
             uploads.github.com, codeload.github.com\n\
             store  npm  NPM_TOKEN  no rule in [secret-store-rules] in config.toml\n\
             steering  proxy_env\n\
             quic443  allowed (HTTP/3 bypasses the proxy)\n"
        );

        // No published root says so, and a project with no broker secret
        // prints one line.
        let mut out = Vec::new();
        let bep = proxy_env();
        render(
            &SpecInputs {
                root_fingerprint: None,
                bep: &bep,
                quic443: None,
                secrets: &secrets,
                acknowledged: false,
                network: boxes::NetworkMode::OwnIp,
                box_zone_resolver: false,
                github_hosts: HOSTS,
                store_rules: &StoreRules::new(),
                tables: BepTables::SESSION,
            },
            &mut out,
        )
        .expect("renders");
        assert!(
            String::from_utf8(out)
                .unwrap()
                .starts_with("root CA  not published yet.")
        );
        let none = rendered(&SecretGrants::new(), &proxy_env(), None, false).unwrap();
        assert_eq!(
            none,
            "This project declares no broker secret, so its box does not use the proxy.\n"
        );

        // Networking §5.4: steering `off` with a GitHub grant writes one
        // warning row after the `steering` row, and still renders.
        let off = BepSettings {
            steering: Some(Steering::Off),
            ..BepSettings::default()
        };
        let text = rendered(&secrets, &off, None, false).expect("renders with a warning");
        let warning = BepWarning::SteeringOffWithGrant {
            grants: vec!["GH_TOKEN".into()],
        };
        assert!(
            text.contains(&format!("steering  off\nwarning  {warning}\n")),
            "{text}"
        );
        assert_eq!(text.matches("warning  ").count(), 1, "{text}");
        // `proxy_env` writes no warning.
        let text = rendered(&secrets, &proxy_env(), None, false).expect("renders");
        assert!(!text.contains("warning  "), "{text}");
    }

    /// #2446, BEP-072: the root row is the fingerprint of the root
    /// certificate the proxy published, read from its identity file. An
    /// identity with no certificate reads as not published.
    #[test]
    fn box_spec_shows_the_root_certificate_fingerprint() {
        let der = b"0\x82\x01\x0a a root certificate's DER".to_vec();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");
        let identity = bep::publish::Identity::default();
        identity
            .clone()
            .with_root_certificate(&der)
            .publish(&path)
            .expect("publishes");

        let fingerprint = root_fingerprint(Some(&path)).expect("a published root");
        assert_eq!(fingerprint, bep::publish::certificate_fingerprint(&der));
        let secrets = SecretGrants::from([("GH_TOKEN".to_string(), grant(&["github:user-token"]))]);
        let bep = proxy_env();
        let mut out = Vec::new();
        render(
            &SpecInputs {
                root_fingerprint: Some(&fingerprint),
                bep: &bep,
                quic443: None,
                secrets: &secrets,
                acknowledged: false,
                network: boxes::NetworkMode::OwnIp,
                box_zone_resolver: false,
                github_hosts: HOSTS,
                store_rules: &StoreRules::new(),
                tables: BepTables::SESSION,
            },
            &mut out,
        )
        .expect("renders");
        let text = String::from_utf8(out).unwrap();
        let first = text.lines().next().unwrap();
        assert_eq!(first, format!("root CA  certificate SHA256:{fingerprint}"));
        assert!(!text.contains("thumbprint"), "{text}");
        // 32 bytes as uppercase hex pairs joined by colons.
        let hex = first.trim_start_matches("root CA  certificate SHA256:");
        assert_eq!(hex.split(':').count(), 32, "{hex}");
        assert!(
            hex.split(':').all(|pair| pair.len() == 2
                && pair
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())),
            "{hex}"
        );

        // An identity with no certificate gives no fingerprint.
        identity.publish(&path).expect("publishes");
        assert_eq!(root_fingerprint(Some(&path)), None);
        assert_eq!(root_fingerprint(None), None);
    }

    /// BEP-038: a `full` member is marked `full` beside its declared scope.
    #[test]
    fn box_spec_marks_full_breadth_member() {
        for scope in ["github:user-token", "github:repo:full"] {
            let secrets = SecretGrants::from([("GH_TOKEN".to_string(), grant(&[scope]))]);
            let text = rendered(&secrets, &proxy_env(), None, false).expect("renders");
            assert!(
                text.contains(&format!("grant  {scope}  full  GH_TOKEN")),
                "{text}"
            );
            assert!(
                !text.contains("acknowledge_full_breadth_unenrolled"),
                "{text}"
            );
        }
    }

    /// BEP-038: the allowed stance is flagged whether `allow` was declared
    /// or `auto` resolved to it, and a blocked stance prints no row.
    #[test]
    fn box_spec_flags_allowed_quic_stance_on_grant_box() {
        let secrets = SecretGrants::from([("GH_TOKEN".to_string(), grant(&["github:user-token"]))]);
        let flag = "quic443  allowed (HTTP/3 bypasses the proxy)";
        let both = BepSettings {
            steering: Some(Steering::Both),
            ..BepSettings::default()
        };
        let cases = [
            (proxy_env(), None, true),
            (proxy_env(), Some(Quic443::Auto), true),
            (both.clone(), Some(Quic443::Allow), true),
            (both.clone(), None, false),
            (both, Some(Quic443::Auto), false),
            (proxy_env(), Some(Quic443::Block), false),
        ];
        for (bep, quic443, flagged) in cases {
            let text = rendered(&secrets, &bep, quic443, false).expect("renders");
            assert_eq!(text.contains(flag), flagged, "{bep:?} {quic443:?}\n{text}");
        }
    }

    /// BEP-057: with the acknowledgement in the client configuration, a
    /// narrower grant renders `full` with the acknowledgement beside it.
    /// Without it, `min box spec` refuses with exit 3.
    #[test]
    fn acknowledged_narrow_grant_renders_full() {
        let dir = tempfile::tempdir().expect("tempdir");
        let user = dir.path().join("config.toml");
        std::fs::write(
            &user,
            "[loadouts]\ndefault_loadouts = []\n\n[secrets]\nacknowledge_full_breadth_unenrolled = true\n",
        )
        .unwrap();
        let organization = dir.path().join("missing.toml");
        let acknowledged =
            crate::config::acknowledged_in(&[user, organization.clone()]).expect("reads");
        assert!(acknowledged);
        assert!(!crate::config::acknowledged_in(&[organization]).expect("reads"));

        let secrets = SecretGrants::from([("GH_TOKEN".to_string(), grant(&["github:repo:read"]))]);
        let text = rendered(&secrets, &proxy_env(), None, acknowledged).expect("renders");
        assert!(
            text.contains("grant  github:repo:read  full  GH_TOKEN  hosts github.com"),
            "{text}"
        );
        assert!(
            text.contains(
                "  acknowledge_full_breadth_unenrolled is set in config.toml: for the life \
                 of this box, GH_TOKEN reaches every repository your GitHub sign-in reaches"
            ),
            "{text}"
        );

        let err = rendered(&secrets, &proxy_env(), None, false).expect_err("refused");
        let refused = err
            .downcast_ref::<ActivationRefused>()
            .expect("an activation refusal");
        assert_eq!(refused.exit_code(), 3);
        assert!(refused.to_string().contains("GH_TOKEN"), "{refused}");
        assert!(
            refused
                .to_string()
                .contains("acknowledge_full_breadth_unenrolled"),
            "{refused}"
        );
    }
}

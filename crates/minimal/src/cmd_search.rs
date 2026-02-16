use clap::ValueEnum;
use common::SpecOrigin;
use graph::{BuildSpec, BuildSpecInput, BuildSpecRef, RuntimeDep};
use mctx::{Context, Error};
use serde::Serialize;
use tracing::debug;

#[derive(Debug, clap::Args)]
pub struct SearchArgs {
    /// Search query (matches package name, supports partial/fuzzy). Empty string lists all.
    query: String,

    /// Only show packages from a specific origin/layer
    #[arg(long)]
    origin: Option<String>,

    /// Output format
    #[arg(long, default_value = "table")]
    format: OutputFormat,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Yaml,
    Toml,
    /// Just names, one per line (for scripting)
    Names,
}

#[derive(Debug, clap::Args)]
pub struct InfoArgs {
    /// Package name to show details for
    package: String,

    /// Output format
    #[arg(long, default_value = "text")]
    format: InfoFormat,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum InfoFormat {
    Text,
    Json,
    Yaml,
    Toml,
}

/// Serializable representation of a package for structured output.
#[derive(Serialize)]
struct PackageEntry {
    name: String,
    version: String,
    outputs: Vec<String>,
}

/// Serializable representation of detailed package info for structured output.
#[derive(Serialize)]
struct PackageInfo {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    origin: String,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_provenance: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    source_archives: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    outputs: Vec<OutputEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    build_inputs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    runtime_deps: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    needs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tests: Vec<String>,
    spec_hash: String,
}

#[derive(Serialize)]
struct OutputEntry {
    name: String,
    kind: String,
}

/// Wrapper for TOML serialization of a list (TOML requires a top-level table).
#[derive(Serialize)]
struct PackageList {
    packages: Vec<PackageEntry>,
}

#[derive(Serialize)]
struct PackageInfoWrapper {
    package: PackageInfo,
}

pub async fn cmd_search(args: SearchArgs, ctx: &mut Context) -> Result<(), Error> {
    let t0 = std::time::Instant::now();
    let graph = ctx.graph_from_all_packages()?;
    debug!(
        phase = "graph_load",
        elapsed_ms = t0.elapsed().as_millis() as u64
    );

    let query_lower = args.query.to_lowercase();

    // Only search top-level packages — these are the ones users can reference
    // in minimal.toml or use via `minimal shell`. Transitive build dependencies
    // (internal toolchain components, bootstrap specs, etc.) are excluded.
    let mut matches: Vec<(BuildSpecRef, &BuildSpec)> = graph
        .top_levels
        .iter()
        .filter_map(|bsr| graph.get(bsr).map(|spec| (*bsr, spec)))
        .filter(|(_, spec)| {
            if query_lower.is_empty() {
                return true;
            }
            let name_lower = spec.name.to_lowercase();
            name_lower.starts_with(&query_lower)
                || name_lower.contains(&query_lower)
                || fuzzy_match(&query_lower, &name_lower)
        })
        .collect();

    // Filter by origin if specified
    if let Some(ref origin_filter) = args.origin {
        let origin_lower = origin_filter.to_lowercase();
        matches.retain(|(_, spec)| {
            let origin_str = format_origin(&spec.from);
            origin_str.to_lowercase().contains(&origin_lower)
        });
    }

    // Sort: exact prefix matches first, then contains, then fuzzy; alphabetical within each tier
    if !query_lower.is_empty() {
        matches.sort_by(|(_, a), (_, b)| {
            let a_name = a.name.to_lowercase();
            let b_name = b.name.to_lowercase();
            let a_score = match_score(&query_lower, &a_name);
            let b_score = match_score(&query_lower, &b_name);
            a_score.cmp(&b_score).then(a_name.cmp(&b_name))
        });
    } else {
        matches.sort_by(|(_, a), (_, b)| a.name.cmp(&b.name));
    }

    match args.format {
        OutputFormat::Table => print_table(&matches),
        OutputFormat::Names => {
            for (_, spec) in &matches {
                println!("{}", spec.name);
            }
        }
        fmt => {
            let entries: Vec<PackageEntry> = matches
                .iter()
                .map(|(_, spec)| PackageEntry {
                    name: spec.name.clone(),
                    version: upstream_version(spec).unwrap_or_default(),
                    outputs: spec.outputs.keys().cloned().collect(),
                })
                .collect();
            match fmt {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&entries).unwrap());
                }
                OutputFormat::Yaml => print_yaml_list(&entries),
                OutputFormat::Toml => {
                    let wrapper = PackageList { packages: entries };
                    println!("{}", toml::to_string_pretty(&wrapper).unwrap());
                }
                _ => unreachable!(),
            }
        }
    }

    if matches.is_empty() {
        eprintln!("No packages found matching '{}'", args.query);
    } else {
        eprintln!("\n{} package(s) found", matches.len());
    }

    Ok(())
}

pub async fn cmd_info(args: InfoArgs, ctx: &mut Context) -> Result<(), Error> {
    let graph = ctx.graph_from_all_packages()?;

    let found = graph.by_name(&args.package);

    match found {
        Some(bsr) => {
            let spec = graph.get(bsr).unwrap();

            let build_deps: Vec<String> = spec
                .inputs
                .iter()
                .filter_map(|input| match input {
                    BuildSpecInput::Build(dep_bsr) => graph.get(dep_bsr).map(|s| s.name.clone()),
                    BuildSpecInput::Subset(si) => graph.get(&si.from).map(|s| s.name.clone()),
                    _ => None,
                })
                .collect();

            let rt_deps: Vec<String> = spec
                .runtime_deps
                .iter()
                .map(|rd| match rd {
                    RuntimeDep::Build(dep_bsr) => dep_bsr,
                    RuntimeDep::Subset(si) => &si.from,
                })
                .filter_map(|dep_bsr| graph.get(dep_bsr).map(|s| s.name.clone()))
                .collect();

            let sources: Vec<String> = spec
                .inputs
                .iter()
                .filter_map(|input| match input {
                    BuildSpecInput::Source(si) => Some(format_source_fetch(&si.from)),
                    _ => None,
                })
                .collect();

            let outputs: Vec<OutputEntry> = spec
                .outputs
                .iter()
                .map(|(name, output)| OutputEntry {
                    name: name.clone(),
                    kind: format_output(output),
                })
                .collect();

            let needs: Vec<String> = spec.abstract_deps.keys().cloned().collect();

            let tests: Vec<String> = spec
                .tests
                .as_ref()
                .map(|t| t.keys().cloned().collect())
                .unwrap_or_default();

            let pkg_type = if spec.is_pure_prebuilt() {
                Some("prebuilt".to_string())
            } else if spec.is_pure_collection() {
                Some("collection".to_string())
            } else {
                None
            };

            let hash = graph.spec_hash(bsr);

            let info = PackageInfo {
                name: spec.name.clone(),
                version: upstream_version(spec),
                origin: format_origin(&spec.from),
                target: format!("{:?}", spec.target),
                r#type: pkg_type,
                source_provenance: spec.attrs.get("source_provenance").map(format_provenance),
                source_archives: sources,
                outputs,
                build_inputs: build_deps,
                runtime_deps: rt_deps,
                needs,
                tests,
                spec_hash: hash.0.to_string(),
            };

            match args.format {
                InfoFormat::Text => print_info_text(&info, spec),
                InfoFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&info).unwrap());
                }
                InfoFormat::Yaml => print_yaml_info(&info),
                InfoFormat::Toml => {
                    let wrapper = PackageInfoWrapper { package: info };
                    println!("{}", toml::to_string_pretty(&wrapper).unwrap());
                }
            }
        }
        None => {
            eprintln!("Package '{}' not found", args.package);

            // Suggest similar names from top-level packages only
            let query_lower = args.package.to_lowercase();
            let suggestions: Vec<&str> = graph
                .top_levels
                .iter()
                .filter_map(|bsr| graph.get(bsr))
                .filter(|spec| {
                    let name_lower = spec.name.to_lowercase();
                    name_lower.contains(&query_lower) || fuzzy_match(&query_lower, &name_lower)
                })
                .map(|spec| spec.name.as_str())
                .take(5)
                .collect();
            if !suggestions.is_empty() {
                eprintln!("Did you mean:");
                for s in suggestions {
                    eprintln!("  - {}", s);
                }
            }
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_info_text(info: &PackageInfo, spec: &BuildSpec) {
    println!("Package: {}", info.name);

    if let Some(ver) = &info.version {
        println!("Version: {}", ver);
    }

    println!("Origin:  {}", info.origin);
    println!("Target:  {}", info.target);

    if let Some(t) = &info.r#type {
        println!("Type:    {}", t);
    }

    if let Some(prov) = &info.source_provenance {
        println!("Source:  {}", prov);
    }

    if !info.source_archives.is_empty() {
        println!("\nSource archives:");
        for src in &info.source_archives {
            println!("  - {}", src);
        }
    }

    if !info.outputs.is_empty() {
        println!("\nOutputs:");
        for o in &info.outputs {
            println!("  {}: {}", o.name, o.kind);
        }
    }

    if !info.build_inputs.is_empty() {
        println!("\nBuild inputs:");
        for dep in &info.build_inputs {
            println!("  - {}", dep);
        }
    }

    if !info.runtime_deps.is_empty() {
        println!("\nRuntime dependencies:");
        for dep in &info.runtime_deps {
            println!("  - {}", dep);
        }
    }

    if !info.needs.is_empty() {
        println!("\nNeeds:");
        for name in &info.needs {
            println!("  - {}", name);
        }
    }

    if !info.tests.is_empty() {
        println!("\nTests:");
        for name in &info.tests {
            println!("  - {}", name);
        }
    }

    // Extra attrs not captured in the structured info
    let reserved = ["upstream_version", "source_provenance"];
    let extra_attrs: Vec<_> = spec
        .attrs
        .iter()
        .filter(|(k, _)| !reserved.contains(&k.as_str()))
        .collect();
    if !extra_attrs.is_empty() {
        println!("\nAttributes:");
        for (k, v) in &extra_attrs {
            println!("  {}: {}", k, format_attr(v));
        }
    }

    println!("\nSpec hash: {}", info.spec_hash);
}

/// Returns a score for sorting: 0 = exact, 1 = prefix, 2 = contains, 3 = fuzzy.
fn match_score(query: &str, name: &str) -> u8 {
    if name == query {
        0
    } else if name.starts_with(query) {
        1
    } else if name.contains(query) {
        2
    } else {
        3
    }
}

/// Simple subsequence fuzzy matcher: all query chars appear in order in target.
fn fuzzy_match(query: &str, target: &str) -> bool {
    let mut query_chars = query.chars();
    let mut current = query_chars.next();
    for c in target.chars() {
        if let Some(q) = current {
            if c == q {
                current = query_chars.next();
            }
        } else {
            return true;
        }
    }
    current.is_none()
}

fn format_origin(origin: &SpecOrigin) -> String {
    match origin {
        SpecOrigin::LocalDir { given, .. } => format!("local:{}", given.display()),
        SpecOrigin::Repo(repo) => match repo {
            common::repo_spec::Repo::Git { url, rev, .. } => {
                format!("{}@{}", url, &rev[..rev.len().min(8)])
            }
        },
        SpecOrigin::Inline => "inline".to_string(),
    }
}

fn format_attr(val: &graph::dep_graph::AttrValue) -> String {
    match val {
        graph::dep_graph::AttrValue::String(s) => s.clone(),
        graph::dep_graph::AttrValue::Bool(b) => b.to_string(),
        graph::dep_graph::AttrValue::List(items) => {
            let formatted: Vec<String> = items.iter().map(format_attr).collect();
            formatted.join(", ")
        }
        graph::dep_graph::AttrValue::Map(map) => {
            let formatted: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}={}", k, format_attr(v)))
                .collect();
            formatted.join(", ")
        }
        graph::dep_graph::AttrValue::EnumVariant(variant, val) => {
            format!("'{} {}", variant, format_attr(val))
        }
    }
}

fn format_provenance(val: &graph::dep_graph::AttrValue) -> String {
    if let graph::dep_graph::AttrValue::Map(map) = val {
        let category = map
            .get("category")
            .map(|v| match v {
                graph::dep_graph::AttrValue::EnumVariant(s, _) => s.clone(),
                other => format_attr(other),
            })
            .unwrap_or_default();
        let owner = map.get("owner").map(format_attr).unwrap_or_default();
        let repo = map.get("repo").map(format_attr).unwrap_or_default();

        if !owner.is_empty() && !repo.is_empty() {
            format!("{} ({}/{})", category, owner, repo)
        } else {
            category
        }
    } else {
        format_attr(val)
    }
}

fn format_source_fetch(fetch: &graph::SourceFetch) -> String {
    match fetch {
        graph::SourceFetch::Web { url, .. } => url.clone(),
        graph::SourceFetch::Local { filename, .. } => format!("local:{}", filename),
    }
}

fn format_output(output: &graph::BuildOutput) -> String {
    match output {
        graph::BuildOutput::Binary { glob } => format!("binary({})", glob),
        graph::BuildOutput::Library { glob, .. } => format!("library({})", glob),
        graph::BuildOutput::Data { glob, .. } => format!("data({})", glob),
    }
}

/// Extract upstream_version from a BuildSpec's attrs, if present.
fn upstream_version(spec: &BuildSpec) -> Option<String> {
    spec.attrs.get("upstream_version").map(format_attr)
}

fn print_table(matches: &[(BuildSpecRef, &BuildSpec)]) {
    if matches.is_empty() {
        return;
    }

    let name_width = matches
        .iter()
        .map(|(_, s)| s.name.len())
        .max()
        .unwrap_or(4)
        .clamp(4, 40);

    let ver_width = matches
        .iter()
        .map(|(_, s)| upstream_version(s).as_deref().unwrap_or("-").len())
        .max()
        .unwrap_or(7)
        .clamp(7, 15);

    println!(
        "{:<nw$}  {:<vw$}  OUTPUTS",
        "NAME",
        "VERSION",
        nw = name_width,
        vw = ver_width,
    );
    println!(
        "{:-<nw$}  {:-<vw$}  {:-<20}",
        "",
        "",
        "",
        nw = name_width,
        vw = ver_width,
    );

    for (_, spec) in matches {
        let outputs: Vec<&String> = spec.outputs.keys().collect();
        let name_display = if spec.name.len() > 40 {
            format!("{}...", &spec.name[..37])
        } else {
            spec.name.clone()
        };
        let ver = upstream_version(spec);
        println!(
            "{:<nw$}  {:<vw$}  {}",
            name_display,
            ver.as_deref().unwrap_or("-"),
            if outputs.is_empty() {
                "-".to_string()
            } else {
                outputs
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            nw = name_width,
            vw = ver_width,
        );
    }
}

/// Print a YAML list of package entries without requiring a YAML crate.
fn print_yaml_list(entries: &[PackageEntry]) {
    for entry in entries {
        println!("- name: \"{}\"", entry.name);
        println!("  version: \"{}\"", entry.version);
        if entry.outputs.is_empty() {
            println!("  outputs: []");
        } else {
            println!("  outputs:");
            for o in &entry.outputs {
                println!("    - \"{}\"", o);
            }
        }
    }
}

/// Print YAML for detailed package info without requiring a YAML crate.
fn print_yaml_info(info: &PackageInfo) {
    println!("name: \"{}\"", info.name);
    if let Some(ver) = &info.version {
        println!("version: \"{}\"", ver);
    }
    println!("origin: \"{}\"", info.origin);
    println!("target: \"{}\"", info.target);
    if let Some(t) = &info.r#type {
        println!("type: \"{}\"", t);
    }
    if let Some(prov) = &info.source_provenance {
        println!("source_provenance: \"{}\"", prov);
    }
    print_yaml_string_list("source_archives", &info.source_archives);
    if !info.outputs.is_empty() {
        println!("outputs:");
        for o in &info.outputs {
            println!("  - name: \"{}\"", o.name);
            println!("    kind: \"{}\"", o.kind);
        }
    }
    print_yaml_string_list("build_inputs", &info.build_inputs);
    print_yaml_string_list("runtime_deps", &info.runtime_deps);
    print_yaml_string_list("needs", &info.needs);
    print_yaml_string_list("tests", &info.tests);
    println!("spec_hash: \"{}\"", info.spec_hash);
}

fn print_yaml_string_list(key: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    println!("{}:", key);
    for item in items {
        println!("  - \"{}\"", item);
    }
}

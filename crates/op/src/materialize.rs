//! Materializing a declared output — an OCI image, or a single file lifted out
//! of the built package closure — into a sink.
//!
//! [`Materialize`] requires [`Options::graph`]'s top levels to be built and in
//! [`Options::cache`] already, and takes the target architecture from the
//! graph. [`OutputSpec`] is self-contained, so a caller with no `minimal.toml`
//! can build one directly.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use futures::channel::mpsc::UnboundedSender;
use graph::Transitives;

use crate::oci_image::OciImage;
use crate::{Error, Options, Runnable};

/// What to produce, independent of where it goes or what built it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSpec {
    /// A tarball of an OCI image layout, one layer per package in the closure.
    OciImage {
        /// The image's entrypoint, already split into argv.
        entrypoint: Option<Vec<String>>,
        /// The image's default command, already split into argv.
        cmd: Option<Vec<String>>,
        /// Environment variables baked into the image config.
        vars: HashMap<String, String>,
    },
    /// A single file at `path`, taken from the first package in the closure
    /// that ships it.
    RawFile { path: String },
}

impl TryFrom<mfile::OutputKind> for OutputSpec {
    type Error = Error;

    /// Word-splits the shell-string forms `minimal.toml` permits, so an
    /// unbalanced quote errors here rather than reaching the image config.
    fn try_from(kind: mfile::OutputKind) -> Result<Self, Error> {
        fn argv(field: &str, v: mfile::StrOrList) -> Result<Vec<String>, Error> {
            match v {
                mfile::StrOrList::Single(s) => shlex::split(&s).ok_or_else(|| {
                    Error::Other(anyhow!("`{field}` is not a valid shell word list: {s:?}"))
                }),
                mfile::StrOrList::Multiple(v) => Ok(v),
            }
        }

        Ok(match kind {
            mfile::OutputKind::OciImage {
                entrypoint,
                cmd,
                vars,
            } => OutputSpec::OciImage {
                entrypoint: entrypoint.map(|e| argv("entrypoint", e)).transpose()?,
                cmd: cmd.map(|c| argv("cmd", c)).transpose()?,
                vars,
            },
            mfile::OutputKind::RawFile { path } => OutputSpec::RawFile { path },
        })
    }
}

/// Where an artifact's bytes go.
pub enum Sink {
    /// Create (or truncate) this file and write into it.
    Path(PathBuf),
    /// Stream into a writer the caller owns. Carries no unix mode, so a
    /// [`OutputSpec::RawFile`] arrives without its executable bit — see
    /// [`Report::mode`].
    Writer(Box<dyn Write + Send>),
}

/// Progress emitted while an artifact is assembled. [`Materialize`] never
/// prints; every consumer renders these itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializeEvent {
    /// Assembly of the named output began, from these top-level packages.
    Started {
        output: String,
        packages: Vec<String>,
    },
    /// The image will be assembled from this many layers, base layer included.
    Layers { total: usize },
    /// A layer's assembly started.
    LayerStarted { package: String, subset: bool },
    /// A layer was archived, compressed and digested. `bytes` is compressed.
    LayerFinished {
        package: String,
        subset: bool,
        bytes: u64,
    },
    /// The image's target architecture, as read from the graph.
    Architecture { arch: String },
    /// A [`OutputSpec::RawFile`] was located in this package's cached build.
    Found { package: String, path: String },
    /// The artifact is complete.
    Finished { bytes: u64 },
}

impl MaterializeEvent {
    /// This event as one human-readable log line. Shared so every transport
    /// reports a materialize identically.
    pub fn render(&self) -> String {
        fn layer(package: &str, subset: bool) -> Cow<'_, str> {
            match subset {
                true => Cow::Owned(format!("{package} (subset)")),
                false => Cow::Borrowed(package),
            }
        }

        match self {
            MaterializeEvent::Started { output, packages } => {
                format!("Materializing {output} from packages: {packages:?}")
            }
            MaterializeEvent::Layers { total } => format!(
                "Will create {total} layers: base layer + {} packages",
                total.saturating_sub(1)
            ),
            MaterializeEvent::LayerStarted { package, subset } => {
                format!("Creating layer for: {}", layer(package, *subset))
            }
            MaterializeEvent::LayerFinished {
                package,
                subset,
                bytes,
            } => format!(
                "Created layer for {}: {}",
                layer(package, *subset),
                size::Size::from_bytes(*bytes)
            ),
            MaterializeEvent::Architecture { arch } => format!("OCI image architecture: {arch}"),
            MaterializeEvent::Found { package, path } => format!("Found {path} in {package}"),
            MaterializeEvent::Finished { bytes } => {
                format!("Wrote {}", size::Size::from_bytes(*bytes))
            }
        }
    }
}

/// Best-effort progress reporting; a hung-up receiver must never fail the
/// artifact.
#[derive(Clone)]
pub(crate) struct Emitter(Option<UnboundedSender<MaterializeEvent>>);

impl Emitter {
    pub(crate) fn send(&self, event: MaterializeEvent) {
        if let Some(tx) = &self.0 {
            let _ = tx.unbounded_send(event);
        }
    }
}

/// What was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// Bytes written to the sink.
    pub bytes: u64,
    /// The source file's unix mode, for a [`OutputSpec::RawFile`]. Already
    /// applied for [`Sink::Path`]; a [`Sink::Writer`] caller must reapply it.
    pub mode: Option<u32>,
}

/// Produces the artifact described by `spec` from the already-built top levels
/// of [`Options::graph`].
pub struct Materialize {
    /// The image's `org.opencontainers.image.ref.name` annotation.
    pub name: String,
    pub spec: OutputSpec,
    pub sink: Sink,
    pub events: Option<UnboundedSender<MaterializeEvent>>,
}

impl Runnable for Materialize {
    type Result = Report;

    /// Archives and gzips the whole closure on the calling thread (via
    /// `rayon`): an async caller should `spawn_blocking` this.
    #[tracing::instrument(skip_all, fields(output = %self.name), err)]
    async fn run(&mut self, opts: &Options<'_>) -> Result<Report, Error> {
        // Destructured for disjoint field borrows.
        let Materialize {
            name,
            spec,
            sink,
            events,
        } = self;
        let events = Emitter(events.clone());

        events.send(MaterializeEvent::Started {
            output: name.clone(),
            packages: opts
                .graph
                .top_levels
                .iter()
                .filter_map(|bsr| opts.graph.get(bsr))
                .map(|build| build.name.clone())
                .collect(),
        });

        let report = match spec {
            OutputSpec::OciImage {
                entrypoint,
                cmd,
                vars,
            } => {
                let image = OciImage {
                    name,
                    entrypoint: entrypoint.as_deref(),
                    cmd: cmd.as_deref(),
                    vars,
                };
                // Flushed explicitly: dropping a buffered sink would swallow
                // the error and truncate the artifact silently.
                let bytes = match sink {
                    Sink::Path(path) => {
                        let file = std::fs::File::create(&path).map_err(|e| {
                            Error::Other(anyhow!("creating {}: {e}", path.display()))
                        })?;
                        let mut w = image.write(opts, Counted::new(file), &events).await?;
                        w.flush()?;
                        w.bytes
                    }
                    Sink::Writer(w) => {
                        let mut w = image.write(opts, Counted::new(w), &events).await?;
                        w.flush()?;
                        w.bytes
                    }
                };
                Report { bytes, mode: None }
            }
            OutputSpec::RawFile { path } => extract_raw_file(opts, path, sink, &events)?,
        };

        events.send(MaterializeEvent::Finished {
            bytes: report.bytes,
        });
        Ok(report)
    }
}

/// Finds `path` in the closure of the graph's top levels and delivers it to
/// `sink`. Probed in package-name order: a path shipped by more than one
/// package must resolve the same way on every run.
fn extract_raw_file(
    opts: &Options<'_>,
    path: &str,
    sink: &mut Sink,
    events: &Emitter,
) -> Result<Report, Error> {
    let rel_path = path.strip_prefix('/').unwrap_or(path);

    let mut closure: Vec<_> =
        Transitives::for_toplevels(opts.graph, opts.graph.top_levels.to_vec(), false)
            .into_keys()
            .map(|bsr| (opts.graph.get(&bsr).map(|b| b.name.clone()), bsr))
            .collect();
    closure.sort();

    for (package, bsr) in closure {
        let dir = opts
            .cache
            .read_dir(&opts.graph.spec_hash(&bsr))
            .map_err(|e| Error::Other(anyhow!(e)))?;
        let candidate = dir.path().join(rel_path);
        if !candidate.exists() {
            continue;
        }

        let package = package.unwrap_or_default();
        events.send(MaterializeEvent::Found {
            package: package.clone(),
            path: path.to_string(),
        });
        return deliver_file(&candidate, sink);
    }

    Err(Error::Other(anyhow!(
        "raw-file output {path:?} was not found in the built package set"
    )))
}

/// Copies `src` into `sink`, preserving its unix mode when the sink is a path.
fn deliver_file(src: &Path, sink: &mut Sink) -> Result<Report, Error> {
    let mode = std::fs::metadata(src)
        .map_err(|e| Error::Other(anyhow!("reading {}: {e}", src.display())))?
        .permissions()
        .mode();

    let bytes = match sink {
        // `fs::copy` carries the mode across, which a writer cannot.
        Sink::Path(dest) => std::fs::copy(src, &dest).map_err(|e| {
            Error::Other(anyhow!(
                "copying output file {} to {}: {e}",
                src.display(),
                dest.display()
            ))
        })?,
        Sink::Writer(w) => {
            let mut f = std::fs::File::open(src)
                .map_err(|e| Error::Other(anyhow!("opening {}: {e}", src.display())))?;
            let n = std::io::copy(&mut f, w)
                .map_err(|e| Error::Other(anyhow!("streaming {}: {e}", src.display())))?;
            // A buffered writer holds the tail until flushed.
            w.flush()
                .map_err(|e| Error::Other(anyhow!("flushing {}: {e}", src.display())))?;
            n
        }
    };

    Ok(Report {
        bytes,
        mode: Some(mode),
    })
}

/// Tallies bytes passing through, so [`Report::bytes`] works for any [`Sink`].
pub(crate) struct Counted<W> {
    inner: W,
    pub(crate) bytes: u64,
}

impl<W: Write> Counted<W> {
    fn new(inner: W) -> Self {
        Self { inner, bytes: 0 }
    }
}

impl<W: Write> Write for Counted<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::Layer;
    use graph::Graph;
    use indoc::indoc;
    use lcache::{Cache, EntryMeta, LocalDir, MetaInner};
    use tempfile::TempDir;

    /// A closure of two packages that both ship `bin/tool`: `zzz` is the top
    /// level and `aaa` its runtime dependency. Name order therefore disagrees
    /// with dependency order, which is what makes it a useful collision case.
    const COLLIDING: &str = indoc! {r#"
        let {BuildSpec, OutputData, ..} = import "minimal.ncl" in
        let aaa = {
            name = "aaa",
            build_deps = [],
            cmd = "",
            outputs = { f = {glob = "bin/tool"} | OutputData },
        } | BuildSpec
        in
        {
            name = "zzz",
            build_deps = [],
            runtime_deps = [aaa],
            cmd = "",
            outputs = { f = {glob = "bin/tool"} | OutputData },
        } | BuildSpec
    "#};

    /// Ingests `ncl` and makes `top_level` the graph's sole top level.
    fn graph_from(ncl: &str, top_level: &str) -> Graph {
        let mut g = Graph::new()
            .ingest(Layer::new_for_test(ncl.to_string()).unwrap())
            .unwrap();
        g.top_levels = vec![*g.by_name(top_level).expect("package in graph")];
        g
    }

    /// Fakes a completed build of `package` whose only file is `path`, holding
    /// `content` and carrying `mode`.
    fn fake_build(
        cache: &Cache<LocalDir>,
        graph: &Graph,
        package: &str,
        path: &str,
        content: &[u8],
        mode: u32,
    ) {
        let hash = graph.spec_hash(graph.by_name(package).expect("package in graph"));
        let pending = cache.write_dir(&hash).expect("write cache dir");
        let file = pending.path().join(path);
        std::fs::create_dir_all(file.parent().unwrap()).expect("create parent dir");
        std::fs::write(&file, content).expect("write build output");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode))
            .expect("set output mode");
        pending
            .finalize(EntryMeta {
                inner: MetaInner::Spec(package.to_string()),
                ..Default::default()
            })
            .expect("finalize cache entry");
    }

    fn materialize(graph: &Graph, cache: Cache<LocalDir>, sink: Sink) -> Result<Report, Error> {
        let opts = Options {
            cache,
            graph,
            exec_base: "/not-exists".into(),
            ot: None,
        };
        futures::executor::block_on(
            Materialize {
                name: "out".to_string(),
                spec: OutputSpec::RawFile {
                    path: "/bin/tool".to_string(),
                },
                sink,
                events: None,
            }
            .run(&opts),
        )
    }

    /// A raw-file output is copied out of the package that ships it, and a
    /// path sink preserves the source's mode — an extracted binary that lost
    /// its executable bit would be useless.
    #[test]
    fn raw_file_copies_to_a_path_preserving_mode() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let graph = graph_from(
            indoc! {r#"
                let {BuildSpec, OutputData, ..} = import "minimal.ncl" in
                {
                    name = "only",
                    build_deps = [],
                    cmd = "",
                    outputs = { f = {glob = "bin/tool"} | OutputData },
                } | BuildSpec
            "#},
            "only",
        );
        fake_build(&cache, &graph, "only", "bin/tool", b"#!/bin/sh\n", 0o755);

        let dest = tmp.path().join("extracted");
        let report = materialize(&graph, cache, Sink::Path(dest.clone())).expect("materialize");

        assert_eq!(std::fs::read(&dest).unwrap(), b"#!/bin/sh\n");
        assert_eq!(report.bytes, 10);
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o755,
            "a path sink must carry the source's executable bit across"
        );
    }

    /// A writer sink gets the bytes, but cannot carry a unix mode — so the
    /// report has to hand the mode back for the caller to reapply.
    #[test]
    fn raw_file_streams_to_a_writer_and_reports_the_mode() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let graph = graph_from(
            indoc! {r#"
                let {BuildSpec, OutputData, ..} = import "minimal.ncl" in
                {
                    name = "only",
                    build_deps = [],
                    cmd = "",
                    outputs = { f = {glob = "bin/tool"} | OutputData },
                } | BuildSpec
            "#},
            "only",
        );
        fake_build(&cache, &graph, "only", "bin/tool", b"streamed", 0o755);

        // A file stands in for any writer the caller owns; the point is that
        // `Materialize` never learns where the bytes are going.
        let dest = tmp.path().join("streamed");
        let sink = Sink::Writer(Box::new(std::fs::File::create(&dest).unwrap()));
        let report = materialize(&graph, cache, sink).expect("materialize");

        assert_eq!(std::fs::read(&dest).unwrap(), b"streamed");
        assert_eq!(report.bytes, 8);
        assert_eq!(
            report.mode.expect("a raw file always has a mode") & 0o777,
            0o755
        );
    }

    /// When two packages in the closure ship the same path, the winner is
    /// decided by package name — not by `HashMap` iteration order, which would
    /// vary from run to run.
    #[test]
    fn raw_file_resolves_collisions_deterministically() {
        for _ in 0..8 {
            let tmp = TempDir::new().unwrap();
            let cache = Cache::at_dir(tmp.path()).unwrap();
            let graph = graph_from(COLLIDING, "zzz");
            fake_build(&cache, &graph, "aaa", "bin/tool", b"from-aaa", 0o755);
            fake_build(&cache, &graph, "zzz", "bin/tool", b"from-zzz", 0o755);

            let dest = tmp.path().join("extracted");
            materialize(&graph, cache, Sink::Path(dest.clone())).expect("materialize");

            assert_eq!(
                std::fs::read(&dest).unwrap(),
                b"from-aaa",
                "the first package in name order must win every time"
            );
        }
    }

    /// A path no package ships is a user-facing mistake, so the error has to
    /// name it rather than reporting an empty search.
    #[test]
    fn raw_file_missing_from_the_closure_is_an_error() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let graph = graph_from(
            indoc! {r#"
                let {BuildSpec, OutputData, ..} = import "minimal.ncl" in
                {
                    name = "only",
                    build_deps = [],
                    cmd = "",
                    outputs = { f = {glob = "bin/other"} | OutputData },
                } | BuildSpec
            "#},
            "only",
        );
        fake_build(&cache, &graph, "only", "bin/other", b"not it", 0o644);

        let err = materialize(&graph, cache, Sink::Path(tmp.path().join("extracted")))
            .expect_err("the path is in no package");
        assert!(
            err.to_string().contains("/bin/tool"),
            "the error must name the path that was not found, got: {err}"
        );
    }

    /// Every event renders to a line, and the ones carrying sizes render them
    /// for humans rather than as raw byte counts. Any caller can produce the
    /// CLI's output without reimplementing the wording.
    #[test]
    fn events_render_as_log_lines() {
        assert_eq!(
            MaterializeEvent::Layers { total: 3 }.render(),
            "Will create 3 layers: base layer + 2 packages"
        );
        assert_eq!(
            MaterializeEvent::LayerFinished {
                package: "gcc".to_string(),
                subset: true,
                bytes: 3_170_893,
            }
            .render(),
            "Created layer for gcc (subset): 3.02 MiB"
        );
        assert_eq!(
            MaterializeEvent::LayerStarted {
                package: "gcc".to_string(),
                subset: false,
            }
            .render(),
            "Creating layer for: gcc"
        );
        assert_eq!(
            MaterializeEvent::Found {
                package: "kernel".to_string(),
                path: "/boot/vmlinuz".to_string(),
            }
            .render(),
            "Found /boot/vmlinuz in kernel"
        );
    }

    /// `minimal.toml` lets `entrypoint`/`cmd` be a shell string or an argv
    /// list. Both must reach the image config as argv.
    #[test]
    fn output_spec_splits_shell_strings_into_argv() {
        let spec: OutputSpec = mfile::OutputKind::OciImage {
            entrypoint: Some(mfile::StrOrList::Single("/bin/sh -c 'echo hi'".to_string())),
            cmd: Some(mfile::StrOrList::Multiple(vec!["--flag".to_string()])),
            vars: HashMap::new(),
        }
        .try_into()
        .expect("a well-formed entrypoint converts");

        assert_eq!(
            spec,
            OutputSpec::OciImage {
                entrypoint: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "echo hi".to_string()
                ]),
                cmd: Some(vec!["--flag".to_string()]),
                vars: HashMap::new(),
            }
        );
    }

    /// An unbalanced quote used to panic inside the image writer. Converting up
    /// front turns it into an error naming the field at fault.
    #[test]
    fn output_spec_rejects_an_unparseable_entrypoint() {
        let err: Error = mfile::OutputKind::OciImage {
            entrypoint: Some(mfile::StrOrList::Single(
                "/bin/sh -c 'unbalanced".to_string(),
            )),
            cmd: None,
            vars: HashMap::new(),
        }
        .try_into()
        .map(|_: OutputSpec| ())
        .expect_err("an unbalanced quote cannot be split");

        assert!(
            err.to_string().contains("entrypoint"),
            "the error must name the offending field, got: {err}"
        );
    }
}

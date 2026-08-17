//! Decoding of container declarations, laid out at `<layer>/containers/<name>/spec.ncl`.

use common::{Target, target::Arch};
use nickel_lang_core::{
    eval::{cache::CacheImpl, value::NickelValue},
    program::Program,
    term::{IndexMap, RuntimeContract},
};
use serde::{Deserialize, Serialize};

use crate::{Error, ObjTy, eval_if_closure, packages_array_from_term, record_data_from_val};

/// The transport protocol of an [ExposedPort].
///
/// OCI recognises only `tcp` and `udp`, and spells them lowercase in the
/// `ExposedPorts` keys of the image config.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

impl std::fmt::Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Proto::Tcp => write!(f, "tcp"),
            Proto::Udp => write!(f, "udp"),
        }
    }
}

/// Word-splits the string form of an argv field into OCI exec form.
///
/// OCI has no shell form, so a string is split into words here and an
/// unbalanced quote is an error rather than something a shell would see.
/// Mirrors how `minimal.toml` outputs handle `entrypoint`/`cmd`.
fn argv_from_term(
    field: &'static str,
    rt: &NickelValue,
    program: &mut Program<CacheImpl>,
) -> Result<Vec<String>, Error> {
    let rt = eval_if_closure(rt, program)?;

    let argv = if let Some(s) = rt.as_string() {
        shlex::split(s.as_ref()).ok_or_else(|| {
            Error::Other(format!(
                "container `{field}` is not a valid shell word list: {:?}",
                s.as_ref()
            ))
        })?
    } else if let Some(a) = rt.as_array() {
        // `CmdSpec` is an `any_of`, so its element contract does not fire on
        // its own: without the element check here a non-string argv entry
        // reaches `String::deserialize` and panics.
        let pending = a.iter_pending_contracts().cloned().collect::<Vec<_>>();
        a.iter()
            .map(|elem| {
                let elem = RuntimeContract::apply_all(
                    elem.clone(),
                    pending.iter().cloned(),
                    elem.pos_idx(),
                );
                let elem = eval_if_closure(&elem, program)?;
                String::deserialize(elem).map_err(|_| {
                    Error::Other(format!("container `{field}` must be a list of strings"))
                })
            })
            .collect::<Result<Vec<_>, Error>>()?
    } else {
        todo!(
            "error for `{}` field being non-string & non-array, got {:?}",
            field,
            rt
        );
    };

    if argv.is_empty() {
        return Err(Error::Other(format!(
            "container `{field}` must not be empty"
        )));
    }

    Ok(argv)
}

/// A port exposed by a container image.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposedPort {
    /// The protocol the port speaks. Defaults to TCP, matching the OCI
    /// bare-port form.
    pub proto: Proto,
    /// The port number, always within 1-65535.
    pub port: u16,
}

impl ExposedPort {
    /// Deserializes an exposed-port structure from the given nickel term tree.
    pub(crate) fn from_term(
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
    ) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        let mut proto: Option<Proto> = None;
        let mut port: Option<u16> = None;

        if let Some(r) = record_data_from_val(&rt) {
            r.fields
                .iter()
                .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                    let Some(field_rt) = field.value.as_ref() else {
                        return Ok(());
                    };
                    // Field contracts are pending until applied; without this
                    // the contracts declared in minimal.ncl never run.
                    let field_rt = &RuntimeContract::apply_all(
                        field_rt.clone(),
                        field.pending_contracts.iter().cloned(),
                        field_rt.pos_idx(),
                    );

                    match ident_and_loc.label() {
                        "proto" => {
                            let p_rt = eval_if_closure(field_rt, program)?;
                            proto = Some(Proto::deserialize(p_rt).map_err(|_| {
                                Error::Other(
                                    "container port `proto` must be 'Tcp or 'Udp".to_string(),
                                )
                            })?);
                            Ok(())
                        }
                        "port" => {
                            // Deserialized as a float and range-checked here:
                            // integer deserialization saturates rather than
                            // failing, which would silently turn 70000 into
                            // 65535.
                            let n = f64::deserialize(eval_if_closure(field_rt, program)?).map_err(
                                |_| Error::Other("container port must be a number".to_string()),
                            )?;
                            if n.fract() != 0.0 || !(1.0..=65535.0).contains(&n) {
                                return Err(Error::Other(format!(
                                    "container port must be a whole number within 1-65535, got {n}"
                                )));
                            }
                            port = Some(n as u16);
                            Ok(())
                        }
                        _ => Ok(()),
                    }
                })?;
        } else {
            todo!("unexpected term for exposed_ports entry: {:?}", rt);
        }

        // A bare port is TCP in the OCI `ExposedPorts` form.
        let proto = proto.unwrap_or_default();
        let port = match port {
            Some(port) => port,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Container,
                    pos: rt.pos(program.pos_table()),
                    field: "port",
                });
            }
        };

        Ok(ExposedPort { proto, port })
    }
}

/// Parses a nickel tree representing a map of `String` to `String`.
fn string_map_from_term(
    rt: &NickelValue,
    program: &mut Program<CacheImpl>,
) -> Result<IndexMap<String, String>, Error> {
    let rt = eval_if_closure(rt, program)?;
    if let Some(r) = record_data_from_val(&rt) {
        r.fields
            .iter()
            .map(
                |(ident_and_loc, field)| -> Result<(String, String), Error> {
                    Ok((
                        ident_and_loc.label().to_string(),
                        String::deserialize(eval_if_closure(
                            field.value.as_ref().unwrap(),
                            program,
                        )?)
                        .unwrap(),
                    ))
                },
            )
            .collect::<Result<IndexMap<_, _>, Error>>()
    } else {
        todo!("unexpected term for string map: {:?}", rt)
    }
}

/// A container, a declared image assembled from packages.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Container {
    /// The human-readable name declared on the container. Unique within a repo/layer.
    pub name: String,

    /// The names of build-specs/packages which make up the image.
    pub packages: Vec<String>,

    /// The entrypoint of the image, in OCI exec form.
    pub entrypoint: Option<Vec<String>>,
    /// The default command of the image, appended to the entrypoint.
    pub cmd: Option<Vec<String>>,
    /// The architecture the image targets.
    ///
    /// Must agree with the architecture the packages were built for; see
    /// [Container::check_target].
    pub arch: Option<Arch>,
    /// The working directory processes in the image start in.
    pub working_dir: Option<String>,

    /// The environment variables baked into the image.
    ///
    /// Values are concrete: an image config carries `KEY=VALUE` strings, so
    /// there is no host-inheriting form here.
    pub env_vars: IndexMap<String, String>,

    /// The ports the image declares it listens on.
    pub exposed_ports: Vec<ExposedPort>,
    /// The paths in the image which are declared as volumes.
    pub volumes: Vec<String>,
    /// The user processes in the image run as.
    pub user: Option<String>,
    /// The signal used to stop the container.
    pub stop_signal: Option<String>,

    /// Labels applied to the image.
    pub labels: IndexMap<String, String>,
    /// Additional image-config fields, applied verbatim.
    pub config: IndexMap<String, String>,
}

impl Container {
    /// Deserializes a container structure from the given nickel term tree.
    pub fn from_term(rt: &NickelValue, program: &mut Program<CacheImpl>) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        let mut ty: Option<ObjTy> = None;
        let mut name: Option<String> = None;
        let mut packages: Option<Vec<String>> = None;
        let mut entrypoint: Option<Vec<String>> = None;
        let mut cmd: Option<Vec<String>> = None;
        let mut arch: Option<Arch> = None;
        let mut working_dir: Option<String> = None;
        let mut env_vars: Option<IndexMap<String, String>> = None;
        let mut exposed_ports: Option<Vec<ExposedPort>> = None;
        let mut volumes: Option<Vec<String>> = None;
        let mut user: Option<String> = None;
        let mut stop_signal: Option<String> = None;
        let mut labels: Option<IndexMap<String, String>> = None;
        let mut config: Option<IndexMap<String, String>> = None;

        if let Some(r) = record_data_from_val(&rt) {
            r.fields
                .iter()
                .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                    let Some(field_rt) = field.value.as_ref() else {
                        return Ok(());
                    };
                    // Field contracts are pending until applied; without this
                    // the contracts declared in minimal.ncl never run.
                    let field_rt = &RuntimeContract::apply_all(
                        field_rt.clone(),
                        field.pending_contracts.iter().cloned(),
                        field_rt.pos_idx(),
                    );

                    match ident_and_loc.label() {
                        "ty" => {
                            ty = Some(
                                ObjTy::deserialize(eval_if_closure(field_rt, program)?).unwrap(),
                            );
                            Ok(())
                        }
                        "name" => {
                            name = Some(
                                String::deserialize(eval_if_closure(field_rt, program)?).unwrap(),
                            );
                            Ok(())
                        }
                        "packages" => {
                            packages =
                                Some(packages_array_from_term("packages", field_rt, program)?);
                            Ok(())
                        }
                        "entrypoint" => {
                            entrypoint = Some(argv_from_term("entrypoint", field_rt, program)?);
                            Ok(())
                        }
                        "cmd" => {
                            cmd = Some(argv_from_term("cmd", field_rt, program)?);
                            Ok(())
                        }
                        "arch" => {
                            arch = Some(
                                Arch::deserialize(eval_if_closure(field_rt, program)?).unwrap(),
                            );
                            Ok(())
                        }
                        "working_dir" => {
                            working_dir = Some(
                                String::deserialize(eval_if_closure(field_rt, program)?).unwrap(),
                            );
                            Ok(())
                        }
                        "env_vars" => {
                            env_vars = Some(string_map_from_term(field_rt, program)?);
                            Ok(())
                        }
                        "exposed_ports" => {
                            let ports_rt = eval_if_closure(field_rt, program)?;

                            if let Some(a) = ports_rt.as_array() {
                                // Element contracts are pending on the array.
                                let pending =
                                    a.iter_pending_contracts().cloned().collect::<Vec<_>>();
                                exposed_ports = Some(
                                    a.iter()
                                        .map(|p| {
                                            let p = RuntimeContract::apply_all(
                                                p.clone(),
                                                pending.iter().cloned(),
                                                p.pos_idx(),
                                            );
                                            ExposedPort::from_term(&p, program)
                                        })
                                        .collect::<Result<Vec<_>, Error>>()?,
                                );
                            } else {
                                todo!(
                                    "handle exposed_ports value being non-array {:?}",
                                    field.value
                                );
                            }

                            Ok(())
                        }
                        "volumes" => {
                            let volumes_rt = eval_if_closure(field_rt, program)?;

                            if let Some(a) = volumes_rt.as_array() {
                                // Element contracts are pending on the array.
                                let pending =
                                    a.iter_pending_contracts().cloned().collect::<Vec<_>>();
                                volumes = Some(
                                    a.iter()
                                        .map(|v| {
                                            let v = RuntimeContract::apply_all(
                                                v.clone(),
                                                pending.iter().cloned(),
                                                v.pos_idx(),
                                            );
                                            Ok(String::deserialize(eval_if_closure(&v, program)?)
                                                .unwrap())
                                        })
                                        .collect::<Result<Vec<_>, Error>>()?,
                                );
                            } else {
                                todo!("handle volumes value being non-array {:?}", field.value);
                            }

                            Ok(())
                        }
                        "user" => {
                            user = Some(
                                String::deserialize(eval_if_closure(field_rt, program)?).unwrap(),
                            );
                            Ok(())
                        }
                        "stop_signal" => {
                            stop_signal = Some(
                                String::deserialize(eval_if_closure(field_rt, program)?).unwrap(),
                            );
                            Ok(())
                        }
                        "labels" => {
                            labels = Some(string_map_from_term(field_rt, program)?);
                            Ok(())
                        }
                        "config" => {
                            config = Some(string_map_from_term(field_rt, program)?);
                            Ok(())
                        }
                        _ => Ok(()),
                    }
                })?;
        }

        match ty {
            Some(ObjTy::Container) => {} // happy path
            None => {
                return Err(Error::MissingTy(
                    program.files(),
                    rt.pos(program.pos_table()),
                ));
            }
            Some(ty) => {
                return Err(Error::UnexpectedObject {
                    files: program.files(),
                    got: ty,
                    want: ObjTy::Container,
                    pos: rt.pos(program.pos_table()),
                });
            }
        };
        let name = match name {
            Some(name) => name,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Container,
                    pos: rt.pos(program.pos_table()),
                    field: "name",
                });
            }
        };
        let packages = match packages {
            Some(packages) => packages,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Container,
                    pos: rt.pos(program.pos_table()),
                    field: "packages",
                });
            }
        };
        if packages.is_empty() {
            return Err(Error::Other(format!(
                "container {name}: `packages` must not be empty; an image with no packages has an empty rootfs"
            )));
        }

        // `ExposedPorts` and `Volumes` are sets in the image config, so
        // duplicates would collapse into one another on the way out.
        let exposed_ports = exposed_ports.unwrap_or_default();
        if let Some(dupe) = first_duplicate(exposed_ports.iter().map(|p| (p.port, p.proto))) {
            return Err(Error::Other(format!(
                "container {name}: port {}/{} is exposed more than once",
                dupe.0, dupe.1
            )));
        }
        let volumes = volumes.unwrap_or_default();
        for volume in &volumes {
            check_volume_path(&name, volume)?;
        }
        if let Some(dupe) = first_duplicate(volumes.iter()) {
            return Err(Error::Other(format!(
                "container {name}: volume `{dupe}` is declared more than once"
            )));
        }

        Ok(Self {
            name,
            packages,
            entrypoint,
            cmd,
            arch,
            working_dir,
            env_vars: env_vars.unwrap_or_default(),
            exposed_ports,
            volumes,
            user,
            stop_signal,
            labels: labels.unwrap_or_default(),
            config: config.unwrap_or_default(),
        })
    }

    /// Checks that a declared `arch` agrees with the target the packages are
    /// built for.
    ///
    /// A mismatch produces an image whose manifest advertises one
    /// architecture while its binaries are built for another: it pulls
    /// cleanly and then fails at exec time. Decoding cannot enforce this on
    /// its own, because `arch` is also how a caller selects the target; the
    /// code that resolves a container against a graph calls this once both
    /// are known.
    pub fn check_target(&self, target: &Target) -> Result<(), Error> {
        match &self.arch {
            Some(arch) if arch != target.arch() => Err(Error::Other(format!(
                "container {}: declares arch {:?} but its packages are built for {:?}; \
                 the image would fail at exec time",
                self.name,
                arch,
                target.arch(),
            ))),
            _ => Ok(()),
        }
    }
}

/// Checks a volume mountpoint: a clean absolute path that is not the root.
///
/// The equivalent of the `AbsolutePath` contract in `minimal.ncl`, done here
/// because a contract used inside an `Array` cannot refer to that file's
/// bindings.
fn check_volume_path(name: &str, path: &str) -> Result<(), Error> {
    let invalid = |why: &str| {
        Err(Error::Other(format!(
            "container {name}: volume `{path}` {why}"
        )))
    };

    if path == "/" {
        return invalid("cannot be the root directory");
    }
    if !path.starts_with('/') {
        return invalid("must be an absolute path");
    }
    if path.ends_with('/') || path.contains("//") {
        return invalid("must not have a trailing or repeated `/`");
    }
    if path.split('/').any(|c| c == "." || c == "..") {
        return invalid("must not contain `.` or `..` path components");
    }

    Ok(())
}

/// Returns the first item that appears more than once, if any.
fn first_duplicate<T: std::hash::Hash + Eq + Clone, I: IntoIterator<Item = T>>(
    items: I,
) -> Option<T> {
    let mut seen = std::collections::HashSet::new();
    items.into_iter().find(|item| !seen.insert(item.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::*;
    use indoc::indoc;

    /// Parses a container from the fields of a `container { .. }` record,
    /// surfacing contract violations (which are Nickel eval errors) as `Err`.
    fn parse_body(body: &str) -> Result<Container, Error> {
        let src =
            format!("let {{container, ..}} = import \"minimal.ncl\" in\ncontainer {{\n{body}\n}}");
        let (term, mut program, _origin, _target) =
            Loader::new(src, None, &LoadOptions::for_test())?.finish()?;
        Container::from_term(&term, &mut program)
    }

    const VALID: &str = r#"name = "web", packages = ["glibc"],"#;

    /// Renders the diagnostic a user would see, so a case cannot pass by
    /// failing for an unrelated reason.
    fn err_text(e: &Error) -> String {
        use codespan_reporting::term::termcolor::Buffer;
        let mut buf = Buffer::no_color();
        e.report_to(&mut buf);
        String::from_utf8(buf.into_inner()).unwrap()
    }

    #[test]
    fn rejects_invalid_fields() {
        // (case, container body, the reason it must be rejected for)
        let cases = [
            // name: registry reference grammar
            (
                "uppercase name",
                r#"name = "Web", packages = ["a"],"#,
                "not a valid image name",
            ),
            (
                "spaces in name",
                r#"name = "my web app", packages = ["a"],"#,
                "not a valid image name",
            ),
            (
                "punctuation in name",
                r#"name = "web!", packages = ["a"],"#,
                "not a valid image name",
            ),
            (
                "leading separator in name",
                r#"name = "-web", packages = ["a"],"#,
                "not a valid image name",
            ),
            // packages
            (
                "empty packages",
                r#"name = "web", packages = [],"#,
                "must not be empty",
            ),
            (
                "numeric package entry",
                r#"name = "web", packages = [1],"#,
                "contract broken by the value of `packages`",
            ),
            // arch: closed enum, not a string
            (
                "arch as string",
                r#"name = "web", packages = ["a"], arch = "amd64","#,
                "contract broken",
            ),
            (
                "unknown arch",
                r#"name = "web", packages = ["a"], arch = 'X86,"#,
                "contract broken",
            ),
            // working_dir: clean absolute path
            (
                "relative working_dir",
                r#"name = "web", packages = ["a"], working_dir = "srv","#,
                "must be an absolute path",
            ),
            (
                "trailing slash working_dir",
                r#"name = "web", packages = ["a"], working_dir = "/srv/","#,
                "trailing or repeated",
            ),
            (
                "dotdot working_dir",
                r#"name = "web", packages = ["a"], working_dir = "/srv/../etc","#,
                "`.` or `..`",
            ),
            (
                "repeated slash working_dir",
                r#"name = "web", packages = ["a"], working_dir = "/srv//x","#,
                "trailing or repeated",
            ),
            // volumes
            (
                "root volume",
                r#"name = "web", packages = ["a"], volumes = ["/"],"#,
                "cannot be the root",
            ),
            (
                "relative volume",
                r#"name = "web", packages = ["a"], volumes = ["var/lib"],"#,
                "must be an absolute path",
            ),
            (
                "trailing slash volume",
                r#"name = "web", packages = ["a"], volumes = ["/var/"],"#,
                "trailing or repeated",
            ),
            (
                "dotdot volume",
                r#"name = "web", packages = ["a"], volumes = ["/var/../etc"],"#,
                "`.` or `..`",
            ),
            (
                "duplicate volumes",
                r#"name = "web", packages = ["a"], volumes = ["/v", "/v"],"#,
                "declared more than once",
            ),
            // ports
            (
                "port zero",
                r#"name = "web", packages = ["a"], exposed_ports = [{port = 0}],"#,
                "within 1-65535",
            ),
            (
                "port too large",
                r#"name = "web", packages = ["a"], exposed_ports = [{port = 70000}],"#,
                "within 1-65535",
            ),
            (
                "fractional port",
                r#"name = "web", packages = ["a"], exposed_ports = [{port = 8080.5}],"#,
                "whole number",
            ),
            (
                "negative port",
                r#"name = "web", packages = ["a"], exposed_ports = [{port = -1}],"#,
                "within 1-65535",
            ),
            (
                "unknown proto",
                r#"name = "web", packages = ["a"], exposed_ports = [{port = 80, proto = 'Sctp}],"#,
                "contract broken",
            ),
            (
                "proto as string",
                r#"name = "web", packages = ["a"], exposed_ports = [{port = 80, proto = "tcp"}],"#,
                "contract broken",
            ),
            (
                "duplicate exposed port",
                r#"name = "web", packages = ["a"], exposed_ports = [{port = 80}, {port = 80, proto = 'Tcp}],"#,
                "exposed more than once",
            ),
            // env var names
            (
                "equals in env name",
                r#"name = "web", packages = ["a"], env_vars = {"A=B" = "1"},"#,
                "not a valid environment variable name",
            ),
            (
                "leading digit env name",
                r#"name = "web", packages = ["a"], env_vars = {"1PORT" = "1"},"#,
                "not a valid environment variable name",
            ),
            (
                "dash in env name",
                r#"name = "web", packages = ["a"], env_vars = {"MY-VAR" = "1"},"#,
                "not a valid environment variable name",
            ),
            (
                "empty env name",
                r#"name = "web", packages = ["a"], env_vars = {"" = "1"},"#,
                "not a valid environment variable name",
            ),
            // user
            (
                "empty user",
                r#"name = "web", packages = ["a"], user = "","#,
                "not a valid user",
            ),
            (
                "space in user",
                r#"name = "web", packages = ["a"], user = "ngin x","#,
                "not a valid user",
            ),
            (
                "triple user",
                r#"name = "web", packages = ["a"], user = "a:b:c","#,
                "not a valid user",
            ),
            // stop_signal
            (
                "numeric stop_signal",
                r#"name = "web", packages = ["a"], stop_signal = "9","#,
                "not a valid signal name",
            ),
            (
                "lowercase stop_signal",
                r#"name = "web", packages = ["a"], stop_signal = "sigterm","#,
                "not a valid signal name",
            ),
            (
                "unprefixed stop_signal",
                r#"name = "web", packages = ["a"], stop_signal = "TERM","#,
                "not a valid signal name",
            ),
            // argv
            (
                "empty entrypoint string",
                r#"name = "web", packages = ["a"], entrypoint = "","#,
                "must not be empty",
            ),
            (
                "empty cmd array",
                r#"name = "web", packages = ["a"], cmd = [],"#,
                "must not be empty",
            ),
            (
                "numeric cmd entry",
                r#"name = "web", packages = ["a"], cmd = [1, 2],"#,
                "contract broken by the value of `cmd`",
            ),
            (
                "numeric entrypoint entry",
                r#"name = "web", packages = ["a"], entrypoint = [1],"#,
                "contract broken by the value of `entrypoint`",
            ),
            (
                "unbalanced quote in entrypoint",
                r#"name = "web", packages = ["a"], entrypoint = "sh -c 'echo hi","#,
                "not a valid shell word list",
            ),
        ];

        for (case, body, reason) in cases {
            let err = parse_body(body)
                .err()
                .unwrap_or_else(|| panic!("expected `{case}` to be rejected: {body}"));
            let text = err_text(&err);
            assert!(
                text.contains(reason),
                "`{case}` was rejected, but not for `{reason}`:\n{text}"
            );
        }
    }

    #[test]
    fn accepts_valid_fields() {
        let cases = [
            ("root working_dir", format!(r#"{VALID} working_dir = "/","#)),
            (
                "nested working_dir",
                format!(r#"{VALID} working_dir = "/srv/app","#),
            ),
            (
                "dotfile path",
                format!(r#"{VALID} working_dir = "/srv/.cache","#),
            ),
            ("numeric user", format!(r#"{VALID} user = "1000","#)),
            ("uid:gid", format!(r#"{VALID} user = "1000:1000","#)),
            ("named user", format!(r#"{VALID} user = "nobody","#)),
            ("user:group", format!(r#"{VALID} user = "nginx:www-data","#)),
            (
                "realtime signal",
                format!(r#"{VALID} stop_signal = "SIGRTMIN+3","#),
            ),
            (
                "plain signal",
                format!(r#"{VALID} stop_signal = "SIGQUIT","#),
            ),
            (
                "boundary ports",
                format!(r#"{VALID} exposed_ports = [{{port = 1}}, {{port = 65535}}],"#),
            ),
            (
                "same port, different proto",
                format!(r#"{VALID} exposed_ports = [{{port = 53}}, {{port = 53, proto = 'Udp}}],"#),
            ),
            (
                "underscore env name",
                format!(r#"{VALID} env_vars = {{_X1 = "v"}},"#),
            ),
            (
                "dotted image name",
                r#"name = "my.app_v2-beta", packages = ["a"],"#.to_string(),
            ),
            (
                "pathed image name",
                r#"name = "team/web", packages = ["a"],"#.to_string(),
            ),
        ];

        for (case, body) in cases {
            parse_body(&body).unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("expected `{case}` to be accepted: {body}");
            });
        }
    }

    #[test]
    fn defaults_and_shapes() {
        // A bare port is TCP, matching the OCI `ExposedPorts` form.
        let c = parse_body(&format!(r#"{VALID} exposed_ports = [{{port = 8080}}],"#)).unwrap();
        assert_eq!(
            c.exposed_ports,
            vec![ExposedPort {
                proto: Proto::Tcp,
                port: 8080
            }]
        );
        assert_eq!(Proto::Tcp.to_string(), "tcp");
        assert_eq!(Proto::Udp.to_string(), "udp");

        // A string argv is word-split into exec form; quoting is honoured.
        let c = parse_body(&format!(
            r#"{VALID} entrypoint = "/bin/sh -c 'echo hi'", cmd = ["--flag", "x y"],"#
        ))
        .unwrap();
        assert_eq!(
            c.entrypoint,
            Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hi".to_string()
            ])
        );
        assert_eq!(c.cmd, Some(vec!["--flag".to_string(), "x y".to_string()]));
    }

    #[test]
    fn check_target_rejects_mismatched_arch() {
        use common::{Target, target::Arch};

        let c = parse_body(&format!(r#"{VALID} arch = 'Arm64,"#)).unwrap();
        assert_eq!(c.arch, Some(Arch::Arm64));

        let arm = Target::new(Arch::Arm64, common::target::OS::Linux);
        let amd = Target::new(Arch::Amd64, common::target::OS::Linux);
        assert!(c.check_target(&arm).is_ok());
        assert!(c.check_target(&amd).is_err());

        // No declared arch: nothing to contradict.
        let c = parse_body(VALID).unwrap();
        assert!(c.check_target(&amd).is_ok());
    }

    #[test]
    fn parse() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {container, ..} = import \"minimal.ncl\" in
                container {
                    name = \"web\",

                    packages = [\"glibc\", \"nginx\"],

                    entrypoint = \"/usr/bin/nginx -g\",
                    cmd = [\"-c\", \"/etc/nginx/nginx.conf\"],
                    arch = 'Amd64,
                    working_dir = \"/srv\",

                    env_vars.PORT = \"8080\",

                    exposed_ports = [
                        { port = 80 },
                        { proto = 'Udp, port = 443 },
                    ],
                    volumes = [\"/var/lib/nginx\"],
                    user = \"nginx\",
                    stop_signal = \"SIGQUIT\",

                    labels.\"org.opencontainers.image.title\" = \"web\",
                    config.Healthcheck = \"curl localhost\",
                }
                "
            }
            .to_string(),
            None,
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("load failed");
        })
        .finish()
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("finish failed");
        });

        let c = Container::from_term(&term, &mut program).unwrap();

        assert_eq!(
            c,
            Container {
                name: "web".to_string(),
                packages: vec!["glibc".to_string(), "nginx".to_string()],
                entrypoint: Some(vec!["/usr/bin/nginx".to_string(), "-g".to_string()]),
                cmd: Some(vec!["-c".to_string(), "/etc/nginx/nginx.conf".to_string()]),
                arch: Some(Arch::Amd64),
                working_dir: Some("/srv".to_string()),
                env_vars: IndexMap::from_iter([("PORT".to_string(), "8080".to_string())]),
                exposed_ports: vec![
                    ExposedPort {
                        proto: Proto::Tcp,
                        port: 80
                    },
                    ExposedPort {
                        proto: Proto::Udp,
                        port: 443
                    },
                ],
                volumes: vec!["/var/lib/nginx".to_string()],
                user: Some("nginx".to_string()),
                stop_signal: Some("SIGQUIT".to_string()),
                labels: IndexMap::from_iter([(
                    "org.opencontainers.image.title".to_string(),
                    "web".to_string()
                )]),
                config: IndexMap::from_iter([(
                    "Healthcheck".to_string(),
                    "curl localhost".to_string()
                )]),
            }
        )
    }

    #[test]
    fn parse_minimal() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {container, ..} = import \"minimal.ncl\" in
                container {
                    name = \"bare\",
                    packages = [\"glibc\"],
                }
                "
            }
            .to_string(),
            None,
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("load failed");
        })
        .finish()
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("finish failed");
        });

        let c = Container::from_term(&term, &mut program).unwrap();

        assert_eq!(
            c,
            Container {
                name: "bare".to_string(),
                packages: vec!["glibc".to_string()],
                ..Default::default()
            }
        )
    }

    #[test]
    fn wrong_object_type() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {stack, ..} = import \"minimal.ncl\" in
                stack {
                    name = \"rust\",
                    build_cmd = \"cargo build\",
                }
                "
            }
            .to_string(),
            None,
            &LoadOptions::for_test(),
        )
        .unwrap()
        .finish()
        .unwrap();

        assert!(matches!(
            Container::from_term(&term, &mut program),
            Err(Error::UnexpectedObject {
                got: ObjTy::Stack,
                want: ObjTy::Container,
                ..
            })
        ));
    }
}

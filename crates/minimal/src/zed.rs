//! Registering a session as a Zed SSH remote (`min session setup-zed <session>`).
//!
//! Zed opens a remote project by shelling out to `ssh` with the `args` recorded
//! in its `ssh_connections` settings array. A session is reachable the same way
//! `min session attach` reaches it — over the daemon's UDS via our own `proxy`
//! subcommand as an SSH `ProxyCommand`, with the session selected by the
//! `MINIMAL_SESSION_ID` env var. Zed spawns ssh itself, so we cannot put that
//! var in ssh's environment the way [`minimal_client::attach`] does; the
//! equivalent over an argv is `-o SetEnv MINIMAL_SESSION_ID=<id>`.
//!
//! The pieces of the ssh invocation are deliberately built from the same
//! helpers `attach` uses ([`minimal_client::attach::shell_quote`],
//! [`minimal_client::attach::host_key_opts`]) so a Zed remote and a
//! `min session attach` agree on transport, host identity, and quoting.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use serde_json_lenient::{Value, json};

/// The env var the daemon reads off the SSH channel to pick the session
/// (mirrors `minimald::MINIMAL_SESSION_ID_ENV`).
pub const SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

/// The session's project root inside the box. Mirrors minimald's
/// `env::WORKSPACE_ROOT` (itself `/` + `sandbox2::SESSION_DEFAULT_WD`), which
/// the CLI cannot reference directly: `sandbox2` is Linux-only and `min` builds
/// on macOS.
pub const WORKSPACE_ROOT: &str = "/workbench";

/// Zed's user settings file.
///
/// Zed reads `~/.config/zed/settings.json` on macOS as well as Linux — it does
/// not use `~/Library/Application Support` for the settings file — so this is
/// the same path on both platforms, with `$XDG_CONFIG_HOME` honoured only where
/// Zed itself honours it.
pub fn default_settings_path() -> Result<PathBuf, anyhow::Error> {
    #[cfg(target_os = "linux")]
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("zed").join("settings.json"));
    }
    let home = dirs::home_dir().context("cannot determine the home directory")?;
    Ok(home.join(".config").join("zed").join("settings.json"))
}

/// Everything needed to render one `ssh_connections` entry.
pub struct Connection {
    /// SSH host identity. Must be the provider-instance alias, because that is
    /// what the daemon keys its `known_hosts` entry on.
    pub host: String,
    /// Local login name. The daemon authenticates the *session* from
    /// `MINIMAL_SESSION_ID`, so this is only the local user ssh presents.
    pub username: String,
    /// Session UUID, carried in `SetEnv`.
    pub session_id: String,
    /// Full `min proxy --socket <sock>` command line, already shell-quoted.
    pub proxy_command: String,
    /// `StrictHostKeyChecking` / `UserKnownHostsFile` pair from
    /// [`minimal_client::attach::host_key_opts`].
    pub host_key_opts: [String; 2],
}

impl Connection {
    /// The `SetEnv` argument that both selects the session and identifies this
    /// entry on a later upsert.
    fn set_env_arg(&self) -> String {
        format!("SetEnv {SESSION_ID_ENV}={}", self.session_id)
    }

    /// Render the entry as Zed sees it.
    ///
    /// The host-key options ride along because Zed spawns a bare `ssh` with no
    /// access to our config: without them ssh consults the user's own
    /// `known_hosts`, does not find the provider alias, and the connection dies
    /// on an interactive host-key prompt Zed cannot answer.
    ///
    /// `projects` is always the single [`WORKSPACE_ROOT`] entry — the session's
    /// project root is where a box's work happens, and it is the same path for
    /// every session.
    pub fn entry(&self) -> Value {
        let [strict, known_hosts] = &self.host_key_opts;
        json!({
            "host": self.host,
            "username": self.username,
            "args": [
                "-o", self.set_env_arg(),
                "-o", format!("ProxyCommand={}", self.proxy_command),
                "-o", strict,
                "-o", known_hosts,
            ],
            "projects": [ { "paths": [WORKSPACE_ROOT] } ],
        })
    }
}

/// What [`upsert`] did, for reporting.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// No entry for this session existed; one was appended.
    Inserted,
    /// An entry for this session existed and its transport was rewritten.
    Updated,
    /// An entry for this session existed and already matched exactly.
    Unchanged,
}

/// Insert or refresh this session's entry in `settings["ssh_connections"]`.
///
/// Identity is the `SetEnv MINIMAL_SESSION_ID=<id>` argument, not the host:
/// every session on a provider shares that provider's host alias, so the host
/// alone would collapse them all onto one entry.
///
/// An existing entry is replaced outright, so a re-run restores the canonical
/// single-[`WORKSPACE_ROOT`] `projects` list: any extra project directories Zed
/// itself appended as the user opened them are dropped.
pub fn upsert(settings: &mut Value, conn: &Connection) -> Result<Outcome, anyhow::Error> {
    let obj = match settings {
        Value::Object(o) => o,
        Value::Null => {
            *settings = json!({});
            settings.as_object_mut().expect("just set to an object")
        }
        other => bail!(
            "expected the Zed settings file to hold a JSON object, found {}",
            kind_of(other)
        ),
    };

    let list = obj
        .entry("ssh_connections".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if list.is_null() {
        *list = Value::Array(Vec::new());
    }
    let Some(list) = list.as_array_mut() else {
        bail!(
            "expected `ssh_connections` to be a JSON array, found {}",
            kind_of(list)
        );
    };

    let marker = conn.set_env_arg();
    let existing = list.iter().position(|e| has_arg(e, &marker));
    let entry = conn.entry();

    match existing {
        None => {
            list.push(entry);
            Ok(Outcome::Inserted)
        }
        Some(i) if list[i] == entry => Ok(Outcome::Unchanged),
        Some(i) => {
            list[i] = entry;
            Ok(Outcome::Updated)
        }
    }
}

/// Does this entry carry `arg` in its `args` array?
fn has_arg(entry: &Value, arg: &str) -> bool {
    entry
        .get("args")
        .and_then(Value::as_array)
        .is_some_and(|args| args.iter().any(|a| a.as_str() == Some(arg)))
}

/// Human-readable JSON type name, for error messages.
fn kind_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Read Zed's settings file, tolerating the JSONC Zed ships (`//` comments and
/// trailing commas) and treating an absent or empty file as `{}`.
pub fn read_settings(path: &Path) -> Result<Value, anyhow::Error> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(json!({})),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    if raw.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json_lenient::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

/// Write `settings` back, leaving a `<name>.bak` copy of whatever was there.
///
/// Round-tripping through [`Value`] renders a *canonical* document: comments do
/// not survive, and object keys come back in the sort order [`Value`]'s map
/// imposes rather than the order the user wrote them. That is why the previous
/// contents are preserved next to the file rather than simply overwritten.
pub fn write_settings(path: &Path, settings: &Value) -> Result<Option<PathBuf>, anyhow::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let backup = match std::fs::read(path) {
        Ok(prev) => {
            // Suffix the whole file name rather than replacing its extension:
            // `--settings` takes an arbitrary path, and `with_extension` would
            // turn a `settings.jsonc` into a `settings.json.bak` that both
            // mislabels the backup and can collide with a real one.
            let backup = match path.file_name() {
                Some(name) => {
                    let mut n = name.to_os_string();
                    n.push(".bak");
                    path.with_file_name(n)
                }
                None => bail!("cannot back up {}: path has no file name", path.display()),
            };
            std::fs::write(&backup, prev)
                .with_context(|| format!("writing {}", backup.display()))?;
            Some(backup)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };

    let mut rendered =
        serde_json_lenient::to_string_pretty(settings).context("serializing Zed settings")?;
    rendered.push('\n');
    std::fs::write(path, rendered).with_context(|| format!("writing {}", path.display()))?;

    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        Connection {
            host: "local-minimald0".to_string(),
            username: "tom".to_string(),
            session_id: "019f8ab5-27ba-7260-a03c-3914b9595a1a".to_string(),
            proxy_command: "'/home/tom/.local/bin/min' proxy --socket '/run/ssh.sock'".to_string(),
            host_key_opts: [
                "StrictHostKeyChecking=no".to_string(),
                "UserKnownHostsFile=/dev/null".to_string(),
            ],
        }
    }

    #[test]
    fn entry_carries_the_session_and_the_proxy() {
        let e = conn().entry();
        assert_eq!(e["host"], "local-minimald0");
        assert_eq!(e["username"], "tom");
        // Exactly one project, exactly one path — not configurable.
        assert_eq!(e["projects"], json!([{"paths": ["/workbench"]}]));

        let args: Vec<&str> = e["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        assert!(args.contains(&"SetEnv MINIMAL_SESSION_ID=019f8ab5-27ba-7260-a03c-3914b9595a1a"));
        assert!(
            args.iter()
                .any(|a| a.starts_with("ProxyCommand=") && a.contains("proxy --socket"))
        );
        // Every option must be introduced by its own `-o`.
        assert_eq!(args.iter().filter(|a| **a == "-o").count(), args.len() / 2);
    }

    /// A first run on a machine with no `ssh_connections` key at all.
    #[test]
    fn upsert_creates_the_array() {
        let mut settings = json!({"theme": "One Dark"});
        assert_eq!(upsert(&mut settings, &conn()).unwrap(), Outcome::Inserted);
        assert_eq!(settings["ssh_connections"].as_array().unwrap().len(), 1);
        // Unrelated settings survive.
        assert_eq!(settings["theme"], "One Dark");
    }

    /// Re-running the command must refresh in place, not append a duplicate.
    #[test]
    fn upsert_is_idempotent_for_the_same_session() {
        let mut settings = json!({});
        assert_eq!(upsert(&mut settings, &conn()).unwrap(), Outcome::Inserted);
        assert_eq!(upsert(&mut settings, &conn()).unwrap(), Outcome::Unchanged);
        assert_eq!(settings["ssh_connections"].as_array().unwrap().len(), 1);
    }

    /// A moved socket (daemon reinstalled, provider dir changed) rewrites the
    /// existing entry rather than leaving a stale one behind.
    #[test]
    fn upsert_rewrites_a_stale_proxy_command() {
        let mut settings = json!({});
        upsert(&mut settings, &conn()).unwrap();

        let mut moved = conn();
        moved.proxy_command = "'/opt/min' proxy --socket '/run/new.sock'".to_string();
        assert_eq!(upsert(&mut settings, &moved).unwrap(), Outcome::Updated);

        let list = settings["ssh_connections"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert!(has_arg(
            &list[0],
            "ProxyCommand='/opt/min' proxy --socket '/run/new.sock'"
        ));
    }

    /// Two sessions on the same provider share a host alias, so they must be
    /// told apart by their session id — not collapsed onto one entry.
    #[test]
    fn upsert_keeps_sessions_on_one_host_distinct() {
        let mut settings = json!({});
        upsert(&mut settings, &conn()).unwrap();

        let mut other = conn();
        other.session_id = "019f8ab5-0000-0000-0000-000000000000".to_string();
        assert_eq!(upsert(&mut settings, &other).unwrap(), Outcome::Inserted);

        assert_eq!(settings["ssh_connections"].as_array().unwrap().len(), 2);
    }

    /// Zed appends to `projects` as the user opens directories over the
    /// connection. `projects` is ours to define, so a re-run resets it to the
    /// single workspace root rather than accumulating those.
    #[test]
    fn upsert_resets_projects_to_the_workspace_root() {
        let mut settings = json!({});
        upsert(&mut settings, &conn()).unwrap();
        settings["ssh_connections"][0]["projects"]
            .as_array_mut()
            .unwrap()
            .push(json!({"paths": ["/home/dev/notes"]}));

        let mut moved = conn();
        moved.proxy_command = "'/opt/min' proxy".to_string();
        assert_eq!(upsert(&mut settings, &moved).unwrap(), Outcome::Updated);

        assert_eq!(
            settings["ssh_connections"][0]["projects"],
            json!([{"paths": ["/workbench"]}])
        );
    }

    /// Entries for *other* hosts must be left exactly as they were.
    #[test]
    fn upsert_leaves_foreign_connections_alone() {
        let foreign = json!({"host": "build-box", "username": "ci", "projects": []});
        let mut settings = json!({"ssh_connections": [foreign.clone()]});
        upsert(&mut settings, &conn()).unwrap();

        let list = settings["ssh_connections"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], foreign);
    }

    #[test]
    fn upsert_rejects_a_non_array_ssh_connections() {
        let mut settings = json!({"ssh_connections": "nope"});
        let err = upsert(&mut settings, &conn()).unwrap_err().to_string();
        assert!(err.contains("array"), "unhelpful error: {err}");
    }

    /// The reason this reads through serde_json_lenient: Zed ships a settings
    /// file full of `//` commentary and trailing commas, and strict serde_json
    /// rejects both.
    #[test]
    fn read_settings_accepts_the_jsonc_zed_ships() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{
  // Zed's default settings file is commented throughout.
  "theme": "One Dark",
  "ssh_connections": [],
}"#,
        )
        .unwrap();

        let settings = read_settings(&path).unwrap();
        assert_eq!(settings["theme"], "One Dark");
    }

    #[test]
    fn read_settings_treats_missing_and_empty_as_empty_object() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("settings.json");
        assert_eq!(read_settings(&missing).unwrap(), json!({}));

        std::fs::write(&missing, "\n  \n").unwrap();
        assert_eq!(read_settings(&missing).unwrap(), json!({}));
    }

    #[test]
    fn write_settings_creates_the_dir_and_backs_up_what_was_there() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("zed").join("settings.json");

        assert_eq!(write_settings(&path, &json!({"a": 1})).unwrap(), None);
        assert!(path.is_file());

        let backup = write_settings(&path, &json!({"a": 2})).unwrap().unwrap();
        assert_eq!(backup, path.with_file_name("settings.json.bak"));
        assert!(
            std::fs::read_to_string(&backup)
                .unwrap()
                .contains("\"a\": 1"),
            "backup must hold the pre-write contents"
        );
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"a\": 2"));
    }

    /// `--settings` takes an arbitrary path, so the backup suffixes the whole
    /// file name — replacing the extension would name a `.jsonc` backup as if
    /// it were the `.json` one, and let the two collide.
    #[test]
    fn write_settings_backs_up_beside_a_non_json_name() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("settings.jsonc");

        write_settings(&path, &json!({"a": 1})).unwrap();
        let backup = write_settings(&path, &json!({"a": 2})).unwrap().unwrap();

        assert_eq!(backup, path.with_file_name("settings.jsonc.bak"));
        assert!(
            std::fs::read_to_string(&backup)
                .unwrap()
                .contains("\"a\": 1")
        );
    }

    /// The round trip a real run performs: parse a commented file, upsert, and
    /// write it back as something Zed can still read.
    #[test]
    fn round_trip_through_a_commented_file_stays_parseable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("settings.json");
        std::fs::write(&path, "{\n  // keep me honest\n  \"vim_mode\": true,\n}").unwrap();

        let mut settings = read_settings(&path).unwrap();
        upsert(&mut settings, &conn()).unwrap();
        write_settings(&path, &settings).unwrap();

        let reparsed = read_settings(&path).unwrap();
        assert_eq!(reparsed["vim_mode"], true);
        assert_eq!(reparsed["ssh_connections"].as_array().unwrap().len(), 1);
    }
}

use super::state::{claim_install_id, new_install_id, record_disclosed, valid_install_id};
use super::*;
use std::ffi::OsString;
use std::time::SystemTime;

fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
    move |n| {
        pairs
            .iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| OsString::from(v))
    }
}

#[test]
fn the_switches_each_turn_it_off_in_order() {
    assert_eq!(off_switch(ConfigState::Enabled, env(&[])), None);
    assert_eq!(
        off_switch(ConfigState::Enabled, env(&[("DO_NOT_TRACK", "1")])),
        Some(UpdateDisabledReason::Env("DO_NOT_TRACK"))
    );
    assert_eq!(
        off_switch(ConfigState::Enabled, env(&[("CI", "true")])),
        Some(UpdateDisabledReason::Env("CI"))
    );
    assert_eq!(
        off_switch(ConfigState::Enabled, env(&[("CI", "")])),
        None,
        "an empty CI is unset"
    );
    for v in ["0", "false", "NO", " off "] {
        assert_eq!(
            off_switch(ConfigState::Enabled, env(&[("MINIMAL_TELEMETRY", v)])),
            Some(UpdateDisabledReason::Env("MINIMAL_TELEMETRY")),
            "{v:?} is falsy"
        );
    }
    assert_eq!(
        off_switch(ConfigState::Enabled, env(&[("MINIMAL_TELEMETRY", "1")])),
        None,
        "the OTel opt-in is not a switch here"
    );
    assert_eq!(
        off_switch(ConfigState::Disabled, env(&[])),
        Some(UpdateDisabledReason::Config)
    );
    assert_eq!(
        off_switch(ConfigState::Unreadable, env(&[])),
        Some(UpdateDisabledReason::ConfigUnreadable),
        "an unreadable config fails closed, and says that, not a setting it may not hold"
    );
    assert!(
        UpdateDisabledReason::ConfigUnreadable
            .to_string()
            .contains("could not be read")
    );
    assert_eq!(
        off_switch(ConfigState::Disabled, env(&[("DO_NOT_TRACK", "1")])),
        Some(UpdateDisabledReason::Env("DO_NOT_TRACK")),
        "the environment is named ahead of the config"
    );
}

#[test]
fn the_build_key_is_the_embedded_hash_else_the_version() {
    assert_eq!(build_key("0.8.0-dev.198.ge8f53f6e"), "e8f53f6e");
    assert_eq!(build_key("0.7.1"), "0.7.1");
    assert_eq!(
        build_key("0.7.1-dev.3.gzz"),
        "0.7.1-dev.3.gzz",
        "not a hash"
    );
}

#[test]
fn the_install_file_precedence_is_user_then_package_then_source() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = tmp.path().join("state");
    let prefix = tmp.path().join("prefix");
    let exe = prefix.join("bin").join("min");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(prefix.join("share").join("minimal")).unwrap();

    let source = read_install(&state, Some(&exe));
    assert_eq!(source.channel, SOURCE_CHANNEL);
    assert_eq!(source.key, build_key(version::VERSION));

    std::fs::write(
        prefix.join("share").join("minimal").join(INSTALL_FILE),
        "channel = \"stable\"\nmethod = \"brew\"\nkey = \"0.7.0\"\n",
    )
    .unwrap();
    let packaged = read_install(&state, Some(&exe));
    assert_eq!(
        (
            packaged.channel.as_str(),
            packaged.method.as_str(),
            packaged.key.as_str()
        ),
        ("stable", "brew", "0.7.0")
    );

    std::fs::write(
        state.join(INSTALL_FILE),
        "channel = \"nightly\"\nmethod = \"installer\"\nkey = \"5a93a07a\"\n",
    )
    .unwrap();
    let user = read_install(&state, Some(&exe));
    assert_eq!(
        (
            user.channel.as_str(),
            user.method.as_str(),
            user.key.as_str()
        ),
        ("nightly", "installer", "5a93a07a")
    );

    std::fs::write(state.join(INSTALL_FILE), "channel = \n").unwrap();
    assert_eq!(
        read_install(&state, Some(&exe)).method,
        "brew",
        "an unparsable user file is absent"
    );
    std::fs::write(
        state.join(INSTALL_FILE),
        "channel = \"../x?a=b\"\nmethod = \"installer\"\nkey = \"0.7.1\"\n",
    )
    .unwrap();
    assert_eq!(
        read_install(&state, Some(&exe)).method,
        "brew",
        "a field outside the charset makes the file absent"
    );
    std::fs::write(
        state.join(INSTALL_FILE),
        "channel = \"stable\"\nmethod = \"installer\"\nkey = \"0.7.1\\u001b[31m\"\n",
    )
    .unwrap();
    assert_eq!(
        read_install(&state, Some(&exe)).method,
        "brew",
        "a control character makes the file absent"
    );
}

#[test]
fn install_fields_are_the_installer_charset_bounded() {
    for ok in [
        "stable",
        "0.7.1",
        "5a93a07a",
        "installer",
        "0.8.0-dev.198.ge8f53f6e",
    ] {
        assert!(valid_field(ok), "{ok}");
    }
    for bad in [
        "",
        "../x",
        "a?b=c",
        "a&b",
        "a b",
        "\u{1b}[31m",
        &"x".repeat(65),
    ] {
        assert!(!valid_field(bad), "{bad:?}");
    }
}

#[test]
fn the_state_round_trips_and_a_bad_file_is_the_default() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("sub").join(STATE_FILE);
    assert_eq!(read_state(&path), State::default());
    let state = State {
        install_id: Some("0f4b7c1e-2d3a-4b5c-8d6e-7f8091a2b3c4".into()),
        checked_at: Some(7),
        latest: Some("0.7.2".into()),
        latest_channel: Some("stable".into()),
        notified: None,
        disclosed: true,
    };
    write_state(&path, &state).unwrap();
    assert_eq!(read_state(&path), state);
    assert!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count() == 1,
        "no temp file left behind"
    );
    std::fs::write(&path, "{not json").unwrap();
    assert_eq!(read_state(&path), State::default());
}

/// Two first commands at once mint one id between them: the second finds
/// the first's on disk under the lock, and a child's answer written in the
/// meantime is not clobbered by the disclosure write.
#[test]
fn a_first_run_claims_one_id_and_keeps_what_was_written_meanwhile() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path();
    let path = dir.join(STATE_FILE);
    let first = claim_install_id(dir, &path).expect("minted");
    let second = claim_install_id(dir, &path).expect("read back");
    assert_eq!(first.install_id, second.install_id, "one id for both");
    assert!(!dir.join(LOCK_FILE).exists(), "the lock is released");
    // the lock held by another command: no mint, no clobber
    std::fs::write(dir.join(LOCK_FILE), b"").unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(claim_install_id(dir, &path).is_none());
    assert!(!path.exists(), "nothing written while the lock is held");
    std::fs::remove_file(dir.join(LOCK_FILE)).unwrap();
    // a child's answer lands between the read and the disclosure write
    let state = claim_install_id(dir, &path).unwrap();
    record_answer(&path, Some(("stable".into(), "0.7.2".into())));
    record_disclosed(&path).unwrap();
    let read = read_state(&path);
    assert!(read.disclosed);
    assert_eq!(
        read.latest.as_deref(),
        Some("0.7.2"),
        "the answer written meanwhile stays"
    );
    assert_eq!(read.install_id, state.install_id);
}

/// A hand-edited state file cannot put anything into the request query or
/// onto the terminal: a field outside its charset reads as absent (the id
/// is minted again, the pointer fetched again), the rest is kept.
#[test]
fn a_state_field_outside_its_charset_reads_as_absent() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join(STATE_FILE);
    let state = State {
        install_id: Some("id&x=1".into()),
        checked_at: Some(7),
        latest: Some("0.7.2\u{1b}[31m".into()),
        latest_channel: Some("stable".into()),
        notified: Some("../etc".into()),
        disclosed: true,
    };
    write_state(&path, &state).unwrap();
    let read = read_state(&path);
    assert_eq!(read.install_id, None);
    assert_eq!(read.latest, None);
    assert_eq!(read.notified, None);
    assert_eq!(read.latest_channel.as_deref(), Some("stable"));
    assert_eq!(read.checked_at, Some(7));
    assert!(read.disclosed);
    assert!(valid_install_id(&new_install_id()), "what we mint passes");
}

#[test]
fn a_check_is_due_daily() {
    let day = INTERVAL.as_secs();
    assert!(due(&State::default(), 1_000_000));
    let s = State {
        checked_at: Some(1_000_000),
        ..State::default()
    };
    assert!(!due(&s, 1_000_000 + day - 1));
    assert!(due(&s, 1_000_000 + day));
    assert!(!due(&s, 999_000), "a clock that went backwards is not due");
    // a stamp a little ahead is skew and not due; one more than a day ahead (a wrong clock
    // once, a copied state file) is due now rather than holding the check off for weeks
    assert!(!due(&s, 1_000_000 - 3_600), "an hour of skew is not due");
    assert!(
        due(&s, 1_000_000 - day - 1),
        "more than a day ahead is due now"
    );
}

#[test]
fn the_lock_is_exclusive_until_stale() {
    let tmp = tempfile::TempDir::new().unwrap();
    let lock = tmp.path().join(LOCK_FILE);
    assert!(acquire_lock(&lock));
    assert!(!acquire_lock(&lock), "held");
    let old = SystemTime::now() - LOCK_STALE - Duration::from_secs(1);
    std::fs::File::options()
        .write(true)
        .open(&lock)
        .unwrap()
        .set_modified(old)
        .unwrap();
    assert!(acquire_lock(&lock), "a stale lock is taken over");
    release_lock(&lock);
    assert!(acquire_lock(&lock), "released");
}

#[test]
fn the_disclosure_is_owed_on_the_first_terminal_run_whatever_came_before() {
    let fresh = State::default();
    assert!(disclosure_due(&fresh, true));
    assert!(!disclosure_due(&fresh, false), "no terminal, no text");
    let scripted_first = State {
        install_id: Some("id".into()),
        ..State::default()
    };
    assert!(
        disclosure_due(&scripted_first, true),
        "an id minted by a script's run does not count as disclosed"
    );
    let shown = State {
        disclosed: true,
        ..scripted_first
    };
    assert!(!disclosure_due(&shown, true), "once");
}

#[test]
fn recording_an_answer_keeps_what_another_command_wrote_meanwhile() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join(STATE_FILE);
    write_state(
        &path,
        &State {
            install_id: Some("id".into()),
            ..State::default()
        },
    )
    .unwrap();
    // Between the child's read and its write, a command told the user
    // about 0.7.2 and wrote `notified`.
    write_state(
        &path,
        &State {
            install_id: Some("id".into()),
            notified: Some("0.7.2".into()),
            disclosed: true,
            ..State::default()
        },
    )
    .unwrap();
    record_answer(&path, Some(("stable".into(), "0.7.2".into())));
    let after = read_state(&path);
    assert_eq!(
        after.notified.as_deref(),
        Some("0.7.2"),
        "the notice is not printed again"
    );
    assert!(after.disclosed);
    assert_eq!(after.latest.as_deref(), Some("0.7.2"));
    assert!(after.checked_at.is_some());
    record_answer(&path, None);
    let failed = read_state(&path);
    assert_eq!(
        failed.latest.as_deref(),
        Some("0.7.2"),
        "a failed check keeps the last answer"
    );
    assert!(
        failed.checked_at.is_some(),
        "and still counts as a check, so there is no retry storm"
    );
}

#[test]
fn recording_the_notice_keeps_an_answer_that_landed_meanwhile() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join(STATE_FILE);
    write_state(
        &path,
        &State {
            install_id: Some("id".into()),
            ..State::default()
        },
    )
    .unwrap();
    // The child finished between this command's read and its notice.
    record_answer(&path, Some(("stable".into(), "0.7.2".into())));
    record_notified(&path, "0.7.2");
    let after = read_state(&path);
    assert_eq!(after.notified.as_deref(), Some("0.7.2"));
    assert_eq!(
        after.latest.as_deref(),
        Some("0.7.2"),
        "the child's answer survives the notice"
    );
    assert!(
        after.checked_at.is_some(),
        "and so does its checked_at, so no second check is spawned"
    );
}

#[test]
fn the_notice_is_owed_once_per_new_pointer_on_a_channel_install() {
    let install = Install {
        channel: "stable".into(),
        method: "installer".into(),
        key: "0.7.1".into(),
    };
    let mut state = State {
        latest: Some("0.7.2".into()),
        latest_channel: Some("stable".into()),
        ..State::default()
    };
    assert_eq!(notice_due(&state, &install), Some("0.7.2"));
    state.notified = Some("0.7.2".into());
    assert_eq!(notice_due(&state, &install), None, "told already");
    state.latest = Some("0.7.3".into());
    assert_eq!(
        notice_due(&state, &install),
        Some("0.7.3"),
        "a newer pointer is told again"
    );
    state.latest = Some("0.7.1".into());
    assert_eq!(
        notice_due(&state, &install),
        None,
        "the installed key is up to date"
    );
    state.latest = Some("0.7.9".into());
    state.latest_channel = Some("nightly".into());
    assert_eq!(
        notice_due(&state, &install),
        None,
        "an answer for another channel is not this install's"
    );
    state.latest_channel = Some("source".into());
    let source = Install::source();
    state.latest = Some("anything".into());
    assert_eq!(
        notice_due(&state, &source),
        None,
        "a source build is never notified"
    );
}

/// A `--version` install (`channel = "pinned"`) is counted and never told: there is no channel to
/// upgrade along. A command that takes the terminal does not get the notice; a plain one does.
#[test]
fn a_pinned_install_is_never_told_and_the_notice_waits_for_a_plain_command() {
    let state = State {
        latest: Some("0.9.0".into()),
        latest_channel: Some(PINNED_CHANNEL.into()),
        ..Default::default()
    };
    let pinned = Install {
        channel: PINNED_CHANNEL.into(),
        method: "installer".into(),
        key: "0.8.0".into(),
    };
    assert_eq!(notice_due(&state, &pinned), None);
    assert!(
        !leaves_the_notice_visible(&None),
        "bare `min` attaches to a box"
    );
    assert!(leaves_the_notice_visible(&Some(crate::cli::Command::Dirs)));
    assert!(!leaves_the_notice_visible(&Some(crate::cli::Command::Dash)));
    assert!(!leaves_the_notice_visible(&Some(
        crate::cli::Command::DebugAnswererCommand
    )));
}

#[test]
fn the_notice_names_the_pointer_and_the_upgrade_path() {
    let install = Install {
        channel: "stable".into(),
        method: "installer".into(),
        key: "0.7.1".into(),
    };
    let text = notice(&install, "0.7.2");
    assert!(text.contains("0.7.2"), "{text}");
    assert!(
        text.contains(
            "the stable channel is now at 0.7.2. How to update: https://docs.minimal.dev/"
        ),
        "{text}"
    );
    let brew = Install {
        method: "brew".into(),
        ..install.clone()
    };
    assert!(
        notice(&brew, "0.7.2")
            .contains("is now at 0.7.2. How to update: https://docs.minimal.dev/")
    );
    let other = Install {
        method: "snap".into(),
        ..install
    };
    assert!(notice(&other, "0.7.2").contains(DOCS_URL));
    assert!(disclosure().contains("MINIMAL_TELEMETRY=0"));
}

#[test]
fn the_request_carries_the_eight_fields_and_nothing_more() {
    let install = Install {
        channel: "stable".into(),
        method: "installer".into(),
        key: "0.7.1".into(),
    };
    let url = request_url("https://u.example/v1/", &install, "abc");
    let (path, query) = url.split_once('?').unwrap();
    assert_eq!(path, "https://u.example/v1/stable/0.7.1");
    let keys: Vec<_> = query
        .split('&')
        .map(|kv| kv.split_once('=').unwrap().0)
        .collect();
    assert_eq!(keys, ["os", "arch", "install", "id"]);
    assert!(query.ends_with("install=installer&id=abc"));
}

/// A stub answering `status` after `delay`, on 127.0.0.1; the URL to GET.
fn stub(status: &'static str, body: &'static str, delay: Duration) -> String {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(1) {
            let mut s = stream.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            std::thread::sleep(delay);
            let _ = write!(
                s,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://127.0.0.1:{port}/v1/stable/0.7.1?os=linux&arch=x86_64&install=installer&id=x")
}

#[tokio::test]
async fn a_good_answer_is_the_channel_and_the_pointer() {
    let url = stub(
        "200 OK",
        r#"{"channel":"stable","latest":"0.7.2"}"#,
        Duration::ZERO,
    );
    assert_eq!(
        fetch_latest(&url).await,
        Some(("stable".into(), "0.7.2".into()))
    );
}

#[tokio::test]
async fn a_404_an_odd_body_and_a_slow_endpoint_are_silent_within_the_budget() {
    let url = stub("404 Not Found", "{}", Duration::ZERO);
    assert_eq!(fetch_latest(&url).await, None);
    let url = stub(
        "200 OK",
        r#"{"channel":"stable","latest":"../x"}"#,
        Duration::ZERO,
    );
    assert_eq!(
        fetch_latest(&url).await,
        None,
        "a pointer outside the charset is refused"
    );
    let url = stub(
        "200 OK",
        r#"{"channel":"stable","latest":"0.7.2"}"#,
        REQUEST_BUDGET + Duration::from_secs(2),
    );
    let t0 = std::time::Instant::now();
    assert_eq!(fetch_latest(&url).await, None);
    assert!(
        t0.elapsed() < REQUEST_BUDGET + Duration::from_millis(900),
        "gave up at the budget: {:?}",
        t0.elapsed()
    );
    let unreachable = "http://127.0.0.1:9/v1/stable/0.7.1";
    assert_eq!(fetch_latest(unreachable).await, None);
}

/// The disclosure is one sentence for a person: it names the switches by their
/// settings, with no type name of this module's in it (a rename once put
/// `UpdateDisabledReason:` where `Off:` belongs, review 2026-10-28).
#[test]
fn the_disclosure_reads_as_a_sentence() {
    let text = disclosure();
    assert!(
        text.contains("Off: MINIMAL_TELEMETRY=0, or [telemetry] enabled = false in config.toml."),
        "{text}"
    );
    assert!(
        !text.contains("UpdateDisabledReason") && !text.contains("::"),
        "{text}"
    );
    assert!(text.ends_with(DOCS_URL), "{text}");
}

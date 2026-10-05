//! The telemetry switches: each variable is read once into a small value,
//! and [`Switches::decide`] settles, from those values alone, what each
//! signal exports and spools. `CI` is not a switch: a CI runner neither
//! enables nor blocks export.
//!
//! Headers: the OTLP exporter reads the plain `OTEL_EXPORTER_OTLP_HEADERS`
//! (or a signal's `OTEL_EXPORTER_OTLP_<signal>_HEADERS`) by itself and sends
//! them to whatever endpoint it is given. Those are ambient, often a key for
//! another backend, so they never go to an endpoint named by a `MINIMAL_`
//! variable: such an endpoint gets `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS`
//! only, and with plain headers set and no `MINIMAL_` ones its signal is not
//! exported at all ([`SignalDecision::refused`]).

use std::ffi::OsString;

/// How a boolean-ish variable is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub(crate) enum Flag {
    Unset,
    /// `1`, `true`, `yes` or `on`, any case.
    True,
    /// `0`, `false`, `no` or `off`, any case.
    False,
    Other,
}

impl Flag {
    pub(crate) fn parse(v: Option<&str>) -> Self {
        match v.map(str::to_ascii_lowercase).as_deref() {
            None | Some("") => Self::Unset,
            Some("1" | "true" | "yes" | "on") => Self::True,
            Some("0" | "false" | "no" | "off") => Self::False,
            Some(_) => Self::Other,
        }
    }
}

/// What `OTEL_<signal>_EXPORTER` names: the OTel spec's comma-separated list
/// of exporter names, each entry trimmed and read in any case. minimal has
/// one exporter, so the list reads as: `none` alone turns the signal off;
/// unset or `otlp` exports; a list naming anything else (`console`,
/// `zipkin`, `none` beside `otlp`, a value that is not UTF-8) is
/// unsupported and exports as if the variable were unset, with one warning
/// from init (langsec F15: the old reading knew only the word `none`, so
/// `console` exported over OTLP silently and ` none` did not turn off).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub(crate) enum Exporter {
    /// Unset, empty, or every entry is `otlp`.
    Otlp,
    /// Every entry is `none`.
    Off,
    /// Some entry is neither, or the whole value is not UTF-8.
    Unsupported,
}

impl Exporter {
    /// `v` is the variable: `None` unset, `Some(None)` set but not UTF-8.
    pub(crate) fn parse(v: Option<Option<&str>>) -> Self {
        let v = match v {
            None => return Self::Otlp,
            Some(None) => return Self::Unsupported,
            Some(Some(v)) => v,
        };
        let (mut seen, mut all_none, mut all_otlp) = (false, true, true);
        for e in v.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            seen = true;
            all_none &= e.eq_ignore_ascii_case("none");
            all_otlp &= e.eq_ignore_ascii_case("otlp");
        }
        match (seen, all_none, all_otlp) {
            (false, _, _) | (true, _, true) => Self::Otlp,
            (true, true, false) => Self::Off,
            (true, false, false) => Self::Unsupported,
        }
    }
}

/// Which names an endpoint setting is present under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub(crate) enum Source {
    Neither,
    /// `MINIMAL_<name>` only.
    Prefixed,
    /// `<name>` only.
    Plain,
    Both,
}

/// The name an endpoint is read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pick {
    Prefixed,
    Plain,
}

impl Source {
    /// The `MINIMAL_` name is present, alone or beside the plain one.
    fn prefixed(self) -> bool {
        matches!(self, Self::Prefixed | Self::Both)
    }
}

/// One signal's own settings (`TRACES` or `LOGS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub(crate) struct SignalSwitches {
    /// `OTEL_<signal>_EXPORTER` is [`Exporter::Off`], read under the
    /// `MINIMAL_` name when that is set, else under the plain one.
    pub(crate) off: bool,
    /// `OTEL_<signal>_EXPORTER` is [`Exporter::Unsupported`]: the signal
    /// exports as if it were unset, and init warns once.
    pub(crate) unsupported_exporter: bool,
    /// `OTEL_EXPORTER_OTLP_<signal>_ENDPOINT`.
    pub(crate) endpoint: Source,
    /// The plain `OTEL_EXPORTER_OTLP_<signal>_HEADERS` is set (it has no
    /// `MINIMAL_` form).
    pub(crate) headers: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub(crate) struct Switches {
    /// `OTEL_SDK_DISABLED=true`, any case; no other value counts.
    pub(crate) sdk_disabled: bool,
    /// `DO_NOT_TRACK`: any non-empty value vetoes telemetry, `0` and `false`
    /// included (the consoledonottrack.com convention). Only
    /// [`Flag::Unset`] lets it through.
    pub(crate) do_not_track: Flag,
    /// `MINIMAL_TELEMETRY`.
    pub(crate) telemetry: Flag,
    /// `MINIMAL_OTEL_SPOOL`.
    pub(crate) spool: Flag,
    /// `OTEL_EXPORTER_OTLP_ENDPOINT`.
    pub(crate) endpoint: Source,
    /// `OTEL_EXPORTER_OTLP_HEADERS`.
    pub(crate) headers: Source,
    pub(crate) traces: SignalSwitches,
    pub(crate) logs: SignalSwitches,
}

/// Where one signal's records are sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Export {
    Off,
    /// The signal's own endpoint, as given.
    Signal(Pick),
    /// The base endpoint plus the signal's path.
    Base(Pick),
}

impl Export {
    /// Whether the endpoint is read from a `MINIMAL_` name.
    pub(crate) fn prefixed(self) -> bool {
        matches!(
            self,
            Self::Signal(Pick::Prefixed) | Self::Base(Pick::Prefixed)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SignalDecision {
    /// Where the signal goes. An export through a [`Pick::Prefixed`] name
    /// sends `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` and never the plain ones.
    pub(crate) export: Export,
    /// The export the signal would have had, when it was refused because
    /// it is to a `MINIMAL_` endpoint, plain headers are set and no
    /// `MINIMAL_` headers are; `export` is then [`Export::Off`].
    pub(crate) refused: Option<Export>,
    pub(crate) spool: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Decision {
    pub(crate) traces: SignalDecision,
    pub(crate) logs: SignalDecision,
}

impl Switches {
    /// Read the switches through `var`, which gives a variable's value when
    /// it is set and non-empty, as the bytes the environment holds. A value
    /// that is not UTF-8 is present (presence is what the vetoes and the
    /// endpoint and header sources read) but is no word: it is
    /// [`Flag::Other`], never `true` and never `none`. Decoded through
    /// `std::env::var` it read as absent, and a `DO_NOT_TRACK` every
    /// getenv-based tool saw as set let telemetry on (langsec F4).
    pub(crate) fn read(var: impl Fn(&str) -> Option<OsString>) -> Self {
        // `Some(None)`: set, but not UTF-8.
        let text = |name: &str| var(name).map(|v| v.into_string().ok());
        let source = |name: &str| match (
            var(&format!("MINIMAL_{name}")).is_some(),
            var(name).is_some(),
        ) {
            (false, false) => Source::Neither,
            (true, false) => Source::Prefixed,
            (false, true) => Source::Plain,
            (true, true) => Source::Both,
        };
        let signal = |signal: &str| {
            let exporter = format!("OTEL_{signal}_EXPORTER");
            let exporter = text(&format!("MINIMAL_{exporter}")).or_else(|| text(&exporter));
            let exporter = Exporter::parse(exporter.as_ref().map(|v| v.as_deref()));
            SignalSwitches {
                off: exporter == Exporter::Off,
                unsupported_exporter: exporter == Exporter::Unsupported,
                endpoint: source(&format!("OTEL_EXPORTER_OTLP_{signal}_ENDPOINT")),
                headers: var(&format!("OTEL_EXPORTER_OTLP_{signal}_HEADERS")).is_some(),
            }
        };
        let flag = |name: &str| match text(name) {
            None => Flag::Unset,
            Some(None) => Flag::Other,
            Some(Some(v)) => Flag::parse(Some(&v)),
        };
        Self {
            sdk_disabled: text("OTEL_SDK_DISABLED")
                .is_some_and(|v| v.is_some_and(|v| v.eq_ignore_ascii_case("true"))),
            do_not_track: flag("DO_NOT_TRACK"),
            telemetry: flag("MINIMAL_TELEMETRY"),
            spool: flag("MINIMAL_OTEL_SPOOL"),
            endpoint: source("OTEL_EXPORTER_OTLP_ENDPOINT"),
            headers: source("OTEL_EXPORTER_OTLP_HEADERS"),
            traces: signal("TRACES"),
            logs: signal("LOGS"),
        }
    }

    /// The explicit opt-in: `MINIMAL_TELEMETRY` true, with
    /// `OTEL_SDK_DISABLED` not true and `DO_NOT_TRACK` not set to anything.
    pub(crate) fn enabled(self) -> bool {
        !self.sdk_disabled && self.do_not_track == Flag::Unset && self.telemetry == Flag::True
    }

    pub(crate) fn decide(self) -> Decision {
        let spool = self.enabled() && self.spool != Flag::False;
        let prefixed_headers = matches!(self.headers, Source::Prefixed | Source::Both);
        // A `MINIMAL_` endpoint, base or per-signal, always beats a plain
        // one, per-signal plain ones included: the plain names are ambient
        // (often another program's collector), so a plain
        // `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` must not take Minimal's
        // traces away from `MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT` (TEL-004).
        // Within one family, the signal's own endpoint beats the base.
        let signal = |s: SignalSwitches| {
            let export = if !self.enabled() || s.off {
                Export::Off
            } else if s.endpoint.prefixed() {
                Export::Signal(Pick::Prefixed)
            } else if self.endpoint.prefixed() {
                Export::Base(Pick::Prefixed)
            } else if s.endpoint == Source::Plain {
                Export::Signal(Pick::Plain)
            } else if self.endpoint == Source::Plain {
                Export::Base(Pick::Plain)
            } else {
                Export::Off
            };
            let plain_headers = s.headers || matches!(self.headers, Source::Plain | Source::Both);
            let refused =
                (export.prefixed() && plain_headers && !prefixed_headers).then_some(export);
            SignalDecision {
                export: if refused.is_some() {
                    Export::Off
                } else {
                    export
                },
                refused,
                spool: spool && !s.off,
            }
        };
        Decision {
            traces: signal(self.traces),
            logs: signal(self.logs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_parse_any_case_and_keep_junk_apart() {
        assert_eq!(Flag::parse(None), Flag::Unset);
        assert_eq!(Flag::parse(Some("")), Flag::Unset);
        for v in ["1", "true", "YES", "On"] {
            assert_eq!(Flag::parse(Some(v)), Flag::True, "{v}");
        }
        for v in ["0", "FALSE", "no", "off"] {
            assert_eq!(Flag::parse(Some(v)), Flag::False, "{v}");
        }
        for v in ["2", "enabled", " 1"] {
            assert_eq!(Flag::parse(Some(v)), Flag::Other, "{v}");
        }
    }

    #[test]
    fn only_true_disables_the_sdk() {
        for (v, disabled) in [("true", true), ("TRUE", true), ("1", false), ("yes", false)] {
            let s = Switches::read(|n| (n == "OTEL_SDK_DISABLED").then(|| v.into()));
            assert_eq!(s.sdk_disabled, disabled, "{v}");
        }
    }

    /// T4: `DO_NOT_TRACK` set to any non-empty value turns telemetry off,
    /// whatever `MINIMAL_TELEMETRY` says; unset or empty leaves it on.
    #[test]
    fn any_do_not_track_value_vetoes_telemetry() {
        let with = |dnt: Option<&str>| {
            Switches::read(|n| match n {
                "MINIMAL_TELEMETRY" => Some("1".into()),
                "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://h:4318".into()),
                "DO_NOT_TRACK" => dnt.map(OsString::from),
                _ => None,
            })
        };
        assert!(with(Some("")).enabled(), "an empty DO_NOT_TRACK is unset");
        let on = with(None);
        assert!(on.enabled());
        assert_eq!(on.decide().traces.export, Export::Base(Pick::Plain));
        for v in [
            "1", "true", "yes", "2", "enabled", " 1", "0", "false", "off",
        ] {
            let s = with(Some(v));
            assert!(!s.enabled(), "DO_NOT_TRACK={v:?}");
            let d = s.decide();
            for sd in [d.traces, d.logs] {
                assert_eq!(sd.export, Export::Off, "DO_NOT_TRACK={v:?}");
                assert!(!sd.spool, "DO_NOT_TRACK={v:?}");
            }
        }
    }

    /// TEL-008: a `MINIMAL_` endpoint with plain headers set and no
    /// `MINIMAL_` headers is refused, and nothing else is: plain headers to a
    /// plain endpoint, `MINIMAL_` headers beside plain ones, and a
    /// signal-specific plain header for the other signal all export.
    #[test]
    fn plain_headers_refuse_a_prefixed_endpoint_unless_prefixed_headers_are_set() {
        let decide = |vars: &[&str]| {
            let vars: Vec<String> = vars.iter().map(|v| (*v).to_owned()).collect();
            Switches::read(|n| {
                (n == "MINIMAL_TELEMETRY" || vars.iter().any(|v| v == n)).then(|| "1".into())
            })
            .decide()
        };
        let prefixed = Export::Base(Pick::Prefixed);
        let d = decide(&[
            "MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_HEADERS",
        ]);
        for sd in [d.traces, d.logs] {
            assert_eq!(sd.export, Export::Off);
            assert_eq!(sd.refused, Some(prefixed));
            assert!(sd.spool, "a refused signal still spools");
        }
        let d = decide(&[
            "MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_HEADERS",
            "MINIMAL_OTEL_EXPORTER_OTLP_HEADERS",
        ]);
        assert_eq!((d.traces.export, d.traces.refused), (prefixed, None));
        let d = decide(&["OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS"]);
        assert_eq!(d.traces.export, Export::Base(Pick::Plain));
        assert_eq!(d.traces.refused, None);
        let d = decide(&[
            "MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
        ]);
        assert_eq!((d.traces.export, d.traces.refused), (prefixed, None));
        assert_eq!(
            (d.logs.export, d.logs.refused),
            (Export::Off, Some(prefixed))
        );
        let d = decide(&[
            "MINIMAL_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_HEADERS",
        ]);
        assert_eq!(d.traces.refused, Some(Export::Signal(Pick::Prefixed)));
        assert_eq!(d.logs.export, Export::Base(Pick::Plain));
    }

    /// TEL-004: a `MINIMAL_` endpoint, base or per-signal,
    /// beats every plain one, a plain per-signal endpoint included; within
    /// one family the signal's own endpoint beats the base.
    #[test]
    fn a_minimal_endpoint_beats_a_plain_signal_endpoint() {
        let decide = |vars: &[&str]| {
            Switches::read(|n| (n == "MINIMAL_TELEMETRY" || vars.contains(&n)).then(|| "1".into()))
                .decide()
        };
        // The reviewer's case: Minimal's base plus an ambient plain traces
        // endpoint for another program. Both signals go to Minimal's base.
        let d = decide(&[
            "MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        ]);
        assert_eq!(d.traces.export, Export::Base(Pick::Prefixed));
        assert_eq!(d.logs.export, Export::Base(Pick::Prefixed));
        // A MINIMAL_ per-signal endpoint beats the MINIMAL_ base.
        let d = decide(&[
            "MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT",
            "MINIMAL_OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
        ]);
        assert_eq!(d.logs.export, Export::Signal(Pick::Prefixed));
        assert_eq!(d.traces.export, Export::Base(Pick::Prefixed));
        // With no MINIMAL_ endpoint, the plain per-signal one beats the
        // plain base.
        let d = decide(&[
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        ]);
        assert_eq!(d.traces.export, Export::Signal(Pick::Plain));
        assert_eq!(d.logs.export, Export::Base(Pick::Plain));
    }

    /// Langsec F4: a set variable whose value is not UTF-8 is present. As
    /// `DO_NOT_TRACK` it vetoes (read through `std::env::var` it was absent,
    /// and the veto failed open); as `MINIMAL_TELEMETRY` it never opts in;
    /// `OTEL_SDK_DISABLED` keeps its rule, only the word `true` disables.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_value_is_present_and_never_enables() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;
        let junk = || OsString::from_vec(vec![0xff]);
        let read = |dnt: bool, telemetry: OsString, sdk: Option<OsString>| {
            Switches::read(|n| match n {
                "MINIMAL_TELEMETRY" => Some(telemetry.clone()),
                "DO_NOT_TRACK" => dnt.then(junk),
                "OTEL_SDK_DISABLED" => sdk.clone(),
                "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://h:4318".into()),
                _ => None,
            })
        };
        let s = read(true, "1".into(), None);
        assert_eq!(s.do_not_track, Flag::Other);
        assert!(!s.enabled(), "a non-UTF-8 DO_NOT_TRACK is a veto");
        let s = read(false, junk(), None);
        assert_eq!(s.telemetry, Flag::Other);
        assert!(
            !s.enabled(),
            "a non-UTF-8 MINIMAL_TELEMETRY is not an opt-in"
        );
        let s = read(false, "1".into(), Some(junk()));
        assert!(!s.sdk_disabled, "only the word true disables the SDK");
        assert!(s.enabled());
    }

    /// Langsec F15: `OTEL_<signal>_EXPORTER` is the OTel spec's comma list,
    /// each entry trimmed and read in any case. `none` alone turns the
    /// signal off; unset and `otlp` export; a list naming an exporter this
    /// build does not have (`console`, `zipkin`, `none` beside `otlp`, a
    /// value that is not UTF-8) exports as if unset and is marked
    /// unsupported, for init's one warning.
    #[test]
    fn the_exporter_variable_is_a_list() {
        assert_eq!(Exporter::parse(None), Exporter::Otlp, "unset");
        assert_eq!(
            Exporter::parse(Some(None)),
            Exporter::Unsupported,
            "not UTF-8"
        );
        for (v, want) in [
            ("otlp", Exporter::Otlp),
            ("OTLP , otlp", Exporter::Otlp),
            (",", Exporter::Otlp),
            ("none", Exporter::Off),
            ("NONE", Exporter::Off),
            (" none ,none", Exporter::Off),
            ("console", Exporter::Unsupported),
            ("otlp,console", Exporter::Unsupported),
            ("otlp,none", Exporter::Unsupported),
            ("zipkin, none", Exporter::Unsupported),
            ("nonexistent", Exporter::Unsupported),
        ] {
            assert_eq!(Exporter::parse(Some(Some(v))), want, "{v:?}");
        }
        let s = Switches::read(|n| match n {
            "OTEL_TRACES_EXPORTER" => Some("console".into()),
            "OTEL_LOGS_EXPORTER" => Some(" None".into()),
            _ => None,
        });
        assert!(!s.traces.off && s.traces.unsupported_exporter);
        assert!(s.logs.off && !s.logs.unsupported_exporter);
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;
            let s = Switches::read(|n| {
                (n == "OTEL_LOGS_EXPORTER").then(|| OsString::from_vec(vec![0xff]))
            });
            assert!(!s.logs.off && s.logs.unsupported_exporter);
            assert!(!s.traces.unsupported_exporter);
        }
    }

    #[test]
    fn a_prefixed_exporter_setting_hides_the_plain_one() {
        let s = Switches::read(|n| match n {
            "MINIMAL_OTEL_TRACES_EXPORTER" => Some("otlp".into()),
            "OTEL_TRACES_EXPORTER" | "OTEL_LOGS_EXPORTER" => Some("none".into()),
            _ => None,
        });
        assert!(!s.traces.off);
        assert!(s.logs.off);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{Decision, Export, Flag, Pick, SignalDecision, SignalSwitches, Source, Switches};

    fn signals(s: Switches, d: Decision) -> [(SignalSwitches, SignalDecision); 2] {
        [(s.traces, d.traces), (s.logs, d.logs)]
    }

    /// Nothing is exported unless `MINIMAL_TELEMETRY` is true, and never
    /// while `OTEL_SDK_DISABLED` is true or `DO_NOT_TRACK` is set to any
    /// value; with export off the plain `OTEL_*` settings change nothing.
    #[kani::proof]
    fn nothing_is_exported_without_the_opt_in() {
        let s: Switches = kani::any();
        let opted_in = s.telemetry == Flag::True;
        let vetoed = s.sdk_disabled || s.do_not_track != Flag::Unset;
        for (_, d) in signals(s, s.decide()) {
            if !opted_in || vetoed {
                assert_eq!(d.export, Export::Off);
            }
        }
    }

    /// `OTEL_SDK_DISABLED=true` leaves nothing spooled.
    #[kani::proof]
    fn a_disabled_sdk_spools_nothing() {
        let s: Switches = kani::any();
        kani::assume(s.sdk_disabled);
        for (_, d) in signals(s, s.decide()) {
            assert!(!d.spool);
        }
    }

    /// A present `MINIMAL_`-prefixed endpoint is the one used, and a plain
    /// one only when no prefixed one is present for the signal, base or
    /// per-signal: a plain per-signal endpoint never beats a `MINIMAL_`
    /// base (TEL-004).
    #[kani::proof]
    fn a_prefixed_endpoint_wins() {
        let s: Switches = kani::any();
        let prefixed = |src: Source| matches!(src, Source::Prefixed | Source::Both);
        for (sig, d) in signals(s, s.decide()) {
            let any_prefixed = prefixed(sig.endpoint) || prefixed(s.endpoint);
            match d.refused.unwrap_or(d.export) {
                Export::Signal(p) => assert_eq!(p == Pick::Prefixed, prefixed(sig.endpoint)),
                Export::Base(p) => assert_eq!(p == Pick::Prefixed, prefixed(s.endpoint)),
                Export::Off => {}
            }
            if let Export::Signal(Pick::Plain) | Export::Base(Pick::Plain) = d.export {
                assert!(!any_prefixed);
            }
        }
    }

    /// Plain headers are never sent to a `MINIMAL_` endpoint: a signal is
    /// exported through a prefixed name only when no plain headers are set
    /// for it or `MINIMAL_OTEL_EXPORTER_OTLP_HEADERS` is set (the exporter
    /// then strips the plain ones), else it is refused and still spooled;
    /// and only that case is refused.
    #[kani::proof]
    fn a_prefixed_endpoint_never_carries_plain_headers() {
        let s: Switches = kani::any();
        let d = s.decide();
        let prefixed_headers = matches!(s.headers, Source::Prefixed | Source::Both);
        for (sig, d) in signals(s, d) {
            let plain_headers = sig.headers || matches!(s.headers, Source::Plain | Source::Both);
            if let Export::Signal(Pick::Prefixed) | Export::Base(Pick::Prefixed) = d.export {
                assert!(!plain_headers || prefixed_headers);
            }
            if let Some(e) = d.refused {
                assert_eq!(d.export, Export::Off);
                assert!(matches!(
                    e,
                    Export::Signal(Pick::Prefixed) | Export::Base(Pick::Prefixed)
                ));
                assert!(plain_headers && !prefixed_headers);
                assert_eq!(d.spool, s.enabled() && s.spool != Flag::False && !sig.off);
            }
        }
    }

    /// With export enabled, a signal is sent to the first endpoint present
    /// in this order: its own `MINIMAL_` endpoint, the `MINIMAL_` base, its
    /// own plain endpoint, the plain base. It is off only when none is set,
    /// its exporter is `none`, or it is refused (plain headers and a
    /// `MINIMAL_` endpoint); a refusal names the endpoint it would have used.
    #[kani::proof]
    fn an_enabled_signal_goes_to_the_nearest_endpoint() {
        let s: Switches = kani::any();
        kani::assume(s.enabled());
        let prefixed = |src: Source| matches!(src, Source::Prefixed | Source::Both);
        for (sig, d) in signals(s, s.decide()) {
            let want = if sig.off {
                Export::Off
            } else if prefixed(sig.endpoint) {
                Export::Signal(Pick::Prefixed)
            } else if prefixed(s.endpoint) {
                Export::Base(Pick::Prefixed)
            } else if sig.endpoint != Source::Neither {
                Export::Signal(Pick::Plain)
            } else if s.endpoint != Source::Neither {
                Export::Base(Pick::Plain)
            } else {
                Export::Off
            };
            assert_eq!(d.refused.unwrap_or(d.export), want);
            assert!(d.refused.is_none() || d.export == Export::Off);
        }
    }

    /// A signal is spooled exactly when telemetry is enabled, the spool is
    /// not switched off, and the signal's exporter is not `none`.
    #[kani::proof]
    fn the_spool_follows_its_switches() {
        let s: Switches = kani::any();
        let on = !s.sdk_disabled && s.do_not_track == Flag::Unset && s.telemetry == Flag::True;
        for (sig, d) in signals(s, s.decide()) {
            assert_eq!(d.spool, on && s.spool != Flag::False && !sig.off);
        }
    }
}

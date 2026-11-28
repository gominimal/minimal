//! Which rule the gate reports for an outcome.
//!
//! Layer 5 of the crate, composition: it decides nothing the layers below did not. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! The gate writes an event for a frame it drops, an answer address it
//! refuses and a publish it refuses, and the event names a rule. This is the
//! one place that says which rule belongs to which outcome of the kernel.
//! Rules are numbers here; [`NAMES`] gives the name each is reported under.
//!
//! The map is a table for each kind of outcome: [`egress_rule`],
//! [`ingress_rule`], [`rebind_rule`], [`publish_rule`], and for a frame
//! refused before any decision [`said_rule`] and [`heard_rule`].
//!
//! THEOREM RP1, for every outcome:
//!   (a) [`egress`], [`ingress`], [`rebind`] and [`publish`] return their
//!       tables;
//!   (b) a rule is a number below [`RULES`], so `NAMES` has its string;
//!   (c) an egress decision is reported with no rule exactly when it admits
//!       the frame, and with a rule or as [`Reported::Internal`] when it
//!       does not;
//!   (d) a frame toward a box is reported with a rule exactly when it is not
//!       delivered, apart from the two outcomes in (e);
//!   (e) `Internal` is reported only for an outcome the gate does not build:
//!       a pin's refusal carried as a decision, the cohort's arm for a frame
//!       that is not IPv4, and a table handed a frame for another box;
//!   (f) an answer address is reported with no rule exactly when it is
//!       admitted, and a publish exactly when it is not refused;
//!   (g) TCP or UDP on a first fragment without a whole header is reported
//!       with a rule of its own, one for a frame a guest sent and one for a
//!       frame toward a guest; toward a guest, bytes that are no frame
//!       (IG2's malformed arm) are reported with a rule of their own as well,
//!       a different number from the rule the reader's reason has for a frame
//!       a guest sent. Nothing else is reported by those two tables: a frame
//!       goes on to its decision, and a frame a guest sent that is no frame is
//!       the reader's to name.
//!
//! What it does not say: that every rule of `NAMES` is reported from here.
//! Twenty-six are, three of them on the frame reader's reasons (by
//! `not_a_frame`); the other fourteen are not reported from here.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::cohort::{CohortArm, CohortJudged};
use crate::flow::Inbound;
use crate::frame::Reason;
use crate::gate::{Arrived, Decision, Stray};
#[cfg(verus_keep_ghost)]
use crate::gate::{arrived_delivers, decision_admits};
use crate::ingress::{Heard, Seen};
use crate::judge::Judged;
use crate::ledger::Published;
use crate::node::{NodeArm, NodeJudged};
use crate::notes::Noted;
use crate::pins::Egress;
use crate::rebind::Rebind;
use crate::route::Said;
use crate::row::RowArm;
use crate::split::Arm;

/// How many rule numbers there are: 0 is "no rule".
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const RULES: u8 = 41;

/// The name each rule is reported under, by number.
pub const NAMES: [&str; RULES as usize] = [
    "none",
    "egress-unknown-source",
    "egress-node-plane-unpinned",
    "egress-switch-control-surface",
    "egress-inbound-flow-cap",
    "egress-deny-all-dns-query",
    "egress-infrastructure-destination",
    "host-alias",
    "box-name",
    "egress-uncredentialed-proxy-destination",
    "egress-proxy-opening-toward-box",
    "egress-unregistered-source",
    "egress-unregistered-live-lease",
    "egress-undeclared-verb",
    "egress-unregistered-publish",
    "egress-unknown-publish-address",
    "egress-undeclared-publish-record",
    "egress-publish-at-revoking-address",
    "egress-publish-ledger-full",
    "egress-publish-listener-held",
    "egress-undeclared-retract",
    "egress-malformed-publish",
    "egress-control-upgrade",
    "egress-connection-cap",
    "egress-accept-failed",
    "egress-range-probe",
    "egress-host-ip-boxes",
    "egress-backpressure",
    "ingress-backpressure",
    "egress-foreign-source",
    "egress-ipv6",
    "egress-undeclared-ethertype",
    "egress-truncated-ipv4",
    "egress-undeclared-protocol",
    "egress-denied-subnet",
    "egress-undeclared-subnet",
    "dns-rebinding-denied-subnet",
    "dns-rebinding-infrastructure",
    "egress-truncated-transport",
    "ingress-truncated-transport",
    "ingress-truncated-ipv4",
];

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const NONE: u8 = 0;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const UNKNOWN_SOURCE: u8 = 1;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const NODE_PLANE_UNPINNED: u8 = 2;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const SWITCH_CONTROL: u8 = 3;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const INBOUND_FLOW_CAP: u8 = 4;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const DENY_ALL_DNS: u8 = 5;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const INFRASTRUCTURE: u8 = 6;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const HOST_ALIAS: u8 = 7;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const BOX_NAME: u8 = 8;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const PROXY_LANE: u8 = 9;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const PROXY_OPENING: u8 = 10;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const UNREGISTERED: u8 = 11;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const LIVE_LEASE: u8 = 12;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const LEDGER_FULL: u8 = 18;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const LISTENER_HELD: u8 = 19;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const HOST_IP_BOXES: u8 = 26;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const IPV6: u8 = 30;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const UNDECLARED_ETHERTYPE: u8 = 31;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const TRUNCATED_IPV4: u8 = 32;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const UNDECLARED_PROTOCOL: u8 = 33;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const DENIED_SUBNET: u8 = 34;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const UNDECLARED_SUBNET: u8 = 35;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const DNS_REBIND_DENIED: u8 = 36;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const DNS_REBIND_INFRA: u8 = 37;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const SHORT_HEADER_OUT: u8 = 38;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const SHORT_HEADER_IN: u8 = 39;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const NO_FRAME_IN: u8 = 40;

/// The reported rule, or an outcome the gate does not build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Reported {
    /// The rule's number; 0 is no rule.
    Rule(u8),
    Internal,
}

#[cfg(verus_keep_ghost)]
verus! {

/// The rule of a row's stateless arm.
pub open spec fn row_arm_rule(a: RowArm) -> u8 {
    match a {
        RowArm::Arp => NONE,
        RowArm::LaneAdmit => NONE,
        RowArm::Resolver => NONE,
        RowArm::Rules => NONE,
        RowArm::ControlSurface => SWITCH_CONTROL,
        RowArm::InfraFixed => INFRASTRUCTURE,
        RowArm::InfraPlane => INFRASTRUCTURE,
        RowArm::InfraPrivate => INFRASTRUCTURE,
        RowArm::AliasClosed => HOST_ALIAS,
        RowArm::LaneRefuse => PROXY_LANE,
        RowArm::UndeclaredProtocol => UNDECLARED_PROTOCOL,
        RowArm::DeniedSubnet => DENIED_SUBNET,
        RowArm::UndeclaredSubnet => UNDECLARED_SUBNET,
    }
}

/// The rule of the node's stateless arm.
pub open spec fn node_arm_rule(a: NodeArm) -> u8 {
    match a {
        NodeArm::Arp => NONE,
        NodeArm::AliasOpen => NONE,
        NodeArm::Sibling => NONE,
        NodeArm::Resolver => NONE,
        NodeArm::Baseline => NONE,
        NodeArm::ControlSurface => SWITCH_CONTROL,
        NodeArm::ProxyRefuse => PROXY_LANE,
        NodeArm::InfraFixed => INFRASTRUCTURE,
        NodeArm::InfraPlane => INFRASTRUCTURE,
        NodeArm::InfraPrivate => INFRASTRUCTURE,
        NodeArm::AliasClosed => HOST_ALIAS,
        NodeArm::Unpinned => NODE_PLANE_UNPINNED,
    }
}

/// The report of the cohort's stateless arm.
pub open spec fn cohort_arm_rule(a: CohortArm) -> Reported {
    match a {
        CohortArm::Member => Reported::Rule(NONE),
        CohortArm::LaneAdmit => Reported::Rule(NONE),
        CohortArm::ControlSurface => Reported::Rule(SWITCH_CONTROL),
        CohortArm::LaneRefuse => Reported::Rule(PROXY_LANE),
        CohortArm::AliasClosed => Reported::Rule(HOST_ALIAS),
        CohortArm::Infrastructure => Reported::Rule(INFRASTRUCTURE),
        CohortArm::NoMember => Reported::Rule(HOST_IP_BOXES),
        CohortArm::NeedsPin => Reported::Rule(HOST_IP_BOXES),
        CohortArm::Unbounded => Reported::Rule(HOST_IP_BOXES),
        CohortArm::Arp => Reported::Rule(NONE),
    }
}

/// The report of a DNS pin's answer.
pub open spec fn pinned_rule(e: Egress) -> Reported {
    match e {
        Egress::ByFlow => Reported::Rule(NONE),
        Egress::Retained => Reported::Rule(NONE),
        Egress::Window => Reported::Rule(NONE),
        Egress::Refused => Reported::Internal,
    }
}

/// The table for an egress decision. `lease_live` says the source of an
/// unregistered frame holds a live lease.
pub open spec fn egress_rule(d: Decision, lease_live: bool) -> Reported {
    match d {
        Decision::Refused(Stray::ControlSurface) => Reported::Rule(SWITCH_CONTROL),
        Decision::Refused(Stray::Unregistered) => Reported::Rule(if lease_live { LIVE_LEASE } else { UNREGISTERED }),
        Decision::Refused(Stray::Unknown) => Reported::Rule(UNKNOWN_SOURCE),
        Decision::Row(_, j) => match j {
            Judged::ReplyFlow => Reported::Rule(NONE),
            Judged::Refusal => Reported::Rule(NONE),
            Judged::AliasByName => Reported::Rule(NONE),
            Judged::BoxName => Reported::Rule(NONE),
            Judged::Pinned(e) => pinned_rule(e),
            Judged::BoxNameRefused => Reported::Rule(BOX_NAME),
            Judged::Row(a) => Reported::Rule(row_arm_rule(a)),
        },
        Decision::Node(j) => match j {
            NodeJudged::ReplyFlow => Reported::Rule(NONE),
            NodeJudged::Refusal => Reported::Rule(NONE),
            NodeJudged::Pinned(e) => pinned_rule(e),
            NodeJudged::Node(a) => Reported::Rule(node_arm_rule(a)),
        },
        Decision::Cohort(j) => match j {
            CohortJudged::ReplyFlow => Reported::Rule(NONE),
            CohortJudged::Refusal => Reported::Rule(NONE),
            CohortJudged::Pinned(e) => pinned_rule(e),
            CohortJudged::Cohort(a) => cohort_arm_rule(a),
        },
    }
}

/// The table for what a box's tables saw of a frame toward it.
pub open spec fn seen_rule(s: Seen) -> Reported {
    match s {
        Seen::Passed => Reported::Rule(NONE),
        Seen::ProxyOpening => Reported::Rule(PROXY_OPENING),
        Seen::Noted(n) => if n == Noted::NotThisBox { Reported::Internal } else { Reported::Rule(NONE) },
        Seen::Flow(x) => if x == Inbound::TableFull {
            Reported::Rule(INBOUND_FLOW_CAP)
        } else if x == Inbound::NotThisBox {
            Reported::Internal
        } else {
            Reported::Rule(NONE)
        },
    }
}

/// The table for a frame toward a box.
pub open spec fn ingress_rule(a: Arrived) -> Reported {
    match a {
        Arrived::NotARow => Reported::Rule(NONE),
        Arrived::Row(_, s) => seen_rule(s),
        Arrived::Node(s) => seen_rule(s),
        Arrived::Cohort(s) => seen_rule(s),
    }
}

/// The table for one answer address.
pub open spec fn rebind_rule(r: Rebind) -> u8 {
    match r {
        Rebind::Admitted => NONE,
        Rebind::DeniedSubnet => DNS_REBIND_DENIED,
        Rebind::Infrastructure => DNS_REBIND_INFRA,
    }
}

/// The table for a publish.
pub open spec fn publish_rule(p: Published) -> u8 {
    match p {
        Published::Noted => NONE,
        Published::NotedEvicting(_) => NONE,
        Published::Held => NONE,
        Published::HeldElsewhere => LISTENER_HELD,
        Published::Full => LEDGER_FULL,
    }
}

/// An egress decision the gate does not build.
pub open spec fn unbuilt(d: Decision) -> bool {
    match d {
        Decision::Refused(_) => false,
        Decision::Row(_, j) => j == Judged::Pinned(Egress::Refused),
        Decision::Node(j) => j == NodeJudged::Pinned(Egress::Refused),
        Decision::Cohort(j) => j == CohortJudged::Pinned(Egress::Refused),
    }
}

/// What a box's tables say of a frame for another box.
pub open spec fn misdirected(s: Seen) -> bool {
    s == Seen::Noted(Noted::NotThisBox) || s == Seen::Flow(Inbound::NotThisBox)
}

/// RP1 (b), (c), (e) for an egress decision.
pub proof fn theorem_rp1_egress(d: Decision, lease_live: bool)
    ensures
        match egress_rule(d, lease_live) {
            Reported::Rule(n) => n < RULES && (n == NONE) == decision_admits(d),
            Reported::Internal => !decision_admits(d) && unbuilt(d),
        },
        unbuilt(d) ==> egress_rule(d, lease_live) == Reported::Internal,
{
}

/// RP1 (b), (d), (e) for a frame toward a box.
pub proof fn theorem_rp1_ingress(a: Arrived)
    ensures
        match ingress_rule(a) {
            Reported::Rule(n) => n < RULES && (n == NONE) == arrived_delivers(a),
            Reported::Internal => match a {
                Arrived::NotARow => false,
                Arrived::Row(_, s) => misdirected(s),
                Arrived::Node(s) => misdirected(s),
                Arrived::Cohort(s) => misdirected(s),
            },
        },
{
}

/// RP1 (b), (f).
pub proof fn theorem_rp1_answers_and_publishes(r: Rebind, p: Published)
    ensures
        rebind_rule(r) < RULES,
        (rebind_rule(r) == NONE) == (r == Rebind::Admitted),
        publish_rule(p) < RULES,
        (publish_rule(p) == NONE) == (p != Published::HeldElsewhere && p != Published::Full),
{
}

/// The table for a stateless arm that nothing lifted: the rule of the
/// decision it would be.
pub open spec fn arm_rule(a: Arm, lease_live: bool) -> Reported {
    match a {
        Arm::Refused(s) => egress_rule(Decision::Refused(s), lease_live),
        Arm::Row(i, x) => egress_rule(Decision::Row(i, Judged::Row(x)), lease_live),
        Arm::RowDns(_) => Reported::Rule(DENY_ALL_DNS),
        Arm::Node(x) => egress_rule(Decision::Node(NodeJudged::Node(x)), lease_live),
        Arm::Cohort(x) => egress_rule(Decision::Cohort(CohortJudged::Cohort(x)), lease_live),
        Arm::CohortDns => Reported::Rule(DENY_ALL_DNS),
    }
}

/// The table for what is no frame: the rule of the reader's reason.
pub open spec fn reason_rule(why: Reason) -> u8 {
    match why {
        Reason::Ipv6 => IPV6,
        Reason::Vlan => UNDECLARED_ETHERTYPE,
        Reason::OtherEtherType => UNDECLARED_ETHERTYPE,
        Reason::Short => TRUNCATED_IPV4,
        Reason::ArpShape => TRUNCATED_IPV4,
        Reason::BadVersion => TRUNCATED_IPV4,
        Reason::BadHeaderLength => TRUNCATED_IPV4,
        Reason::BadTotalLength => TRUNCATED_IPV4,
    }
}

/// RP1 (b) for what is no frame: it always has a rule.
pub proof fn theorem_rp1_no_frame_has_a_rule(why: Reason)
    ensures
        NONE < reason_rule(why) < RULES,
{
}

/// The table for what the facts of a frame a guest sent came to: a rule for
/// a short header, and none from here for anything else.
pub open spec fn said_rule(s: Said) -> Option<u8> {
    match s {
        Said::ShortHeader => Some(SHORT_HEADER_OUT),
        Said::Frame(_) => None,
        Said::NotAFrame => None,
    }
}

/// The table for what the facts of a frame toward a guest came to.
pub open spec fn heard_rule(h: Heard) -> Option<u8> {
    match h {
        Heard::ShortHeader => Some(SHORT_HEADER_IN),
        Heard::Transport(_) => None,
        Heard::LaterFragment => None,
        Heard::NoPorts => None,
        Heard::NotV4 => None,
        Heard::Malformed(_) => Some(NO_FRAME_IN),
    }
}

/// RP1 (b), (g).
pub proof fn theorem_rp1_short_headers(s: Said, h: Heard)
    ensures
        (said_rule(s) is Some) == (s == Said::ShortHeader),
        (heard_rule(h) is Some) == !crate::ingress::heard_delivers(h),
        said_rule(s) matches Some(n) ==> NONE < n < RULES,
        heard_rule(h) matches Some(n) ==> NONE < n < RULES,
        said_rule(Said::ShortHeader) != heard_rule(Heard::ShortHeader),
        forall|why: Reason| heard_rule(Heard::Malformed(why)) != Some(reason_rule(why)),
{
}

} // verus!

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == row_arm_rule(a),
))]
fn row_arm(a: RowArm) -> u8 {
    match a {
        RowArm::Arp => NONE,
        RowArm::LaneAdmit => NONE,
        RowArm::Resolver => NONE,
        RowArm::Rules => NONE,
        RowArm::ControlSurface => SWITCH_CONTROL,
        RowArm::InfraFixed => INFRASTRUCTURE,
        RowArm::InfraPlane => INFRASTRUCTURE,
        RowArm::InfraPrivate => INFRASTRUCTURE,
        RowArm::AliasClosed => HOST_ALIAS,
        RowArm::LaneRefuse => PROXY_LANE,
        RowArm::UndeclaredProtocol => UNDECLARED_PROTOCOL,
        RowArm::DeniedSubnet => DENIED_SUBNET,
        RowArm::UndeclaredSubnet => UNDECLARED_SUBNET,
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == node_arm_rule(a),
))]
fn node_arm(a: NodeArm) -> u8 {
    match a {
        NodeArm::Arp => NONE,
        NodeArm::AliasOpen => NONE,
        NodeArm::Sibling => NONE,
        NodeArm::Resolver => NONE,
        NodeArm::Baseline => NONE,
        NodeArm::ControlSurface => SWITCH_CONTROL,
        NodeArm::ProxyRefuse => PROXY_LANE,
        NodeArm::InfraFixed => INFRASTRUCTURE,
        NodeArm::InfraPlane => INFRASTRUCTURE,
        NodeArm::InfraPrivate => INFRASTRUCTURE,
        NodeArm::AliasClosed => HOST_ALIAS,
        NodeArm::Unpinned => NODE_PLANE_UNPINNED,
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == cohort_arm_rule(a),
))]
fn cohort_arm(a: CohortArm) -> Reported {
    match a {
        CohortArm::Member => Reported::Rule(NONE),
        CohortArm::LaneAdmit => Reported::Rule(NONE),
        CohortArm::ControlSurface => Reported::Rule(SWITCH_CONTROL),
        CohortArm::LaneRefuse => Reported::Rule(PROXY_LANE),
        CohortArm::AliasClosed => Reported::Rule(HOST_ALIAS),
        CohortArm::Infrastructure => Reported::Rule(INFRASTRUCTURE),
        CohortArm::NoMember => Reported::Rule(HOST_IP_BOXES),
        CohortArm::NeedsPin => Reported::Rule(HOST_IP_BOXES),
        CohortArm::Unbounded => Reported::Rule(HOST_IP_BOXES),
        CohortArm::Arp => Reported::Rule(NONE),
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == pinned_rule(e),
))]
fn pinned(e: Egress) -> Reported {
    match e {
        Egress::ByFlow => Reported::Rule(NONE),
        Egress::Retained => Reported::Rule(NONE),
        Egress::Window => Reported::Rule(NONE),
        Egress::Refused => Reported::Internal,
    }
}

/// The rule for an egress decision. `lease_live` is read only for a frame
/// from an unregistered source: whether that source holds a live lease.
/// RP1 (a).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == egress_rule(d, lease_live),
))]
pub fn egress(d: Decision, lease_live: bool) -> Reported {
    match d {
        Decision::Refused(Stray::ControlSurface) => Reported::Rule(SWITCH_CONTROL),
        Decision::Refused(Stray::Unregistered) => {
            if lease_live {
                Reported::Rule(LIVE_LEASE)
            } else {
                Reported::Rule(UNREGISTERED)
            }
        }
        Decision::Refused(Stray::Unknown) => Reported::Rule(UNKNOWN_SOURCE),
        Decision::Row(_, j) => match j {
            Judged::ReplyFlow => Reported::Rule(NONE),
            Judged::Refusal => Reported::Rule(NONE),
            Judged::AliasByName => Reported::Rule(NONE),
            Judged::BoxName => Reported::Rule(NONE),
            Judged::Pinned(e) => pinned(e),
            Judged::BoxNameRefused => Reported::Rule(BOX_NAME),
            Judged::Row(a) => Reported::Rule(row_arm(a)),
        },
        Decision::Node(j) => match j {
            NodeJudged::ReplyFlow => Reported::Rule(NONE),
            NodeJudged::Refusal => Reported::Rule(NONE),
            NodeJudged::Pinned(e) => pinned(e),
            NodeJudged::Node(a) => Reported::Rule(node_arm(a)),
        },
        Decision::Cohort(j) => match j {
            CohortJudged::ReplyFlow => Reported::Rule(NONE),
            CohortJudged::Refusal => Reported::Rule(NONE),
            CohortJudged::Pinned(e) => pinned(e),
            CohortJudged::Cohort(a) => cohort_arm(a),
        },
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == seen_rule(s),
))]
fn seen(s: Seen) -> Reported {
    match s {
        Seen::Passed => Reported::Rule(NONE),
        Seen::ProxyOpening => Reported::Rule(PROXY_OPENING),
        Seen::Noted(n) => match n {
            Noted::NotThisBox => Reported::Internal,
            Noted::Noted => Reported::Rule(NONE),
            Noted::Renoted => Reported::Rule(NONE),
            Noted::NotAConnect => Reported::Rule(NONE),
            Noted::ClientAtQuota => Reported::Rule(NONE),
            Noted::Full => Reported::Rule(NONE),
        },
        Seen::Flow(x) => match x {
            Inbound::TableFull => Reported::Rule(INBOUND_FLOW_CAP),
            Inbound::NotThisBox => Reported::Internal,
            Inbound::Opened => Reported::Rule(NONE),
            Inbound::Refreshed { .. } => Reported::Rule(NONE),
            Inbound::Ended => Reported::Rule(NONE),
            Inbound::Untracked => Reported::Rule(NONE),
        },
    }
}

/// The rule for a frame a guest sent that was refused before routing, or
/// `None` when it was not. RP1 (a), (g).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == said_rule(s),
))]
pub fn said(s: Said) -> Option<u8> {
    match s {
        Said::ShortHeader => Some(SHORT_HEADER_OUT),
        Said::Frame(_) => None,
        Said::NotAFrame => None,
    }
}

/// The rule for a frame toward a guest that was dropped before its box's
/// tables, or `None` when it was not. RP1 (a), (g).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == heard_rule(h),
))]
pub fn heard(h: Heard) -> Option<u8> {
    match h {
        Heard::ShortHeader => Some(SHORT_HEADER_IN),
        Heard::Transport(_) => None,
        Heard::LaterFragment => None,
        Heard::NoPorts => None,
        Heard::NotV4 => None,
        Heard::Malformed(_) => Some(NO_FRAME_IN),
    }
}

/// The rule for a stateless arm that nothing lifted. RP1 (a).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == arm_rule(a, lease_live),
))]
pub fn arm(a: Arm, lease_live: bool) -> Reported {
    match a {
        Arm::Refused(s) => egress(Decision::Refused(s), lease_live),
        Arm::Row(i, x) => egress(Decision::Row(i, Judged::Row(x)), lease_live),
        Arm::RowDns(_) => Reported::Rule(DENY_ALL_DNS),
        Arm::Node(x) => egress(Decision::Node(NodeJudged::Node(x)), lease_live),
        Arm::Cohort(x) => egress(Decision::Cohort(CohortJudged::Cohort(x)), lease_live),
        Arm::CohortDns => Reported::Rule(DENY_ALL_DNS),
    }
}

/// The rule for what is no frame. RP1 (a).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == reason_rule(why),
))]
pub fn not_a_frame(why: Reason) -> u8 {
    match why {
        Reason::Ipv6 => IPV6,
        Reason::Vlan => UNDECLARED_ETHERTYPE,
        Reason::OtherEtherType => UNDECLARED_ETHERTYPE,
        Reason::Short => TRUNCATED_IPV4,
        Reason::ArpShape => TRUNCATED_IPV4,
        Reason::BadVersion => TRUNCATED_IPV4,
        Reason::BadHeaderLength => TRUNCATED_IPV4,
        Reason::BadTotalLength => TRUNCATED_IPV4,
    }
}

/// The rule for a frame toward a box. RP1 (a).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == ingress_rule(a),
))]
pub fn ingress(a: Arrived) -> Reported {
    match a {
        Arrived::NotARow => Reported::Rule(NONE),
        Arrived::Row(_, s) => seen(s),
        Arrived::Node(s) => seen(s),
        Arrived::Cohort(s) => seen(s),
    }
}

/// The rule for one answer address. RP1 (a).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == rebind_rule(x),
))]
pub fn rebind(x: Rebind) -> u8 {
    match x {
        Rebind::Admitted => NONE,
        Rebind::DeniedSubnet => DNS_REBIND_DENIED,
        Rebind::Infrastructure => DNS_REBIND_INFRA,
    }
}

/// The rule for a publish. RP1 (a).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == publish_rule(p),
))]
pub fn publish(p: Published) -> u8 {
    match p {
        Published::Noted => NONE,
        Published::NotedEvicting(_) => NONE,
        Published::Held => NONE,
        Published::HeldElsewhere => LISTENER_HELD,
        Published::Full => LEDGER_FULL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_is_distinct_and_the_first_is_none() {
        assert_eq!(NAMES.len(), usize::from(RULES));
        assert_eq!(NAMES[usize::from(NONE)], "none");
        let mut i = 0;
        while i < NAMES.len() {
            let mut j = i + 1;
            while j < NAMES.len() {
                assert_ne!(NAMES[i], NAMES[j]);
                j += 1;
            }
            i += 1;
        }
    }

    #[test]
    fn a_short_header_has_a_rule_for_each_direction_and_nothing_else_does() {
        assert_eq!(said(Said::ShortHeader), Some(SHORT_HEADER_OUT));
        assert_eq!(said(Said::NotAFrame), None);
        assert_eq!(heard(Heard::ShortHeader), Some(SHORT_HEADER_IN));
        assert_eq!(heard(Heard::LaterFragment), None);
        assert_eq!(heard(Heard::NoPorts), None);
        assert_eq!(heard(Heard::NotV4), None);
        assert_eq!(
            heard(Heard::Malformed(Reason::BadVersion)),
            Some(NO_FRAME_IN)
        );
        assert_eq!(NAMES[usize::from(NO_FRAME_IN)], "ingress-truncated-ipv4");
        assert_eq!(
            NAMES[usize::from(SHORT_HEADER_OUT)],
            "egress-truncated-transport"
        );
        assert_eq!(
            NAMES[usize::from(SHORT_HEADER_IN)],
            "ingress-truncated-transport"
        );
    }

    #[test]
    fn each_number_used_here_has_the_products_string() {
        assert_eq!(
            NAMES[usize::from(DENY_ALL_DNS)],
            "egress-deny-all-dns-query"
        );
        assert_eq!(NAMES[usize::from(IPV6)], "egress-ipv6");
        assert_eq!(
            NAMES[usize::from(UNDECLARED_ETHERTYPE)],
            "egress-undeclared-ethertype"
        );
        assert_eq!(NAMES[usize::from(TRUNCATED_IPV4)], "egress-truncated-ipv4");
        assert_eq!(NAMES[usize::from(UNKNOWN_SOURCE)], "egress-unknown-source");
        assert_eq!(
            NAMES[usize::from(NODE_PLANE_UNPINNED)],
            "egress-node-plane-unpinned"
        );
        assert_eq!(
            NAMES[usize::from(SWITCH_CONTROL)],
            "egress-switch-control-surface"
        );
        assert_eq!(
            NAMES[usize::from(INBOUND_FLOW_CAP)],
            "egress-inbound-flow-cap"
        );
        assert_eq!(
            NAMES[usize::from(INFRASTRUCTURE)],
            "egress-infrastructure-destination"
        );
        assert_eq!(NAMES[usize::from(HOST_ALIAS)], "host-alias");
        assert_eq!(NAMES[usize::from(BOX_NAME)], "box-name");
        assert_eq!(
            NAMES[usize::from(PROXY_LANE)],
            "egress-uncredentialed-proxy-destination"
        );
        assert_eq!(
            NAMES[usize::from(PROXY_OPENING)],
            "egress-proxy-opening-toward-box"
        );
        assert_eq!(
            NAMES[usize::from(UNREGISTERED)],
            "egress-unregistered-source"
        );
        assert_eq!(
            NAMES[usize::from(LIVE_LEASE)],
            "egress-unregistered-live-lease"
        );
        assert_eq!(
            NAMES[usize::from(LEDGER_FULL)],
            "egress-publish-ledger-full"
        );
        assert_eq!(
            NAMES[usize::from(LISTENER_HELD)],
            "egress-publish-listener-held"
        );
        assert_eq!(NAMES[usize::from(HOST_IP_BOXES)], "egress-host-ip-boxes");
        assert_eq!(
            NAMES[usize::from(UNDECLARED_PROTOCOL)],
            "egress-undeclared-protocol"
        );
        assert_eq!(NAMES[usize::from(DENIED_SUBNET)], "egress-denied-subnet");
        assert_eq!(
            NAMES[usize::from(UNDECLARED_SUBNET)],
            "egress-undeclared-subnet"
        );
        assert_eq!(
            NAMES[usize::from(DNS_REBIND_DENIED)],
            "dns-rebinding-denied-subnet"
        );
        assert_eq!(
            NAMES[usize::from(DNS_REBIND_INFRA)],
            "dns-rebinding-infrastructure"
        );
    }

    #[test]
    fn a_refusal_has_its_rule_and_an_admit_none() {
        assert_eq!(
            egress(Decision::Refused(Stray::Unregistered), false),
            Reported::Rule(UNREGISTERED)
        );
        assert_eq!(
            egress(Decision::Refused(Stray::Unregistered), true),
            Reported::Rule(LIVE_LEASE)
        );
        assert_eq!(
            egress(Decision::Row(0, Judged::Row(RowArm::Rules)), false),
            Reported::Rule(NONE)
        );
        assert_eq!(
            egress(Decision::Row(0, Judged::Row(RowArm::InfraPlane)), false),
            Reported::Rule(INFRASTRUCTURE)
        );
        assert_eq!(
            egress(Decision::Row(0, Judged::BoxNameRefused), false),
            Reported::Rule(BOX_NAME)
        );
        assert_eq!(
            egress(Decision::Node(NodeJudged::Node(NodeArm::Unpinned)), false),
            Reported::Rule(NODE_PLANE_UNPINNED)
        );
        assert_eq!(
            egress(
                Decision::Cohort(CohortJudged::Cohort(CohortArm::NoMember)),
                false
            ),
            Reported::Rule(HOST_IP_BOXES)
        );
        assert_eq!(
            egress(
                Decision::Cohort(CohortJudged::Cohort(CohortArm::Arp)),
                false
            ),
            Reported::Rule(NONE)
        );
        assert_eq!(
            egress(Decision::Row(0, Judged::Pinned(Egress::Refused)), false),
            Reported::Internal
        );
        assert_eq!(
            ingress(Arrived::Row(0, Seen::Flow(Inbound::TableFull))),
            Reported::Rule(INBOUND_FLOW_CAP)
        );
        assert_eq!(
            ingress(Arrived::Node(Seen::ProxyOpening)),
            Reported::Rule(PROXY_OPENING)
        );
        assert_eq!(
            ingress(Arrived::Row(0, Seen::Noted(Noted::Full))),
            Reported::Rule(NONE)
        );
        assert_eq!(rebind(Rebind::Infrastructure), DNS_REBIND_INFRA);
        assert_eq!(publish(Published::HeldElsewhere), LISTENER_HELD);
    }
}

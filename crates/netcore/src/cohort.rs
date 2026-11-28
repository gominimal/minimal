//! The decision for a frame from the host-address cohort.
//!
//! Layer 4 of the crate, a decision. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! Host-address boxes share one source address, so a frame cannot be tied to
//! one box. The gate therefore admits a cohort frame when some resident
//! box's own rules would admit it, and otherwise refuses it. The members are
//! the resident host-address boxes, in the order the gate holds them.
//!
//! THEOREM CV1: `decide_cohort` returns `cohort_spec`.
//!
//! THEOREMS about the table, for every plan, set of members and frame:
//!   CV2  with no member, no IPv4 frame is admitted (an ARP packet always is,
//!        as a row's and the node's are);
//!   CV3  a frame to the gateway is admitted only as TCP or UDP to port 53,
//!        and any other frame to it is refused by the control surface arm;
//!   CV4  a frame to the proxy's address is admitted only on the lane: some
//!        member declares a credentialed upstream, TCP, port 8118 or 443;
//!   CV5  a frame to the host alias is admitted only when the alias is open
//!        to the cohort for this frame;
//!   CV6  a frame to 169.254.0.0/16 or 127.0.0.0/8 that is not the proxy's
//!        address is never admitted, and no DNS admission is asked for it;
//!        for a plan inside 100.64.0.0/10 the proxy's address is never in
//!        those ranges, so the exception is empty (`theorem_cv6_shared`);
//!   CV7  any other admitted frame has a member whose own rules admit it and
//!        for whom it is not an infrastructure destination; "own rules" is
//!        the member's rules decided as a row's
//!        (`theorem_cv7_member_is_its_row`);
//!   CV8  a DNS admission is asked for only when some member that declares
//!        DNS hosts refused the frame as an undeclared subnet and nothing
//!        else.
//!
//! THEOREM CJ1: `judge_cohort` returns the first of: a reply on a live
//! inbound flow of the node's row, the refusal of a noted connect, the
//! stateless arm, and, for [`CohortArm::NeedsPin`] only, an admission in the
//! DNS tables it is handed, whose owner must be the frame's source; that they
//! are the cohort's own is GE1's.
//!
//! THEOREM CJ2, for a frame without ports (a fragment that is not the first,
//! or a protocol that has none): it is never a reply or a refusal and never
//! on the proxy lane; to the gateway and to the proxy's address it is
//! refused; to the host alias it is refused unless the alias is open, which
//! [`crate::alias`] never says of a frame without ports (AO2); a DNS
//! admission admits it by the destination's window alone and records no
//! flow; the reply table and the notes are as they were. What still admits
//! it reads the address and the protocol only: a member's rules, a DNS
//! admission's window.
//!
//! Reproduced as it is: the cohort has no alias-by-name lift and no box-name
//! lift, and the proxy is tested before the infrastructure ranges.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::flow::{Conversation, TCP};
use crate::judge::{BoxTables, Sent, SentKind};
#[cfg(verus_keep_ghost)]
use crate::judge::{
    dest_of_sent, flows_missed, lemma_refused_reply_missed, notes_same, owners_same, pin_ok,
    pins_same, refusal_ok, reply_ok, tinv,
};
use crate::notes::Segment;
use crate::pins::{Egress, Pins, Transport};
#[cfg(verus_keep_ghost)]
use crate::pins::{owner_of, pinv};
use crate::plan::Plan;
#[cfg(verus_keep_ghost)]
use crate::plan::{spec_contains, spec_gateway, spec_host_alias, spec_proxy_peer, wf};
use crate::policy::Rules;
#[cfg(verus_keep_ghost)]
use crate::policy::rules_of;
use crate::row::{
    DNS_PORT, Dest, PROTO_TCP, PROTO_UDP, PROXY_PORT, PROXY_TLS_PORT, allowed_proto,
    allowed_subnet, any_covers,
};
#[cfg(verus_keep_ghost)]
use crate::row::{
    RowArm, RowRules, admits, allow_covers, covers, dns_at, in_fixed, in_plane, in_private,
    on_lane, proto_allowed, row_spec,
};
use crate::time::Instant;

/// One resident host-address box.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Member {
    pub rules: Rules,
    /// The box declares DNS hosts.
    pub resolves_names: bool,
}

/// What one member says of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum MemberSays {
    /// An infrastructure destination for this member: its rules are not read.
    Infra,
    /// Its rules admit the frame.
    Admit,
    /// Its rules refuse the frame as an undeclared subnet, and it declares
    /// DNS hosts.
    AskPins,
    /// Its rules refuse the frame.
    Refuse,
}

/// The arms of the cohort's decision, in the order they are tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum CohortArm {
    /// Admit: an ARP packet. Reached only where the cohort has an address of
    /// its own: a marked frame is always IPv4.
    Arp,
    /// Drop: the gateway, at anything but TCP or UDP port 53.
    ControlSurface,
    /// Drop: no host-address box is resident.
    NoMember,
    /// Admit: the proxy lane, for a cohort with a laned member.
    LaneAdmit,
    /// Drop: the proxy's address, off the lane.
    LaneRefuse,
    /// Drop: the host alias, not open to the cohort for this frame.
    AliasClosed,
    /// Admit: some member's own rules admit the frame.
    Member,
    /// Drop, unless the cohort's DNS admissions lift it.
    NeedsPin,
    /// Drop: an infrastructure destination for every member.
    Infrastructure,
    /// Drop: no member's rules admit the frame.
    Unbounded,
}

/// How a frame from the cohort was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum CohortJudged {
    ReplyFlow,
    Refusal,
    /// The stateless arm decided, and nothing lifted it.
    Cohort(CohortArm),
    /// Admit: a DNS admission lifted `NeedsPin`.
    Pinned(Egress),
}

#[cfg(verus_keep_ghost)]
verus! {

/// The frame is an infrastructure destination for a row with these rules.
/// The host alias is decided before this is asked.
pub open spec fn infra_for(plan: Plan, rules: RowRules, dst: u32) -> bool {
    let alias = dst as int == spec_host_alias(plan);
    in_fixed(dst) || (!alias && in_plane(dst) && !spec_contains(plan, dst as int))
        || (!alias && in_private(dst) && !allow_covers(rules.allow_subnets, dst))
}

/// What one member says.
pub open spec fn member_spec(plan: Plan, m: Member, dst: u32, proto: u8, port: u16) -> MemberSays {
    if infra_for(plan, rules_of(m.rules), dst) {
        MemberSays::Infra
    } else if proto == PROTO_UDP && dst as int == spec_gateway(plan) && port == DNS_PORT {
        MemberSays::Admit
    } else if !proto_allowed(rules_of(m.rules).allow_protocols, proto) {
        MemberSays::Refuse
    } else if covers(rules_of(m.rules).deny@, dst) {
        MemberSays::Refuse
    } else if !allow_covers(rules_of(m.rules).allow_subnets, dst) {
        if m.resolves_names {
            MemberSays::AskPins
        } else {
            MemberSays::Refuse
        }
    } else {
        MemberSays::Admit
    }
}

/// Some member says `what`.
pub open spec fn some_say(plan: Plan, ms: Seq<Member>, dst: u32, proto: u8, port: u16, what: MemberSays) -> bool {
    exists|i: int| 0 <= i < ms.len() && member_spec(plan, #[trigger] ms[i], dst, proto, port) == what
}

/// Every member says `Infra`.
pub open spec fn all_infra(plan: Plan, ms: Seq<Member>, dst: u32, proto: u8, port: u16) -> bool {
    forall|i: int| 0 <= i < ms.len() ==> member_spec(plan, #[trigger] ms[i], dst, proto, port) == MemberSays::Infra
}

/// Some member declares a credentialed upstream.
pub open spec fn some_laned(ms: Seq<Member>) -> bool {
    exists|i: int| 0 <= i < ms.len() && rules_of((#[trigger] ms[i]).rules).laned
}

pub open spec fn cohort_admits(arm: CohortArm) -> bool {
    arm == CohortArm::Arp || arm == CohortArm::LaneAdmit || arm == CohortArm::Member
}

/// CV6 for a plan inside 100.64.0.0/10: no exception for the proxy's address.
pub proof fn theorem_cv6_shared(plan: Plan, ms: Seq<Member>, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        wf(plan),
        crate::plan::spec_shared(plan),
        in_fixed(dst),
    ensures
        !cohort_admits(cohort_spec(plan, ms, alias_open, Dest::V4 { dst, proto, port })),
        cohort_spec(plan, ms, alias_open, Dest::V4 { dst, proto, port }) != CohortArm::NeedsPin,
{
    // The proxy's address is inside the block, so inside 100.64.0.0/10, and
    // no address of that range is link-local or loopback: `dst` is not it.
    if dst as int == spec_proxy_peer(plan) {
        crate::plan::theorem_a1(plan);
        crate::row::theorem_shared_block(plan, dst);
        assert(dst >> 22 == 0x191u32 ==> !(dst >> 16 == 0xa9feu32 || dst >> 24 == 127u32)) by (bit_vector);
        assert(false);
    }
    theorem_cv6(plan, ms, alias_open, dst, proto, port);
}

/// The result admits the frame.
pub open spec fn cohort_judged_ok(j: CohortJudged) -> bool {
    match j {
        CohortJudged::ReplyFlow => true,
        CohortJudged::Refusal => true,
        CohortJudged::Cohort(arm) => cohort_admits(arm),
        CohortJudged::Pinned(e) => e != Egress::Refused,
    }
}

/// The decision table.
pub open spec fn cohort_spec(plan: Plan, ms: Seq<Member>, alias_open: bool, d: Dest) -> CohortArm {
    match d {
        Dest::Arp => CohortArm::Arp,
        Dest::V4 { dst, proto, port } => {
            if dst as int == spec_gateway(plan) && !dns_at(proto, port) {
                CohortArm::ControlSurface
            } else if ms.len() == 0 {
                CohortArm::NoMember
            } else if dst as int == spec_proxy_peer(plan) {
                if on_lane(some_laned(ms), proto, port) {
                    CohortArm::LaneAdmit
                } else {
                    CohortArm::LaneRefuse
                }
            } else if dst as int == spec_host_alias(plan) && !alias_open {
                CohortArm::AliasClosed
            } else if some_say(plan, ms, dst, proto, port, MemberSays::Admit) {
                CohortArm::Member
            } else if some_say(plan, ms, dst, proto, port, MemberSays::AskPins) {
                CohortArm::NeedsPin
            } else if all_infra(plan, ms, dst, proto, port) {
                CohortArm::Infrastructure
            } else {
                CohortArm::Unbounded
            }
        },
    }
}

/// CV0: an ARP packet is admitted, whoever the members are.
pub proof fn theorem_cv0(plan: Plan, ms: Seq<Member>, alias_open: bool)
    ensures
        cohort_admits(cohort_spec(plan, ms, alias_open, Dest::Arp)),
{
}

/// CV2.
pub proof fn theorem_cv2(plan: Plan, ms: Seq<Member>, alias_open: bool, d: Dest)
    requires
        ms.len() == 0,
        d != Dest::Arp,
    ensures
        !cohort_admits(cohort_spec(plan, ms, alias_open, d)),
        cohort_spec(plan, ms, alias_open, d) != CohortArm::NeedsPin,
{
}

/// CV3.
pub proof fn theorem_cv3(plan: Plan, ms: Seq<Member>, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int == spec_gateway(plan),
        cohort_admits(cohort_spec(plan, ms, alias_open, Dest::V4 { dst, proto, port })),
    ensures
        dns_at(proto, port),
{
}

/// CV3, the other half: a frame to the gateway that is not DNS is refused by
/// the control surface and by no other arm, whoever is resident.
pub proof fn theorem_cv3_named(plan: Plan, ms: Seq<Member>, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int == spec_gateway(plan),
        !dns_at(proto, port),
    ensures
        cohort_spec(plan, ms, alias_open, Dest::V4 { dst, proto, port }) == CohortArm::ControlSurface,
{
}

/// CV4.
pub proof fn theorem_cv4(plan: Plan, ms: Seq<Member>, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int == spec_proxy_peer(plan),
        cohort_admits(cohort_spec(plan, ms, alias_open, Dest::V4 { dst, proto, port })),
    ensures
        on_lane(some_laned(ms), proto, port),
{
}

/// CV5.
pub proof fn theorem_cv5(plan: Plan, ms: Seq<Member>, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int == spec_host_alias(plan),
        cohort_admits(cohort_spec(plan, ms, alias_open, Dest::V4 { dst, proto, port })),
    ensures
        alias_open,
{
}

/// CV6.
pub proof fn theorem_cv6(plan: Plan, ms: Seq<Member>, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        in_fixed(dst),
        dst as int != spec_proxy_peer(plan),
    ensures
        !cohort_admits(cohort_spec(plan, ms, alias_open, Dest::V4 { dst, proto, port })),
        cohort_spec(plan, ms, alias_open, Dest::V4 { dst, proto, port }) != CohortArm::NeedsPin,
{
    assert forall|i: int| 0 <= i < ms.len() implies member_spec(plan, #[trigger] ms[i], dst, proto, port)
        == MemberSays::Infra by {
        assert(infra_for(plan, rules_of(ms[i].rules), dst));
    }
}

/// CV7.
pub proof fn theorem_cv7(plan: Plan, ms: Seq<Member>, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int != spec_proxy_peer(plan),
        cohort_admits(cohort_spec(plan, ms, alias_open, Dest::V4 { dst, proto, port })),
    ensures
        some_say(plan, ms, dst, proto, port, MemberSays::Admit),
{
}

/// CV7's "own rules": past the cohort's own arms for the gateway, the proxy
/// and a closed alias, a member admits a frame exactly when its rules, decided
/// as a row's, admit it, and asks for a DNS admission exactly when they refuse
/// it as an undeclared subnet and it declares names.
pub proof fn theorem_cv7_member_is_its_row(plan: Plan, m: Member, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int == spec_gateway(plan) ==> dns_at(proto, port),
        dst as int != spec_proxy_peer(plan),
        dst as int == spec_host_alias(plan) ==> alias_open,
    ensures
        (member_spec(plan, m, dst, proto, port) == MemberSays::Admit)
            == admits(row_spec(plan, rules_of(m.rules), alias_open, Dest::V4 { dst, proto, port })),
        (member_spec(plan, m, dst, proto, port) == MemberSays::AskPins)
            == (m.resolves_names
                && row_spec(plan, rules_of(m.rules), alias_open, Dest::V4 { dst, proto, port }) == RowArm::UndeclaredSubnet),
{
}

/// CV8.
pub proof fn theorem_cv8(plan: Plan, ms: Seq<Member>, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        cohort_spec(plan, ms, alias_open, Dest::V4 { dst, proto, port }) == CohortArm::NeedsPin,
    ensures
        some_say(plan, ms, dst, proto, port, MemberSays::AskPins),
        !some_say(plan, ms, dst, proto, port, MemberSays::Admit),
{
}

/// The cohort's DNS admission applies: through the cohort's own tables, with
/// a live flow or a live window.
pub open spec fn cohort_pin_lift(pins: Pins, s: Sent, now_ms: u64) -> bool {
    owner_of(pins) == s.src && pin_ok(pins, s, now_ms)
}

/// What `judge_cohort` promises of its result and of the tables before and after.
pub open spec fn cohort_post(plan: Plan, members: Seq<Member>, alias_open: bool, node_before: BoxTables, node_after: BoxTables, pins_before: Pins, pins_after: Pins, sent: Sent, now_ms: u64, r: CohortJudged) -> bool {
    match r {
        CohortJudged::ReplyFlow => {
            &&& reply_ok(plan, node_before.flows, sent, now_ms)
            &&& crate::flow::reply_post(node_before.flows, node_after.flows, crate::judge::conv_of(sent), crate::judge::flags_of(sent), now_ms, true)
            &&& notes_same(node_after.notes, node_before.notes)
            &&& pins_same(pins_after, pins_before)
        },
        CohortJudged::Refusal => {
            &&& !reply_ok(plan, node_before.flows, sent, now_ms)
            &&& refusal_ok(plan, node_before.notes, sent, now_ms)
            &&& crate::notes::refusal_post(node_before.notes, node_after.notes, crate::judge::seg_of(sent), now_ms, true)
            &&& flows_missed(plan, node_after.flows, node_before.flows, sent, now_ms)
            &&& pins_same(pins_after, pins_before)
        },
        CohortJudged::Cohort(arm) => {
            &&& !reply_ok(plan, node_before.flows, sent, now_ms)
            &&& !refusal_ok(plan, node_before.notes, sent, now_ms)
            &&& arm == cohort_spec(plan, members, alias_open, dest_of_sent(sent))
            &&& arm == CohortArm::NeedsPin ==> !cohort_pin_lift(pins_before, sent, now_ms)
            &&& flows_missed(plan, node_after.flows, node_before.flows, sent, now_ms)
            &&& notes_same(node_after.notes, node_before.notes)
            &&& pins_same(pins_after, pins_before)
        },
        CohortJudged::Pinned(e) => {
            &&& !reply_ok(plan, node_before.flows, sent, now_ms)
            &&& !refusal_ok(plan, node_before.notes, sent, now_ms)
            &&& cohort_spec(plan, members, alias_open, dest_of_sent(sent)) == CohortArm::NeedsPin
            &&& cohort_pin_lift(pins_before, sent, now_ms)
            &&& e != Egress::Refused
            &&& crate::pins::egress_post(pins_before, pins_after, crate::judge::dst_of(sent), crate::judge::transport_of(sent), now_ms, e)
            &&& flows_missed(plan, node_after.flows, node_before.flows, sent, now_ms)
            &&& notes_same(node_after.notes, node_before.notes)
        },
    }
}

/// CJ2.
pub proof fn theorem_cj2_no_port_opening_admits_a_frame_without_ports(
    plan: Plan,
    members: Seq<Member>,
    alias_open: bool,
    node_before: BoxTables,
    node_after: BoxTables,
    pins_before: Pins,
    pins_after: Pins,
    sent: Sent,
    now_ms: u64,
    r: CohortJudged,
)
    requires
        crate::judge::portless(sent),
        cohort_post(plan, members, alias_open, node_before, node_after, pins_before, pins_after, sent, now_ms, r),
    ensures
        r != CohortJudged::ReplyFlow,
        r != CohortJudged::Refusal,
        r != CohortJudged::Cohort(CohortArm::LaneAdmit),
        crate::judge::dst_of(sent) as int == spec_gateway(plan) ==> !cohort_judged_ok(r),
        crate::judge::dst_of(sent) as int == spec_proxy_peer(plan) ==> !cohort_judged_ok(r),
        crate::judge::dst_of(sent) as int == spec_host_alias(plan) && !alias_open ==> !cohort_judged_ok(r),
        r matches CohortJudged::Pinned(e) ==> e == Egress::Window
            && crate::pins::flows(pins_after) == crate::pins::flows(pins_before),
        crate::flow::table(node_after.flows) == crate::flow::table(node_before.flows),
        notes_same(node_after.notes, node_before.notes),
{
}

} // verus!

/// What one member says of a frame. The host alias is decided before this.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        wf(*plan),
    ensures
        r == member_spec(*plan, *m, dst, proto, port),
))]
pub fn member_says(plan: &Plan, m: &Member, dst: u32, proto: u8, port: u16) -> MemberSays {
    let alias = dst == plan.host_alias();
    if dst >> 16 == 0xa9feu32 || dst >> 24 == 127u32 {
        return MemberSays::Infra;
    }
    if !alias && dst >> 22 == 0x191u32 && !plan.contains(dst) {
        return MemberSays::Infra;
    }
    let private = dst >> 24 == 10u32 || dst >> 20 == 0xac1u32 || dst >> 16 == 0xc0a8u32;
    let covered = allowed_subnet(m.rules.get(), dst);
    if !alias && private && !covered {
        return MemberSays::Infra;
    }
    if proto == PROTO_UDP && dst == plan.gateway() && port == DNS_PORT {
        return MemberSays::Admit;
    }
    if !allowed_proto(m.rules.get(), proto) {
        return MemberSays::Refuse;
    }
    if any_covers(m.rules.get().deny.as_slice(), dst) {
        return MemberSays::Refuse;
    }
    if !covered {
        if m.resolves_names {
            return MemberSays::AskPins;
        }
        return MemberSays::Refuse;
    }
    MemberSays::Admit
}

/// The arm that decides a frame from the cohort. CV1.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        wf(*plan),
    ensures
        r == cohort_spec(*plan, members@, alias_open, d),
))]
pub fn decide_cohort(plan: &Plan, members: &[Member], alias_open: bool, d: Dest) -> CohortArm {
    let (dst, proto, port) = match d {
        Dest::Arp => return CohortArm::Arp,
        Dest::V4 { dst, proto, port } => (dst, proto, port),
    };
    let dns = (proto == PROTO_TCP || proto == PROTO_UDP) && port == DNS_PORT;
    if dst == plan.gateway() && !dns {
        return CohortArm::ControlSurface;
    }
    if members.is_empty() {
        return CohortArm::NoMember;
    }
    if dst == plan.proxy_peer() {
        let mut laned = false;
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= members.len(),
                laned == (exists|j: int| 0 <= j < i && rules_of((#[trigger] members@[j]).rules).laned),
            decreases members.len() - i,
        ))]
        while i < members.len() {
            if members[i].rules.get().laned {
                laned = true;
            }
            i += 1;
        }
        if laned && proto == PROTO_TCP && (port == PROXY_PORT || port == PROXY_TLS_PORT) {
            return CohortArm::LaneAdmit;
        }
        return CohortArm::LaneRefuse;
    }
    if dst == plan.host_alias() && !alias_open {
        return CohortArm::AliasClosed;
    }
    let mut asks = false;
    let mut every_infra = true;
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= members.len(),
            wf(*plan),
            // What was settled before the loop, for the exit inside it.
            d == (Dest::V4 { dst, proto, port }),
            !(dst as int == spec_gateway(*plan) && !dns_at(proto, port)),
            dst as int != spec_proxy_peer(*plan),
            !(dst as int == spec_host_alias(*plan) && !alias_open),
            forall|j: int| 0 <= j < i ==> member_spec(*plan, #[trigger] members@[j], dst, proto, port) != MemberSays::Admit,
            asks == (exists|j: int| 0 <= j < i && member_spec(*plan, #[trigger] members@[j], dst, proto, port) == MemberSays::AskPins),
            every_infra == (forall|j: int| 0 <= j < i ==> member_spec(*plan, #[trigger] members@[j], dst, proto, port) == MemberSays::Infra),
        decreases members.len() - i,
    ))]
    while i < members.len() {
        match member_says(plan, &members[i], dst, proto, port) {
            MemberSays::Admit => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    // This member is the witness that some member admits.
                    assert(member_spec(*plan, members@[i as int], dst, proto, port) == MemberSays::Admit);
                }
                return CohortArm::Member;
            }
            MemberSays::AskPins => {
                asks = true;
                every_infra = false;
            }
            MemberSays::Refuse => {
                every_infra = false;
            }
            MemberSays::Infra => {}
        }
        i += 1;
    }
    if asks {
        return CohortArm::NeedsPin;
    }
    if every_infra {
        return CohortArm::Infrastructure;
    }
    CohortArm::Unbounded
}

/// Decides a frame from the cohort. `node` is the tables that hold the
/// cohort's reply records and notes: the node's where the two share an
/// address, the cohort's own otherwise; `pins` is the cohort's own DNS
/// tables. CJ1.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        wf(*plan),
        tinv(*old(node)),
        pinv(*old(pins)),
    ensures
        tinv(*final(node)),
        pinv(*final(pins)),
        pins_same(final(node).pins, old(node).pins),
        owners_same(*final(node), *old(node)),
        owner_of(*final(pins)) == owner_of(*old(pins)),
        cohort_post(*plan, members@, alias_open, *old(node), *final(node), *old(pins), *final(pins), sent, now.ms, r),
))]
pub fn judge_cohort(
    plan: &Plan,
    members: &[Member],
    alias_open: bool,
    node: &mut BoxTables,
    pins: &mut Pins,
    sent: Sent,
    now: Instant,
) -> CohortJudged {
    let (dst, proto, l4) = match sent.kind {
        SentKind::Arp => {
            return CohortJudged::Cohort(decide_cohort(plan, members, alias_open, Dest::Arp));
        }
        SentKind::V4 { dst, proto, l4 } => (dst, proto, l4),
    };
    if let Some(x) = l4 {
        if dst != plan.proxy_peer() {
            let c = Conversation {
                proto,
                client: dst,
                client_port: x.dport,
                box_addr: sent.src,
                box_port: x.sport,
            };
            if node.flows.reply(c, x.flags, now) {
                #[cfg(verus_keep_ghost)]
                proof! {
                    crate::judge::lemma_reply_answers(
                        *plan, old(node).flows, node.flows, sent, now.ms, true,
                    );
                }
                return CohortJudged::ReplyFlow;
            }
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_refused_reply_missed(*plan, old(node).flows, node.flows, sent, now.ms);
                crate::judge::lemma_reply_answers(
                    *plan, old(node).flows, node.flows, sent, now.ms, false,
                );
            }
            if proto == TCP {
                let s = Segment {
                    client: dst,
                    client_port: x.dport,
                    box_addr: sent.src,
                    box_port: x.sport,
                    flags: x.flags,
                    seq: x.seq,
                    ack: x.ack,
                    payload_len: x.payload_len,
                };
                if node.notes.refusal(s, now) {
                    return CohortJudged::Refusal;
                }
            }
        }
    }
    let port = match l4 {
        Some(x) => x.dport,
        None => 0,
    };
    let arm = decide_cohort(plan, members, alias_open, Dest::V4 { dst, proto, port });
    match arm {
        CohortArm::NeedsPin => {}
        _ => return CohortJudged::Cohort(arm),
    }
    if pins.owner() == sent.src {
        let transport = match l4 {
            Some(x) => Some(Transport {
                proto,
                sport: x.sport,
                dport: x.dport,
                flags: x.flags,
            }),
            None => None,
        };
        let e = pins.egress(dst, transport, now);
        match e {
            Egress::Refused => {}
            _ => return CohortJudged::Pinned(e),
        }
    }
    CohortJudged::Cohort(arm)
}

/// Whether a result admits the frame.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == cohort_judged_ok(j),
))]
pub fn cohort_judged_admits(j: CohortJudged) -> bool {
    match j {
        CohortJudged::ReplyFlow => true,
        CohortJudged::Refusal => true,
        CohortJudged::Cohort(arm) => match arm {
            CohortArm::Arp => true,
            CohortArm::ControlSurface => false,
            CohortArm::NoMember => false,
            CohortArm::LaneAdmit => true,
            CohortArm::LaneRefuse => false,
            CohortArm::AliasClosed => false,
            CohortArm::Member => true,
            CohortArm::NeedsPin => false,
            CohortArm::Infrastructure => false,
            CohortArm::Unbounded => false,
        },
        CohortJudged::Pinned(e) => match e {
            Egress::Refused => false,
            Egress::ByFlow => true,
            Egress::Retained => true,
            Egress::Window => true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Abilities, Declared, Enforced, Net, Section, effective};
    use crate::row::{Cidr, RowRules};

    // 100.64.0.0/24: gateway .1, proxy .252, node .253, host alias .254.
    const NET: u32 = 0x6440_0000;
    const GW: u32 = NET + 1;
    const PROXY: u32 = NET + 252;
    const ALIAS: u32 = NET + 254;
    const A: u32 = 0xcb00_7107;
    const B: u32 = 0xc633_6407;

    fn plan() -> Plan {
        Plan::new(NET, 24).unwrap()
    }

    /// Rules through the one road: a declaration, enforced whole.
    fn made(r: RowRules) -> Rules {
        let net = |c: &Cidr| Net::V4(*c);
        let d = Declared {
            allow_subnets: match &r.allow_subnets {
                None => Section::Listed(vec![Net::V4(Cidr { addr: 0, prefix: 0 })]),
                Some(v) => Section::Listed(v.iter().map(net).collect()),
            },
            deny_subnets: Section::Listed(r.deny.iter().map(net).collect()),
            allow_protocols: match &r.allow_protocols {
                None => Section::Absent,
                Some(v) => Section::Listed(v.clone()),
            },
            laned: r.laned,
            host_address: false,
        };
        let host = Abilities {
            per_box_host_address: true,
        };
        match effective(&d, &host).enforced() {
            Enforced::Whole(e) => e.rules(),
            Enforced::Part(_) => panic!("every block is kept"),
        }
    }

    fn member(allow: Option<Vec<Cidr>>, laned: bool, resolves_names: bool) -> Member {
        Member {
            rules: made(RowRules {
                allow_protocols: None,
                deny: Vec::new(),
                allow_subnets: allow,
                laned,
            }),
            resolves_names,
        }
    }

    fn only(addr: u32) -> Option<Vec<Cidr>> {
        Some(vec![Cidr { addr, prefix: 32 }])
    }

    fn v4(dst: u32, proto: u8, port: u16) -> Dest {
        Dest::V4 { dst, proto, port }
    }

    #[test]
    fn with_no_member_nothing_passes_but_the_control_surface_still_names_itself() {
        let (p, none) = (plan(), Vec::new());
        assert_eq!(
            decide_cohort(&p, &none, true, v4(A, 6, 443)),
            CohortArm::NoMember
        );
        assert_eq!(
            decide_cohort(&p, &none, true, v4(GW, 17, 53)),
            CohortArm::NoMember
        );
        assert_eq!(
            decide_cohort(&p, &none, true, v4(GW, 6, 80)),
            CohortArm::ControlSurface
        );
    }

    #[test]
    fn a_frame_passes_when_any_one_member_would_admit_it() {
        let p = plan();
        let ms = vec![member(only(A), false, false), member(only(B), false, false)];
        assert_eq!(
            decide_cohort(&p, &ms, false, v4(A, 6, 443)),
            CohortArm::Member
        );
        assert_eq!(
            decide_cohort(&p, &ms, false, v4(B, 6, 443)),
            CohortArm::Member
        );
        assert_eq!(
            decide_cohort(&p, &ms, false, v4(A + 1, 6, 443)),
            CohortArm::Unbounded
        );
        assert_eq!(
            decide_cohort(&p, &ms, false, v4(GW, 17, 53)),
            CohortArm::Member
        );
    }

    #[test]
    fn the_lane_needs_one_laned_member() {
        let p = plan();
        let plain = vec![member(None, false, false)];
        assert_eq!(
            decide_cohort(&p, &plain, false, v4(PROXY, 6, 8118)),
            CohortArm::LaneRefuse
        );
        let laned = vec![member(only(A), false, false), member(only(B), true, false)];
        assert_eq!(
            decide_cohort(&p, &laned, false, v4(PROXY, 6, 8118)),
            CohortArm::LaneAdmit
        );
        assert_eq!(
            decide_cohort(&p, &laned, false, v4(PROXY, 6, 443)),
            CohortArm::LaneAdmit
        );
        assert_eq!(
            decide_cohort(&p, &laned, false, v4(PROXY, 17, 443)),
            CohortArm::LaneRefuse
        );
    }

    #[test]
    fn a_member_that_resolves_names_asks_for_a_dns_admission() {
        let p = plan();
        let ms = vec![
            member(only(A), false, false),
            member(Some(Vec::new()), false, true),
        ];
        assert_eq!(
            decide_cohort(&p, &ms, false, v4(B, 6, 443)),
            CohortArm::NeedsPin
        );
        assert_eq!(
            decide_cohort(&p, &ms, false, v4(A, 6, 443)),
            CohortArm::Member
        );
    }

    #[test]
    fn infrastructure_is_named_only_when_it_is_so_for_every_member() {
        let p = plan();
        let ten = 0x0a01_0203;
        let both_closed = vec![member(only(A), false, false), member(only(B), false, true)];
        assert_eq!(
            decide_cohort(&p, &both_closed, false, v4(ten, 6, 80)),
            CohortArm::Infrastructure
        );
        assert_eq!(
            decide_cohort(&p, &both_closed, false, v4(0xa9fe_a9fe, 6, 80)),
            CohortArm::Infrastructure
        );
        let one_open = vec![member(only(A), false, false), member(None, false, false)];
        assert_eq!(
            decide_cohort(&p, &one_open, false, v4(ten, 6, 80)),
            CohortArm::Member
        );
    }

    #[test]
    fn the_alias_needs_its_opening_and_then_a_member() {
        let p = plan();
        let ms = vec![member(None, false, false)];
        assert_eq!(
            decide_cohort(&p, &ms, false, v4(ALIAS, 6, 8080)),
            CohortArm::AliasClosed
        );
        assert_eq!(
            decide_cohort(&p, &ms, true, v4(ALIAS, 6, 8080)),
            CohortArm::Member
        );
        let closed = vec![member(only(A), false, false)];
        assert_eq!(
            decide_cohort(&p, &closed, true, v4(ALIAS, 6, 8080)),
            CohortArm::Unbounded
        );
    }
}

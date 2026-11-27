# netcore

The decision kernel of the host-side network gate. Pure functions over owned data: bytes in, value out. No I/O, no clock, no locks, no logging, no `unsafe`, and no dependencies in an ordinary build (the verifier's own library is used only when the verifier builds the crate). The calling code, which this crate's comments call the shell, reads sockets, takes locks, reads the clock once for a frame, and calls in; what a frame is and whether it passes is decided here.

## Words

| Word | Meaning here |
|---|---|
| shell | the calling code: sockets, locks, the clock, events. Never verified; kept thin |
| `Gate` | this crate's type holding every box's rules and tables. Not the host program |
| box | one sandboxed workload with an address on the switch's subnet |
| row | a registered box: its address, its rules, its tables |
| node | the in-VM daemon, at its own address on the subnet. It declares no rules; what it may reach is the baseline |
| cohort | the boxes that share one source address (host-address boxes), so that a frame cannot be tied to one of them; a cohort frame is admitted when some member's own rules would admit it |
| mark | a value in the IPv4 header's DSCP field by which a cohort frame is told from the node's own at one address. The guest writes it; the theorems hold whoever does |
| lane | the path to the proxy's address, open only to a row that declares a credentialed upstream |
| alias | the one address in the block that stands for the host itself; closed unless an exposure is configured |
| baseline | the subnets the node may reach, held by the host |
| zone | the DNS zone the switch's resolver answers by itself |
| pin | an address a box may reach because its own DNS lookup returned it for a declared name, for a window |
| lift | a decision that turns one named refusal of a stateless table into an admit (a pin, the alias by name, a box name) |

Each claim the crate makes is a theorem, stated in the index at the top of `src/lib.rs` (and again in their module: most at the top, clause by clause, and the rest beside the proofs that carry them), and machine-checked against the code that is compiled.

## Reading this crate if you do not know Verus

The crate is checked with [Verus](https://github.com/verus-lang/verus), a verifier that proves Rust functions meet specifications written beside them. Everything under `cfg(verus_keep_ghost)` (the `verus! {}` blocks, the `proof!` blocks and the `verus_spec` attributes) exists only when Verus builds the crate. Cargo, clippy, rustdoc and the unit checks never compile it. The contracts are attributes on the ordinary functions, so the code that is verified is the code that ships.

So: you can change a function body like any Rust, and the build and the unit checks will pass. Only the Verus lane says whether its proof still holds. Changing a specification function, a `requires` or `ensures`, a lemma's statement or a Kani harness changes what is claimed, and is reviewed as such (see "Changing it"). `#[cfg(kani)]` modules are bounded model-checking harnesses.

## What is in it

A module uses modules of its own layer and of the layers below, and no other.

| Layer | Module | What it is | Theorems |
|---|---|---|---|
| 0, leaves | `plan` | The address plan of a switch subnet: which addresses are reserved and which may be leased | A1 |
| | `time` | Instants and spans, as types | |
| 1, bounded tables | `pool` | A table with a hard capacity and a quota for a row, kept as a plain list: the specification every table is stated in | G7 |
| | `slab` | The same table as a slab of entries under a sorted index of positions; a lookup reads at most `log2(n) + 1` entries | SB1 |
| | `sweep` | What expiry may remove, and when a sweep is due | SW1 |
| | `flow` | One box's table of inbound conversations and the replies it admits | G6, G6c, K1 |
| | `notes` | Connects noted on the way in, and the one reset from the box that refuses each | N1 |
| | `pins` | One box's DNS admissions: questions asked, addresses admitted, flows opened to them | G5 |
| | `ledger` | Published forwards: one holder for a listener, a bound, eviction | L1 |
| 2, readers | `frame` | One reading of an Ethernet frame: the facts of the IPv4 datagram or ARP packet a receiver would act on, or the reason there are none | P1, P2, P2c |
| | `dnsq` | Whether a DNS query asks only about names in one zone | DQ1, DQ2, DQ4, DQ5 |
| | `dnsa` | The addresses a DNS answer gives for the name it was asked, following its aliases forward | DA1 to DA4 |
| 3, policy to rules | `policy` | From what a box declared to the rules enforced; the only maker of `Rules` | TP1 to TP7 |
| | `row` | A registered row's stateless decision, as an ordered table | V2, V3 to V9 |
| | `alias` | Whether the host alias is open to this source at this port | AO1 to AO5 |
| | `rebind` | The check on an address a DNS answer offers, and the floor no rule list can lift | RB1, FL1 |
| 4, decisions | `origin` | The class of a frame's source | V1 |
| | `route` | Which decision a frame goes to, by its source | RT1, RT2 |
| | `judge` | A row's whole egress decision | J1, J2 |
| | `node`, `cohort` | The node address's and the host-address cohort's decision tables and whole decisions | NV1 to NV7, NJ1 to NJ3; CV1 to CV8, CJ1, CJ2 |
| | `answer` | A DNS answer, from the addresses a reply carried to what the box's tables hold | TA1 to TA5 |
| 5, composition | `gate` | The decision for a frame over one state, with registration, DNS, publishing and retraction | GE1, GI1, GR1, GC1, GD0 to GD2, GB1, GP1, GM1, BN1 |
| | `split` | Entry points that decide from a frame's bytes for one box, without the whole gate | SP1, EP1 to EP3, CF1 |
| | `finish` | Entry points that take a frame's facts through one box's tables to an outcome, in both directions | FN1 to FN3 |
| | `ingress` | What a frame toward a box does to that box's tables | IG1, IG2, IG3 |
| | `isolation` | A decision is settled by what the deciding box's tables hold; every admit has a reason | IS1, IS2 |
| | `report` | Which rule is reported for an outcome | RP1 |

The ones a reviewer of the gate will care about most:

- **P2.** Every fact the reader reports is true of the datagram: version 4, a whole header, a total length that fits the frame; a port only for TCP or UDP, only on a first fragment, only from a whole transport header inside the total length (a UDP datagram with more fragments to come may state a length that runs past it). **P2c:** a frame that carries such a datagram is never refused, so P2 cannot be met by refusing everything.
- **G7.** A table never holds more than its capacity, more than its quota for one row, or one row and key twice. A refusal changes nothing and says why.
- **G6, N1, G5.** A frame a box sends is admitted as a reply, as a refusal, or by a DNS admission only against an unexpired record of that same box; such an admit changes that record's table and at most the frame's own expired record in the reply table (J1).
- **V2, NV1, CV1.** Each stateless decision equals an ordered table written in the specification. **V3 to V8** and their node and cohort counterparts are properties of those tables: link-local and loopback are never admitted; the gateway only at port 53; the proxy only on the lane; the alias only when open; a private address only when declared.
- **RT1, GE1.** Which decision a frame gets is settled by its source address, its family and, at the node's address, the mark; it is decided with that source's rules and tables and no other's (where the cohort shares the node's address, its reply records and notes are the node's). A frame from a source that is no row, not the node and not the cohort is refused. GE1 is stated of `Gate::egress`; a caller that holds one box's tables uses the entry points in `split`, and SP1 says what links the two.
- **GI1.** A frame toward a guest is recorded in the tables of the box it is addressed to and in no other.
- **IS2.** Every admit has its reason: the stateless table, a live record of that box's own reply table, a noted connect, that box's own DNS tables, the alias by name, or a box name.

## What it does not say

A theorem here says "if the caller and the world are as assumed". `axioms/REGISTRY.md` lists every such assumption with the check it has or lacks. The ones to know first:

- That the next hop reads a frame the same way `frame` does (NX1).
- Who hands leases out, or when an address may be reused (NX4).
- That the caller passes the right direction, one clock that does not run backwards, and addresses in the byte order `frame` produces (NC1 to NC3). Addresses are `u32` with the first octet most significant (`10.0.0.5` is `0x0a000005`).
- That a frame's source address belongs to its sender (NC23). The gate routes by source alone.
- That the rules given to the gate are the compiled rules of the manifest (NC7), and that box names are what they stand for (NC4).
- That the caller's locks give what one `Gate` under one borrow gives (NC20, NC21, NC24).

No public function takes a row index or trusts a list length: a row is named by its address, and a DNS answer of more than 65,535 addresses is treated as empty. Results do carry a row's index, and NC10 says how long a caller may keep one.

## What it costs to run

The theorem index says what is proved; this says what a decision costs. A lookup reads at most `log2(n) + 1` entries (SB1: the bound is proved of a count kept beside each read, in text only the verifier sees; that every read raises the count is by reading the two functions). An insert or a removal moves the positions after its place in the index (two bytes each). A slab that fills is rewritten once in as many inserts as the capacity. A guest chooses the keys, how full its tables are and when a sweep runs, so the worst case of each operation is the cost it can make every frame of its own box pay; with the per-box entry points it is not a cost another box waits behind. A table at its capacity reads itself whole at most once in its sweep interval, and once more for each conversation that finished since it last did.

## How the claims are checked

| Evidence | Where | What it is |
|---|---|---|
| Verus on the whole crate | every module | The count pinned in `scripts/verus.sh`, 0 errors, at Verus `0.2026.11.02.8bf68ee` with `--rlimit 0.3` (the verifier's default is 10). The count is of items checked, not a measure of what the contracts say |
| The statements, locked | `crates/netcore-lock/STATEMENTS.lock` | Every specification function, contract, lemma statement, harness and registry row, extracted from the source. A change to any of them is a diff in that file |
| The verifier's own account, locked | `crates/netcore-lock/VIEW.lock` | Each function's kind and a digest of its statement as the verifier resolved it; it must describe the same functions as the text |
| Negative controls | `crates/netcore-lock/controls.toml`, listed by module in `verus/` | A deliberate defect in a copy of the code, which the verifier must reject inside the functions the control names. Every theorem of the crate is the place of at least one rejection. The lists are generated from the file and its runs; `controls.py --check` in the lane keeps every control applicable |
| Unit checks | `#[cfg(test)]` in the modules that have exec code to run | Ordinary tests; they run in CI |
| Kani harnesses | `#[cfg(kani)]` | Bit-level claims: the frame, query and answer readers against a second reader written apart from the code; the table operations listed in the index, for every shape of a small table. The default set runs in CI (`scripts/kani.sh netcore`, and its three heaviest harnesses one to a job); the per-shape harnesses behind the `kani-full` feature are run in full off CI. The index in `src/lib.rs` says, theorem by theorem, which harnesses exist and which operations have none |

**Proof cost is kept away from the limit.** A function's cost in the verifier can move when any module reachable from its own changes. So the lane's limit is 0.3, and each change is also checked at 0.2 with six solver seeds before it lands.

A decision written as a table has two kinds of control. A defect in the code alone must break "the code equals the table". A defect made in the table and the code together leaves that standing and must break a named property of the table. The second kind is what stops the table from being wrong in the same way as the code.

## Changing it

1. A statement (a spec function, a `requires` or `ensures`, a lemma's statement, a harness, a registry row, a control) changes only on purpose, shows as a diff in `STATEMENTS.lock`, and comes with its controls. Proof text inside a body is free.
2. A new refusal or bound comes with the control that breaks it.
3. A fact relied on and not proved gets a row in `axioms/REGISTRY.md` and a check, or it is not relied on.
4. The order of the `pub mod` lines in `src/lib.rs` is fixed: a proof's cost depends on it.

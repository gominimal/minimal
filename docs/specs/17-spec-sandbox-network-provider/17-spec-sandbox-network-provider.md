---
id: 017
title: One network provider for every sandbox
status: draft
owner: tom@minimal.dev
epic: gominimal/minimal#TBD
arch: none
updated: 2026-09-16
---

# 017 — One network provider for every sandbox

## Context

Each PTask has one of three network modes: no network, the host network, or
its own IP address on the local switch (see
[03-spec-networking](../03-spec-networking/03-spec-networking.md) R1.1). An
interactive session is a PTask. A task is a PTask too: a task run mints a
session of its own, so it is a session that no person attaches to. A build is
not a PTask and has no mode: its sandbox is planned from what the build
declares, a resolver or the internet, through the same plan type. The code
that starts an own-IP network, however, is at the top of the daemon, in the
layer that only interactive sessions pass through. A new network option must
pass through four layers of code before it reaches the sandbox. The top layer
also holds the rollback logic for a switch attachment that the sandbox layer
does not know about. Two different paths start a sandbox process, and only one
of the two paths applies the network. Because of this, the daemon drops the
own-IP mode of a task to the host network, which gives that task more network
access than its mode states. That defect makes this work necessary now. After
this change, one interface supplies the network to every sandbox, and the
sandbox layer controls the sequence and the rollback.

**Success:** A task and an interactive session with the same network mode get
the same network, and only one module in the daemon reads the network mode.

**First slice:** The sandbox layer asks the network provider what the sandbox
needs, applies the answer, and starts the process. The two simple modes move to
this path first. A user sees no change in behaviour.

## Users and stories

**Roles:** the contributor who writes daemon code, the person who runs a task
or a session, and the operator who runs the daemon.

- AS A contributor I WANT one place that decides the network of a sandbox SO
  THAT I add a network option in one layer and not in four.
- AS A contributor I WANT the sandbox layer to control the network sequence SO
  THAT a cancelled launch cannot leave an attachment behind.
- AS A person who runs a task I WANT that task to get the network of its own
  mode SO THAT a task and an interactive session with one mode are equal.
- AS A person who runs a task in a session I WANT that task to get the mode of
  the session when the task states no mode of its own SO THAT the task cannot
  reach a host that the session cannot reach.
- AS AN operator I WANT the daemon to release every switch attachment SO THAT
  the switch process stops after the last sandbox stops.

## Requirements

- **017-001** WHEN a sandbox starts with a network provider, THE SYSTEM SHALL
  complete the plan operation before it creates the container, and start the
  attach operation after the process starts.
  tier:     T0
  verify:   `cargo nextest run -p sandbox2 network_phases_run_in_order`

- **017-002** IF a launch stops after the plan operation and before the attach
  operation, THEN THE SYSTEM SHALL run the abandon operation one time.
  tier:     T1
  verify:   `cargo nextest run -p sandbox2 abandoned_launch_releases_the_plan`
  property: for every launch, count(plan) = count(attach) + count(abandon),
            where count(plan) counts plan operations that return a plan; a
            plan operation that fails reserves nothing and owes nothing
  - IF the launch future stops because the caller drops it, THEN THE SYSTEM
    SHALL run the abandon operation one time.
    tier:   T0
    verify: `cargo nextest run -p sandbox2 cancelled_launch_releases_the_plan`

- **017-003** WHEN a sandbox process stops, THE SYSTEM SHALL run the teardown
  operation of the network guard of that sandbox one time.
  tier:     T1
  verify:   `cargo nextest run -p minimald exit_releases_the_network`
  property: for every sandbox, count(attach) = count(teardown)

- **017-004** THE SYSTEM SHALL apply the network provider on the invocation
  path of the sandbox layer and on the path where the caller starts the
  process.
  tier:     T0
  verify:   `cargo nextest run -p sandbox2 both_spawn_paths_apply_the_network`

- **017-005** THE SYSTEM SHALL apply the network mode of a PTask to the sandbox
  of that PTask, for an interactive session and for a task.
  tier:     T1
  verify:   `cargo nextest run -p minimald a_task_takes_the_network_of_its_session`
  property: for every PTask p, the mode of the sandbox of p is equal to the
            mode of p
  - WHEN a task runs in an existing session and states no mode of its own, THE
    SYSTEM SHALL apply the mode of that session to the sandbox of the task.
    tier:   T0
    verify: `cargo nextest run -p minimald a_task_takes_the_network_of_its_session`
  - IF the daemon cannot give a task the network of its mode, THEN THE SYSTEM
    SHALL stop the task with an error and SHALL keep the task off the host
    network.
    tier:   T0
    verify: `cargo nextest run -p minimald a_task_takes_the_network_of_its_session`

- **017-006** THE SYSTEM SHALL limit the network access of a sandbox to the
  access that the mode of that sandbox states.
  tier:     T1
  verify:   `cargo nextest run -p sandbox2 the_mode_bounds_the_network_access`
  property: for every sandbox s, access(s) is a subset of access(mode(s))

- **017-007** IF a plan contains tap parameters, THEN THE SYSTEM SHALL run the
  sandbox in a new network namespace.
  tier:     T1
  verify:   `cargo nextest run -p sandbox2 a_tap_plan_always_isolates`
  property: for every plan p, p has tap parameters implies p isolates the
            network namespace

- **017-008** IF an own-IP attach operation fails, THEN THE SYSTEM SHALL
  decrease the switch attachment count one time for that sandbox.
  tier:     T1
  verify:   `cargo nextest run -p minimald failed_attach_releases_the_switch_once`
  property: after a failed launch, the switch attachment count is equal to the
            count before that launch

- **017-009** WHERE a sandbox has the own-IP mode, THE SYSTEM SHALL write the
  DNS server address of the switch into the resolver file of that sandbox, on
  every deployment model.
  tier:     T0
  verify:   `cargo nextest run -p minimald own_ip_resolver_points_at_the_switch`

- **017-010** WHEN the sandbox layer creates a tap device in the namespace of
  the sandbox, THE SYSTEM SHALL give the file descriptor of that device to the
  network provider one time.
  tier:     T1
  verify:   `cargo nextest run -p sandbox2 the_tap_descriptor_goes_to_the_provider_once`
  property: for every sandbox whose tap the sandbox layer builds, the tap
            descriptor is given one time and closes at teardown

- **017-011** IF the host cannot create a network namespace and the plan needs
  one, THEN THE SYSTEM SHALL stop the launch with an error.
  tier:     T0
  verify:   `cargo nextest run -p sandbox2 no_namespace_support_fails_closed`

## Non-goals

- Egress policy and the DNS proxy: unchanged, in
  [03-spec-networking](../03-spec-networking/03-spec-networking.md) R2.1-R2.2.
- The WireGuard mesh and the remote proxy: unchanged, in 03-spec-networking
  R4.x.
- Ownership of the gvproxy process: unchanged. The daemon owns it on DM2, and
  the microVM host daemon owns it on DM1, DM3 and DM4 (03-spec-networking
  R1.4).
- A new network mode: this work adds none.
- Dynamic ingress port mappings: unchanged, in 03-spec-networking R2.3.
- Tools in the guest root filesystem: none new. The privileged tap mechanism
  runs `ip` and `nsenter`, and the guest root filesystem has both. See
  [The tap mechanism](#the-tap-mechanism).
- A network mode of its own for a task run: the command that starts a task has
  no option for the mode today, and it always asks for the host network. This
  spec makes the mode of a task reach its sandbox; it adds no option. See
  [Open questions](#open-questions).

## Non-functional requirements

- **017-N01** WHILE four own-IP sandboxes start at the same time, THE SYSTEM
  SHALL hold the switch for the address lease of each launch only, and SHALL
  hold four leases at once.
  tier:   T0
  verify: `cargo nextest run -p minimald concurrent_own_ip_launches_do_not_serialize`

## Design reasoning

Three facts about the current code explain the shape below.

First, the sandbox layer has an interface for a network, but only one of the
two paths that start a process uses it. The session layer builds its own
container, command and terminal, and then does the network work itself
(`crates/minimald/src/session_host.rs`). The interface exists at the point
where the difficulty is lowest, and it is absent at the point where the
difficulty is highest.

Second, the interface can describe only the work that comes after the process
starts. Its one operation before the process starts answers a yes-or-no
question about the network namespace. An own-IP sandbox on a native Linux host
needs an address, a netmask, a gateway, an MTU and a DNS server *before* the
process starts, because the sandbox layer builds the tap device inside the
namespace at that moment. The interface cannot return those values, so they
travel as separate configuration fields, and the code that produces them sits
above the sandbox layer.

Third, that one gap has a cost in four crates. The session layer computes the
values, the daemon environment type passes them through, the sandbox
configuration holds them in four fields with a written order of precedence, and
the context crate holds a fifth copy of the mode. The same gap keeps a rollback
guard for the switch count in the session layer, keeps an unsafe descriptor
transfer at the top of the daemon, and holds two attach paths with two
different owners for the same rollback.

### The tap mechanism

An own-IP sandbox needs a tap device inside its network namespace, and there
are two ways to build one. The sandbox layer builds it inside the user and
network namespace of the PTask, without privilege, and hands the descriptor to
the provider; or the daemon builds it in its own namespace under
`CAP_NET_ADMIN`, after the process exists, and moves it into the namespace of
the PTask with the `ip` and `nsenter` programs.

The control channel of the switch decides which. A unix socket (DM2) means a
native host and an unprivileged daemon: the sandbox layer builds the tap, and
the plan carries tap parameters; a root-integration proof drives that path
from the plan to the running process on the native lane
(`crates/minimald/tests/own_ip_tap_root_integration.rs`). A vsock channel
(DM1, DM3 and DM4) means the daemon is root inside a microVM whose network it
owns: the plan asks for a namespace and no tap, and the daemon builds the tap
itself. One function reads the control channel once, before the sandbox
starts, and yields both the transport that carries the descriptor to the
switch and the mechanism.

The choice is not a fallback, and cannot be one. In the x86_64 KVM guest,
asking the sandbox layer for a tap it cannot build destroys the container
supervisor, and the network namespace of the process is gone by the time the
failure is visible, so there is nothing left to put a tap into. Why the
in-namespace mechanism fails there is not known: `/dev/net/tun` is present and
user namespaces are available. Whether it works in the aarch64 libkrun guest is
not proved, because every vsock deployment uses the privileged mechanism. See
[Open questions](#open-questions). The provider holds both mechanisms behind
one attach path with one rollback owner, and 017-010 holds where the sandbox
layer builds the tap, because only that mechanism hands out a descriptor.

### The shape

The network interface gets three operations, and the plan operation returns
data:

```rust
// sandbox2::network
pub struct NetPlan {
    isolate_netns: bool,
    tap: Option<TapSpec>,   // address, netmask, gateway, mtu
    resolver: Resolver,     // None | Host | Nameservers(Vec<Ipv4Addr>)
}

impl NetPlan {                    // constructors only, no public fields
    pub fn host() -> Self;
    pub fn isolated() -> Self;
    pub fn isolated_with_tap(spec: TapSpec) -> Self;   // isolation is implied
    pub fn with_resolver(self, resolver: Resolver) -> Self;
    pub fn isolates_netns(&self) -> bool;              // what the launch reads
    pub fn tap(&self) -> Option<TapSpec>;
    pub fn resolver(&self) -> &Resolver;
}

pub trait Network: Send + Sync + Debug {
    /// Before the process starts: reserve what the sandbox needs, and describe
    /// it. This operation is async and it can fail.
    fn plan(&self) -> PlanFuture<'_>;
    /// After the process starts: wire the namespace of the new process.
    fn attach(&self, spawned: Spawned) -> AttachFuture<'_>;
    /// Release what plan() reserved, when no attach operation follows.
    fn abandon(&self) -> AbandonFuture<'_>;
}

impl Network for NetPlan { .. }  // a plan is its own provider; reserves nothing
pub struct HostNet;               // plans the host network, host resolver
pub struct NoNet;                 // plans an empty namespace
```

The sandbox layer owns the sequence for both paths, as an explicit type with
three steps:

```rust
// sandbox2
impl PlannedLaunch {
    /// plan() -> the caller builds the container from the plan and starts
    /// the process -> attach(). abandon() runs if the launch stops in between.
    pub async fn begin(network: Arc<dyn Network>) -> Result<Self, Error>;
    pub fn plan(&self) -> &NetPlan;
    pub async fn attach(self, spawned: Spawned)
        -> Result<Box<dyn NetGuard>, Error>;
    pub async fn abandon(self);
}
```

A sandbox with no provider of its own passes its own plan, so every launch has
a provider. The container build consumes the resolver of the plan: the host
resolver goes only into a root filesystem that has none, and named servers
replace whatever is there.

The launch owns the release of the plan from `begin` until one of three
transitions, each of which runs exactly once:

- `attach` returns a guard: the guard owns the release from then on, and its
  teardown operation gives the lease back and closes the tap descriptor when
  the sandbox stops. The abandon operation does not run after this.
- `attach` returns an error: the guard does not exist, so the launch still
  owes the release; the launch is dropped on that path, and its drop runs the
  abandon operation. The caller stops the process it started.
- `abandon`, or the drop of a launch that still owes its release: the abandon
  operation runs. A drop cannot await, so it starts the abandon operation on
  the runtime; with no runtime running there is nothing to release to. A
  launch dropped while the plan operation is pending owes nothing, because a
  provider records its reservation in the same poll that takes it.

The provider factory maps each mode to one plan. `HostNet` plans the host
network with the host resolver. `NoNet` plans an empty namespace, no tap and
no resolver. `OwnIp` plans an isolated namespace with the resolver of the
switch, and tap parameters where the sandbox layer builds the tap. The sandbox
layer trusts its provider: what a provider plans is what the sandbox gets, so
the invariant of 017-006 is enforced where providers are made, in the one
function that reads the mode, and no other code in the daemon makes one.

The daemon gets one function that reads the mode, and it returns a provider
for every mode:

```rust
// crates/minimald/src/net/provider.rs
pub(crate) fn network_for(
    mode: NetworkMode,
    switch: &Arc<Mutex<SwitchClient>>,
    identity: &str,                   // the name to register on the switch
    ingress: Option<IngressPolicy>,
) -> Arc<dyn sandbox2::Network>       // HostNet, NoNet, or the own-IP provider
```

Five results follow from these three pieces:

1. Four configuration fields and two builder layers become one value. The mode
   enum leaves the sandbox configuration, and the two DNS controls become the
   one `Resolver` value of the plan.
2. The call site no longer selects between the two deployment paths. The
   provider reads the control channel once, for the transport and the tap
   mechanism together: it returns tap parameters on a native Linux host, and
   returns none inside a microVM. One implementation holds both branches, and
   that implementation owns the rollback.
3. The rollback guard for a cancelled launch moves into the sandbox layer.
   One piece of code holds it, and one test covers it.
4. The unsafe descriptor transfer moves next to the code that creates the
   descriptor, and the provider receives an owned descriptor.
5. The task path calls the same function as the session path, so 017-005
   costs one line instead of a second implementation. A build has no mode: its
   sandbox plans itself from what the build declares, an empty namespace or
   the host network, so the build crate stops carrying the mode enum.

### The alternatives

**Keep the current fields and add more.** Each new option then costs an edit in
four crates, and the two rollback owners stay. The defect in 017-005 stays too,
because the task path has no access to the code that the session path holds.

**Move the switch code into the sandbox layer.** This gives a dependency cycle,
and it breaks the ownership rule of 03-spec-networking R1.4: the daemon owns
the switch process, and the sandbox layer must not know about it. The plan and
the guard keep that rule, because they carry data and not a switch client.

**Give the container object to the provider.** The provider could then set what
it wants directly. This ties every provider to the container library, and it
stops a test double, so the order in 017-001 becomes unverifiable.

### The order of the work

Each step compiles, and each step ships on its own.

1. Move the netmask arithmetic onto the subnet type in the `switch` crate. No
   change in behaviour.
2. Collapse the two attach paths into one that takes the transport as a value,
   and decide the tap mechanism before the sandbox starts, in one function,
   from the control channel. No deployment model changes mechanism. See
   [The tap mechanism](#the-tap-mechanism).
3. Give the privileged mechanism one caller. After step 6 that caller is the
   provider.
4. Add the plan operation and the plan type. The old configuration fields feed
   a plan that the sandbox layer builds. No consumer changes.
5. Add the launch operation, and move the invocation path onto it.
6. Write the own-IP provider, move the rollback guard and the descriptor
   transfer into it, and move the session path onto the launch operation.
   Delete the old configuration fields.
7. Move the task path onto the provider function. This stops the drop to the
   host network, and it satisfies 017-005 for a task.
8. Remove the mode enum from the public interface of the sandbox layer. This
   step touches the build crate and the context crate, and the edits are
   mechanical.
9. Measure one own-IP launch, and set the bound of 017-N01 from that
   measurement.

**Generality:** A second provider fits, because the plan states what the
sandbox needs and not how the provider gets it. A provider for a different
switch, or for a network that a microVM supplies, returns the same plan values.
A provider that must change the container in a way that the plan cannot
describe does not fit; the plan then gets one more field, in one layer, and
every other layer stays the same.

## Security considerations

- **Invariant:** THE SYSTEM SHALL limit the network access of a sandbox to the
  access that the mode of that sandbox states.
  enforced by: one function that maps a mode to a provider, which is the only
  code in the daemon that makes a provider; and an error when the host cannot
  make the namespace that the mode needs.
  covered by: 017-005, 017-006, 017-011

- **Invariant:** THE SYSTEM SHALL leave the switch attachment count unchanged
  after a launch that does not reach the attach operation.
  enforced by: the abandon operation, which the sandbox layer runs on every
  path out of a launch.
  covered by: 017-002, 017-008

- **Invariant:** THE SYSTEM SHALL close the tap descriptor of a sandbox when
  that sandbox stops.
  enforced by: the network guard, whose teardown operation closes the
  descriptor and stops the frame relay.
  covered by: 017-003, 017-010

## Open questions

### Answered

- **The launch operation takes an explicit type with three steps, and not a
  closure.** A closure breaks, for four reasons. The session path builds its
  environment with an asynchronous operation, and a closure that the sandbox
  layer calls is synchronous. That same operation reads the values of the
  plan, so the plan operation must complete before the environment build and
  not only before the container. The environment owns the sandbox, and the
  closure must borrow the environment to build the command, which the borrow
  rules refuse. The closure must also return a terminal and a path, and not
  only a process. The environment build is on the heap today because the
  launch future reaches the query depth limit of the compiler, and one more
  generic layer puts that limit at risk again. The explicit type holds the same
  invariants.
- **The in-VM task path needs no new tools in the guest root filesystem.** The
  privileged mechanism runs `ip` and `nsenter`, and the guest root filesystem
  has both, so no issue is needed. See [The tap mechanism](#the-tap-mechanism).
- **The repository gets a `just` recipe that runs one test.** Separate work
  adds it. The `verify:` lines keep the direct command, because a spec must
  name the test and not the wrapper.

### Open

- [NEEDS CLARIFICATION (HIGH): Why does the in-namespace tap mechanism fail
  inside the x86_64 KVM guest, and does it work inside the aarch64 libkrun
  guest? `/dev/net/tun` is present there and user namespaces are available,
  yet the sandbox layer yields no descriptor. Until the cause is known, every
  vsock deployment uses the privileged mechanism.]
- [NEEDS CLARIFICATION (MEDIUM): A task run always asks for the host network,
  because the command that starts it has no option for the mode. Does the
  option belong to this work, or to a later change? 017-005 holds either way,
  because it reads the mode that the PTask carries.]
- [NEEDS CLARIFICATION (MEDIUM): What time bound do four concurrent own-IP
  launches get? 017-N01 states the structure that keeps them from serializing
  and no duration, because no measurement of one launch exists. Step 9 takes
  the measurement and states the bound from it, with the workload, the timing
  method and the allowed variance.]
- [NEEDS CLARIFICATION (LOW): The epic number and the GitHub handle of the
  owner.]

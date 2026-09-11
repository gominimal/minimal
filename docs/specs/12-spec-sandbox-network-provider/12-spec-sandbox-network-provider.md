---
id: 012
title: One network provider for every sandbox
status: draft
owner: tom@minimal.dev
epic: gominimal/minimal#TBD
arch: none
updated: 2026-09-10
---

# 012 — One network provider for every sandbox

## Context

Each sandboxed unit is a PTask, and each PTask has one of three network modes:
no network, the host network, or its own IP address on the local switch (see
[03-spec-networking](../03-spec-networking/03-spec-networking.md) R1.1). An
interactive session is a PTask. A task is a PTask too: a task run mints a
session of its own, so it is a session that no person attaches to. A build is a
third one. The code that starts an own-IP network, however, is at the top of
the daemon, in the layer that only interactive sessions pass through. A new
network option must pass through four layers of code before it reaches the
sandbox. The top layer also holds the rollback logic for a switch attachment
that the sandbox layer does not know about. Two different paths start a sandbox
process, and only one of the two paths applies the network. Because of this,
the daemon drops the own-IP mode of a task to the host network, which gives
that task more network access than its mode states. That defect makes this work
necessary now. After this change, one interface supplies the network to every
PTask, and the sandbox layer controls the sequence and the rollback.

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

- **012-001** WHEN a sandbox starts with a network provider, THE SYSTEM SHALL
  complete the plan operation before it creates the container, and start the
  attach operation after the process starts.
  tier:     T0
  verify:   `cargo nextest run -p sandbox2 network_phases_run_in_order`

- **012-002** IF a launch stops after the plan operation and before the attach
  operation, THEN THE SYSTEM SHALL run the abandon operation one time.
  tier:     T1
  verify:   `cargo nextest run -p sandbox2 abandoned_launch_releases_the_plan`
  property: for every launch, count(plan) = count(attach) + count(abandon)
  - IF the launch future stops because the caller drops it, THEN THE SYSTEM
    SHALL run the abandon operation one time.
    tier:   T0
    verify: `cargo nextest run -p sandbox2 cancelled_launch_releases_the_plan`

- **012-003** WHEN a sandbox process stops, THE SYSTEM SHALL run the teardown
  operation of the network guard of that sandbox one time.
  tier:     T1
  verify:   `cargo nextest run -p minimald exit_releases_the_network`
  property: for every sandbox, count(attach) = count(teardown)

- **012-004** THE SYSTEM SHALL apply the network provider on the invocation
  path of the sandbox layer and on the path where the caller starts the
  process.
  tier:     T0
  verify:   `cargo nextest run -p sandbox2 both_spawn_paths_apply_the_network`

- **012-005** THE SYSTEM SHALL apply the network mode of a PTask to the sandbox
  of that PTask, for an interactive session, for a task and for a build.
  tier:     T1
  verify:   `cargo nextest run -p minimald every_ptask_kind_gets_its_own_mode`
  property: for every PTask p, the mode of the sandbox of p is equal to the
            mode of p
  - WHEN a task runs in an existing session and states no mode of its own, THE
    SYSTEM SHALL apply the mode of that session to the sandbox of the task.
    tier:   T0
    verify: `cargo nextest run -p minimald a_task_takes_the_mode_of_its_session`
  - IF the daemon cannot give a task the network of its mode, THEN THE SYSTEM
    SHALL stop the task with an error and SHALL keep the task off the host
    network.
    tier:   T0
    verify: `cargo nextest run -p minimald a_failed_task_attach_does_not_use_host_net`

- **012-006** THE SYSTEM SHALL limit the network access of a sandbox to the
  access that the mode of that sandbox states.
  tier:     T1
  verify:   `cargo nextest run -p sandbox2 the_mode_bounds_the_network_access`
  property: for every sandbox s, access(s) is a subset of access(mode(s))

- **012-007** IF a plan contains tap parameters, THEN THE SYSTEM SHALL run the
  sandbox in a new network namespace.
  tier:     T1
  verify:   `cargo nextest run -p sandbox2 a_tap_plan_always_isolates`
  property: for every plan p, p has tap parameters implies p isolates the
            network namespace

- **012-008** IF an own-IP attach operation fails, THEN THE SYSTEM SHALL
  decrease the switch attachment count one time for that sandbox.
  tier:     T1
  verify:   `cargo nextest run -p minimald failed_attach_releases_the_switch_once`
  property: after a failed launch, the switch attachment count is equal to the
            count before that launch

- **012-009** WHERE a sandbox has the own-IP mode, THE SYSTEM SHALL write the
  DNS server address of the switch into the resolver file of that sandbox, on
  every deployment model.
  tier:     T0
  verify:   `cargo nextest run -p sandbox2 own_ip_resolver_points_at_the_switch`

- **012-010** WHEN the sandbox layer creates a tap device in the namespace of
  the sandbox, THE SYSTEM SHALL give the file descriptor of that device to the
  network provider one time.
  tier:     T1
  verify:   `cargo nextest run -p sandbox2 the_tap_descriptor_goes_to_the_provider_once`
  property: for every sandbox, the tap descriptor is given one time and closes
            at teardown

- **012-011** IF the host cannot create a network namespace and the plan needs
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
- The tools that the guest root filesystem needs for the in-VM task attach:
  none on the path this spec describes, because the sandbox layer makes the
  tap in the namespace of the sandbox. The fallback for the one deployment
  model where that does not work still runs `ip` and `nsenter`, and the guest
  root filesystem already has both. See
  [One tap mechanism](#one-tap-mechanism).
- A network mode of its own for a task run: the command that starts a task has
  no option for the mode today, and it always asks for the host network. This
  spec makes the mode of a task reach its sandbox; it adds no option. See
  [Open questions](#open-questions).

## Non-functional requirements

- **012-N01** WHILE four own-IP sandboxes start at the same time, THE SYSTEM
  SHALL complete every launch in less than two times the duration of one
  launch.
  tier:   T0
  verify: `cargo nextest run -p minimald concurrent_own_ip_launches_do_not_serialize`

## Design reasoning

Four facts about the current code explain the shape below.

First, the sandbox layer has an interface for a network, but only one of the
two paths that start a process uses it. The session layer builds its own
container, command and terminal, and then does the network work itself
(`crates/minimald/src/session_host.rs`). The interface exists at the point
where the difficulty is lowest, and it is absent at the point where the
difficulty is highest.

Second, the interface can describe only the work that comes after the process
starts. Its one operation before the process starts answers a yes-or-no
question about the network namespace. An own-IP sandbox needs an address, a
netmask, a gateway, an MTU and a DNS server *before* the process starts,
because the sandbox layer builds the tap device inside the namespace at that
moment. The interface cannot return those values, so they
travel as separate configuration fields, and the code that produces them sits
above the sandbox layer.

Third, that one gap has a cost in four crates. The session layer computes the
values, the daemon environment type passes them through, the sandbox
configuration holds them in four fields with a written order of precedence, and
the context crate holds a fifth copy of the mode. The same gap keeps a rollback
guard for the switch count in the session layer, keeps an unsafe descriptor
transfer at the top of the daemon, and holds two attach paths with two
different owners for the same rollback.

Fourth, those two attach paths exist because of privilege, not because of the
deployment model, and only one of the two follows
[03-spec-networking](../03-spec-networking/03-spec-networking.md) R1.5. That
requirement states one mechanism — "create a network namespace, **provision a
virtual tap interface inside it**, and pass the tap file descriptor to the
running gvproxy" — and names the file-descriptor transport as the only part
that the deployment model changes: a unix socket on DM2, vsock on DM1. The
native path does this. The in-VM path does not: it creates the tap in the
root network namespace of the guest, with `CAP_NET_ADMIN`, and then moves the
tap into the namespace of the sandbox with the `ip` program. See
[One tap mechanism](#one-tap-mechanism).

### One tap mechanism

The rootless mechanism works when the parent process is root, so the in-VM
path can use it too. A proof runs both cases in the native lane
(`crates/minimald/tests/rustslirp_root_integration.rs`).

This removes the second mechanism from the design, and with it the second
rollback owner. The two deployment paths then differ in one value: the
transport that carries the file descriptor to the switch. Both transports
already share one frame relay, so the frames do not change.

**One deployment model does not do this yet.** In the x86_64 KVM guest the
sandbox layer makes no tap, and gives out no file descriptor. This is not a
lack of the two things the mechanism needs: the daemon reports that
`/dev/net/tun` is present and that user namespaces are available. The same
code makes a tap correctly on a native host as root (the proof above, on an
x86_64 runner) and in the aarch64 microVM guest (the session end-to-end proof
on the macOS lane). The cause is in the x86_64 guest and is not yet known.

So the daemon keeps the privileged mechanism as a **fallback**, and uses it
when two conditions hold together: the sandbox layer gave out no file
descriptor, and the daemon is inside a microVM whose network it owns. On a
native host there is no fallback — the daemon is unprivileged by design, and
a failure there must stay a failure. `net::provider::own_ip_fallback_reason`
holds that rule, and a test holds it in place.

The result is still one attach path with one rollback owner, in one module.
The deployment model selects a transport and, in this one case, a way to get
the tap.

Three consequences follow, and they make step 6 below smaller than it would be
with two mechanisms:

1. The provider holds one attach path, not a branch on the deployment model.
2. The daemon stops running the `ip` and `nsenter` programs for the network
   on every deployment model but one, where they remain as a fallback.
3. 012-005 holds the same way on every deployment model, instead of holding
   first on a native Linux host and later inside a microVM.

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
```

The sandbox layer owns the sequence for both paths:

```rust
impl Sandbox<C> {
    /// plan() -> build the container from the plan -> the caller starts the
    /// process -> attach(). abandon() runs if the launch stops in between.
    pub async fn launch<F>(&mut self, spawn: F) -> Result<Launched, Error>
    where F: FnOnce(&Container) -> Result<hakoniwa::Child, Error>;
}
```

The daemon gets one function that reads the mode:

```rust
// crates/minimald/src/net/provider.rs
pub(crate) fn network_for(
    mode: NetworkMode,
    switch: &Arc<Mutex<SwitchClient>>,
    identity: PtaskIdentity,   // the name to register on the switch
    policy: &SessionPolicy,    // ingress today, egress later
) -> Box<dyn sandbox2::Network>
```

Five results follow from these three pieces:

1. Four configuration fields and two builder layers become one value. The mode
   enum leaves the sandbox configuration, and the two DNS controls become the
   one `Resolver` value of the plan.
2. The call site no longer selects between the two deployment paths. The
   provider returns tap parameters on every deployment model, because the
   sandbox layer makes the tap in the namespace of the sandbox in every case.
   The deployment model selects the transport that carries the file descriptor
   to the switch, and nothing else. One implementation owns the rollback.
3. The rollback guard for a cancelled launch moves into the sandbox layer.
   One piece of code holds it, and one test covers it.
4. The unsafe descriptor transfer moves next to the code that creates the
   descriptor, and the provider receives an owned descriptor.
5. The task path and the build path call the same function as the session
   path, so 012-005 costs one line for each of them instead of a second
   implementation.

### The alternatives

**Keep the current fields and add more.** Each new option then costs an edit in
four crates, and the two rollback owners stay. The defect in 012-005 stays too,
because the task path has no access to the code that the session path holds.

**Move the switch code into the sandbox layer.** This gives a dependency cycle,
and it breaks the ownership rule of 03-spec-networking R1.4: the daemon owns
the switch process, and the sandbox layer must not know about it. The plan and
the guard keep that rule, because they carry data and not a switch client.

**Give the container object to the provider.** The provider could then set what
it wants directly. This ties every provider to the container library, and it
stops a test double, so the order in 012-001 becomes unverifiable.

### The order of the work

Each step compiles, and each step ships on its own.

1. Move the netmask arithmetic onto the subnet type in the `switch` crate. No
   change in behaviour.
2. Give the in-VM path the rootless tap mechanism, so that the deployment model
   selects a transport and nothing else. See
   [One tap mechanism](#one-tap-mechanism).
3. Keep the mechanism that step 2 stops using, as the fallback for the one
   deployment model that needs it, and give it one caller.
4. Add the plan operation and the plan type. The old configuration fields feed
   a plan that the sandbox layer builds. No consumer changes.
5. Add the launch operation, and move the invocation path onto it.
6. Write the own-IP provider, move the rollback guard and the descriptor
   transfer into it, and move the session path onto the launch operation.
   Delete the old configuration fields.
7. Move the task path onto the provider function. This stops the drop to the
   host network, and it satisfies 012-005 for a task.
8. Remove the mode enum from the public interface of the sandbox layer. This
   step touches the build crate and the context crate, and the edits are
   mechanical.
9. Measure one own-IP launch, set the bound of 012-N01 from that measurement,
   and add a `just` recipe that runs one test.

Steps 2 and 3 come first because they decide the shape of step 6, and because
they can fail: a proof that the in-VM transport carries a tap that the sandbox
layer made must pass before step 6 is written. If that proof fails, steps 2 and
3 come out and the provider of step 6 keeps a branch on the deployment model.
Every other step stands without them.

**Generality:** A second provider fits, because the plan states what the
sandbox needs and not how the provider gets it. A provider for a different
switch, or for a network that a microVM supplies, returns the same plan values.
A provider that must change the container in a way that the plan cannot
describe does not fit; the plan then gets one more field, in one layer, and
every other layer stays the same.

## Security considerations

- **Invariant:** THE SYSTEM SHALL limit the network access of a sandbox to the
  access that the mode of that sandbox states.
  enforced by: one function that maps a mode to a provider, and an error when
  the host cannot make the namespace that the mode needs.
  covered by: 012-005, 012-006, 012-011

- **Invariant:** THE SYSTEM SHALL leave the switch attachment count unchanged
  after a launch that does not reach the attach operation.
  enforced by: the abandon operation, which the sandbox layer runs on every
  path out of a launch.
  covered by: 012-002, 012-008

- **Invariant:** THE SYSTEM SHALL close the tap descriptor of a sandbox when
  that sandbox stops.
  enforced by: the network guard, whose teardown operation closes the
  descriptor and stops the frame relay.
  covered by: 012-003, 012-010

## Open questions

### Answered

- **The launch operation takes an explicit type with three steps, and not a
  closure.** (Was HIGH.) The limits break, for four reasons. The session path
  builds its environment with an asynchronous operation, and a closure that the
  sandbox layer calls is synchronous. That same operation reads the values of
  the plan, so the plan operation must complete before the environment build
  and not only before the container. The environment owns the sandbox, and the
  closure must borrow the environment to build the command, which the borrow
  rules refuse. The closure must also return a terminal and a path, and not
  only a process. The environment build is on the heap today because the layout
  of the launch future reaches the query depth limit of the compiler, and one
  more generic layer puts that limit at risk again. The explicit type holds the
  same invariants, as this section stated.
- **The in-VM task path needs no tools in the guest root filesystem.** (Was
  HIGH.) The question assumed the daemon must move a tap into the namespace of
  the sandbox. On the path this spec describes it does not. The fallback does,
  and the guest root filesystem already has `ip` and `nsenter`, so no issue is
  needed either way. See [One tap mechanism](#one-tap-mechanism).
- **The repository gets a `just` recipe that runs one test.** (Was MEDIUM.)
  Step 9 adds it. The `verify:` lines keep the direct command, because a spec
  must name the test and not the wrapper.

### Open

- [NEEDS CLARIFICATION (MEDIUM): A task run always asks for the host network,
  because the command that starts it has no option for the mode. Does the
  option belong to this work, or to a later change? 012-005 holds either way,
  because it reads the mode that the PTask carries.]
- [NEEDS CLARIFICATION (MEDIUM): Is the bound in 012-N01 the right one? The
  number states that four launches must not serialize, but no measurement of
  one launch exists today.]
- [NEEDS CLARIFICATION (LOW): The epic number and the GitHub handle of the
  owner.]

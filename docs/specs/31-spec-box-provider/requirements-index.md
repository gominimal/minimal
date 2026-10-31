# BPA — Box Provider — requirement index

Lookup table for [`31-spec-box-provider.md`](31-spec-box-provider.md). Requirement IDs are stable and never reused, so they are not in numeric order in the spec — it groups them by topic instead. Gaps below are requirements withdrawn during drafting.

| ID | Section | In short |
|---|---|---|
| BPA-001 | What a provider advertises | Report the conformance profile |
| BPA-002 | What a provider advertises | Report every optional capability supported |
| BPA-003 | What a provider advertises | Advertise only capabilities that actually work end to end |
| BPA-004 | What a provider advertises | Refuse an unadvertised capability, naming it |
| BPA-005 | The host inventory | A full listing reports every host and its size, architecture, pin state, and gateway where it has one |
| BPA-007 | What a provider advertises | Report whether hosts are a fixed pool or on-demand |
| BPA-008 | What a provider advertises | Report every protocol version spoken |
| BPA-009 | What a provider advertises | Report the oldest client version supported |
| BPA-010 | Reconciling a declared requirement | An oversized create leaves the inventory unchanged |
| BPA-011 | Reconciling a declared requirement | An unsatisfiable create names the unmet dimension |
| BPA-012 | Reconciling a declared requirement | An unsatisfiable create fails finally, never queues |
| BPA-013 | Transport and reach | The three well-known local providers behave as a remote one does — two composed by the client, `local-box` served whole — each at a stated profile |
| BPA-014 | Host state and lifecycle | Every host state is one of the defined set |
| BPA-015 | Host state and lifecycle | An unreachable ready host is still reported ready |
| BPA-016 | Limits | Report the caller's effective limits on request |
| BPA-017 | Limits | Report the caller's current consumption on request |
| BPA-018 | Limits | Enforce limits whether or not the caller asked about them |
| BPA-019 | Limits | An over-limit request names the dimension, limit and usage |
| BPA-020 | Tenancy | Enrolled: each host belongs to exactly one tenant at a time |
| BPA-021 | Tenancy | Refuse any call touching another tenant's host |
| BPA-022 | Tenancy | Enrolled: a host appears in at most one tenant's inventory |
| BPA-023 | Credentials and the enrollment hand-off | Enrolled: returned endpoints terminate at the host's own certificate; un-enrolled: at a socket, with no trust-on-first-use key |
| BPA-024 | Credentials and the enrollment hand-off | Hold no tenant credential but the two bootstrap ones |
| BPA-027 | Limits | Deliver box-level quota config to each host |
| BPA-028 | Limits | Rate-limit each tenant separately |
| BPA-029 | Limits | Fail closed on create when usage is unknown |
| BPA-031 | The egress fabric | Report ready only once confined to the infrastructure set |
| BPA-032 | The egress fabric | Confine on every address family the host can use |
| BPA-033 | The egress fabric | Change the confinement only when the set itself changes |
| BPA-034 | The egress fabric | Report the pin state the platform actually enforces |
| BPA-035 | The egress fabric | Leave no provider-infrastructure credential on the host |
| BPA-036 | The egress fabric | Never write Egress Gateway policy |
| BPA-037 | The egress fabric | A supplied image can establish its association *(association variants)* |
| BPA-038 | The egress fabric | The provider's own channel needs no confinement exception |
| BPA-039 | Limits | Two requests that only jointly exceed a limit: admit at most one |
| BPA-040 | Transport and reach | A provider that binds an endpoint serves at least one wire binding; a composed one binds none |
| BPA-041 | What a provider advertises | Report every wire binding served |
| BPA-042 | Transport and reach | Where an endpoint is bound: both bindings produce identical observable results |
| BPA-043 | Transport and reach | Serve every network endpoint over TLS; restrict a local socket to its user |
| BPA-044 | Transport and reach | Expose no bidirectional streaming endpoint |
| BPA-045 | Authentication, on every call | Enrolled: verify token and proof before executing |
| BPA-046 | Authentication, on every call | Refuse a token whose audience is another provider |
| BPA-047 | Authentication, on every call | Refuse a token from an unconfigured issuer |
| BPA-048 | Authentication, on every call | Refuse a token presented without proof of possession |
| BPA-049 | Authentication, on every call | Refuse a replayed proof of possession |
| BPA-050 | Authentication, on every call | Refuse a token lacking the endpoint's scope |
| BPA-051 | Idempotency | Accept a caller-set idempotency key on every lifecycle call |
| BPA-052 | Idempotency | A repeated key with the same payload returns the first result |
| BPA-053 | Idempotency | A repeated key with the same payload creates nothing further |
| BPA-054 | Idempotency | A reused key with a changed payload is refused |
| BPA-055 | The host inventory | A listing call returns at most one page |
| BPA-056 | The host inventory | Return a cursor whenever results remain |
| BPA-057 | The host inventory | Accept a cursor only in the form it was issued |
| BPA-058 | The host inventory | A returned cursor continues after the last result |
| BPA-059 | The host inventory | Honour state, class and label filters |
| BPA-060 | The host inventory | Treat a caller's page size as a ceiling |
| BPA-061 | The host inventory | Never exceed the provider's own maximum page size |
| BPA-062 | What a provider advertises | Report the provider's maximum page size |
| BPA-063 | Watching for changes | Where `watch` is advertised: emit each state transition exactly once |
| BPA-064 | Watching for changes | Where `watch` is advertised: each event carries the host it concerns |
| BPA-066 | Errors and refusals | Return the code the error model assigns |
| BPA-067 | Errors and refusals | Carry the structured detail the condition names |
| BPA-068 | Errors and refusals | Refusal time does not vary with existence; decided without a lookup |
| BPA-069 | Host state and lifecycle | A created host starts in a pre-ready state |
| BPA-070 | Host state and lifecycle | A deleted host drains rather than vanishing; draining ends resident boxes as a stop does, waiting on none |
| BPA-071 | Host state and lifecycle | Report states in the defined transition order |
| BPA-072 | Host state and lifecycle | A one-time-use host terminates after its first box |
| BPA-073 | The host record | Report the node identity an enrolled host joined with |
| BPA-074 | The host record | Enrolled: report an SSH endpoint and the published DNS name; un-enrolled: the local endpoint and no tenant-zone name |
| BPA-075 | The host record | Never use a label as an authorization input |
| BPA-076 | Credentials and the enrollment hand-off | Enrolling providers: accept the pre-registered node, gateway and candidate key on create |
| BPA-077 | Credentials and the enrollment hand-off | Enrolling providers: fail a host whose first heartbeat contradicts its create request |
| BPA-078 | The egress fabric | Report every Egress Gateway offered |
| BPA-079 | The egress fabric | Enrolling providers: fail at enrolling on a gateway mismatch |
| BPA-080 | Errors and refusals | Multi-tenant: an unknown host id is permission-denied, not not-found |
| BPA-081 | The egress fabric | Report every BEP association endpoint set offered |
| BPA-082 | The egress fabric | Confine to the *complete* assigned BEP set *(association variants)* |
| BPA-083 | The egress fabric | Rotate endpoints add-then-retire, never breaking a live path |
| BPA-084 | The host's memory policy | Report the default box memory size |
| BPA-085 | The host's memory policy | Report whether the host overcommits, and its reservation floor |
| BPA-086 | The host's memory policy | Report memory enforcement as enforced or advisory |
| BPA-087 | The host's memory policy | Report the enforcement the platform delivers, not the configured one |
| BPA-088 | The host's memory policy | An advisory host is reported and counted like an enforced one |
| BPA-089 | Errors and refusals | On-demand: distinguish a create it cannot satisfy from a caller over its limit, by the detail each carries |
| BPA-090 | Limits | Usage counts reservations, not limits, in every dimension |
| BPA-091 | What a provider advertises | On-demand: report the size of the largest host it will create |
| BPA-092 | What a provider advertises | On-demand: report the idempotency window |
| BPA-093 | Reconciling a declared requirement | On-demand: never substitute a requested CPU architecture |
| BPA-094 | Enrollment, and the un-enrolled local case | Un-enrolled: serve over a local socket only, never a network transport |
| BPA-095 | Enrollment, and the un-enrolled local case | Un-enrolled: the socket's access control is the whole authentication; no credential of the provider's own making |

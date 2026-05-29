# Session Domain Model

> Vernacular: the isolation environment is a **Session**. The thing that creates and hosts them is a **Provider**.

## Main diagram

```mermaid
classDiagram
    class Minimal {
        <<client process>>
        +instantiate()
        +discoverSocket()
    }

    class Socket {
        <<connection>>
        +path: $HOME/.minimal/local/[pid].sock
    }

    class Provider {
        <<interface>>
        +listSessions()
        +createSession()
    }

    class Minimald {
        <<provider>>
        backend: Linux
    }

    class MinVMD {
        <<provider>>
        backend: VMs
    }

    class MinHosted {
        <<provider>>
        backend: Hosted
    }

    class MinCloud {
        <<provider>>
        backend: Cloud
    }

    class VM {
        <<host>>
    }

    class Session {
        <<workload>>
    }

    Minimal "1" --> "*" Socket : discovers via local dir
    Socket "1" --> "1" Provider : connects to
    Minimal "1" ..> "*" Provider : connects to many
    Provider "1" --> "1" Socket : creates [pid].sock

    Provider <|.. Minimald : implements
    Provider <|.. MinVMD : implements
    Provider <|.. MinHosted : implements
    Provider <|.. MinCloud : implements

    Minimald  "1" *-- "*" Session : hosts (Linux)
    MinHosted "1" *-- "*" Session : hosts (Hosted)
    MinCloud  "1" *-- "*" Session : hosts (Cloud)
    MinVMD    "1" *-- "*" VM : hosts
    VM        "1" --> "1" Minimald : instantiates
```

## Local Linux deployment

```mermaid
flowchart LR
    M["Minimal<br/>(client process)"] -. "scans ~/.minimal/local/" .-> DIR[("~/.minimal/local/")]
    P1["minimald (pid 4001)"] -- "creates" --> SK1["4001.sock"]
    P2["minvmd (pid 4002)"] -- "creates" --> SK2["4002.sock"]
    SK1 --> DIR
    SK2 --> DIR
    M -- "connects" --> SK1
    M -- "connects" --> SK2
    P1 --> E1["Session 1"]
    P1 --> E2["Session N"]
    P2 -- "hosts" --> guest
    P2 -. "proxies guest socket" .-> MD
    subgraph guest["VM (guest)"]
        MD["minimald (in VM)<br/>~/.minimal/local/&lt;pid&gt;.sock"] --> E3["Session"]
    end
```

## Local macOS deployment

macOS has no native `minimald` (it is a Linux provider), so `Minimal` **cannot talk to a `minimald` directly**. All sessions are reached through a VM. `Minimal` may run **multiple `minvmd`s**, each hosting a VM that runs an in-VM `minimald` whose socket is proxied back to the host.

```mermaid
flowchart LR
    M["Minimal<br/>(host, macOS)"] -. "scans ~/.minimal/local/" .-> DIR[("~/.minimal/local/")]
    P1["minvmd (pid 5001)"] -- "creates" --> SK1["5001.sock"]
    P2["minvmd (pid 5002)"] -- "creates" --> SK2["5002.sock"]
    SK1 --> DIR
    SK2 --> DIR
    M -- "connects" --> SK1
    M -- "connects" --> SK2
    P1 -- "hosts" --> g1
    P2 -- "hosts" --> g2
    P1 -. "proxies guest socket" .-> MD1
    P2 -. "proxies guest socket" .-> MD2
    subgraph g1["VM (guest)"]
        MD1["minimald (in VM)"] --> E1["Session"]
    end
    subgraph g2["VM (guest)"]
        MD2["minimald (in VM)"] --> E2["Session"]
    end
```

- No direct `minimald` on macOS; isolation requires a Linux VM.
- Multiple `minvmd`s are allowed, each a separate provider with its own host socket.
- The host never sees the guest `minimald` except through the `minvmd` proxy.

## VM socket proxying

- The in-VM `minimald` creates its own `~/.minimal/local/<pid>.sock` inside the guest.
- `minvmd` **proxies/forwards** that guest socket back to the host, so host `Minimal` talks to the in-VM `minimald` through `minvmd`.
- `Minimal` connects to `minvmd`'s host socket; `minvmd` relays traffic across the VM boundary to each VM's `minimald`.

```mermaid
flowchart LR
    M["Minimal (host)"] -- "host socket" --> P["minvmd"]
    P == "forward / relay" ==> G["minimald (guest)"]
    G --> E["Session"]
```

## Socket lifecycle

- **Providers own the socket lifecycle**: create `~/.minimal/local/<pid>.sock` on start, remove it on shutdown.
- One socket per provider process; PID namespaces the socket file.
- `Minimal` discovers providers by scanning `~/.minimal/local/` and connecting to each `<pid>.sock`.
- `Minimal` must **detect dead providers**: a `<pid>.sock` may be stale (provider crashed without cleanup). Connect-and-prune or liveness-check on discovery.

## Startup / bootstrap

```mermaid
flowchart TD
    START([Minimal starts]) --> SCAN["scan ~/.minimal/local/"]
    SCAN --> Q{live sockets found?}
    Q -- yes --> CONN["connect to each live <pid>.sock"]
    Q -- no --> HASCFG{config present?}
    HASCFG -- yes --> ALL["start ALL providers in config<br/>(config overrides defaults)"]
    HASCFG -- no --> DEF["start system default provider<br/>(e.g. minimald on Linux)"]
    ALL --> MKSOCK["each provider creates <pid>.sock"]
    DEF --> MKSOCK
    MKSOCK --> CONN
    CONN --> READY([ready])
```

**Bootstrap rules:**
- No config → start the single system-default provider for the OS.
- Config present → start **all** providers listed; config fully overrides defaults.
- A spawned provider creates its `<pid>.sock`, then `Minimal` connects.
- Stale `<pid>.sock` files (dead provider) are skipped/pruned during the scan.

## Glossary

| Term | Meaning |
|------|---------|
| Session | The isolation environment. |
| Provider | Creates and hosts sessions; exposes a socket. |
| minimald | Linux provider — hosts sessions directly. Also runs inside a VM. |
| minvmd | VM provider — hosts VMs; each VM runs a minimald and minvmd proxies its socket to the host. |
| minhosted | Hosted provider — hosts sessions on an externally managed backend. |
| mincloud | Cloud provider — hosts sessions on a cloud backend. |

> Note: `minhosted` and `mincloud` are placeholders. They could be specialized into neocloud or hyperscaler-specific backends (e.g. a per-provider daemon for a specific neocloud, or AWS/GCP/Azure).
| Minimal | Client process; discovers providers via sockets, starts a default/config provider when none exist. |

# Clash API, slices 2 and 3 — Implementation Plan

**Goal:**
- **Selector groups** whose choice survives reloads and restarts.
- **The `rule`/`global`/`direct` modes.**
- **Delay tests** on any outbound.
- **`urltest` groups**, which pick the fastest member themselves.

Together these let Clash dashboards and awg-manager drive shoes the way they
drive sing-box.

**Spec:** `docs/specs/2026-09-09-clash-api.md`, sections "The proxy model",
"Slice 2" and "Slice 3". [Where this plan changes the spec](#where-this-plan-changes-the-spec)
lists the departures; the spec is amended in the same commit as this plan.

**References.** The sources below were read 2026-10-12.
- **The consumer is awg-manager.** Its Clash client is in
  `internal/singbox/clash.go`:
  - `PUT /proxies/{sel}` with `{"name":member}` must answer 2xx;
  - `GET /proxies/{sel}` is read for `now`;
  - `GET /proxies/{name}/delay?url=&timeout=<ms>` treats any status other
    than 200 as a failure;
  - `GET /proxies` is read for the last `history` entry
    (`internal/monitoring/clashstate.go:82-110`).
- **Group shapes.** It emits a `selector` with `default` and
  `interrupt_exist_connections: false`, and a `urltest` with `url`, `interval`
  and `tolerance`, in `internal/singbox/subscription/materialize.go`. Its
  defaults are `https://www.gstatic.com/generate_204`, 60 s and 50 ms
  (`types.go:51`).
- **Group members are always leaf tags**, never other groups
  (`groups.go:196`, aggregate groups included).
- **sing-box is the behaviour to match**, because awg-manager was written
  against it (clone at `e4b7e69`):
  - `experimental/clashapi/proxies.go`: `getProxyDelay`, `updateProxy`,
    `proxyInfo`;
  - `common/urltest/urltest.go`: `urlTest`;
  - `protocol/group/selector.go`: `SelectOutbound`;
  - `protocol/group/urltest.go`: `Select`, `NewURLTestGroup` defaults;
  - `constant/timeout.go`: `DefaultURLTestInterval = 3m`,
    `DefaultURLTestIdleTimeout = 30m`, `TCPTimeout = 15s`.

## What the code does today

Verified at `bf1740f`. These facts shape the design.

- **A named `client_group` doesn't exist at runtime.** Validation flattens it
  (`resolve_client_groups_topologically`, `validate.rs:314-378`) and
  `expand_chain_hop` (`validate.rs:2629-2661`) inlines a reference as
  `Single(config)` or `Pool([configs])`.
- **Every rule of every listener builds its own `ClientChainGroup`**
  (`create_tcp_client_proxy_selector`, `tcp_client_handler_factory.rs:402-447`,
  called once per listener and again for nested handlers), each with its own
  round-robin atomics. So **a selection cannot live in a chain**: it has to be
  process-wide state keyed by group name, which the chains read.
- `client_chain: eu` is **one chain whose hop is a pool** of the group's
  leaves.
  - Pool selection happens in `select_from_pool` (`client_proxy_chain.rs:797`),
    `select_terminal` (`:809`) and `select_subsequent` (`:821`).
  - `ClientChainGroup` adds its own round-robin across chains (`:903`).
- **The routing cache** (`client_proxy_selector.rs:57-96`) stores only the rule
  index or Block. The chain group is read fresh each time (`:519-529`), so
  state read inside a chain is never stale.
  - **A mode override must apply after `judge`, never by rewriting rules**,
    which the cache would hide.
- **The controller can't reach a resolver or a leaf's config.** `ApiState`
  (`clash_api/mod.rs:88-103`) has neither, and the outbound registry keeps only
  key, address, protocol and the UDP flag (`outbound_stats.rs:62`).
- **`state_file`** is parsed (`config/types/clash_api.rs:53`) and read nowhere.
- **A rendering bug.** `render::proxies` inserts groups after leaves
  (`render.rs:109-125`), and the built-in group `direct` (`validate.rs:74`)
  overwrites the leaf `direct`. `/proxies` reports `direct` as a LoadBalance
  group.
- **No HTTP client.** hyper is built without `client`. `tokio-rustls` and
  `webpki-roots` are already dependencies.

## Where this plan changes the spec

| Spec says | Plan does | Why |
| --- | --- | --- |
| `urltest` interval defaults to 5m | 3m, plus `idle_timeout` default 30m | sing-box's defaults (`constant/timeout.go`), which awg-manager configs were tuned against |
| `PUT` on a urltest group pins a member until `DELETE` (mihomo) | `400 {"message":"Must be a Selector"}` | sing-box (`updateProxy`); awg-manager only selects on selectors |
| `select` refuses a chain member that is a pool | `select`/`urltest` members must be leaves, and the group must be the sole entry of the hop that names it | Members are leaves already (groups flatten); a group mixed into a larger pool has no single "selected member" |
| Per-leaf ring of ten `history` entries | Kept: ten, newest last | mihomo dashboards plot it; awg-manager reads the last entry; sing-box keeps one, which is a subset |
| `delay` takes any URL | `http://` is replaced by the default HTTPS URL | sing-box does exactly this (`getProxyDelay`), and awg-manager's default URL is `http://` |
| `GLOBAL` routing chains built at install for every leaf | Built lazily, per selector, on first use of `mode: global` | A router with hundreds of subscription leaves and a listener per subscription should not pay for a mode it never enters |

## Global constraints

- Mobile stays untouched. Everything controller-side is behind `clash-api`.
- **Group modes are configuration, so they compile everywhere.** A mobile
  client can use a selector group fixed at its `default`, at no runtime cost
  beyond one atomic read per connection.
- **Per-packet paths are untouched.** Selection is read once per connection or
  UDP session, never per packet.
- **Two module trees.** A new top-level module goes into both `src/lib.rs` and
  `src/main.rs` (AGENTS.md).
- Every new config option reaches `CONFIG.md`, an example, and the smoke loop
  in `.github/workflows/build.yml`.
- **Gates for every task:** the full AGENTS.md gate, plus
  `cargo clippy --locked --features clash-api --bins --tests -- -D warnings`,
  plus `scripts/check-mobile-features.sh`.

## PR A — selector groups and persistence (slice 2a)

### A1. Config

`ClientConfigGroup` (`config/types/groups.rs:24`) gains:

```yaml
client_group: eu
mode: select          # round_robin (default) | select ; urltest arrives in PR D
default: eu-1         # optional; first member when absent (sing-box)
client_proxies: [eu-1, eu-2]
```

**Validation** (`validate.rs`), each with a test asserting the message:
- In a `select` group:
  - a member that is another group's name is refused: "group 'eu' is a
    selector, so its members must be outbounds, not groups ('asia' is a
    group)";
  - `default` must name a member by its `stats_key`.
- A `select` group referenced inside a `Pool` hop alongside anything else is
  refused: "selector group 'eu' must be the only entry of its hop".
- `mode` on a `round_robin` group keeps today's behaviour exactly. Every
  existing test passes unchanged.

### A2. Shared selection state

**New module `src/group_selection.rs`**, in both module trees:

```rust
pub enum GroupKind { RoundRobin, Select, UrlTest(UrlTestOptions) }
pub struct GroupSelection {
    name: Arc<str>,
    kind: GroupKind,
    members: Box<[Arc<str>]>,   // stats_keys, in pool order
    default_index: usize,
    selected: AtomicUsize,
}
pub fn install(groups: Vec<GroupSelection>);   // replaces the registry
pub fn get(name: &str) -> Option<Arc<GroupSelection>>;
pub fn select(name: &str, member: &str) -> Result<(), SelectError>;
pub fn reset(name: &str) -> Result<(), SelectError>; // back to default
pub fn snapshot() -> Vec<(Arc<str>, GroupKind, Vec<Arc<str>>, usize /*selected*/)>;
```

**Selections survive a reload.** `install` keeps the selection for a group
whose name survives and whose selected member is still present. Otherwise it
falls back to `default` and logs a warning naming the group.

### A3. Carry the group to the pool

1. `expand_chain_hop` records the group name when it expands
   `Single(GroupName)` for a `select` group, as a new internal hop variant or a
   side field. It is never deserialized or serialized.
2. `chain_builder` resolves that name through `group_selection::get` and puts
   the `Arc<GroupSelection>` on the built hop.
3. When it builds a pool hop from a group, it asserts that the pool's member
   keys equal `GroupSelection.members` in order. Both come from the same
   flattened list, so a mismatch is a bug and panics in debug builds.
4. `select_from_pool`, `select_terminal` and `select_subsequent` use
   `selection.selected` when a hop carries one, and the round-robin atomic
   otherwise.

**Install order.** `launch_servers` (`main.rs:1057`) installs the selections
before `start_servers`, next to `install_groups`, so chains are built against
the new registry.

**Tests:**
- Two listeners whose rules name the same `select` group. Select member 2.
  New connections through both listeners exit via member 2.
- A connection opened before the switch keeps its exit (sing-box
  `interrupt_exist_connections: false`).
- A UDP session opened before the switch keeps its exit.
- **Prove it fails:** remove the hop's selection read and confirm the first
  test fails.

### A4. Controller

| Route | Behaviour | Status |
| --- | --- | --- |
| `PUT /proxies/{name}` `{"name":m}` | Select `m` | `204`; `400 {"message":"Must be a Selector"}` if not a select group; `400 {"message":"Selector update error: not found"}` if `m` is not a member; `404` for an unknown name |
| `DELETE /proxies/{name}` | Back to `default` | `204`; same errors |
| `GET /proxies`, `/proxies/{name}`, `/group…` | Select groups render `type: "Selector"`, `now`, `all` | — |

Also:
- Round-robin groups keep `LoadBalance`.
- Fix the `direct` collision: the built-in `direct` group is not rendered,
  because the leaf is what dashboards expect under that name.
- `GLOBAL` stays as it is until PR B. `PUT` on it stays `405`.

**Tests:**
- A wire test with awg-manager's exact request, `PUT /proxies/sel%201` with
  `Content-Type: application/json` and body `{"name":"member-2"}`, answers
  `204`. A following `GET /proxies/sel%201` shows `now: "member-2"`.
- The `direct` collision has a test that fails before the fix.

### A5. `state_file`

- **File format:** `{"selections":{"eu":"eu-2"},"mode":"rule"}`, where `mode`
  is written from PR B on.
- **Writes:** after every successful `PUT`/`DELETE`, written atomically
  (temporary file, `fsync`, rename), the way `AppliedState::save` does in the
  daemon.
- **Reads:** at launch and after every reload, applied after `install` and
  before servers start. Entries naming an unknown group or member are dropped,
  with a warning naming them.
- **Failures:** a write that fails logs at `warn` and the selection still
  applies. A missing file is not an error; an unparsable one is logged and
  ignored.
- **Reload:** the `reconcile_api` keep condition (`main.rs:844-847`) now
  includes `state_file`. Today a kept controller would keep using the old path.

**Tests:**
- Select, restart the process (the `tests/` process harness), and assert `now`
  is restored.
- A file naming a vanished member restores `default` and warns.
- Pointing `state_file` at an unwritable directory keeps the selection working.

### A6. Docs

- `CONFIG.md`: `mode`, `default`, and `state_file` (no longer "parsed, not yet
  used").
- `examples/clash_api_selector.yaml`, cert-free, added to the smoke loop.
- The spec's endpoint table and slice 2 text.

## PR B — modes (slice 2b)

- **Mode state.** `PATCH /configs {"mode":"rule"|"global"|"direct"}` sets a
  process-wide `AtomicU8` in `group_selection`. It is persisted to `state_file`.
  The value is case-insensitive, as mihomo is.
- **Errors.** An unknown mode is `400 {"message":"Body invalid"}`. Other
  `PATCH` fields stay ignored, as today.
- **Routing.**
  - The mode is applied in `ClientProxySelector` after `judge` returns `Allow`,
    so the routing cache is never involved.
  - `Block` stays `Block` in every mode, since blocks are policy.
  - `direct` routes through a per-selector `build_direct_chain_group(resolver)`
    built at selector construction. It is one chain and cheap.
  - `global` routes through a per-selector
    `tokio::sync::OnceCell<ClientChainGroup>`. It is built on first use from a
    pool of every leaf, with the `GLOBAL` selection attached. The `OnceCell` is
    what lets `ConnectDecision<'a>` keep borrowing.
- **`GLOBAL`** becomes a real `select` entry in `group_selection` over every
  leaf. `PUT /proxies/GLOBAL` works, and its default is the first leaf in
  config order (sing-box).
- **Registry.** A connection routed by mode reports `rule: "Global"` or
  `rule: "Direct"` and no rule index.
- **`/configs`** reports the live mode.

**Tests:**
- Each mode routes a fresh connection as described.
- A rule-matched Block stays blocked in `global`.
- A cached-decision path (more than 16 rules) obeys a mode switch. **Prove it
  fails** by applying the mode before the cache, and confirm the test goes red.
- With `mode: global` never set, the `OnceCell` is never initialised.

## PR C — delay tests (slice 3a)

### C1. What the controller can reach

At launch, validation returns `leaves: HashMap<stats_key, ClientConfig>`
covering:
- every leaf from groups, PEM-embedded (`validate.rs:223-227`);
- every inline leaf from rules.

Validation already walks both to fill `OutboundSet`. `launch_servers` installs
the map, plus the default resolver (`dns_registry.get_for_server(None)`), into
`group_selection`. A leaf used only as hop 1 or later of a multi-hop chain is
still tested on its own: its chain is built as a single hop.

### C2. The URL test

`src/url_test.rs` follows sing-box `urlTest`:

1. Parse the URL. Only `https://` is fetched; `http://` and an empty URL are
   replaced by `https://www.gstatic.com/generate_204`.
2. Build the leaf's chain with `build_client_proxy_chain` and connect to
   `host:port` (default 443).
3. **Timing.** The clock starts before connecting. For a chain whose handshake
   is deferred until the first write, it restarts after the connect returns.
   sing-box does the same (`N.NeedHandshakeForWrite`).
4. **The request.** A TLS handshake with `tokio-rustls` over the stream,
   `webpki-roots` trust, and SNI set to the host. Then
   `HEAD <path> HTTP/1.1\r\nHost: <host>\r\nConnection: close\r\nUser-Agent: shoes\r\n\r\n`,
   hand-written.
5. **The result.** Read until the end of the status line. Any `HTTP/1.x <code>`
   is success: sing-box does not check the status and does not follow
   redirects. The delay is the elapsed time in ms, saturating at `u16::MAX`.
6. **No counting.** Test traffic is not counted against the leaf. The chain is
   built without `OutboundCountingStream`, or with a flag that skips it.
   Otherwise every urltest interval adds phantom bytes to every member.

### C3. Routes

| Route | Behaviour |
| --- | --- |
| `GET /proxies/{name}/delay?url=&timeout=` | `timeout` (ms, 1–32767) is required, else `400 {"message":"Body invalid"}`. Success: `{"delay":ms}`. Deadline hit: `504 {"message":"Timeout"}`. Any other failure: `503 {"message":"An error occurred in the delay test"}`. For a group, tests its current member (sing-box `RealTag`). Unknown name: `404` |
| `GET /group/{name}/delay?url=&timeout=` | Tests every member concurrently. Answers `{"member": ms, …}`, with failures omitted (mihomo) |

- **History.** A success appends `{time, delay}` to the leaf's history: ten
  entries, newest last, kept in `group_selection` by `stats_key` and kept
  across reloads for leaves that survive. A failure appends `delay: 0`, which is
  what mihomo shows as a failed test.
- **`alive`** is the outcome of the last test, or `true` if never tested (the
  spec's pessimistic-lie rule).
- These arms go before the catch-all `405` arm (`mod.rs:565-566`).
- After any test, urltest groups containing the leaf re-evaluate (PR D; sing-box
  calls `PerformUpdateCheck`).

**Tests** run against an in-process TLS echo server that answers `HEAD` with
`204`, using the repository's test certificate helper. The test passes a root
store containing that certificate through a test-only seam, since production
uses `webpki-roots`. The URL host is loopback.
- A direct leaf gives `200` with `delay > 0`.
- A leaf pointing at a closed port gives `503`.
- A server that accepts and never answers, with `timeout=200`, gives `504`
  within 1 s.
- Missing `timeout` gives `400`.
- An `http://` URL is fetched as the default HTTPS URL; asserted with a
  test-only default override.
- `history` and `alive` render after each outcome.
- Bytes for the tested leaf are unchanged in `/proxies` after a test.

## PR D — urltest groups (slice 3b)

**Config:**

```yaml
client_group: auto
mode: urltest
url: https://www.gstatic.com/generate_204   # default
interval: 3m                                # default; humantime, minimum 10s
tolerance: 50                               # ms, default
idle_timeout: 30m                           # default
client_proxies: [eu-1, eu-2, us-1]
```

Validation is the same as for `select`: members are leaves and the group is
alone in its hop. `interval` below 10 s is refused.

**Runtime.**
- One background task per urltest group per *process*, owned by
  `group_selection`, not per selector. It is restarted on reload with the new
  options, and a group that survives a reload keeps its history.
- Each tick runs the URL test on every member, at most 8 concurrently, each
  with `timeout = min(interval, 15s)`. sing-box uses `TCPTimeout` (15 s) as the
  per-test cap.
- **Selection** is sing-box `Select`, read in `protocol/group/urltest.go`:
  start from the current member's last delay, and switch to another member only
  if `current > other + tolerance`. With no history, use the first member.
- Selection is stored in the group's `selected`, so chains pick it up exactly as
  in PR A.
- **Idle.** Every connection through the group stores a timestamp. A tick finds
  the group idle when the last use is older than `idle_timeout`, and skips
  testing.
- **Waking up.** The first connection after an idle period triggers an
  immediate test in the background. That connection uses the current selection
  (sing-box `Touch`).
- **Controller.** The group renders `type: "URLTest"` and `now`. `PUT` gets
  `400 Must be a Selector`.

**Tests:**
- Three loopback TLS servers that answer `HEAD` after 10, 80 and 200 ms. After
  the first tick the group selects the 10 ms member.
- Raise that member's delay to 55 ms: the group stays, since the 45 ms gap is
  within the 50 ms tolerance.
- Raise it to 300 ms: the group switches.
- An idle group performs no tests. Assert with a counter on the test servers.
- A reload keeps history and the selection.
- **Prove it fails:** drop the tolerance comparison and confirm the hysteresis
  test fails.

**Docs:** `CONFIG.md` (`mode: urltest` and its options) and
`examples/clash_api_urltest.yaml` in the smoke loop.

## Order and size

| PR | Size | Unblocks |
| --- | --- | --- |
| A | Medium: config, validation, chain read, controller, state file | awg-manager selectors, dashboards' proxy picker |
| B | Small–medium | dashboards' mode switch |
| C | Medium: TLS-over-chain client, history | awg-manager latency matrix, dashboards' test buttons |
| D | Medium: background task, hysteresis | awg-manager subscriptions in `urltest` mode |

A and C are independent of each other. B depends on A, and D on A and C.

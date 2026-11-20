# What this fork carries

The fork is upstream [XTLS/Xray-core](https://github.com/XTLS/Xray-core) **v26.11.9** (`676eaf6`) plus the four changes
below (branch `raycontrol/v26.11.9`; the first three were written on v26.10.31, branch `raycontrol/v26.10.31`, and
moved onto v26.11.9 without a conflict), for the exits of raycontrol (`inner` and REALITY). Each is written to be
rebased: new files where it could be, and in upstream's files only the narrow hooks listed here. A hook is marked
`// fork:` in the code.

After a rebase, run what "Tests" names for each change.

## 1. VLESS inbound: `RemoveUser` closes the user's live connections

Why: removing a user through `HandlerService` only took its UUID out of the validator; its open connections, mux and
XUDP sessions went on. raycontrol removes a user (or a rotated credential) and needs it gone at once.

- New: `proxy/vless/inbound/userconns.go` (the connections of each user).
- Hooks in `proxy/vless/inbound/inbound.go`: the `usersMu` and `conns` fields of `Handler`; `AddUser` and `RemoveUser`
  serialized, `RemoveUser` closing the user's connections; in `Process`, after the request header is decoded, the
  connection is tracked under its user (the raw transport connection from before the decryption handshake) and the
  user looked up again.
- Tests: `proxy/vless/inbound/userconns_test.go`, `userconns_transport_test.go`,
  `testing/scenarios/vless_remove_user_test.go`.

## 2. Per-user limits on new connections (`policy.levels.N.limits`)

Why: every connection a user opens through the node is a conntrack entry, and one user could fill the node's table
(raycontrol `docs/spec/conn-limit-v1.md`, §2 and §3.3; the same model as raycontrol's naive and niko-server). Without
`limits` in the policy nothing below applies, but for the one line marked **always**.

### The limits

By the *base name* of the user's email (`foldAt: "-"`: `u5-0123456789abcdef` is `u5`, so a user's credentials share one
set), per policy level, in one registry per process:

| JSON (`policy.levels.N.limits`) | Limit | Refusal counted as |
|---|---|---|
| `connections` | TCP connections at once, dials in flight included | `tcp` |
| `rate`, `burst` | TCP dials: a token each, retries too; a new connection waits for its token 0.5 s at most | `rate` |
| `failedRate`, `failedBurst` | failed dials (timeout, ECONNREFUSED, EHOSTUNREACH), paid after the failure into debt; in debt new connections are refused | `failed` |
| `udpSessions` | UDP sessions at once (XUDP included); a new one past it takes the place of the quietest, silent 10 s both ways | `udp` (none quiet), `evicted` |
| `udpRate`, `udpBurst` | new UDP destinations | `dest` |
| `udpLive` | UDP pairs (socket, destination) for as long as conntrack keeps them: 30 s after the last packet sent while unanswered, 120 s after the last packet either way once answered, in a live session and after it; and the process's ceiling, a quarter of `nf_conntrack_max`, which refuses only the users above their fair share | `live` |
| `lookupRate`, `lookupBurst` | lookups of names in UDP packets | `lookup` |
| `foldAt`, `foldSuffixes` | how an email becomes the base name: cut at the first `foldAt`; an ending in `foldSuffixes` cut off | |

A number left out or zero turns its limit off. With every number zero (`"limits": {}`) the level has no limiter, and a
network none of whose limits is on takes upstream's path: with only UDP limits, TCP's dial loop is upstream's (five
dials whatever the error), and the other way round. A user without an email has no limits (nothing to key them by),
nor has a connection without a user.

Refusals are counted in the stats app, each counter made at its first refusal: `user>>>BASENAME>>>limit>>>KIND`
(`user>>>u5>>>limit>>>tcp`), read like the traffic counters: `StatsService.QueryStats{pattern: "user>>>"}`. They need
`"stats": {}`; nothing else turns them on.

At a limit: a TCP connection is closed with no data (a VLESS connection: closed; a mux subconnection: End with the
error bit, the mux lives on), exactly as when its dial fails; a UDP packet is dropped; a UDP session refused is closed
the same way, and one that gives way ends as when its idle timer runs out. The log says nothing at warning; at debug the
dispatcher logs `too many connections`, at info the outbound handler logs the same as the error of the connection,
neither with a user or a destination beyond what those levels log anyway. (At debug `app/stats` logs the name of every
counter it creates, these too.)

### Files

New:

- `common/connlimit/` — the limits: no Xray types but `session.Inbound` in `context.go`. `connlimit_test.go`,
  `udp_test.go`: on a fake clock.
- `app/policy/limits.go` — the registry and the limiter of each level with `limits`; ties the counters to the stats.
- `infra/conf/policy_limits.go` — the JSON.
- `app/dispatcher/connlimit.go` — `admit`: the token before routing.
- `proxy/freedom/limit.go` — the place, the dial loop, the UDP socket's accounting.

Hooks in upstream's files:

- `app/policy/config.proto`: message `Policy.Limits` and field `limits = 4`; `config.pb.go` is generated
  (`go run ./infra/vprotogen/main.go -pwd .`).
- `app/policy/manager.go`: the `limits` field of `Instance`, set in `New`.
- `infra/conf/policy.go`: the `Limits` field of `Policy`, one line in `Build`.
- `app/dispatcher/default.go`, `routedDispatch`: `d.admit` before the route is picked. The token is taken here
  because routing may resolve the destination's name (`IPOnDemand`): a connection refused asks the resolver nothing.
- `proxy/freedom/freedom.go`:
  - `Process`: `h.limit` takes the place before the dial loop, `defer lease.done()`;
  - the dial loop runs on `lease.retry(retry.ExponentialBackoff(5, 100))`: with limits, each dial after the first
    takes a token, ECONNREFUSED, ENETUNREACH and EPERM are not dialed again, and the pause ends with the context;
  - `lease.done()` before each of the two `h.blackhole` calls: a blackholed connection holds no place for its 30 to
    90 s;
  - `lease.evictable(timer)` after the idle timer is made;
  - `PacketWriter.WriteMultiBuffer`: `w.limitLookup()` before a name is looked up;
  - **always**, limits or not: in `PacketWriter.WriteMultiBuffer`, EPERM from the socket drops the packet instead of
    ending the session. The node's conntrack guard and egress policy reject a packet with an ICMP error the socket
    sees as EPERM; upstream ended the whole UDP session on it. The drop is logged at debug, once a session, without
    the destination (the `epermLogged` field of `PacketWriter`).

  The UDP pairs need no hook: `limit.go` puts its own `net.PacketConn` inside the `PacketConnWrapper` the dialer
  returns, and `PacketWriter` and `PacketReader` send and receive through it.

Not limited, or not exactly: an outbound other than freedom takes the token in the dispatcher but holds no place; a
dial that races several addresses (`happyEyeballs`) pays one token; a freedom reached through another outbound's
`dialerProxy` is counted as a connection of its own, and a UDP session of a freedom that itself has a `dialerProxy`
holds its place but its pairs are not seen (it never gives way either). raycontrol's configs have none of these.

### Tests

`go test -race ./common/connlimit/ ./app/policy/ ./app/dispatcher/ ./infra/conf/ ./proxy/freedom/`

- `common/connlimit`: every limit on a fake clock.
- `app/policy`, `infra/conf`, `app/dispatcher`: the limiter of a level and its counters, the JSON, `admit`.
- `proxy/freedom/limit_test.go`, `eperm_test.go`: `Process` with a dialer and a clock of the test's.
- `proxy/freedom/limit_inbound_test.go`: a whole Xray in the test's process, a VLESS inbound to freedom, the client
  spoken by the test (VLESS, mux, XUDP) or, once, an Xray client over REALITY and Vision: what a client sees at each
  limit, the counters through `StatsService`, the log, and that nothing changes without `limits`. One test waits the
  10 s a UDP session must be quiet to give way (`-short` skips it).

## 3. A unix socket left by a killed process does not block the next one

Upstream takes a file lock (`<address>.lock`) before it listens on a unix socket in the file system, but does not
remove a socket file that is already there. A process that was killed (SIGKILL, or SIGTERM before its handlers were
set) leaves the file, and every start after it fails with `bind: address already in use` until someone removes it by
hand: raycontrol saw `inner` and REALITY loop on their API socket after quick restarts in a row.

- Hook in `transport/internet/system_listener.go`, `DefaultListener.Listen`: once the lock is held, a path that is a
  socket is removed before the bind. The lock means no process that takes it listens there. Anything that is not a
  socket is left alone, and the bind fails as before.
- Tests: `transport/internet/system_listener_stale_test.go` (`go test ./transport/internet/ -run TestListen`).

## 4. REALITY: no server_name ack of its own

REALITY borrows the handshake of its target and pads each of its own handshake records to the length of the
target's (`third_party/reality/conn.go`, "mimic recorded handshakeLen"); a record of its own longer than the
target's fails the handshake. The `github.com/xtls/reality` that upstream's v26.11.9 requires (`4bb46b2`) acks the
client's server_name in its EncryptedExtensions, 4 bytes, whatever the target does. A target that acks no name and
picks no ALPN (`openssl s_server` by default) has shorter EncryptedExtensions, and every REALITY handshake to it
failed with `payload[0]: 8, padding: -4`; upstream's Xray at `676eaf6` fails the same way. A client does not need
the ack (RFC 6066 leaves it to the server; Go's and uTLS's clients never ask for it). Without it REALITY's EncryptedExtensions are empty:
never longer than the target's, and padded to the target's length as before, so they look the same on the wire.

- `third_party/reality/`: the module at the version upstream's `go.mod` requires, file for file but for the hook,
  built through a `replace` in `go.mod` (`third_party/README.md`). `infra/vformat/main.go` skips `third_party`, which
  keeps its module's formatting.
- Hook in `third_party/reality/handshake_server_tls13.go`, `sendServerParameters`: the three lines that set
  `encryptedExtensions.serverNameAck` are gone.
- Tests: `transport/internet/reality/target_test.go` (`go test ./transport/internet/reality/ -run
  TestTargetExtensions`): targets of Go's that ack the name, pick ALPN, or do neither; the last fails without the
  change.
- A new upstream version that requires another `github.com/xtls/reality`: copy that version over the old one
  (`go mod download -json github.com/xtls/reality@VERSION` names its directory), put the hook back, and update the
  table in `third_party/README.md`. If that REALITY no longer acks a name the target did not, drop the copy and
  the `replace`.

Upstream's own tests in `proxy/blackhole`, `app/proxyman/outbound` and `core` fail under `-race` with races in the
tests themselves (as at v26.10.31 and v26.11.9, without the fork's changes in those files); they pass without it.

## Who pins it

raycontrol builds its Xray from this fork by commit (`XRAY_COMMIT` in raycontrol's `deploy/versions.env`). A
release is rebuilt from its pin, so the branches that hold the pins are never rewritten or deleted:

| raycontrol | Commit | Branch |
|---|---|---|
| v0.2.0 … v0.20.x | `a4a3dff`: upstream v26.10.31, without changes | upstream's history |
| v0.21.0 … v0.24.x | `88b1d7b` (tag `v26.10.31-raycontrol.1`) | `raycontrol/v26.10.31` |
| v0.25.0 | `5648b7a` | `raycontrol/v26.10.31` |
| v0.25.1 | `15f4069` | `raycontrol/v26.11.9` |
| v0.26.0 … v0.34.x | `46b58d4` | `raycontrol/v26.11.9` |
| v0.35.0 on | `fd9d28f` | `raycontrol/v26.11.9` |

The interop tests of niko-server and Niko run upstream's Xray (`676eaf6`, `a4a3dff`), not the fork's.
`claude/clever-feynman-w0e2v1` is the old working line; every pin is on the two `raycontrol/*` branches as well.

## Working on it

- The newest `raycontrol/<version>` is the fork's default branch. A change goes there by a pull request from a branch
  of its own, with a test that fails without it and its section in this file.
- A new upstream version is a new branch: upstream's tag with the fork's commits rebased onto it, as v26.10.31 became
  v26.11.9 (`git switch -c raycontrol/v26.11.9 raycontrol/v26.10.31 && git rebase --onto v26.11.9 v26.10.31`). The
  tests named in each section pass on it. Then raycontrol moves `XRAY_COMMIT`, the default branch moves to the new
  branch, and the old branch stays.
- Checks (`.github/workflows/checks.yml`): "Commit messages" (no bare `#N`; in a fork GitHub links a bare `#N` to
  upstream's issues, so write `arngory/Xray-core#N`) and "Secrets" (gitleaks, rules in `.gitleaks.toml`). Both take
  only the pull request's own line, not upstream's commits. Upstream's workflows (`test.yml` and the rest) run as
  upstream has them.
- Upstream's tests (`test.yml`, on Linux, macOS and Windows) need `geoip.dat` and `geosite.dat` from the Actions
  cache that "Scheduled assets update" fills from XTLS/Xray-rules-dat. GitHub runs no schedule in a fork until it is
  turned on, and drops a cache nobody used for 7 days: when the tests miss the files, run that workflow by hand on
  the default branch (Actions → Scheduled assets update → Run workflow), or turn its schedule on.
- The fork's own tests run on all three: Vision's splice is Linux's (and Android's), so only there do they look for it.
- A pull request that changes the checks themselves is merged by the owner.
- The rules shared with raycontrol, niko-server and Niko: raycontrol's
  [CONTRIBUTING.md](https://github.com/arngory/raycontrol/blob/main/CONTRIBUTING.md).

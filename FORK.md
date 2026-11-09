# What this fork carries

The fork is upstream [XTLS/Xray-core](https://github.com/XTLS/Xray-core) **v26.10.31** (`a4a3dff`) plus the two changes
below, for the exits of raycontrol (`inner` and REALITY). Each is written to be rebased: new files where it could be, and
in upstream's files only the narrow hooks listed here. A hook is marked `// fork:` in the code.

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
    sees as EPERM; upstream ended the whole UDP session on it.

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

Upstream's own tests in `proxy/blackhole`, `app/proxyman/outbound` and `core` fail under `-race` with races in the
tests themselves (as at v26.10.31, without the fork's changes in those files); they pass without it.

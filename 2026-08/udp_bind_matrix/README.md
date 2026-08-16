# UDP bind / REUSE / connect matrix — macOS vs Linux

Observations distilled from the existing captures:

- `results/udp_bind_matrix-macos.txt` — darwin, port 58086, targets `127.0.0.1` + `192.168.64.4`
- `results/udp_bind_matrix-linux.txt` — linux, port 44932, targets `127.0.0.1` + `172.17.0.1` (docker bridge)
- harness: `udp_bind_matrix.py`

## Method (what a row means)

Two UDP sockets are bound one after another to the **same port** with every combination of:

- bind address: `127.0.0.1` (specific) vs `0.0.0.0` (wildcard), both orders
- reuse option: `none` | `addr` (SO_REUSEADDR) | `port` (SO_REUSEPORT) | `both`

When both bind, 26 senders (A–Z, each on a distinct ephemeral source port) burst datagrams at the target. The payload letter *is* the sender's source-port label, so delivery attribution needs no port bookkeeping. Column `b2/err` = `Y` (second bind OK) or `EADDRINUSE`. Two connect policies:

- `none` — pure address/reuse rules pick a single receiving socket
- `auto` — nc-faithful: after the FIRST datagram, that socket `connect()`s to the sender's source; every fresh-source packet then "escapes" to the sibling socket

All rows here are `src=many`. (`single`/`dual` topologies exist in the script but were not captured; `--connect auto` is a no-op for `src=single`.)

## 1. Bind rules (can the second socket bind at all?)

Same-address co-bind (e.g. 127.0.0.1 + 127.0.0.1) — `N` = EADDRINUSE, `Y` = bound:

| reuse1 \ reuse2 (Linux) | none | addr | port | both |
|---|---|---|---|---|
| none | N | N | N | N |
| addr | N | **Y** | N | **Y** |
| port | N | N | **Y** | **Y** |
| both | N | **Y** | **Y** | **Y** |

| reuse1 \ reuse2 (macOS) | none | addr | port | both |
|---|---|---|---|---|
| none | N | N | N | N |
| addr | N | N | N | N |
| port | N | N | **Y** | **Y** |
| both | N | N | **Y** | **Y** |

- **Linux:** co-bind works only when both sockets share SO_REUSEADDR *or* both share SO_REUSEPORT. The options never mix: `addr,port` and `port,addr` fail even though each socket has one.
- **macOS:** same-address co-bind requires **SO_REUSEPORT on both**; SO_REUSEADDR alone (even on both) is *not* sufficient — the classic BSD difference.

Mixed wildcard/specific (127.0.0.1 + 0.0.0.0, either order):

| reuse1 \ reuse2 (Linux) | none | addr | port | both |
|---|---|---|---|---|
| none | N | N | N | N |
| addr | N | **Y** | N | **Y** |
| port | N | N | **Y** | **Y** |
| both | N | **Y** | **Y** | **Y** |

| reuse1 \ reuse2 (macOS) | none | addr | port | both |
|---|---|---|---|---|
| none | N | **Y** | **Y** | **Y** |
| addr | N | **Y** | **Y** | **Y** |
| port | N | **Y** | **Y** | **Y** |
| both | N | **Y** | **Y** | **Y** |

- **Linux:** same "share REUSEADDR or share REUSEPORT" rule as identical addresses; REUSEPORT on one side never helps.
- **macOS:** the second (new) bind succeeds only when *it* has SO_REUSEADDR or SO_REUSEPORT; the first socket's options are irrelevant. Wildcard-over-specific and specific-over-wildcard both behave this way.

## 2. Delivery when both sockets are bound and both can hear

- **Mixed specific+wildcard → loopback:** on BOTH OSes the specific `127.0.0.1` socket receives all 26 packets; the wildcard socket starves (e.g. `127.0.0.1 addr 0.0.0.0 addr → A+→1=26`, reverse → `A+→2=26`). Options irrelevant.
- **Same-address + REUSEPORT — the big OS divergence:**
  - Linux: packets are **split across both sockets** by kernel 4-tuple hash — e.g. 127.0.0.1×2 → 10/16, 13/13, 16/10; 0.0.0.0×2 → 12/14, 13/13, 14/12. Roughly balanced, varies per run; receipt order interleaves (A→1, B→2, E→1, C→2, …) since each distinct source port (the only varying 4-tuple component) hashes to a fixed socket.
  - Linux `addr`/`addr` (SO_REUSEADDR only): **no distribution** either — all 26 go to one socket (`A+→2=26`); only the REUSEPORT group gets hashing.
  - macOS: **no distribution** — one socket takes all 26. For 127.0.0.1×2 the *last-bound* socket wins; for 0.0.0.0×2 the *first-bound* wins.
- **Non-loopback target** (192.168.64.4 / 172.17.0.1): only `0.0.0.0`-bound sockets can hear it; 127.0.0.1-only pairs are skipped ("no listener hears this target"). Mixed binds → wildcard gets everything; same-address REUSEPORT → Linux splits (10/16 … 11/15), macOS again single-socket.

## 3. `--connect auto` (nc-faithful discover-then-connect)

Identical on both OSes — the headline result:

- The receiver of the **first** datagram `connect()`s to that sender's source; the connected socket then accepts ONLY that source, so every other (fresh-source) packet escapes to the sibling socket → deterministic **1 + 25** split (`A+→s1=1, B+→s2=25 …`; `[auto-connected: N]` = pinned socket).
- Which socket wins the first datagram is emergent (address rules/hash): both `[auto-connected: 1]` and `[auto-connected: 2]` appear across configs; the 1/25 split itself is universal, even on macOS, where plain REUSEPORT does no distribution.
- When only ONE socket can hear the target (non-loopback mixed binds), escaped packets land on the deaf `127.0.0.1` socket and are dropped: **only 1 datagram is received** (`A→2` alone). This is the nc / DNS-retry double-socket behavior: the connected socket filters by peer, the sibling silently can't hear the rest.

## Harness notes / caveats

- Fresh ephemeral port per run (printed in header); 30 ms settle between scenarios; 800 ms receipt deadline + 150 ms quiet-drain; select() poll granularity 20 ms; first 40 receipts shown in `order`.
- A UDP datagram is always delivered to exactly one socket; payload = sender letter, so counts are content-attributed.
- Targets: loopback always, plus the first detected non-loopback IPv4 (macOS 192.168.64.4, Linux 172.17.0.1); explicitly-assigned addresses only, 0.0.0.0 filtered.
- With no reuse option the second bind always fails (`EADDRINUSE`) — rows marked "skip: second not bound" mean s1 held the port and s2 could not share it.

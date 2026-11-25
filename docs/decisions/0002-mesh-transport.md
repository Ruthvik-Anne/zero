# 0002 — Datagram streams for the mesh overlay

Status: **accepted for the spike; production hardening is listed under
Consequences.** Date: 2026-11-26. Requirements: MESH-01, MESH-04, MESH-05,
MESH-07.

## Question

The mesh needs to carry Zero's own traffic — session journal chunks, telemetry,
and control messages — between peers that may sit behind NATs and may only be
reachable through an approved relay. MESH-01 forbids a TUN device, administrator
rights, and Android `VpnService`, so the overlay must live in the application.
Should it run a userspace TCP/IP stack, or keep the carrier as datagrams and add
a small reliable session-stream layer above it?

## Options

| Concern | Userspace TCP/IP stack | Datagrams + session stream |
|---|---|---|
| No TUN, admin, or VpnService | Only if every consumer uses the in-app stack; carrying IP for unmodified apps needs a TUN/`VpnService` interface, which MESH-01 forbids. | Natural: the carrier is an application UDP socket (or an overlay over one), with no packet interface at all. |
| NAT traversal (MESH-04) | TCP over the punched path needs the stack to own SYN/ACK state, keepalive, and rebinding; a symmetric-NAT fallback still needs TCP/443 or a relay. | Matches MESH-04 directly: STUN, UDP punch, TCP/443 fallback, and relay all carry the same opaque datagrams. |
| Relay-friendly (MESH-05) | A relay sees a stream of IP packets it cannot parse, with per-connection state, retransmission, and control segments. Metering and store-and-forward are opaque. | Fixed-size, self-describing frames. A relay can forward, size-check, and meter them without parsing payloads, exactly like the existing ciphertext envelope. |
| Head-of-line blocking | A lost segment blocks every later byte on that connection; multiple connections need multiple sockets. | A lost fragment blocks only its own stream's contiguous prefix. Independent streams can be muxed later without cross-stream blocking. Within one stream, ordering is still enforced. |
| Complexity | Very high: connection state machine, RTO estimation, SACK, windows, congestion control, path MTU, TIME_WAIT, attacks on each. Reimplementing TCP is a large, security-sensitive surface; adopting a stack (smoltcp, lwIP, gVisor netstack) adds a large dependency and integration surface. | Small: sequence numbers, a bounded window, acks, retransmission, a bounded reassembly buffer, and a per-fragment hash. The prototype is one module with no sockets. |
| MTU | The stack must discover and honour the path MTU, handle fragmentation (IPv4) or packet-too-big, and keep timers per path. | The mesh chooses the fragment size; the prototype defaults to 512-byte payloads, well under a typical 1500-byte path and a WireGuard tunnel. There is no IP fragmentation to reason about. |
| Retransmission | Implemented inside TCP, with mature but intricate RTO and fast-retransmit rules. | Explicit and inspectable: the sender resends an unacknowledged fragment after a fixed wait, up to a configured budget, then fails the stream. |
| Mobile battery | The system stack can be serviced while the app sleeps, but an in-app stack must be woken for every timer; the radio sees keepalives and retransmits either way. | Acks can be batched and the idle keepalive can be long; retransmit timers only wake the app while a stream is active. The mesh's existing cost policy (MESH-14) can defer work on battery or metered links. |
| Implementation risk | High: a from-scratch stack is easy to get subtly wrong, and a borrowed stack is a large new supply-chain and platform surface. | Low and testable: every rule is a pure state machine over injected bytes, exercised in memory with loss, reordering, duplication, and corruption. The risk moves to missing congestion control, which is explicit and bounded. |

## Decision

- **Use datagram streams.** The overlay stays a WireGuard-style datagram
  carrier: encrypted, unordered, and unreliable at the wire level. A small
  reliable **session-stream layer** supplies fragmentation, sequence numbers,
  acks, retransmission, a bounded window, duplicate suppression, bounded
  reassembly, and a per-fragment hash for the traffic Zero actually sends
  (session journal chunks and telemetry).
- **Keep the carrier abstract.** `zero_mesh::transport::DatagramIo` is the only
  seam: `send(peer, bytes)` and `recv() -> Option<(peer, bytes)>`. The real
  userspace overlay supplies it; tests and the prototype supply the in-memory
  `SimulatedNet`. The stream layer never sees a socket, an address family, a
  clock, or a key.
- **Do not build a TCP/IP stack.** There is no IP routing, no ARP, no
  connection handshake, no congestion-control algorithm, and no packet
  interface. If Zero later needs to carry arbitrary IP traffic for unmodified
  applications, that is a new requirement and a new decision (see below), not a
  silent extension of this layer.
- **Relays stay opaque.** A session frame is forwarded as bytes by the existing
  approved-relay and ciphertext-envelope rules; the relay sees framing metadata
  and sizes, never the payload.

## Prototypes

| Prototype | Code | Evidence |
|---|---|---|
| Fragmentation, acks, retransmission, reassembly, and a byte-identical session JSONL transfer over a lossy/reordering/duplicating carrier | `zero-mesh::transport` (`SessionStream`, `Reassembler`, `move_stream`, `SimulatedNet`) | `$env:CARGO_INCREMENTAL='0'; cargo test -p zero-mesh -j 1 transport::` — 16 tests; the Done criterion is `a_session_jsonl_stream_moves_byte_identically` |
| Loss repairs by retransmission | `SessionStream::poll` / `on_ack` | `loss_is_repaired_by_retransmission` — the moved bytes are identical and `retransmits > 0` |
| Reordering is buffered, duplicates are suppressed, corruption is rejected | `Reassembler` / `decode_frame` | `reordered_fragments_are_buffered_and_ordered`, `duplicate_fragments_are_suppressed`, `a_corrupt_datagram_fails_the_stream` |
| Bounds and failure modes | `StreamConfig`, `Reassembler`, `move_stream` | `oversized_streams_fragments_and_configs_are_rejected`, `the_reassembly_buffer_is_bounded`, `the_send_window_is_bounded`, `a_stalled_stream_times_out` |
| No socket in the module | `src/transport.rs` | `the_module_opens_no_socket_and_reads_no_clock` scans the source |

The prototype runs both endpoints in one call, so `move_stream` can prove
byte-identical reassembly without a network. The same `SessionStream` and
`Reassembler` are intended to run on the two hosts once the overlay carrier
exists.

## Consequences

- The mesh now owns retransmission and reassembly. The prototype is fixed-window
  and has **no congestion control, pacing, or RTT estimation**; before production
  it needs at least a byte budget in flight, backoff on repeated loss, and a
  response to sustained loss on a metered or battery-powered link.
- One session stream is ordered, so a lost fragment still blocks later bytes of
  that stream until it is repaired (head-of-line blocking inside the stream).
  The benefit is that independent streams can be multiplexed later without one
  stream's loss blocking another; the prototype does not yet multiplex.
- Corrupt datagrams fail the stream in the prototype instead of being dropped
  and awaited again. A production receiver must verify, drop, count, and let
  retransmission repair the frame; an unauthenticated datagram must never be
  able to end a healthy stream.
- Fragment size is a mesh choice, not a discovered path MTU. The 512-byte default
  is conservative; a larger value must stay under the overlay and outer path
  budgets, including any WireGuard and relay encapsulation.
- The layer carries no cryptography. Confidentiality and authentication come
  from the userspace overlay (the WireGuard-style carrier) before a frame
  reaches `DatagramIo`; a relay still forwards only ciphertext. Transport
  encryption and key agreement therefore remain a prerequisite of the real
  overlay, not of this prototype.
- The wire format is versioned (`PROTOCOL_VERSION`) and fixed for the spike. A
  future format change needs a version bump and a negotiation rule; there is no
  negotiation today.
- A stalled or oversized stream is a typed `StreamError` (`Corrupt`,
  `Oversized`, `Timeout`, `Invalid`, `Io`). It is not a `ZeroError`; callers map
  it to their own surface. Nothing is written to the destination unless the
  whole reassembled stream matches the source byte for byte.
- The ACK and fragment counters are diagnostics, not a billing or audit record.
  MESH-15 audit remains later work.

## What would change it

- **Carrying arbitrary IP traffic for unmodified applications.** Then a
  userspace TCP/IP stack is required, and it needs a packet interface — TUN,
  `VpnService`, or a platform equivalent. MESH-01 would have to change first.
- **Measured RTT, loss, and fairness that a fixed window cannot serve.** Adopt
  an existing transport (for example a QUIC-style multiplexed transport over the
  same datagram carrier) instead of growing this layer into a congestion-control
  implementation.
- **Many concurrent latency-sensitive streams**, where per-stream ordering is
  the bottleneck. Add stream multiplexing with independent windows and resets,
  or move to a transport that already provides it.
- **A platform that exposes a sanctioned userspace packet API with no admin
  rights and no VPN slot.** That would remove the strongest constraint against
  the userspace-stack option and justify revisiting the comparison.
- **A failure of the session layer under real paths** (NAT rebinding, long
  outages, middlebox reordering) that the in-memory harness cannot reproduce.
  That would push the work toward a proven transport rather than an expanded
  prototype.

## Links

- Overview and test evidence: [docs/mesh.md](../mesh.md#transport-t-mesh-07).
- Prior decision format: [0001 — Sandbox prototype](0001-sandbox.md).
- Requirements: MESH-01 (app-level overlay, no TUN/admin/`VpnService`), MESH-04
  (STUN, UDP punch, TCP/443 fallback), MESH-05 (ciphertext-only relay), MESH-07
  (easy defaults and join).

# AddrPort UDP transport: allocations, control and DNSSEC

The adapter uses ReadMsgUDPAddrPort/WriteMsgUDPAddrPort, keeping the actual UDPAddr,
its IP bytes, receive scratch and outgoing packet-info in one request-owned object.
Handlers still see *net.UDPAddr for ACLs, split zones and UDP truncation. No pooling,
queue, batching or scheduling change is added. TSIG uses library verification/signing.

## Native Linux IPv4 microbenchmark

The microbenchmark performs a sequential full UDP echo exchange (client and server
syscalls, no DNS parsing), one outstanding datagram, both variants with packet-info
enabled. Three repetitions on dev. Library: 488 B/op, 12 allocations, median
24.996 us/op. Final owned-buffer adapter: 320 B/op, one allocation, median
23.212 us/op. Allocation counts are the strong result; wall time is affected by
VPS scheduling. This is NOT one allocation for an entire DNS request and NOT
proof of a network p95 target. The earlier two-allocation variant and its source
snapshot are preserved separately; it was not used for the network control.

## Network control

15 native Linux amd64 trials on dev, two resolver CPUs/workers, one client CPU,
sleep pacing, warm UDP forward cache at 15k offered QPS. Five eight-second repeats
per implementation, rotating order, 600k requests each. Baseline 67cfc62; its binary
hash was verified against the reused remote baseline before testing.

Median p95: BIND 9.598907 ms, baseline 12.726550 ms, candidate 10.083080 ms.
Losses: 4,668 / 1,196 / 253. Median goodput: 14,911.63 / 14,994.86 / 14,998.52 QPS.
Candidate p95 is 20.77% below baseline but 5.04% ABOVE BIND. Losses are 78.85%
below baseline and 94.58% below BIND. All acceptance checks except the 20% BIND
p95 advantage pass; overall acceptance is false. Raw data preserve every trial.

## DNSSEC

Each set contains 18 loopback trials, three five-second repeats per implementation
and scenario: validated cache 5k QPS, mixed 10% new names 5k, all new names 500.
Every successful response requires AD and the expected A address. Every trial also
checks that a corrupted signed response yields SERVFAIL. All 315k requests per
set completed with zero errors/loss, and all validation probes passed. The signed
fixture shares a resolver CPU; these are not DNSSEC BIND comparisons.

The first set is retained in dnssec-first. A correctness-test transfer/execution
could overlap its final portion; it is therefore exploratory. The entire set was
repeated after those tasks ended, with results in dnssec-clean. No successful or
losing trial was selectively dropped.

Clean-set median p95, baseline / candidate:
- Validated cache: 3.827506 / 3.599770 ms.
- Mixed: 14.162451 / 21.878916 ms.
- All misses: 27.370651 / 18.754268 ms.

The mixed-workload regression and shared-VPS variation prevent a general latency
claim. The initial DNSSEC set also showed worse candidate mixed p95. Production
was not deployed or reconfigured; service/DNS and absence of lab listeners were
checked afterward.

## Implementation status and reproduction

The adapter is retained as opt-in experimental code, not enabled in normal builds:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags gdns_udp_addrport -o gdns ./cmd/gdns
python3 scripts/build-bind9-performance.py --arch amd64 --baseline-ref 67cfc62 --candidate-tags gdns_udp_addrport --out /tmp/gdns-addrport-bundle
```

Without the tag (and on non-Linux platforms) the constructor uses the original
library transport. The tag was added after measurement without changing adapter
logic. Exact measured source/diff/binary hashes are retained in metadata and the
micro source snapshots. Both standard and tagged Linux builds compile; the final
tagged native Linux tests passed IPv4/IPv6, wildcard source retention, TSIG,
concurrency and malformed ancillary-data checks. Host race tests/vet pass; they
exclude Linux-specific implementation, so no native Linux race run is claimed.

Further work must target the DNSSEC mixed-workload regression and reproducible
network p95, rather than infer whole-server speed from reduced allocations.

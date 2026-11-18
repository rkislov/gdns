# Mixed DNSSEC investigation — 2026-11-18

All network experiments ran on dev.kislovs.ru, with the fixture sharing CPU 0
with the resolver (CPUs 0,1, two workers) and the generator on CPU 2. The
production service was not replaced. This is a synthetic local signed zone,
not an Internet recursion benchmark or a BIND comparison.

## Initial diagnostic profiles

`profiles-before` compares the old default UDP transport (67cfc62) with the
previous experimental AddrPort transport. CPU profiles sampled eight seconds;
block times are accumulated across goroutines, not per-request delays.
Validator.Validate consumed 48.24% of candidate CPU samples; chain construction
consumed about 35%. Candidate socket write-lock delay was 3.96 seconds,
versus 3.24 seconds for the default transport. Cache mutex contention was small
(about 1.1 ms for cache puts). These profiles identify costs, not causation of
all observed tail-latency differences.

## Cache-only experiment

Keep the complete immutable signed cache entry and check signature validity
before returning a private A/AAAA copy for clients without DO. Avoid copying
RRSIG records that clientResponse would immediately remove. DO requests,
multiple address answers, aliases and authority sections retain the generic
copy path. Added signature expiry/inception and ownership tests.

Host microbenchmark: five allocations become one; median plain response
349.6 → 264.6 ns, EDNS 380.4 → 280.0 ns. These are CPU microbenchmarks, not UDP
latency. Full host tests and race tests pass; the cross-compiled core test
binary also passes natively on Linux (without race instrumentation).

`cache-only` has three five-second trials for each implementation/scenario.
Baseline is 66c856c built with gdns_udp_addrport, candidate adds the cache change.
Median p95 in ms, baseline → candidate:

- Warm, 5,000 qps: 3.109209 → 6.562179.
- Mixed (10% unique names), 5,000 qps: 18.217709 → 22.884012.
- All unique names, 500 qps: 17.451358 → 15.586043.

All 315,000 measured queries completed without errors/timeouts and passed the
AD/IP check. Every trial also checked a bogus signature produces SERVFAIL.
The cache-only change does **not** demonstrate a network p95 improvement.

`cache-profiles` is a separate diagnostic run: allocation samples decrease
133.35 → 129.14 MiB, but accumulated socket write-lock delay is 2.37 → 3.66 s.
Profiling results are not acceptance latency measurements. Grouped loader
statistics distinguish unique and repeated names, not directly observed cache
hits; loss remains accounted across all queries.

## Parallel socket writer experiment

Duplicate the UDP socket into a second Go poll descriptor. Both descriptors
share the same kernel socket/source port, but have independent Go write locks.
Round-robin writes use both descriptors; there is no batching or response queue.
Duplicate failure falls back to one writer. Deadline updates and Close cover
both descriptors. Native Linux transport tests pass, including TSIG, IPv4/v6,
concurrent requests, deadline expiration/reset, and port release after Close.

`parallel-writer` compares 66c856c AddrPort against signed cache + two writers:
five ten-second mixed trials per implementation, 5,000 qps. Median p95
11.278659 → 9.937589 ms (-11.89%), zero errors/timeouts across 500,000 queries.
Unique-name median p95: 24.025428 → 21.201974 ms; repeated-name median p95:
9.520369 → 7.984146 ms. The candidate had somewhat lower median CPU steal
(about 18% vs 19% on resolver CPUs), so this set alone does not establish
causation or a stable performance gain.

The intermediate source gated signed-address cache copying on
`gdns_udp_addrport`; `writer-final` repeats the experiment at that stage.
After the repeat failed, the final source additionally requires
`gdns_dnssec_mixed` for both the signed cache and duplicate writer. Ordinary
builds and the existing AddrPort-only build retain the previous behavior. Linux
transport race instrumentation is not covered by the host macOS race tests.

## Repeated results and decision

`writer-final`: five ten-second mixed trials per implementation at 5,000 qps.
Median p95 12.471615 → 12.817937 ms (+2.78%), zero errors/timeouts across
500,000 queries. Unique-name p95: 27.153304 → 25.887311 ms; repeated-name p95:
10.330144 → 10.853499 ms. Resolver CPU steal medians were approximately
20.7%/19.8% for baseline and 19.3%/19.6% for candidate; the shared-host setup
and variable scheduling remain important limits on causal interpretation.

Separate three-by-five-second controls:

- `writer-warm`, 5,000 qps: 3.672527 → 5.559425 ms.
- `writer-miss`, 500 qps: 15.756139 → 12.904450 ms.
- Zero errors/timeouts in both (165,000 queries), valid AD and bogus SERVFAIL
  probes passed for every trial.

`writer-profiles` shows aggregate socket write-lock blocking decreasing
3.62 → 2.00 seconds in the eight-second profile. DNSSEC validation still
accounts for 46.96% of candidate CPU samples and state construction for 32.34%.
Profiled p95 itself was 12.22 → 45.28 ms; these instrumented runs are preserved
for diagnosis, not substituted for normal latency measurements.

**No stable improvement of mixed p95 has been established.** Neither the
regression nor the historical “20% faster than BIND” target is resolved by
these experiments. No BIND run was made in this iteration. No production
binary was replaced. The experimental code is retained only for further
controlled investigation, enabled explicitly with both build tags:

`go build -tags gdns_udp_addrport,gdns_dnssec_mixed ./cmd/gdns`

The additional final build guard does not alter the enabled experiment's
algorithm. `gated-smoke` records a final integration check of that guarded
build (not an acceptance benchmark); native transport tests cover both tag
configurations. Full host tests and race tests pass, with the Linux-only
transport covered by native non-race tests, not host race instrumentation.

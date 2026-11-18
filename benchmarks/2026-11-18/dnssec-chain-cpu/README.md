# DNSSEC chain work and CPU contention — 2026-11-18

Baseline: b20fa9c with `gdns_udp_addrport`, without the rejected mixed-cache /
parallel-writer experiment. Candidate uses the same transport and crypto limit
of 32. Production gdns on dev.kislovs.ru is not replaced by these tests.

## Implementation

An internal DS-absence lookup authenticates only its scoped NSEC/NSEC3 proof
RRsets. Its SOA is not used to prove a delegation, is not returned to a client,
and is not marked authenticated. Its conservative expiry contribution is still
retained, so this change cannot extend the existing chain-state lifetime.
Client-facing negative answers still authenticate SOA. Signer/zone scoping,
DS/DNSKEY verification, denial coverage, NSEC3 opt-out/iteration limits, signature
period checks, per-view state and work budgets are unchanged.

This follows [RFC 4035 section 5.4](https://www.rfc-editor.org/rfc/rfc4035.html#section-5.4):
the authenticated NSEC RRsets establish absence. The existing NSEC3 proof engine
continues to validate NSEC3 coverage and delegation semantics.

The answer walk retains section headers of the already-private message instead
of deep-copying it a second time. The common address + signature response skips
string-based deduplication because records of different RR types cannot be
identical. Duplicate records of the same type still use the general path.

New tests cover actual signature work for an internal proof, tampered/expired/
missing denial, mandatory SOA authentication for client negative responses,
concurrent input ownership and same-type deduplication. Existing tests cover
secure/insecure chains, bad DS and signatures, aliases, wildcard, NSEC3 and
route isolation. Host full race tests and native Linux DNSSEC tests are recorded.

## Rejected CPU limiter

`cpu-limit` tests a concurrency cap of GOMAXPROCS/2 (one slot on this setup).
Mixed median p95 was 18.406703 → 16.529300 ms, but the candidate timed out 78
queries (baseline zero). Rejected; no limiter change remains in the source.
Its exact experimental source is retained in metadata.json.

## Microbenchmark

Three local Apple M4 / GOMAXPROCS=2 repetitions, not network p95 measurements:

- Cached chain: median 40.104 → 38.883 microseconds, 93 → 69 allocations.
- Uncached leaf with cached parent chain: 117.383 → 78.306 microseconds,
  206 → 138 allocations. Fixture responses are pre-signed; signing is outside
  the measured section. Both versions do the same forced leaf-state eviction.

## Network experiment method

Unchanged signed fixture and load generator, resolver on CPUs 0,1 with two
workers, generator on CPU 2, fixture sharing CPU 0. The VPS has measurable CPU
steal; this setup does not establish performance on independent hosts.
Mixed input is 5,000 qps with 10% unique names. Each series has five alternating
pairs of ten-second trials, 500,000 total queries. Two series are planned before
accepting the result: both median p95 values must decrease, with no errors or
timeouts and maintained offered-rate goodput. All trials require AD and correct
answer IP, plus an explicit bogus-signature SERVFAIL probe before load.

## Shared-CPU results (not sufficient to accept a stable p95 win)

- Series A mixed: 18.904661 → 15.910579 ms (-15.84%).
- Series B mixed: 18.913239 → 25.645125 ms (+35.59%).
- All 1,000,000 queries in these two series completed without errors/timeouts.
- Warm control: 4.660616 → 4.327066 ms, zero losses.
- All-miss control at 500 qps: 23.552754 → 13.832396 ms, zero losses.
  Each control uses three five-second trials per implementation.

In the separate eight-second diagnostic profiles, accumulated CPU samples in
chain-state construction decreased 2.71 → 2.29 s and total Validate samples
3.69 → 3.22 s. Total resolver CPU samples were 7.55 → 7.19 s. These are separate
instrumented runs, not acceptance latency measurements.

## Additional isolated CPU arrangement

The shared-CPU mixed result failed replication. A second arrangement tests the
same binaries, same fixture and same 5,000-qps workload with resolver CPU 1 /
GOMAXPROCS=1 / one UDP worker, fixture CPU 0 and generator CPU 2. This avoids
fixture signing competing directly with the resolver. Two new five-pair series
are run, with the same criteria. Results must be attributed to this arrangement,
not substituted for the shared-CPU results or generalized to two-worker service.

The single-resolver-CPU arrangement was rejected: candidate repeat 1 recorded
9 timeouts. The run was stopped during its tenth trial; nine completed trials
and metadata are retained in `isolated-a`. No second series was started.

A final arrangement retains two resolver CPUs (0,1), two workers and
GOMAXPROCS=2, but moves the signed fixture to CPU 2 alongside the generator.
Both implementations use this identical placement. This removes fixture CPU
competition from resolver CPUs without reducing resolver capacity. Generator
lateness and CPU steal remain recorded; this is still a single-host test.

Dedicated resolver CPU results with the original generator:

- `dedicated-a`: 15.071982 → 11.929446 ms, zero losses.
- `dedicated-b`: 8.335017 → 10.191213 ms, zero losses.
- This arrangement also failed to reproduce a mixed-p95 improvement.

## Corrected mixed workload generator

The old `i % 10 == 0` rule with eight UDP flows puts all unique names on the
four even-numbered flows. The revised generator gives every flow exactly one
unique name per ten queries, preserving the same aggregate 10% miss ratio.
A unit test verifies per-flow counts. `-local-port-base` optionally fixes the
eight source ports so each baseline/candidate pair uses the same flow tuples.
This removes one source of worker-distribution variation; it does not eliminate
VPS steal or turn the single-host setup into an independent network benchmark.

`balanced-a` and `balanced-b` use this new generator with source ports
22700–22707, two resolver CPUs/workers, and fixture + generator on CPU 2.
The resolver binaries are unchanged from the chain-only experiments. Old and
new workload results are kept separate; only within-series baseline/candidate
comparisons are meaningful. The actual load-generator hash is in every run's
metadata; `balanced-load-main.go.txt` records its source.

Balanced workload results:

- `balanced-a`: 10.558876 → 10.166848 ms (-3.71%), zero losses.
- `balanced-b`: 16.086136 → 14.168405 ms (-11.92%), zero losses.
- 1,000,000 queries total; minimum trial goodput exceeded 4,985 qps.

A longer confirmation set (`balanced-long`) uses ports 22716–22723 and five
20-second pairs, keeping every other setting and both resolver binaries fixed.
It is intentionally a second flow-tuple set, not a search for favourable ports.
The fixed-per-flow workload is a controlled comparison, not a guarantee for
arbitrary client mixes or VPS contention. No comparison with BIND is made here.

## Final confirmation and scope

`balanced-long`: median p95 **11.917470 → 8.668679 ms (-27.26%)**.
The same chain-only candidate therefore lowers median p95 in all three corrected
workload series (-3.71%, -11.92%, -27.26%). Across them, **2,000,000 queries**
completed with **zero errors and zero timeouts**, valid AD/IP responses and
bogus-signature SERVFAIL probes. Every trial achieved at least 4,985 qps against
5,000 offered. Resolver/fixture binaries and load-generator hashes are recorded.

This meets the declared repeated-series criterion for the tested balanced
workload, fixed source tuples and dedicated resolver CPUs. Individual trials
still vary; the earlier shared-CPU/random-flow sets did not demonstrate stable
p95 improvement and are retained above. Changing benchmark CPU placement and
flow distribution is a measurement control, not an application optimization.
This is not a universal latency guarantee, a production load result, or evidence
of a 20% advantage over BIND. Production service/binary were left unchanged.

The retained application changes are the DNSSEC proof/answer optimizations;
crypto concurrency remains 32. The accepted candidate does not enable the old
`gdns_dnssec_mixed` cache/parallel-writer experiment. The ordinary Linux build
also compiles; the measured binaries use the existing `gdns_udp_addrport` tag.
Final native DNSSEC tests and the complete host race suite pass. Linux-only
transport race instrumentation is not claimed by the host race run.

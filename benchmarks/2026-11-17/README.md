# gdns performance investigation, 17 November 2026

This directory preserves successful and unsuccessful trials. The network target
is **not demonstrated** by the cache microbenchmarks. Production gdns on
`dev.kislovs.ru` was not replaced or reconfigured for these measurements.

## Changes under test

- Structured cache keys avoid formatting/allocating a singleflight string on hits.
  Strings are still constructed on misses. Split-zone identity, type, DO and CD
  remain part of the key.
- Single A/AAAA cached responses own their message, record and IP bytes in one
  allocation; EDNS storage is allocated only when needed. Other response types
  retain deep copying, TTL aging and signature validity checks.
- Linux UDP workers request a bounded 1 MiB receive buffer, subject to the
  kernel's existing `rmem_max`. No sysctl is changed. Larger queues can reduce
  loss while increasing latency when a server cannot keep up.
- Unsigned UDP responses reuse a bounded 1232-byte packing buffer. The buffer is
  returned only after synchronous Write completes. TSIG continues through the
  DNS library's signing path. TCP/DoT/DoH behavior is unchanged by this pool.

## Method and interpretation

The fixed control is warmed forward-cache UDP at 15,000 offered queries/s,
512 A names, TTL 3600, five repeats of eight seconds. BIND 9.20.30, baseline
`cce7c27` and candidate run in rotating order. Each trial starts a new resolver,
primes the cache and warms the traffic. The acceptance condition is candidate
median p95 <= 0.80 * BIND median p95, errors no greater than BIND, and median
actual QPS >= 0.99 * BIND. This condition was selected before measurements.
The final summarizer also checks comparable successful throughput (both within
1% of the offered rate and within 1% of each other); lossy saturation runs
cannot establish the requested latency advantage at comparable throughput.

Additional scenarios cover UDP at 5k/30k, TCP at 5k, all misses at 1k and 10%
misses at 5k, three repeats each. Functional checks include A, AAAA, CNAME, SRV,
NXDOMAIN and positive/negative TTL aging. DNSSEC validation and query logging
are disabled for this forward-cache comparison; these results do not represent
recursive DNSSEC validation throughput. Per-query telemetry accounting remains
enabled; the standalone Prometheus HTTP exporter is disabled.

The open-loop generator uses one absolute-time paced sender and eight separate
receivers, validates responses, records actual-send RTT, scheduled latency and
sender lateness. Persistent TCP connections exclude setup time. A one-second
final drain is allowed. `raw.json` includes p50/p95/p99, successful QPS, sent/OK/
error/timeout counts, cgroup CPU and end-of-trial memory, and UDP kernel counters.
RTT percentiles describe received successful responses: high-loss implementations
can appear faster because their slowest requests were discarded.

Memory is cgroup memory at trial end, **not peak heap or cache-only footprint**.
CPU is an approximate average over the measured load and observation overhead.
CPU/memory profiles are separate runs with profiling overhead and must not be
used for acceptance latency. Allocation profiles subtract the start snapshot.

## Environments and result sets

- `bind9-initial`: 60 local ARM64 Docker Desktop trials, initial cache changes.
  Control p95: BIND 0.093375 ms, baseline 0.084292 ms, candidate 0.073417 ms.
  Candidate had 373 timeouts out of 600,000 requests; BIND/baseline had none.
  Latency ratio 0.7863, **acceptance false due to loss**.
- `bind9`: 60 local ARM64 trials with increased UDP receive buffer.
  Control p95: BIND 0.280333 ms, baseline 0.138334 ms, candidate 0.408917 ms.
  BIND had 143 timeouts; baseline/candidate had none. Ratio 1.4587,
  **acceptance false**. Do not discard the noisy repetitions.
- `linux-initial/results-amd64`: all 15 fixed control trials on the dev VPS,
  plus four completed diagnostic trials before stopping this revision to test
  pooled packing. This is intentionally not labelled a complete 60-trial suite.
  Control p95: BIND 21.051556 ms, baseline 25.480304 ms, candidate 33.615905 ms.
  Timeouts: 31,780 / 28,350 / 12,563 respectively, out of 600,000 each.
  **Acceptance false**.
- `linux-initial/profiles-amd64`: native Linux baseline/candidate CPU and
  allocation profiles before pooled packing.
- `bind9-profiles-verified`: complete local baseline/candidate profiles before
  pooled packing. An earlier incomplete profiling attempt was excluded because
  macOS `/var` vs `/private/var` path canonicalization prevented the baseline Go
  overlay from applying; the runner now resolves the path and checks artifacts.
- `bind9-profiles-pooled`: local profiles after pooled packing. Estimated
  eight-second allocation traffic decreased from 144.83 MiB baseline to
  132.20 MiB candidate (about 9%). This is allocation traffic, not resident RAM.
- `bind9-profiles-contention`: separate two-worker local mutex/block profiles.
  No material cache-lock waiting was observed in this warmed workload. Timer
  waits and UDP socket write serialization dominate the observed waits; this
  does not rule out contention in other workloads.
- `micro`: three local repetitions at GOMAXPROCS 1/2/4, plus a parallel secure
  cache CPU/mutex/block profile. For one CPU, median cache-only time changed
  from 217.4 to 172.2 ns, 264 to 224 B, 5 to 1 allocations. The secure cached
  answer changed from 396.9 to 378.9 ns, 448 to 416 B, 6 to 5 allocations.
  These are in-process costs and **not proof of a network p95 target**.

Local trials use two resolver CPUs, two client CPUs and two authority CPUs.
The native amd64 VPS has three vCPUs: resolver CPU 0, client CPUs 1/2, authority
CPU 0, one worker per resolver. Authority is idle on warm hits; it shares the
resolver CPU on misses, limiting interpretation of miss throughput. Containers
use an internal Docker network, no published host ports, 512 MiB memory limits,
and the same upstream. Native amd64 and ARM64 medians are never pooled.

The VPS showed roughly 26% CPU steal during a separate ten-second observation
(`linux-initial/host-cpu-observation.json`). Later trials record host CPU tick
deltas individually. This shared VPS cannot provide a clean isolated CPU
latency comparison. Kernel receive-buffer errors and sender lateness are real
limitations, not reasons to selectively exclude losing trials.

## Reproduction

Build the pinned test image on the target's native architecture:

```sh
docker build -t gdns-performance-bind:local -f scripts/performance/Dockerfile.bind .
```

Run on a native six-CPU ARM64 Docker host:

```sh
python3 scripts/bind9-performance.py --out /tmp/gdns-results
python3 scripts/bind9-performance.py --profile-only --out /tmp/gdns-profiles
```

For an amd64 host without Go, cross-compile locally, transfer the resulting
folder, then run its bundled script on that host:

```sh
python3 scripts/build-bind9-performance.py --arch amd64 --out /tmp/gdns-bundle
python3 /path/to/gdns-bundle/bind9-performance.py \
  --arch amd64 --workers 1 --server-cpus 0 --client-cpus 1,2 --auth-cpus 0 \
  --prebuilt-dir /path/to/gdns-bundle --out /tmp/gdns-results
```

Use a fresh output directory for each run; existing results are never replaced.
`--quick` is exploratory, not the five-repeat acceptance series. Repeat the
same command with `--profile-only` and a fresh directory for profiles. The
runner removes only its uniquely named containers/network on normal completion.
The baseline commit, candidate diff, binary hashes, image ID, Go/BIND/kernel
versions and CPU layout are stored in metadata. Do not compare different
candidate revisions without checking their binary hashes.

```sh
python3 scripts/summarize-bind9-performance.py /tmp/gdns-results
go tool pprof -top /tmp/gdns-profiles/candidate.cpu
go tool pprof -top -alloc_space -base /tmp/gdns-profiles/candidate-start.mem /tmp/gdns-profiles/candidate.mem
```

## Final native Linux results

`linux-final/results-pooled` contains all 60 trials for the final candidate;
`all-scenarios-summary.json` includes all rates/scenarios and CPU/RAM values.
The tested candidate SHA256 matched a fresh build of the final source before
committing (Go build info embeds VCS metadata):
`98a8b8b93cf73016d34d1cebcb5c0339b5cb13965c2f5f4bfdac747962338f6c`.
All 18 functional checks passed. UDP counters confirm no upstream traffic in
warmed-cache measurements.

At 15,000 offered QPS, median p95 was BIND **20.281859 ms**, baseline gdns
**24.615183 ms**, final candidate **28.236199 ms**. The candidate/BIND ratio is
**1.3922**, not <= 0.80. Actual successful QPS was approximately 14,518 / 14,402 /
14,874 respectively: goodput is not comparable within 1%. Timeouts were
22,903 / 23,754 / 4,541 out of 600,000 sent for each implementation. Loss fell
from 3.959% baseline to 0.757% candidate, but tail latency increased.
**The acceptance criterion is not met.**

Median CPU consumption for this control was 0.586 / 0.718 / 0.712 cores; end
cgroup memory was 6.9 / 10.5 / 10.8 MiB. Across scenarios, gdns memory fluctuates
substantially because startup password hashing allocations can remain until GC;
these values do not demonstrate a reduction in resident memory. Median host CPU
steal during the control was 27.7% / 27.1% / 26.3% respectively.

For baseline versus candidate, other scenario median p95 values were:

- UDP warm 5k: 14.231 versus 14.249 ms; neither lost requests.
- UDP warm 30k: 39.885 versus 50.422 ms; 182,333 versus 115,845 timeouts
  out of 720,000 requests each. Some trials also lost packets in the client's
  receive buffer, so this is not a pure measurement of server capacity.
- TCP warm 5k: 13.407 versus 16.091 ms; no errors.
- UDP all-miss 1k: 16.686 versus 15.519 ms; no errors.
- UDP 10% miss at 5k: 24.376 versus 24.510 ms; no errors.

`linux-final/profiles-pooled` contains complete before/after CPU and allocation
profiles. Kernel syscalls account for roughly 40–44% of CPU samples. Allocation
traffic in the sampled window was about 144.08 MiB baseline versus 137.22 MiB
candidate; because native profiling runs lost different numbers of requests,
this is not an exact per-query percentage improvement. The packing allocation
site disappears from the candidate's leading allocation sites, corroborating
the pooled buffer change. Profiling runs are excluded from acceptance timing.

The result justifies fewer cache/packing allocations and a bounded UDP backlog,
but not a claim that gdns is now faster overall or 20% faster than BIND. Further
latency work needs a less contended CPU environment and a separate load host;
system-call batching is a possible subsequent experiment, not an implemented
or validated improvement here.

## Validation

Full Go race tests pass, including cache ownership/isolation and signature
expiry checks. New tests exercise concurrent pooled writes, propagation of
write errors and retention of the TSIG signing path. Linux socket tests verify
actual receive buffer sizes and UDP worker binding. Outputs are in `validation`.
The candidate is an isolated development branch, not a deployed release.

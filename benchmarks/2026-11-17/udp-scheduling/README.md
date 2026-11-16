# UDP scheduling experiments (Linux amd64)

The requested 20% p95 advantage over BIND **was not achieved**. These are six
exploratory sets of nine trials, not successful acceptance runs. Each variant
was compared with BIND 9.20.30 and gdns commit `21ece49` (the previous optimized
version), in rotating order. All 54 trials are preserved, including regressions.
Production gdns was not replaced or reconfigured.

## Fixed workload and results

Warm forward cache, UDP, 512 A names, TTL 3600, 15,000 offered queries/s,
three repetitions of five seconds per implementation: 225,000 requests each.
DNSSEC and query logging disabled; per-query telemetry enabled. Percentiles are
RTT of successful responses, not the latency of lost queries. Losses below are
errors plus timeouts. Values in each sequence are BIND / baseline / candidate.

- `fair-quick`: yield reader after every request. Median p95
  19.127 / 27.640 / 21.954 ms; losses 6,942 / 958 / 2,795.
  Rejected: more losses than baseline and slower than BIND.
- `batch-quick`: `recvmmsg` up to 16 available packets, yield each read.
  p95 17.205 / 31.519 / 20.090 ms; losses 4,580 / 6,637 / 2,024.
  Lower baseline latency and loss in this exploratory set, but slower than BIND.
- `batch-io-quick`: private packet-info storage, reader yield every eight reads,
  synchronous acknowledged `sendmmsg` queue, no batching timer.
  p95 19.999 / 32.945 / 23.976 ms; losses 7,526 / 2,703 / 972.
  Slower than BIND.
- `paced-batch-io-quick`: same batch transport with Linux absolute-timer client
  pacing instead of busy wait. p95 10.724 / 28.012 / 16.433 ms;
  losses 3,349 / 1,105 / 895. Slower than BIND; do not attribute the difference
  from the preceding set solely to transport code.
- `adaptive-two-quick`: batch-send only when receive batch contained multiple
  packets; two resolver CPUs/workers and one client CPU; absolute-timer pacing.
  p95 10.294 / 13.036 / 18.851 ms; losses 5,504 / 1,152 / 150.
  Rejected: p95 regressed against baseline despite lower losses.
- `read-direct-quick`: batch reads, private packet-info, yield every eight reads,
  direct synchronous sends; absolute-timer pacing; one resolver CPU again.
  p95 7.803 / 13.308 / 15.276 ms; losses 2,726 / 555 / 1,697.
  Rejected: worse baseline latency and loss.

All sets except `adaptive-two-quick` assign CPU 0 to resolver, CPUs 1/2 to
client, and CPU 0 to the idle-on-cache-hits authority. Containers use the same
internal network, upstream and 512 MiB limit. CPU affinity is not physical CPU
reservation. The VPS has substantial steal time: median per-implementation
host samples in these sets are roughly 20–26%. Client p95 send lateness is
several milliseconds (and higher in the one-client-CPU experiment). No losing
trials are excluded because of steal or sender lateness. These measurements
cannot establish a portable throughput or latency guarantee.

## Decision and retained work

The experimental UDP transport was removed from the active source tree; no
runtime change from this investigation is being recommended for deployment.
Exact source snapshots for the later candidates are in metadata and
`read-direct-source.json`; `adaptive-runtime-source.json` preserves the transport
and tests before direct-send simplification. Early reader-only sets lack a full
untracked-source snapshot; their tracked diff and measured binary hashes remain
in their metadata. Do not claim those older sources are exactly reproducible.

Kept in the benchmark tools:

- Linux optional absolute `CLOCK_MONOTONIC` sleep pacing, with thread-local timer
  slack restored afterward; no host sysctl changes. Original spin mode remains
  default. Pacing mode is recorded and must match within comparisons.
- Explicit baseline revision and inclusion of untracked Go sources in bundles.
- `--control-only`: five eight-second repetitions per implementation without
  other scenarios. `--quick` is exploratory and cannot pass acceptance.
- Acceptance requires p95 <=80% of BIND, better p95 than baseline, no more losses
  than either comparator, at least five control repetitions, and median successful
  throughput within 1% of 15k QPS and within 1% across all three implementations.

`assessment.json` applies those checks to every set. Original runner summaries
are retained unchanged; the stronger assessment is authoritative here.

## Validation and limitations

Experimental native Linux ARM64 race tests covered IPv4/IPv6, wildcard source
address preservation, TSIG, concurrent requests, shutdown, buffer ownership,
partial sends and malformed ancillary data. The `recvmmsg` ENOSYS fallback was
also tested with seccomp. Logs are included. These are correctness tests, not
performance evidence; performance above is native Linux amd64 on dev.

External Linux-client connectivity was attempted through a temporary published
UDP port. No UDP packets reached the server, so no external comparison is
reported. The test port, source-restricted firewall rule, containers and network
were removed. The diagnostic script is archived as text, not a supported tool.

For a defensible next acceptance run, use a reachable separate Linux generator
and a server with stable CPU availability. Preserve the same workload, baseline,
loss and goodput criteria. This requires infrastructure access; repeating the
same noisy shared-VPS test cannot substantiate the requested 20% claim.

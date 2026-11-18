# Two-worker control

Same packet-info candidate and baseline 67cfc62 as the preceding one-worker
experiment, with two resolver CPUs (0,1), two workers, and one generator CPU (2).
BIND receives the same two resolver CPUs and workers. Authority shares CPU 0;
the workload is warmed cache hits. Five eight-second repeats at 15k offered QPS,
600,000 queries per implementation, rotating order, Linux sleep pacing.

Median p95: BIND 7.087080 ms, baseline 6.633758 ms, candidate 5.764925 ms.
Losses: 3,817 / 102 / 39. Median successful QPS: 14,953.39 / 14,986.28 /
14,995.41. Candidate p95 is 18.66% below BIND and 13.10% below baseline.
Candidate loss is 0.0065%, versus BIND 0.6362% and baseline 0.0170%.
Comparable-goodput, no-loss-regression and five-repeat checks pass; the 20%
p95 advantage check still fails. Do not round 18.66% up to the requested 20%.

This is a promising configuration-dependent result, not a general speed claim.
Do not directly attribute differences from the one-CPU series solely to worker
count: CPU allocation, generator affinity and host conditions changed together.
Generator median p95 lateness was 6.430 / 2.716 / 3.952 ms respectively, so the
actual offered traffic was not identically smooth. Candidate per-trial p95 ranged
from 4.873 to 13.280 ms; all trials are retained. Independent repetition and mixed/
miss workload validation of this two-worker configuration remain outstanding.

No code change was made between the one- and two-worker candidate runs. Exact
candidate source is in the parent candidate-source.json and run metadata. The
adapter remains experimental rather than enabled globally because the one-worker
configuration increased losses. Production was not updated; service and a DNS
query were checked after the run. Only dev was used for load testing.

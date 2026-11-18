# Full validation of yielding every eight UDP reads

60 native Linux amd64 trials on dev, using the previous exact `yield8` bundle
and its stored source metadata and binary hashes. Baseline 21ece49; BIND 9.20.30.
One resolver CPU/worker, two generator CPUs, Linux absolute sleep pacing.
Production was not replaced. No second server was used.

The fixed control used five eight-second repeats at 15k offered QPS, rotating
implementation order, 600,000 requests each. Median p95 in ms:
BIND 6.172077, baseline 10.869625, candidate 7.398500.
Losses: 5,324 / 1,369 / 1,570. Candidate p95 improved 31.9% against baseline,
but losses increased by 201 (14.7%). Candidate p95 remained 19.9% above BIND,
not 20% below it. Comparable-goodput acceptance also failed. Overall acceptance
is false. No individual winning run was selected in place of these aggregates.

Additional scenarios each have three repetitions. Median p95 baseline/candidate:
- Warm UDP 5k: 4.292/4.242 ms; both lossless.
- Warm UDP 30k overload: 42.927/21.682 ms; losses 106,922/74,545.
- TCP 5k: 2.705/3.297 ms; both lossless.
- UDP all misses 1k: 6.174/8.087 ms; both lossless.
- UDP 10% misses 5k: 7.140/7.817 ms; losses 2,538/0.

The complete per-scenario comparison including BIND is in scenarios.json;
raw.json preserves all 60 trials, sender lateness, CPU steal and kernel counters.
This shared VPS exhibits substantial variation, including in TCP where the
experimental UDP reader is not used. These results establish observed behavior
in these series, not causality for every difference or a portable speed guarantee.
DNSSEC validation and query logging were disabled for the comparison.

Host race tests and vet passed. The experimental code is preserved in the earlier
17-Nov dev-capacity/yield8-source.json and this run's metadata; it was removed
again from active runtime sources because the no-loss-regression requirement
failed. The first series' improvement in both loss and p95 did not reproduce.
No production deployment is recommended from this experiment.

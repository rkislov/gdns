# Repeated two-worker control and full scenario suite

60 native Linux amd64 trials on dev with the exact previous packet-info candidate
and baseline 67cfc62. Two resolver CPUs/workers, one generator CPU, sleep pacing.
All raw trials are preserved. Production was not changed.

The repeated 15k control (five eight-second runs each, 600k queries each) produced:
- BIND: median p95 5.961480 ms; losses 1,390.
- Baseline gdns: 10.500411 ms; losses 334.
- Candidate: 10.548690 ms; losses 86.

The previous candidate p95 advantage over BIND did not reproduce. Lower loss
versus BIND and baseline did reproduce in this control. Neither a general p95
advantage nor the requested 20% target is established; acceptance remains false.

Additional medians/losses are in scenarios.json. UDP mixed at 5k and all misses
at 1k favored the candidate in this series, with no loss. At 30k overload it had
higher p95 and loss than baseline. TCP and warm UDP 5k were lossless. The shared
VPS and sender jitter still limit causal interpretation; do not select the best
of the two control series as the overall result.

The full unsigned suite finished before the separate DNSSEC experiment started.

# Dev-only follow-up: capacity and reader scheduling

All performance runs used the native amd64 dev VPS and an isolated internal
Docker network. Production was not updated. Results were collected after the
interrupted session on 18 November 2026. No second host is required by these
scripts. These measurements do not establish the requested 20% advantage.

## Capacity diagnostic

`capacity-stable-sweep` contains 27 trials: warm UDP at 1k/5k/10k offered QPS,
three five-second repeats per implementation, rotating order. Baseline is
cce7c27; candidate is the existing optimized runtime (0a5392c, runtime unchanged
from 21ece49). Linux sleep pacing, one resolver CPU, two client CPUs, one worker,
512 cached A names, no DNSSEC validation or query logging.

Median p95 in ms, BIND / old gdns / optimized gdns:

- 1k: 4.560 / 5.563 / 4.402; losses 0 / 0 / 0 out of 15,000 each.
- 5k: 4.956 / 7.171 / 9.970; losses 70 / 0 / 0 out of 75,000 each.
- 10k: 5.446 / 16.220 / 11.791; losses 156 / 1,178 / 0 out of 150,000 each.

The initial progress statement that all implementations were lossless at 5k
was premature and was corrected after reading the complete summary. The raw
results above include every trial. Host steal medians were about 21–26%; sender
p95 lateness medians were about 2.5–4.7 ms. Even the lossless 1k workload has
millisecond p95, so saturation alone does not explain the observed latency.
The capacity sweep is diagnostic, not acceptance at the fixed 15k target.

## Yield every eight UDP reads

`yield8-control` contains the full 15-trial fixed control: five eight-second
repetitions at 15k offered QPS per implementation, 600,000 requests each.
Baseline is 21ece49, candidate adds runtime.Gosched after each eight reads.
There is no new batch transport, sender queue or timer. Other setup is as above.

Median p95: BIND 11.457844 ms, baseline 28.282413 ms, candidate 17.956876 ms.
Losses: 10,323 / 8,095 / 6,949. Median goodput: 14,739.95 / 14,912.58 /
14,938.47 successful QPS. Candidate p95 was 36.5% lower than baseline and losses
14.2% lower, but p95 was 56.7% higher than BIND. Comparable-goodput acceptance
also failed. This is one series on a noisy VPS, not a portable speed guarantee.

The candidate passed host Go race tests and vet; logs and the exact source
snapshot are retained. Native Linux transport test binary was built and uploaded
but not executed before interruption. Lower-load and miss-path performance of
this reader variant remains unverified. The scheduling experiment was therefore
removed from active runtime sources; it is not enabled or deployed by this commit.

The retained runner addition is `--capacity-sweep`, mutually exclusive with
quick, control-only and profiling modes. It records diagnostic summaries and
always reports acceptance false. Original raw results and metadata are preserved.

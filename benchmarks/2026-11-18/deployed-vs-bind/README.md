# Deployed gdns versus BIND — 2026-11-18

The requested stable 20% p95 advantage over BIND is **not established**. Both
15k-QPS control series fail that criterion. gdns loses substantially fewer
requests, but its median p95 is higher. Lower loss does not imply lower p95,
and p95 here is calculated only from successful responses.

## Scope and method

- Host: dev.kislovs.ru, native Linux amd64, three vCPUs. No second host.
- BIND 9.20.30, image ID and build details retained in metadata.
- gdns: exact installed `/usr/bin/gdns`, source 23a3c32 with
  `gdns_udp_addrport`, without `gdns_dnssec_mixed`; SHA256
  `cb9851bcd8db5b3b1b249b14901f9e3b355c86b2f7d16e98fed9cc8069731770`.
- Each resolver: CPUs 0,1, two workers, 512 MiB container limit. Generator and
  authoritative fixture: CPU 2. Query logging off. Trial order alternates.
- Plain DNS uses an isolated internal Docker network and a local authoritative
  fixture; DNSSEC is disabled on both implementations in these trials.
- DNSSEC uses the same signed local fixture and explicit zone trust anchor for
  both resolvers, host networking, and validation enabled. Successful answers
  must have AD and the expected IP; each trial checks a valid answer and bogus
  signature rejection with SERVFAIL. This is not full Internet recursion.
- Fixed UDP client ports: base 22700, then 22716 for the long control. The mixed
  workload contains 10% unique names, balanced across all eight UDP flows.
- Reported latency and successful QPS are medians of per-trial values, not a
  merged distribution. Loss is the sum of errors and timeouts divided by sent
  requests. At overload this can include client send failures; kernel counters
  and sender lateness are retained to distinguish causes.
- Primary criterion fixed before execution: five repetitions, p95 <=80% of
  BIND, no worse loss, each median goodput >=99% of offered 15k QPS and within
  1% of one another. A 20% throughput gain is a separate criterion.

## Primary controls

Eight-second trials, five per resolver, 600,000 requests each:

- BIND: p95 7.829 ms; successful throughput 14,910.34 QPS; 3,034 lost (0.5057%).
- gdns: p95 10.336 ms; successful throughput 14,996.78 QPS; 81 lost (0.0135%).
- gdns p95 is 32.03% higher; goodput is 0.58% higher. No 20% speedup.

Twenty-second trials, five per resolver, 1,500,000 requests each:

- BIND: p95 10.519 ms; successful throughput 14,870.98 QPS; 11,120 lost (0.7413%).
- gdns: p95 11.712 ms; successful throughput 14,997.29 QPS; 462 lost (0.0308%).
- gdns p95 is 11.34% higher; goodput is 0.85% higher. No 20% speedup.

Both series maintain comparable goodput under the preset criterion. Neither
supports a zero-loss claim. No losing repeat was excluded.

## Other plain-DNS scenarios

Three trials per resolver in each scenario; BIND / gdns:

- UDP warm 5k: p95 4.302 / 3.536 ms, about 5k successful QPS each;
  34 / 0 lost of 120,000 each. gdns p95 is 17.8% lower.
- TCP warm 5k: p95 5.486 / 4.598 ms, 4,998 / 5,000 successful QPS;
  zero losses of 75,000 each. gdns p95 is 16.2% lower.
- UDP all misses 1k: p95 8.747 / 7.418 ms, about 1k successful QPS each;
  zero losses of 15,000 each. gdns p95 is 15.2% lower.
- UDP mixed 5k: p95 7.088 / 4.276 ms, about 4,999 successful QPS each;
  zero losses of 75,000 each. gdns p95 is 39.7% lower in this scenario.
- UDP warm 30k overload: p95 19.836 / 43.189 ms, 22,183 / 26,432 successful
  QPS; 57,211 / 18,524 unsuccessful of 720,000 each. Observed goodput is 19.2%
  higher for gdns, but the generator falls behind its schedule. This is not an
  independent measurement of resolver capacity, and neither a 20% gain nor a
  lossless capacity claim follows from it.

## DNSSEC comparison

Five ten-second trials per resolver per scenario; BIND / gdns:

- Warm 5k: p95 5.323 / 5.456 ms; 4,999.70 / 5,000.00 successful QPS;
  19 / 0 lost of 250,000 each.
- Mixed 5k: p95 14.446 / 17.399 ms; 4,993.36 / 4,997.91 successful QPS;
  370 / 0 lost of 250,000 each. gdns p95 is 20.44% higher, despite zero loss.
- All misses 500: p95 14.329 / 13.232 ms; 499.96 / 499.83 successful QPS;
  zero losses of 25,000 each. gdns p95 is 7.66% lower.

All 30 valid-AD and bogus-SERVFAIL prechecks passed. Every successful load
response also required AD and the expected answer. All 525,000 gdns requests
succeeded. These results do not meet the 20% p95 objective.

`comparison.json` contains calculated aggregates for every scenario, including
trial ranges and sender lateness; `dnssec/raw.json` retains all DNSSEC trials.
After testing, production remained active/running with zero systemd restarts
and its binary hash unchanged. Public-port queries returned NOERROR+AD for
cloudflare.com and SERVFAIL/DNSSEC Bogus for dnssec-failed.org.

## Provenance and limitations

`full/raw.json` contains all 40 completed plain-DNS trials. An SSH disconnect
stopped the original runner after 20 completed trials; `interrupted/` preserves
those original rows and metadata. The resumed runner verified binary hashes,
image, CPU placement, workers, pacing and port parameters, retained the 20 rows
unchanged, and ran only missing trials. Do not count `interrupted` again when
aggregating the full series. `control/` is the separate ten-trial long repeat.

This shared VPS has substantial CPU steal and scheduler variation. A local
load generator competes for host resources; at high load sender lateness
becomes material. These measurements establish behavior in these specific
runs, not a portable performance guarantee. They do not cover DoH/DoT, feed
refresh load, production query logging, or every DNSSEC chain shape.

The v0.7.3 release additionally merges the scheduled-feed changes already in
v0.7.2. Its version-stamped artifacts have different hashes; these measurements
must not be described as tests of those exact release files.

## Reproduction

Use the repository's `scripts/build-bind9-performance.py` to produce a bundle
with `--candidate-tags gdns_udp_addrport`, or reuse the exact stored bundle
identified by the metadata. Native tools are `cmd/gdns-loadtest` and
`cmd/gdns-bench-upstream` (the latter named `gdns-secure-fixture` in the stage).
Run tests sequentially on otherwise idle experimental ports:

```sh
python3 scripts/bind9-performance.py --arch amd64 \
  --server-cpus 0,1 --client-cpus 2 --auth-cpus 2 --workers 2 --pacing sleep \
  --bind-only-compare --local-port-base 22700 --prebuilt-dir "$BUNDLE" --out "$OUT_FULL"
python3 scripts/bind9-performance.py --arch amd64 \
  --server-cpus 0,1 --client-cpus 2 --auth-cpus 2 --workers 2 --pacing sleep \
  --bind-only-compare --local-port-base 22716 --prebuilt-dir "$BUNDLE" \
  --control-only --control-seconds 20 --out "$OUT_CONTROL"
python3 scripts/dnssec-transport-validation.py --bind-compare --stage "$STAGE" \
  --binaries "$BUNDLE" --fixture-cpus 2 --local-port-base 22700 \
  --repeats 5 --seconds 10 --out "$OUT_DNSSEC"
```

Each output path should be new. The DNSSEC stage requires `gdns-secure-load`
and `gdns-secure-fixture`. Docker image `gdns-performance-bind:local` comes from
`scripts/performance/Dockerfile.bind`. Raw output, configurations and binary
hashes are retained; generated admin credentials and private logs are excluded.

# DNSSEC validation with the packet-info transport

18 native Linux amd64 trials on dev, comparing baseline 67cfc62 and the unchanged
packet-info candidate. Three five-second repetitions per implementation/scenario,
rotating implementation order. Resolver affinity CPUs 0,1; client CPU 2; signed
fixture CPU 0. This is a separate loopback diagnostic, not a BIND comparison and
not directly comparable with the unsigned Docker network measurements.

The local ECDSA-P256 fixture supplies a public trust anchor and signed A/DNSKEY
answers. Before every measured trial, a valid response must have AD and the
expected A address; a deliberately corrupted signed A response must return
SERVFAIL. Every successful load response must also have AD, the correct question,
A address and RCODE, and no truncation. Queries request AD but not DO, so signatures
are validated upstream but not returned in client answers. The fixture's dynamic
signing shares a resolver CPU and contributes to miss/mixed costs.

Median p95, baseline / candidate:
- Validated cache, 5k QPS: 3.611578 / 8.884155 ms.
- Mixed 10% new names, 5k QPS: 11.100750 / 14.769710 ms.
- New names, 500 QPS: 12.670604 / 27.592879 ms.

All 315,000 measured requests across both implementations completed without errors
or loss. All AD and bogus-SERVFAIL probes passed. Candidate p95 was worse in all
three scenarios in this series; combined with the non-reproducing unsigned p95
win, this does not justify enabling the adapter globally. No production deployment
was made. These are observations on a variable shared VPS, not isolated proof of
causality for every difference.

Two setup attempts produced no measured load: the first queried before startup;
the next exposed a missing required root anchor in the minimal test configuration.
The runner now retries startup connection failures and includes the project's
root DS alongside the local fixture anchor, with automatic anchor updates off.
Private configs, DBs and admin tokens remain on the server and are not archived.
The archived anchor is public DNSKEY material. Server and fixture processes are
terminated in finally blocks. Metadata includes binary hashes and candidate source.

Retained tooling changes: load generator zone/expected-IP/required-AD options,
fixture bogus-name option, and scripts/dnssec-transport-validation.py. Host cmd
race tests and vet passed; native signed/invalid-signature checks exercise both
Linux server binaries. This does not claim a native Linux race-detector run.

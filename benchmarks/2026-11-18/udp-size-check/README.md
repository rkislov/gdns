# Single-address UDP size check

A conservative constant-time upper bound skips the library truncation walk only
for one question, one A/AAAA answer, and no authority/additional records. Textual
DNS names plus one byte bound their uncompressed wire size; escaped names only
reduce that size. All other replies, including EDNS and DNSSEC record sets, use
the original library truncation. Compression is disabled exactly as by the
library when an uncompressed answer fits. The existing TC bit is preserved.

Three native Linux amd64 microbenchmark repetitions on dev: median library
38.88 ns/op, bounded check 5.345 ns/op, both zero allocations. These numbers
measure this operation alone. They are not end-to-end DNS latency or evidence
of the 20% BIND target. At 15k QPS, the isolated saving is approximately 0.5 ms
of CPU per second; this alone cannot resolve millisecond tail latency.

Differential wire tests cover A/AAAA and TXT fallback, escaped/root/maximum-length
names, EDNS, payload limits, and preserved/set TC. Native Linux TestUDP checks
passed; the final added TC=false cases passed the host race test. Full host
race tests and vet passed before that test-only extension. Production was not
deployed or reconfigured. No network loss or p95 improvement is claimed.

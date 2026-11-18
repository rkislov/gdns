# UDP packet-info experiment

Native Linux amd64 control on dev: 15k offered UDP QPS, five eight-second repeats
per implementation, rotating order, 600,000 queries each. Baseline 67cfc62,
BIND 9.20.30. One resolver CPU, two client CPUs, one worker, Linux sleep pacing.
Warm forwarding cache, 512 A names, DNSSEC validation and journal disabled.

Candidate replaces miekg/dns UDP session ancillary parsing with a PacketConn
adapter: each request owns a fixed-size outgoing packet-info buffer, and input
ancillary scratch is local to ReadFrom. Source address handling is preserved for
wildcard IPv4/IPv6, with library fallback for unusual ancillary layouts. The
handler sees the real *net.UDPAddr, retaining client policies and UDP truncation.
No batching, queues or scheduling changes were introduced.

Median p95: BIND 6.662254 ms, baseline 15.056285 ms, candidate 12.695232 ms.
Losses: 6,250 / 1,751 / 2,772. Median successful QPS: 14,895.82 / 14,960.22 /
14,974.45. Candidate p95 improved 15.7% against baseline, but losses increased
by 1,021 (58.3%). Candidate p95 was 90.6% above BIND. Acceptance false.
All trials, host CPU counters, sender lateness, UDP counters and source metadata
are preserved. The shared VPS introduces variation; this set does not establish
causality for each difference or a portable latency guarantee.

Native Linux tests passed for wildcard/bound IPv4/IPv6, source-address retention,
TSIG, parallel requests and ancillary-buffer ownership/malformed data. Host
race tests and vet passed, but host race tests exclude Linux-specific code;
no native Linux race run is claimed. Full candidate source is archived as JSON.

The experiment was removed from active runtime sources because it did not meet
the no-loss-regression requirement. Production was not updated. Reduced design
allocation overhead is not being claimed as a measured end-to-end CPU win.

# Full DNS network path, 2026-11-06

The network benchmark starts an isolated DNS listener on an ephemeral loopback port. Parallel clients send prepacked requests and read raw replies. It includes server Unpack/Resolve/Pack/socket work and client socket/scheduler costs. The production listener/configuration is untouched. Linux measurements ran on dev.kislovs.ru (3 vCPU), GOMAXPROCS=3; local packing measurements ran on Apple M4. These are closed-loop/cohosted measurements, not remote-client saturation or p95/p99 results.

## Findings

Linux CPU samples were dominated by syscalls (approximately 54–56% flat), with additional scheduler/netpoll work. DNS parsing remains visible. A single synchronous loopback request costs much more than constructing its response.

The first candidate reused a 4096-byte response packing buffer through sync.Pool. It removed 80 bytes and one allocation per small reply, but local serialization got slower (approximately 141–145 ns allocating versus 150–168 ns pooled). Linux alternating runs likewise did not show a throughput win. This candidate was **rejected**; production still uses the standard DNS WriteMsg/Pack path, including TSIG. Its small packing prototype remains only in BenchmarkResponsePacking for reproducibility.

The retained change allocates a local reply and its one-question section together. Protocol tests compare flags, opcode, question and wire representation with dns.Msg.SetReply, including malformed multi-question inputs and ownership independence.

Measured allocation changes:

- Primary AnswerAs, logging off: 264 → 256 B/op, 5 → 4 allocs/op.
- Blocked AnswerAs, logging off: 168 → 160 B/op, 2 → 1 allocs/op.
- Complete loopback path: one allocation fewer for both UDP and TCP.

In the two alternating retained-change runs, primary processing was 1042–1349 ns/op versus 1254–1484 baseline; blocked processing 771–846 versus 835–894. This is encouraging for construction overhead, but too few noisy samples for a precise speedup claim. Total UDP/TCP time remained within the range of host variability. No material overall QPS increase is claimed.

## Files and reproduction

`linux-before.txt` and `linux-after.txt` are three profiled repeats before/after the rejected packing pool. `linux-alternating.txt` orders candidates: before, pool, pool, before, before, pool. `linux-combined.txt` orders candidates: before, retained combined allocation, retained, before. `before/after-*-top.txt` summarize the rejected pool profiles. `packing.txt` and `local-before.txt` are macOS measurements.

Run `go test ./internal/core -run '^$' -bench BenchmarkNetworkDNS -benchtime=3s -count=3 -cpuprofile=/tmp/network.cpu -memprofile=/tmp/network.mem` with GOMAXPROCS=3. The harness is in `internal/core/network_benchmark_test.go`; the serialization prototype is in `internal/core/packing_benchmark_test.go`.

Next meaningful experiment: separate load generator and Linux receive/send batching, with latency percentiles and mixed response sizes. The current shared-host profile does not justify replacing miekg/dns socket handling in this release.

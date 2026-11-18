# dev.kislovs.ru deployment — 2026-11-18

Deployed at 07:49 MSK on explicit user request. The production service now runs
exactly the tested Linux amd64 candidate associated with source commit 23a3c32,
built with `gdns_udp_addrport` (without `gdns_dnssec_mixed`). No rebuild or
version stamping was performed. Its embedded version is `dev (unknown; unknown)`;
the SHA-256 below identifies the deployed artifact unambiguously.

- Previous binary: `8325c7934322aba54242d591717962708acf366f0a612fd44a16e7a312b5c7f0`.
- Installed binary: `cb9851bcd8db5b3b1b249b14901f9e3b355c86b2f7d16e98fed9cc8069731770`.
- Root-only backup: `/var/backups/gdns/20261118T044931Z-23a3c32`.
- Backup includes the old executable and top-level operational state files,
  including SQLite/configuration/credentials, copied while the service was stopped.
  Credentials and database contents are not included in this repository.

The candidate hash was checked before and after installation. The executable was
replaced atomically, and systemd restarted the service. Configuration and service
settings were preserved (recursive mode, DNSSEC enabled, automatic UDP workers).
The deploy script included rollback on startup or validation failure; rollback
was not needed. Follow-up status: active, PID 1706737, NRestarts=0.

Twelve before/after protocol checks passed: UDP/TCP A, authenticated A/AAAA/DNSKEY,
a signed negative response, bogus-chain SERVFAIL, CD bypass without AD, and
valid/bogus answers via both DoH and DoT. TLS certificates were verified against
the configured certificate and hostname dev.kislovs.ru. Web root returned HTTP
200; an additional steady-state query returned AD. Results are in
[dev-23a3c32.json](dev-23a3c32.json).

This records functional post-deployment checks, not a new production load test.
Historical benchmark notes saying production was unchanged refer to the period
before this explicitly requested deployment.

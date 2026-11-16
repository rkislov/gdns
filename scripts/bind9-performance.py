#!/usr/bin/env python3
# Copyright 2026 Кислов Роман Сергеевич
# SPDX-License-Identifier: Apache-2.0
"""Native Linux Docker comparison (ARM64 by default). No public listeners or production changes.
Acceptance load fixed before measurements: warm UDP, 15000 QPS, 8 seconds,
5 control repeats. Additional rates 5000/30000 and TCP/miss/mixed are diagnostics.
"""
import argparse, json, pathlib, subprocess as sp, tempfile, time, os, statistics, hashlib, shutil
p = argparse.ArgumentParser()
p.add_argument('--out', required=True)
modes = p.add_mutually_exclusive_group()
modes.add_argument('--quick', action='store_true')
modes.add_argument('--control-only', action='store_true')
modes.add_argument('--profile-only', action='store_true')
p.add_argument('--arch', default='arm64')
p.add_argument('--server-cpus', default='2,3')
p.add_argument('--client-cpus', default='0,1')
p.add_argument('--auth-cpus', default='4,5')
p.add_argument('--workers', type=int, default=2)
p.add_argument('--prebuilt-dir')
p.add_argument('--pacing', choices=['spin','sleep'], default='spin')
a = p.parse_args()
root = pathlib.Path(__file__).resolve().parents[1]
out = pathlib.Path(a.out).resolve()
out.mkdir(parents=True, exist_ok=True)
if (out / 'raw.json').exists() or (out / 'metadata.json').exists():
    raise SystemExit('Use a new output directory; existing results are preserved')
lab = pathlib.Path(tempfile.mkdtemp(prefix='gdns-bind-perf-')).resolve()
image = 'gdns-performance-bind:local'
network = 'gdns-bind-perf-' + str(os.getpid())
server = network + '-server'
auth = network + '-auth'
client = network + '-client'
prefix = '172.29.94.'

def run(cmd, **kw):
    return sp.check_output(cmd, text=True, **kw).strip()

def docker(*args):
    return run(['docker', *args])

def remove(name):
    sp.run(['docker', 'rm', '-f', name], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
host_arch = docker('info', '--format', '{{.Architecture}}')
host_arch = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(host_arch, host_arch)
if host_arch != a.arch:
    raise SystemExit('Native Docker architecture required; emulation invalidates comparison')
if int(docker('info', '--format', '{{.NCPU}}')) <= max(map(int, (a.server_cpus + ',' + a.client_cpus + ',' + a.auth_cpus).split(','))):
    raise SystemExit('Insufficient CPUs for requested affinity')
env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=a.arch)
base = lab / 'baseline'
base.mkdir()
source_metadata = None
if a.prebuilt_dir:
    source = pathlib.Path(a.prebuilt_dir)
    source_metadata = json.loads((source / 'source.json').read_text())
    for name in ['baseline-bin', 'candidate', 'load'] + (['baseline-profile', 'candidate-profile'] if a.profile_only else []):
        shutil.copy2(source / name, lab / name)
else:
    archive = sp.Popen(['git', 'archive', 'cce7c27'], cwd=root, stdout=sp.PIPE)
    sp.run(['tar', '-x', '-C', str(base)], stdin=archive.stdout, check=True)
    archive.stdout.close()
    assert archive.wait() == 0
    for name, source, package in [('baseline', base, './cmd/gdns'), ('candidate', root, './cmd/gdns'), ('load', root, './cmd/gdns-loadtest')]:
        sp.run(['go', 'build', '-trimpath', '-o', str(lab / name) if name != 'baseline' else str(lab / 'baseline-bin'), package], cwd=source, env=env, check=True)
if a.profile_only and (not a.prebuilt_dir):
    for impl, source in [('baseline', base), ('candidate', root)]:
        original = source / 'cmd/gdns/main.go'
        patched = lab / (impl + '-profile-main.go')
        hook = 'func main() {\n runtime.MemProfileRate=4096\n go func(){time.Sleep(4*time.Second);prefix:=os.Getenv("GDNS_PROFILE");runtime.GC();base,err:=os.Create(prefix+"-start.mem");if err!=nil{panic(err)};pprof.Lookup("allocs").WriteTo(base,0);base.Close();f,err:=os.Create(prefix+".cpu");if err!=nil{panic(err)};if err=pprof.StartCPUProfile(f);err!=nil{panic(err)};runtime.SetMutexProfileFraction(1);runtime.SetBlockProfileRate(1000000);time.Sleep(8*time.Second);pprof.StopCPUProfile();f.Close();runtime.GC();f,err=os.Create(prefix+".mem");if err!=nil{panic(err)};pprof.Lookup("allocs").WriteTo(f,0);f.Close();for _,kind:=range []string{"mutex","block"}{f,err=os.Create(prefix+"."+kind);if err!=nil{panic(err)};pprof.Lookup(kind).WriteTo(f,0);f.Close()}}()\n'
        patched.write_text(original.read_text().replace('import (', 'import (\n"runtime"\n"runtime/pprof"', 1).replace('func main() {', hook, 1))
        overlay = lab / (impl + '-overlay.json')
        overlay.write_text(json.dumps({'Replace': {str(original): str(patched)}}))
        sp.run(['go', 'build', '-overlay', str(overlay), '-trimpath', '-o', str(lab / (impl + '-profile')), './cmd/gdns'], cwd=source, env=env, check=True)
(lab / 'auth.zone').write_text('$TTL 3600\n@ IN SOA ns.bench.test. hostmaster.bench.test. (1 3600 600 86400 3600)\n@ IN NS ns.bench.test.\nns IN A 192.0.2.53\n' + ''.join((f'n{i} IN A 192.0.2.1\n' for i in range(512))) + '*.miss IN A 192.0.2.1\naaaa IN AAAA 2001:db8::1\nalias IN CNAME n0.bench.test.\n_service._tcp IN SRV 0 100 389 n0.bench.test.\n')
opts = 'directory "/tmp"; listen-on { any; }; listen-on-v6 { none; }; allow-query { any; }; dnssec-validation no; minimal-responses yes;'
(lab / 'auth.conf').write_text('options { ' + opts + ' recursion no; }; controls {}; zone "bench.test" { type primary; file "/lab/auth.zone"; };')
(lab / 'bind.conf').write_text('options { ' + opts + ' recursion yes; allow-recursion { any; }; forward only; forwarders { ' + prefix + '10; }; max-cache-size 64m; stale-answer-enable no; prefetch 0; }; controls {};')
config = {'dns_listen': '0.0.0.0:53', 'http_listen': '127.0.0.1:8080', 'mode': 'forward', 'upstreams': [prefix + '10:53'], 'allowed_clients': [prefix + '0/24'], 'udp_workers': a.workers, 'query_log': False, 'query_log_limit': 100, 'cache_size': 10000, 'dnssec_validation': False, 'zones': [], 'blocked': [], 'feeds': []}
(lab / 'gdns.json').write_text(json.dumps(config))
for f in ['auth.zone', 'auth.conf', 'bind.conf', 'gdns.json']:
    (out / f).write_bytes((lab / f).read_bytes())

def container(name, ip, cpus, entry, args):
    return docker('run', '-d', '--name', name, '--platform', 'linux/' + a.arch, '--network', network, '--ip', prefix + str(ip), '--cpuset-cpus', cpus, '--memory', '512m', '-v', str(out) + ':/results', '-e', 'GOMAXPROCS=' + str(a.workers if name != client else 2), '-v', str(lab) + ':/lab:ro', '--entrypoint', entry, image, *args)

def udp_stats(name):
    lines = docker('exec', name, 'cat', '/proc/net/snmp').splitlines()
    headers = next((i for i, x in enumerate(lines) if x.startswith('Udp:')))
    return dict(zip(lines[headers].split()[1:], map(int, lines[headers + 1].split()[1:])))

def host_cpu():
    return {line.split()[0]: list(map(int, line.split()[1:])) for line in pathlib.Path('/proc/stat').read_text().splitlines() if line.startswith('cpu')}

def cpu():
    return int(dict((line.split() for line in docker('exec', server, 'cat', '/sys/fs/cgroup/cpu.stat').splitlines()))['usage_usec'])

def load(rate, seconds, transport, mode, prime=False):
    return docker('exec', client, '/lab/load', '-pacing', a.pacing, '-server', prefix + '11:53', '-rate', str(rate), '-seconds', str(seconds), '-transport', transport, '-mode', mode, *(['-prime'] if prime else []))
rows = []
metadata = {'baseline_commit': source_metadata.get('baseline_commit', 'cce7c27') if source_metadata else 'cce7c27', 'candidate_commit': source_metadata['candidate_commit'] if source_metadata else run(['git', 'rev-parse', 'HEAD'], cwd=root), 'candidate_diff': source_metadata['candidate_diff'] if source_metadata else run(['git', 'diff'], cwd=root), 'image': json.loads(docker('image', 'inspect', image))[0]['Id'], 'architecture': 'linux/' + a.arch, 'resolver_cpus': a.server_cpus, 'client_cpus': a.client_cpus, 'auth_cpus': a.auth_cpus, 'workers': a.workers, 'memory_limit': '512m', 'acceptance_qps': 15000, 'ttl': 3600, 'working_set': 512, 'log': False, 'dnssec': False, 'lab': str(lab), 'go_version': source_metadata['go_version'] if source_metadata else run(['go', 'version']), 'docker_version': docker('version', '--format', '{{.Server.Version}}'), 'kernel': docker('info', '--format', '{{.KernelVersion}}')}
if source_metadata and 'candidate_untracked_sources' in source_metadata:
    metadata['candidate_untracked_sources'] = source_metadata['candidate_untracked_sources']
metadata['pacing'] = a.pacing
metadata['binary_sha256'] = {name: hashlib.sha256((lab / name).read_bytes()).hexdigest() for name in ['baseline-bin', 'candidate', 'load']}
(out / 'metadata.json').write_text(json.dumps(metadata, indent=2))
docker('network', 'create', '--internal', '--subnet', prefix + '0/24', network)
try:
    container(auth, 10, a.auth_cpus, 'named', ['-g', '-n', str(a.workers), '-c', '/lab/auth.conf'])
    container(client, 20, a.client_cpus, 'sleep', ['36000'])
    time.sleep(1)
    (out / 'bind-version.txt').write_text(docker('exec', auth, 'named', '-V'))
    scenarios = [('udp', 'warm', 15000, 5, 8), ('udp', 'warm', 5000, 3, 8), ('udp', 'warm', 30000, 3, 8), ('tcp', 'warm', 5000, 3, 5), ('udp', 'miss', 1000, 3, 5), ('udp', 'mixed', 5000, 3, 5)]
    if a.control_only:
        scenarios = scenarios[:1]
    if a.profile_only:
        for impl in ['baseline', 'candidate']:
            remove(server)
            container(server, 11, a.server_cpus, '/bin/sh', ['-c', f'cp /lab/gdns.json /tmp/gdns.json; GDNS_PROFILE=/results/{impl} exec /lab/{impl}-profile -config /tmp/gdns.json -database /tmp/gdns.db -metrics-listen ""'])
            for attempt in range(30):
                try:
                    load(100, 1, 'udp', 'warm', True)
                    break
                except sp.CalledProcessError:
                    time.sleep(0.3)
            before = udp_stats(server)
            (out / (impl + '-load.json')).write_text(load(15000, 15, 'udp', 'warm'))
            after = udp_stats(server)
            (out / (impl + '-udp.json')).write_text(json.dumps({k: after[k] - before[k] for k in before}, indent=2))
        for impl in ['baseline', 'candidate']:
            for suffix in ['.cpu', '-start.mem', '.mem']:
                if not (out / (impl + suffix)).is_file():
                    raise RuntimeError('Missing profiling artifact: ' + impl + suffix)
        scenarios = []
    if a.quick:
        scenarios = [('udp', 'warm', 15000, 3, 5)]
    for transport, mode, rate, repeats, duration in scenarios:
        for repeat in range(repeats):
            impls = ['bind', 'baseline', 'candidate']
            impls = impls[repeat % 3:] + impls[:repeat % 3]
            for impl in impls:
                remove(server)
                if impl == 'bind':
                    container(server, 11, a.server_cpus, 'named', ['-g', '-n', str(a.workers), '-c', '/lab/bind.conf'])
                else:
                    container(server, 11, a.server_cpus, '/bin/sh', ['-c', f'''cp /lab/gdns.json /tmp/gdns.json; exec /lab/{('baseline-bin' if impl == 'baseline' else 'candidate')} -config /tmp/gdns.json -database /tmp/gdns.db -metrics-listen ""'''])
                for attempt in range(30):
                    try:
                        load(100, 1, transport, 'warm', True)
                        break
                    except sp.CalledProcessError:
                        time.sleep(0.3)
                else:
                    raise RuntimeError('startup failed ' + impl)
                if repeat == 0:
                    check = json.loads(docker('exec', client, '/lab/load', '-server', prefix + '11:53', '-transport', transport, '-check'))
                    (out / f'functional-{impl}-{transport}-{mode}-{rate}.json').write_text(json.dumps(check, indent=2))
                load(rate, 2, transport, 'warm')
                time.sleep(0.2)
                server_udp_before = udp_stats(server)
                client_udp_before = udp_stats(client)
                host_before = host_cpu() if pathlib.Path('/proc/stat').exists() else {}
                before = cpu()
                row = json.loads(load(rate, duration, transport, mode))
                after = cpu()
                server_udp_after = udp_stats(server)
                client_udp_after = udp_stats(client)
                host_after = host_cpu() if host_before else {}
                row['host_cpu_ticks_delta'] = {k: [b - a for a, b in zip(host_before[k], host_after[k])] for k in host_before}
                row['server_udp_delta'] = {k: server_udp_after[k] - server_udp_before[k] for k in server_udp_before}
                row['client_udp_delta'] = {k: client_udp_after[k] - client_udp_before[k] for k in client_udp_before}
                row.update(impl=impl, repeat=repeat, cpu_cores=(after - before) / 1000000.0 / (duration + 0.1), memory_bytes=int(docker('exec', server, 'cat', '/sys/fs/cgroup/memory.current')))
                rows.append(row)
                (out / 'raw.json').write_text(json.dumps(rows, indent=2))
                print(json.dumps(row), flush=True)
finally:
    for name in [server, client, auth]:
        remove(name)
    sp.run(['docker', 'network', 'rm', network], stdout=sp.DEVNULL)
if a.profile_only:
    raise SystemExit(0)
control = [r for r in rows if r['transport'] == 'udp' and r['mode'] == 'warm' and (r['target_qps'] == 15000)]
medians = {impl: statistics.median((r['p95_ms'] for r in control if r['impl'] == impl)) for impl in ['bind', 'baseline', 'candidate']}
errors = {impl: sum((r['errors'] + r['timeouts'] for r in control if r['impl'] == impl)) for impl in medians}
qps = {impl: statistics.median((r['qps'] for r in control if r['impl'] == impl)) for impl in medians}
checks = {
    'p95_twenty_percent_better_than_bind': medians['candidate'] <= 0.8 * medians['bind'],
    'p95_better_than_baseline': medians['candidate'] < medians['baseline'],
    'loss_not_worse': errors['candidate'] <= min(errors['bind'], errors['baseline']),
    'comparable_goodput': min(qps.values()) >= 0.99 * 15000 and min(qps.values()) >= 0.99 * max(qps.values()),
    'full_control_repeats': all(sum(r['impl'] == impl for r in control) >= 5 for impl in medians),
}
summary = {'p95_medians_ms': medians, 'candidate_bind_ratio': medians['candidate'] / medians['bind'], 'errors': errors, 'qps_medians': qps, 'acceptance_checks': checks, 'acceptance_met': all(checks.values())}
(out / 'summary.json').write_text(json.dumps(summary, indent=2))
print(json.dumps(summary))

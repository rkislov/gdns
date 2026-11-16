#!/usr/bin/env python3
# Copyright 2026 Кислов Роман Сергеевич
# SPDX-License-Identifier: Apache-2.0
"""Summarize raw trials without selecting favorable repeats."""
import argparse
import json
import pathlib
import statistics

parser = argparse.ArgumentParser()
parser.add_argument('directory', type=pathlib.Path)
args = parser.parse_args()
rows = json.loads((args.directory / 'raw.json').read_text())
groups = {}
for row in rows:
    key = (row['transport'], row['mode'], row['target_qps'], row['impl'])
    groups.setdefault(key, []).append(row)
summary = []
for (transport, mode, rate, impl), trials in groups.items():
    result = dict(transport=transport, mode=mode, target_qps=rate,
                  impl=impl, repeats=len(trials))
    for field in ('p50_ms', 'p95_ms', 'p99_ms', 'qps', 'cpu_cores', 'memory_bytes',
                  'send_lateness_p95_ms', 'send_lateness_p99_ms'):
        if all(field in row for row in trials):
            result[field + '_median'] = statistics.median(row[field] for row in trials)
    for field in ('sent', 'ok', 'errors', 'timeouts'):
        result[field] = sum(row[field] for row in trials)
    result['p95_ms_min'] = min(row['p95_ms'] for row in trials)
    result['p95_ms_max'] = max(row['p95_ms'] for row in trials)
    steals = []
    for row in trials:
        ticks = row.get('host_cpu_ticks_delta', {}).get('cpu')
        if ticks and sum(ticks):
            steals.append(100 * ticks[7] / sum(ticks))
    if steals:
        result['host_steal_percent_median'] = statistics.median(steals)
    summary.append(result)
output = args.directory / 'all-scenarios-summary.json'
output.write_text(json.dumps(summary, indent=2) + '\n')
print(output)

control = {impl: [row for row in rows if row['impl'] == impl and
                 row['transport'] == 'udp' and row['mode'] == 'warm' and
                 row['target_qps'] == 15000] for impl in ('bind', 'candidate')}
complete = all(len(trials) == 5 and all(row['seconds'] == 8 for row in trials)
               for trials in control.values())
evaluation = {'complete_control': complete, 'acceptance_met': False}
if complete:
    qps = {impl: statistics.median(row['qps'] for row in trials)
           for impl, trials in control.items()}
    latency = {impl: statistics.median(row['p95_ms'] for row in trials)
               for impl, trials in control.items()}
    errors = {impl: sum(row['errors'] + row['timeouts'] for row in trials)
              for impl, trials in control.items()}
    comparable = (min(qps.values()) >= .99 * 15000 and
                  abs(qps['candidate'] - qps['bind']) <= .01 * qps['bind'])
    evaluation.update(qps_medians=qps, p95_medians_ms=latency, errors=errors,
                      comparable_goodput=comparable,
                      candidate_bind_ratio=latency['candidate'] / latency['bind']
                      if latency['bind'] else None,
                      acceptance_met=comparable and latency['bind'] > 0 and
                      latency['candidate'] <= .8 * latency['bind'] and
                      errors['candidate'] <= errors['bind'])
(args.directory / 'acceptance-evaluation.json').write_text(
    json.dumps(evaluation, indent=2) + '\n')

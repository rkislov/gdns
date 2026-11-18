#!/usr/bin/env python3
# Copyright 2026 Кислов Роман Сергеевич
# SPDX-License-Identifier: Apache-2.0
"""Isolated loopback DNSSEC transport validation; run after other load tests."""
import argparse,hashlib,json,os,pathlib,subprocess as sp,time,statistics
p=argparse.ArgumentParser();p.add_argument('--stage',required=True);p.add_argument('--binaries');p.add_argument('--profile',action='store_true');p.add_argument('--mode',choices=['warm','mixed','miss']);p.add_argument('--repeats',type=int,default=3);p.add_argument('--seconds',type=int,default=5);p.add_argument('--out',required=True);a=p.parse_args()
stage=pathlib.Path(a.stage).resolve();out=pathlib.Path(a.out).resolve();out.mkdir(mode=0o700,exist_ok=False)
binary_dir=pathlib.Path(a.binaries).resolve() if a.binaries else stage/'packet'
source=json.loads((binary_dir/'source.json').read_text())
metadata={'baseline_commit':source['baseline_commit'],'candidate_source':source,'resolver_cpus':'0,1','client_cpus':'2','fixture_cpus':'0','workers':2,'dnssec':True,'request_do':False,'request_ad':True,'fixture_shares_resolver_cpu':True,'bind_comparison':False,'profiling':a.profile}
binary_names={'baseline-bin': 'baseline-profile' if a.profile else 'baseline-bin', 'candidate': 'candidate-profile' if a.profile else 'candidate'}
metadata['runner_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
metadata['requested_mode']=a.mode
metadata['repeats']=1 if a.profile else a.repeats
metadata['seconds']=15 if a.profile else a.seconds
metadata['sha256']={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in {'baseline-bin':binary_dir/binary_names['baseline-bin'],'candidate':binary_dir/binary_names['candidate'],'load':stage/'gdns-secure-load','fixture':stage/'gdns-secure-fixture'}.items()}
(out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
processes=[];rows=[]
def start(args,cpus,log,extra=None):
 f=open(out/log,'w');proc=sp.Popen(['taskset','-c',cpus,*args],env=dict(os.environ,GOMAXPROCS='2',**(extra or {})),stdout=f,stderr=sp.STDOUT);f.close();processes.append(proc);return proc
def stop(proc):
 if proc.poll() is None:
  proc.terminate()
  try:proc.wait(timeout=10)
  except sp.TimeoutExpired:proc.kill();proc.wait()
def run(args):return sp.check_output(args,text=True,timeout=40)
def cpu_times():
 return {fields[0]:[int(x) for x in fields[1:9]] for line in pathlib.Path('/proc/stat').read_text().splitlines() if (fields:=line.split()) and fields[0] in ['cpu0','cpu1','cpu2']}
def load(mode,rate,seconds,prime=False):
 return json.loads(run(['taskset','-c','2',str(stage/'gdns-secure-load'),'-server','127.0.0.1:1253','-pacing','sleep','-zone','cache.bench.invalid.','-answer-ip','192.0.2.77','-require-ad','-mode',mode,'-rate',str(rate),'-seconds',str(seconds)]+(['-prime'] if prime else [])) or '{}')
try:
 fixture=start([str(stage/'gdns-secure-fixture'),'-listen','127.0.0.1:1254','-anchor',str(out/'anchor'),'-bogus-name','bogus.cache.bench.invalid.'],'0','fixture.private.log')
 for _ in range(100):
  if (out/'anchor').exists():break
  if fixture.poll() is not None:raise RuntimeError('fixture exited')
  time.sleep(.1)
 anchor=(out/'anchor').read_text().strip()
 config={'dns_listen':'127.0.0.1:1253','http_listen':'127.0.0.1:1280','mode':'forward','upstreams':['127.0.0.1:1254'],'allowed_clients':['127.0.0.0/8'],'udp_workers':2,'query_log':False,'cache_size':10000,'dnssec_validation':True,'dnssec':{'auto_update':{'enabled':False},'trust_anchors':['. 3600 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',anchor]},'zones':[],'blocked':[],'feeds':[]}
 cases=[('mixed',5000)] if a.profile else [('warm',5000),('mixed',5000),('miss',500)]
 if a.mode: cases=[case for case in cases if case[0]==a.mode]
 for mode,rate in cases:
  for repeat in range(1 if a.profile else a.repeats):
   for impl in (['baseline-bin','candidate'] if repeat%2==0 else ['candidate','baseline-bin']):
    tag=f'{mode}-{repeat}-{impl}';cfg=out/(tag+'.private.json');cfg.write_text(json.dumps(config));cfg.chmod(0o600)
    server=start([str(binary_dir/binary_names[impl]),'-config',str(cfg),'-database',str(out/(tag+'.db')),'-metrics-listen',''],'0,1',tag+'.private.log',{'GDNS_PROFILE':str(out/tag)} if a.profile else None)
    try:
     for _ in range(50):
      if server.poll() is not None:raise RuntimeError('resolver exited')
      try:answer=run(['dig','@127.0.0.1','-p','1253','cache.bench.invalid.','A','+dnssec','+time=1','+tries=1'])
      except sp.CalledProcessError:
       time.sleep(.1);continue
      if 'status: NOERROR' in answer and ' ad;' in answer and '192.0.2.77' in answer:break
      time.sleep(.1)
     else:raise RuntimeError('validated AD answer absent')
     bogus=run(['dig','@127.0.0.1','-p','1253','bogus.cache.bench.invalid.','A','+dnssec','+time=2','+tries=1'])
     if 'status: SERVFAIL' not in bogus:raise RuntimeError('invalid signature accepted')
     load('warm',100,1,True)
     before=cpu_times()
     row=load(mode,rate,15 if a.profile else a.seconds)
     after=cpu_times()
     row['cpu_steal_fraction']={cpu:(after[cpu][7]-values[7])/max(1,sum(after[cpu])-sum(values)) for cpu,values in before.items()}
     row.update(impl=impl,repeat=repeat,valid_ad_probe=True,bogus_servfail_probe=True);rows.append(row)
     (out/'raw.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps(row),flush=True)
    finally:stop(server)
 summary={mode:{impl:{'p95_ms':statistics.median(x['p95_ms'] for x in rows if x['mode']==mode and x['impl']==impl),'losses':sum(x['errors']+x['timeouts'] for x in rows if x['mode']==mode and x['impl']==impl)} for impl in ['baseline-bin','candidate']} for mode,_ in cases}
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary),flush=True)
finally:
 for proc in reversed(processes):stop(proc)

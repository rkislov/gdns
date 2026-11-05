#!/usr/bin/env python3
# Copyright 2026 Кислов Роман Сергеевич
# SPDX-License-Identifier: Apache-2.0
"""Bounded dnsperf tests on the authorized dev host; restore configuration finally.

Run as root on dev.kislovs.ru. This changes the running administrative config
while testing, stores a private recovery backup, and restores it on completion.
All traffic is synthetic and local to the same host. No external names are flooded.
"""
import datetime,json,os,re,subprocess,time,urllib.request
from pathlib import Path

BASE='http://127.0.0.1:8080/api/'
TOKEN=Path('/var/lib/ghole/config.json.token').read_text().strip()
OUT=Path('/var/lib/ghole/benchmarks/2026-11-05')
OUT.mkdir(parents=True,exist_ok=True);OUT.chmod(0o700)
rows=[]

def request(path,data=None,etag=None):
    headers={'Authorization':'Bearer '+TOKEN}
    if etag: headers['If-Match']=etag
    req=urllib.request.Request(BASE+path,data=None if data is None else json.dumps(data,separators=(',',':')).encode(),headers=headers,method='GET' if data is None else 'PUT')
    with urllib.request.urlopen(req,timeout=180) as r:return json.load(r),r.headers.get('ETag')

def apply(c):
    _,etag=request('config')
    request('config',c,etag)

def metric(text,key):
    m=re.search(r'^\s*'+re.escape(key)+r':\s*([0-9.]+)',text,re.M)
    return float(m.group(1)) if m else None

def run(name,mode,rate,file,duration=10,outstanding=512):
    args=['dnsperf','-m',mode,'-s','45.87.247.8','-a','127.0.0.1','-d',str(file),'-c','8','-T','2','-q',str(outstanding),'-Q',str(rate),'-l',str(duration),'-t','1','-O','latency-histogram']
    if mode=='dot':args+=['-p','853','-O','tls-sni=dev.kislovs.ru']
    elif mode=='doh':args+=['-p','443','-O','tls-sni=dev.kislovs.ru','-O','doh-uri=https://dev.kislovs.ru/dns-query','-O','doh-method=POST']
    else:args+=['-p','53']
    started=datetime.datetime.now(datetime.timezone.utc).isoformat()
    result=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=duration+15)
    text=result.stdout;(OUT/(name+'.txt')).write_text(text)
    row={'name':name,'transport':mode,'target_qps':rate,'duration_seconds':duration,'started_utc':started,'exit_code':result.returncode,'sent':metric(text,'Queries sent'),'completed':metric(text,'Queries completed'),'lost':metric(text,'Queries lost'),'qps':metric(text,'Queries per second'),'average_ms':None,'command':args}
    value=metric(text,'Average Latency (s)');row['average_ms']=None if value is None else value*1000
    m=re.search(r'Response codes:\s*(.+)',text);row['response_codes']=m.group(1).strip() if m else None
    row['process']=subprocess.check_output(['systemctl','show','ghole','-p','MemoryCurrent','-p','CPUUsageNSec','-p','TasksCurrent'],text=True).strip()
    rows.append(row);save();print(json.dumps(row),flush=True)
    if result.returncode!=0:raise RuntimeError(name+' failed; see raw output')
    if not row['completed']:raise RuntimeError(name+' returned no replies')
    if row['sent'] and (row['lost'] or 0)/row['sent']>0.01:return False
    time.sleep(1);return True

def save():
    report={'date':'2026-11-05','host':'dev.kislovs.ru','environment':{'os':subprocess.check_output(['uname','-srmo'],text=True).strip(),'vcpus':os.cpu_count(),'method':'dnsperf 2.14.0, client and server on same host; local synthetic traffic; 8 clients / 2 generator threads; server query log disabled'},'results':rows}
    (OUT/'results.json').write_text(json.dumps(report,indent=2)+'\n')

def main():
    global rows
    original,_=request('config');backup=OUT/'configuration.private.json';backup.write_text(json.dumps(original));backup.chmod(0o600)
    rows=[]
    corpus=OUT/'primary.txt';corpus.write_text('host.bench.invalid. A\n')
    split=OUT/'split.txt';split.write_text('split.bench.invalid. A\n')
    blocked=OUT/'blocked.txt';blocked.write_text('d999999.blocked.invalid. A\n')
    try:
        c=json.loads(json.dumps(original));c['query_log']=False
        c['zones'].append({'name':'bench.invalid.','kind':'primary','clients':[],'servers':[],'records':['bench.invalid. 60 IN SOA ns.bench.invalid. hostmaster.bench.invalid. 1 3600 600 86400 60','host.bench.invalid. 60 IN A 192.0.2.123','split.bench.invalid. 60 IN A 192.0.2.10'],'record_views':[{'clients':['127.0.0.0/28'],'records':['split.bench.invalid. 60 IN A 10.28.0.10']}]})
        apply(c)
        for rate in (5000,10000,20000,40000):
            if not run('primary_udp_'+str(rate),'udp',rate,corpus):break
        run('split_28_udp_10000','udp',10000,split)
        run('primary_tcp_2000','tcp',2000,corpus)
        run('primary_dot_1000','dot',1000,corpus)
        run('primary_doh_1000','doh',1000,corpus)
        # Build one million synthetic blocked domains; keep original blocking data.
        c['feeds'].append({'name':'loadtest-synthetic','url':'','enabled':True,'domains':['d'+str(i)+'.blocked.invalid' for i in range(1000000)]})
        apply(c)
        for rate in (10000,20000):
            if not run('million_blocklist_udp_'+str(rate),'udp',rate,blocked):break
    finally:
        apply(original)
        print('Original configuration restored.',flush=True)
        save()

if __name__=='__main__':
    main()

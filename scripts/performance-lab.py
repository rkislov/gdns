#!/usr/bin/env python3
# Copyright 2026 Кислов Роман Сергеевич
# SPDX-License-Identifier: Apache-2.0
"""Run bounded comparisons in an isolated instance on the authorized dev host.
Never changes the production configuration, listeners, clocks or trust state.
Raw configurations, tokens and the lab database stay private on the server.
"""
import argparse,copy,json,os,pathlib,pwd,re,secrets,signal,socket,ssl,struct,subprocess,time,urllib.request
P=argparse.ArgumentParser();P.add_argument('--binary',required=True);P.add_argument('--fixture',required=True);P.add_argument('--tag',required=True);P.add_argument('--workers',type=int,default=0);P.add_argument('--root',default='/var/lib/ghole/performance-lab');P.add_argument('--repeats',type=int,default=2);A=P.parse_args()
root=pathlib.Path(A.root)/A.tag;root.mkdir(parents=True,exist_ok=True);root.chmod(0o700);account=pwd.getpwnam('ghole');os.chown(root.parent,account.pw_uid,account.pw_gid);root.parent.chmod(0o700);os.chown(root,account.pw_uid,account.pw_gid)
rows=[];token=secrets.token_hex(32);processes=[]
def call(path,data=None):
 h={'Authorization':'Bearer '+token};method='GET'
 if data is not None:
  _,etag=call('config');h['If-Match']=etag;method='PUT'
 r=urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:1180/api/'+path,data=None if data is None else json.dumps(data,separators=(',',':')).encode(),headers=h,method=method),timeout=180)
 return json.load(r),r.headers.get('ETag')
def spawn(args,name,extra=None):
 env=dict(os.environ);env.update(extra or {});p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=open(root/(name+'.private.log'),'w'),stderr=subprocess.STDOUT,user=account.pw_uid,group=account.pw_gid,extra_groups=[],env=env,start_new_session=True);processes.append(p);return p
def stop(p):
 if p and p.poll() is None:
  p.send_signal(signal.SIGTERM)
  try:p.wait(timeout=20)
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
def ready(p):
 for _ in range(600):
  if p.poll() is not None:raise RuntimeError('lab process exited; inspect private log')
  try:
   s,_=call('status')
   if s['dnssec']['rfc5011']['state']=='healthy':return s
  except (OSError,KeyError):pass
  time.sleep(.25)
 raise RuntimeError('lab startup timed out')
def wire(name,do=True):
 q=struct.pack('!6H',1234,256,1,0,0,int(do))+b''.join(bytes([len(x)])+x.encode() for x in name.rstrip('.').split('.'))+b'\0'+struct.pack('!HH',1,1)
 if do:q+=b'\0'+struct.pack('!HHIH',41,1232,32768,0)
 return q
def probe(name,rcode=0,ad=False,ip=None):
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.settimeout(20);s.sendto(wire(name),('127.0.0.1',1153));packet=s.recv(65535)
 flags=struct.unpack('!H',packet[2:4])[0];assert flags&15==rcode and bool(flags&32)==ad,(name,flags)
 if ip:assert socket.inet_aton(ip) in packet,(name,'wrong split/primary answer')
def cpu(p):
 text=pathlib.Path('/proc/'+str(p.pid)+'/stat').read_text().rsplit(')',1)[1].split();return (int(text[11])+int(text[12]))/os.sysconf('SC_CLK_TCK')
def extract(text,key):
 m=re.search(r'^\s*'+re.escape(key)+r':\s*([0-9.]+)',text,re.M);return float(m.group(1)) if m else None
def save():
 (root/'results.json').write_text(json.dumps({'tag':A.tag,'binary':subprocess.check_output([A.binary,'-version'],text=True).strip(),'configured_udp_workers':A.workers,'environment':{'os':subprocess.check_output(['uname','-srmo'],text=True).strip(),'vcpus':os.cpu_count(),'method':'isolated process; generator and signed fixture share the host; query journal and Prometheus enabled; no production settings changed'},'results':rows},indent=2)+'\n')
def run(p,label,name,rate,repeat,mode='udp'):
 corpus=root/(label+'.queries.txt');corpus.write_text(name+' A\n')
 args=['dnsperf','-m',mode,'-s','127.0.0.1','-p',str(1853 if mode=='dot' else 1153),'-D','-d',str(corpus),'-c','8','-T','2','-q','128','-Q',str(rate),'-l','5','-t','1']
 if mode=='dot':args+=['-O','tls-sni=dev.kislovs.ru']
 before,_=call('status');startcpu=cpu(p);start=time.monotonic()
 result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20);elapsed=time.monotonic()-start;cpu_used=cpu(p)-startcpu;after,_=call('status')
 file=f'{label}_{mode}_{rate}_{repeat}.txt';(root/file).write_text(result.stdout)
 row={'case':label,'transport':mode,'target_qps':rate,'repeat':repeat,'sent':extract(result.stdout,'Queries sent'),'completed':extract(result.stdout,'Queries completed'),'lost':extract(result.stdout,'Queries lost'),'qps':extract(result.stdout,'Queries per second'),'average_ms':(extract(result.stdout,'Average Latency (s)') or 0)*1000,'maximum_ms':None,'server_cpu_seconds':cpu_used,'server_cpu_percent':round(100*cpu_used/elapsed,2),'udp_workers':after.get('udp_workers',1),'query_delta':after['queries']-before['queries'],'cache_hits':after['cache_hits']-before['cache_hits'],'rss_bytes':int(re.search(r'^VmRSS:\s*(\d+)',pathlib.Path('/proc/'+str(p.pid)+'/status').read_text(),re.M).group(1))*1024,'output':file,'command':args}
 codes=re.search(r'Response codes:\s*(.+)',result.stdout);row['response_codes']=codes.group(1) if codes else None
 maximum=re.search(r'Average Latency.*max ([0-9.]+)',result.stdout);row['maximum_ms']=float(maximum.group(1))*1000 if maximum else None
 assert result.returncode==0 and row['completed'] and row['sent'],result.stdout[-1500:]
 expected='NXDOMAIN' if label=='blocked_million' else 'NOERROR'
 assert row['response_codes'] and row['response_codes'].startswith(expected+' ') and '100.00%' in row['response_codes'],row
 rows.append(row);save();print(json.dumps(row),flush=True)
 # Stop escalating after >=1% losses; a bounded overload probe is enough.
 return row['lost']/row['sent']<.01
try:
 main_token=pathlib.Path('/var/lib/ghole/config.json.token').read_text().strip()
 original=json.load(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8080/api/config',headers={'Authorization':'Bearer '+main_token})))
 helper=spawn([A.fixture,'-listen','127.0.0.1:1154','-anchor',str(root/'fixture.anchor')],'fixture',{'GOMAXPROCS':'1'})
 for _ in range(100):
  if (root/'fixture.anchor').exists():break
  if helper.poll() is not None:raise RuntimeError('fixture exited')
  time.sleep(.05)
 c=copy.deepcopy(original);c.update(dns_listen='127.0.0.1:1153',http_listen='127.0.0.1:1180',doh_listen='127.0.0.1:1443',dot_listen='127.0.0.1:1853',udp_workers=A.workers,query_log=True)
 c['dnssec']['trust_anchors'].append((root/'fixture.anchor').read_text().strip());c['dnssec']['auto_update']['enabled']=True
 c['zones']=[z for z in c['zones'] if z['name'] not in ('bench.invalid.','cache.bench.invalid.')]
 c['zones'] += [{'name':'bench.invalid.','kind':'primary','clients':[],'servers':[],'records':['bench.invalid. 3600 IN SOA ns.bench.invalid. hostmaster.bench.invalid. 1 3600 600 86400 3600','host.bench.invalid. 3600 IN A 192.0.2.123','split.bench.invalid. 3600 IN A 192.0.2.10'],'record_views':[{'clients':['127.0.0.0/28'],'records':['split.bench.invalid. 3600 IN A 10.28.0.10']}]},{'name':'cache.bench.invalid.','kind':'forward','clients':[],'records':[],'servers':['127.0.0.1:1154']}]
 c['feeds'].append({'name':'performance-lab-synthetic','enabled':True,'domains':['d'+str(i)+'.blocked.invalid' for i in range(1000000)],'url':''})
 config=root/'config.private.json';config.write_text(json.dumps(c,separators=(',',':')));config.chmod(0o600);os.chown(config,account.pw_uid,account.pw_gid)
 p=spawn([A.binary,'-config',str(config),'-database',str(root/'ghole.db'),'-import-config','-metrics-listen','127.0.0.1:1190'],'server',{'GHOLE_ADMIN_TOKEN':token})
 state=ready(p);print('Ready',A.tag,'workers',state.get('udp_workers',1),flush=True)
 probe('host.bench.invalid.',ip='192.0.2.123');probe('split.bench.invalid.',ip='10.28.0.10');probe('d999999.blocked.invalid.',rcode=3);probe('cache.bench.invalid.',ad=True,ip='192.0.2.77')
 for label,name in [('primary','host.bench.invalid.'),('split_28','split.bench.invalid.'),('blocked_million','d999999.blocked.invalid.'),('secure_cache','cache.bench.invalid.')]:
  for rate in [5000,10000,20000,30000]:
   healthy=True
   for repeat in range(A.repeats):healthy=run(p,label,name,rate,repeat) and healthy
   if not healthy:break
 for mode,rate in [('tcp',4000),('dot',2000)]:
  for repeat in range(A.repeats):run(p,'primary','host.bench.invalid.',rate,repeat,mode)
 # Independent HTTP/2 measurement on the same loopback-only HTTPS listener.
 payload=root/'doh-query.bin';payload.write_bytes(wire('host.bench.invalid.'))
 req=urllib.request.Request('https://dev.kislovs.ru:1443/dns-query',data=payload.read_bytes(),headers={'Content-Type':'application/dns-message'})
 # The explicit TLS probe checks trust and SNI before h2load's throughput run.
 with socket.create_connection(('127.0.0.1',1443),timeout=10) as raw:
  with ssl.create_default_context().wrap_socket(raw,server_hostname='dev.kislovs.ru') as tls:assert tls.version()
 for repeat in range(A.repeats):
  args=['h2load','-n','20000','-c','4','-m','16','-t','1','--connect-to=127.0.0.1:1443','-d',str(payload),'-H','content-type: application/dns-message','https://dev.kislovs.ru:1443/dns-query']
  startcpu=cpu(p);result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60);used=cpu(p)-startcpu
  output=f'primary_doh_h2load_{repeat}.txt';(root/output).write_text(result.stdout);assert result.returncode==0 and '20000 succeeded' in result.stdout,result.stdout[-1500:]
  m=re.search(r'finished in .*?,\s*([0-9.]+) req/s',result.stdout);rows.append({'case':'primary','transport':'doh','repeat':repeat,'completed':20000,'qps':float(m.group(1)) if m else None,'server_cpu_seconds':used,'output':output,'command':args});save();print('DoH',A.tag,repeat,rows[-1]['qps'],flush=True)
 # Cold DNSSEC: bypass only the reply cache; validation and authenticated keys stay on.
 updated,_=call('config');updated['cache_size']=0;call('config',updated)
 for repeat in range(A.repeats):run(p,'dnssec_uncached','cache.bench.invalid.',500,repeat)
 print('PASS',A.tag,'rows',len(rows),flush=True)
finally:
 for process in reversed(processes):stop(process)
 if rows:save()

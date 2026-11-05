#!/usr/bin/env python3
# Copyright 2026 Кислов Роман Сергеевич
# SPDX-License-Identifier: Apache-2.0
"""Retest persistent transports and cross-check DoH with an independent HTTP/2 tool."""
import importlib.util,json,struct,subprocess,urllib.request
from pathlib import Path
spec=importlib.util.spec_from_file_location('loadtest',Path(__file__).with_name('loadtest-dev.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.OUT=m.OUT/'retest';m.OUT.mkdir(exist_ok=True);m.OUT.chmod(0o700)
original,_=m.request('config');backup=m.OUT/'configuration.private.json';backup.write_text(json.dumps(original));backup.chmod(0o600)
try:
 c=json.loads(json.dumps(original));c['query_log']=False;c['zones'].append({'name':'bench.invalid.','kind':'primary','clients':[],'servers':[],'records':['bench.invalid. 60 IN SOA ns.bench.invalid. hostmaster.bench.invalid. 1 3600 600 86400 60','host.bench.invalid. 60 IN A 192.0.2.123']});m.apply(c)
 corpus=m.OUT/'primary.txt';corpus.write_text('host.bench.invalid. A\n')
 m.run('primary_udp_5000_small_window','udp',5000,corpus,outstanding=128)
 m.run('primary_udp_10000_small_window','udp',10000,corpus,outstanding=128)
 m.run('persistent_tcp_2000','tcp',2000,corpus,outstanding=128)
 m.run('persistent_dot_1000','dot',1000,corpus,outstanding=128)
 name='host.bench.invalid';wire=struct.pack('!6H',0,256,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
 payload=m.OUT/'dns-query.bin';payload.write_bytes(wire)
 request=urllib.request.Request('https://dev.kislovs.ru/dns-query',data=wire,headers={'Content-Type':'application/dns-message'})
 response=urllib.request.urlopen(request,timeout=5).read();header=struct.unpack('!6H',response[:12]);assert header[1]&15==0 and header[3]>0,'DoH probe did not return successful DNS answer'
 args=['h2load','-n','10000','-c','8','-m','8','-t','1','-d',str(payload),'-H','content-type: application/dns-message','https://dev.kislovs.ru/dns-query']
 result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30);(m.OUT/'doh_http2_h2load.txt').write_text(result.stdout);print(result.stdout,flush=True)
 if result.returncode:raise RuntimeError('h2load failed')
finally:
 m.apply(original);m.save();print('Original configuration restored.',flush=True)

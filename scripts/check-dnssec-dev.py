#!/usr/bin/env python3
# Copyright 2026 Кислов Роман Сергеевич
# SPDX-License-Identifier: Apache-2.0
# Read-only smoke test for the authorized development deployment.
# Requires this client's source address to be allowed by the server DNS ACL.
import socket, ssl, struct, urllib.request, json, time
HOST='dev.kislovs.ru';IP='45.87.247.8'
context=ssl.create_default_context()
def query(name,do=True,cd=False,ad=False):
 labels=b''.join(bytes([len(x)])+x.encode() for x in name.rstrip('.').split('.'))+b'\0'
 flags=0x100|(0x10 if cd else 0)|(0x20 if ad else 0)
 packet=struct.pack('!6H',12345,flags,1,0,0,int(do))+labels+struct.pack('!HH',1,1)
 if do:packet+=b'\0'+struct.pack('!HHIH',41,1232,0x8000,0)
 return packet
def exact(s,n):
 b=b''
 while len(b)<n:
  part=s.recv(n-len(b))
  if not part:raise RuntimeError('short DNS stream')
  b+=part
 return b
def exchange(mode,data):
 if mode=='doh':
  r=urllib.request.Request('https://'+HOST+'/dns-query',data=data,headers={'Content-Type':'application/dns-message','Accept':'application/dns-message'})
  with urllib.request.urlopen(r,timeout=25,context=context) as response:
   assert response.headers.get_content_type()=='application/dns-message'
   return response.read()
 if mode=='udp':
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
   s.settimeout(25);s.sendto(data,(IP,53));return s.recv(65535)
 with socket.create_connection((IP,853 if mode=='dot' else 53),timeout=25) as raw:
  s=context.wrap_socket(raw,server_hostname=HOST) if mode=='dot' else raw
  with s:
   s.sendall(struct.pack('!H',len(data))+data);return exact(s,struct.unpack('!H',exact(s,2))[0])
cases=[('secure','cloudflare.com',True,False,False,0,True),('insecure','www.github.com',True,False,False,0,False),('bogus','dnssec-failed.org',True,False,False,2,False),('cd','dnssec-failed.org',True,True,False,0,False),('bogus-no-do','dnssec-failed.org',False,False,False,2,False),('secure-no-do','cloudflare.com',False,False,True,0,True),('nxdomain','gdns-does-not-exist-20261105.se',True,False,False,3,True),('primary','router.home.arpa',True,False,False,0,False)]
results=[]
for mode in ['udp','tcp','dot','doh']:
 for label,name,do,cd,ad,rcode,want_ad in cases:
  start=time.monotonic();packet=exchange(mode,query(name,do,cd,ad));identifier,flags,qd,an,ns,ar=struct.unpack('!6H',packet[:12])
  row=dict(transport=mode,case=label,rcode=flags&15,ad=bool(flags&0x20),cd=bool(flags&0x10),answers=an,ms=round((time.monotonic()-start)*1000,2))
  print(json.dumps(row),flush=True)
  assert identifier==12345 and flags&0x8000 and not flags&0x200 and qd==1 and flags&15==rcode and bool(flags&0x20)==want_ad,row
  assert not cd or flags&0x10,row
  results.append(row)
print('PASS',len(results),'DNSSEC transport checks',flush=True)

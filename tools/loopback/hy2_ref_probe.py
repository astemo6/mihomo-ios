#!/usr/bin/env python3
"""hy2-frag reference probe: the same UDP rungs as testHysteria2UDPEcho, sent through sing-box's OWN hysteria2
client (socks inbound :19080 -> hy2 outbound -> hy2-in :18006 -> echo :18081). Separates a server-side loss
(sing-box inbound) from one specific to the NativeCore client. Prints one "HY2REF" line."""
import socket,struct,time,sys
def assoc():
    t=socket.create_connection(("127.0.0.1",19080)); t.sendall(b"\x05\x01\x00"); t.recv(2)
    t.sendall(b"\x05\x03\x00\x01"+socket.inet_aton("0.0.0.0")+struct.pack(">H",0)); r=t.recv(10)
    port=struct.unpack(">H",r[8:10])[0]; return t,port
try:
    t,port=assoc()
except Exception as e:
    print("HY2REF socks failed", e); sys.exit(0)
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.settimeout(0.3)
hdr=b"\x00\x00\x00\x01"+socket.inet_aton("127.0.0.1")+struct.pack(">H",18081)
def pat(n,seed): return bytes(((j*13+seed*7)&0xff) for j in range(n))
def send(p): u.sendto(hdr+p,("127.0.0.1",port))
def collect(want,t=1.5):
    got=0;end=time.time()+t
    while time.time()<end and want:
        try: d,_=u.recvfrom(70000)
        except socket.timeout: continue
        p=d[10:]
        if p in want: want.remove(p); got+=1
    return got
def rung(name,payloads,gap=0):
    want=list(payloads)
    for p in payloads:
        send(p)
        if gap: time.sleep(gap/1000)
    out.append("%s:%d/%d" % (name, collect(want), len(payloads)))
out=[]
rung("warm",[b"x"*29])
rung("u1173",[pat(1173,1197)])
rung("u1276",[pat(1276,1300)])
rung("b3x976",[pat(976,1000+i) for i in range(3)])
rung("b8x976",[pat(976,2000+i) for i in range(8)])
for i in range(5): rung("f3000",[pat(3000,101+i)])
rung("f3000gap",[pat(3000,300+i) for i in range(2)],gap=10)
rung("b3x976g0",[pat(976,3000+i) for i in range(3)])
print("HY2REF " + " ".join(out), flush=True)

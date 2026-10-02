"""Finite-endpoint UDP NAT models with independent mapping/filtering controls.
All nft rules live in fixture-owned router namespaces, never the host namespace.
"""


RELAY = "198.18.0.2"
PRIVATE = "10.77.0.2"


def install(net, name, public, mapping, filtering, port_base=40000):
    # The two remote address classes and two destination port classes are enough
    # to distinguish EIM/ADM/APDM in this fixture, not a generic NAT emulator.
    mappings = [("", 40000)]
    if mapping == "adm":
        mappings = [(f"ip daddr {RELAY}", 40000), ("", 40001)]
    elif mapping == "apdm":
        mappings = [("udp dport { 9002, 40001, 40002 }", 40002), (f"ip daddr {RELAY}", 40000), ("", 40001)]
    mappings = [(condition, port + port_base - 40000) for condition, port in mappings]
    allow = {
        "eif": "udp dport @opened",
        "adf": "udp dport . ip saddr @allowed_ip",
        "apdf": "udp dport . ip saddr . udp sport @allowed_endpoint",
    }[filtering]
    script = '''table ip nat_fixture {
 set opened { type inet_service; flags dynamic,timeout; timeout 30s; size 32; }
 set allowed_ip { type inet_service . ipv4_addr; flags dynamic,timeout; timeout 30s; size 128; }
 set allowed_endpoint { type inet_service . ipv4_addr . inet_service; flags dynamic,timeout; timeout 30s; size 256; }
 chain classify {
'''
    for condition, port in mappings:
        script += f' {condition} meta mark set {port} return\n'
    script += ''' }
 chain outbound { type filter hook prerouting priority -120; policy accept;
  iifname "lan" udp sport 7331 jump classify
'''
    script += f''' }}
 chain inbound {{ type filter hook prerouting priority -110; policy accept;
  iifname "wan" meta l4proto udp {allow} counter accept
  iifname "wan" meta l4proto udp counter drop
 }}
 chain dstnat {{ type nat hook prerouting priority dstnat; policy accept;
  iifname "wan" udp dport @opened counter dnat to {PRIVATE}:7331
 }}
 chain forward {{ type filter hook forward priority filter; policy drop;
  iifname "lan" oifname "wan" ip saddr {PRIVATE} meta l4proto udp counter accept
  iifname "wan" oifname "lan" ip daddr {PRIVATE} udp dport 7331 counter accept
 }}
 chain srcnat {{ type nat hook postrouting priority srcnat; policy accept;
'''
    for port in range(port_base, port_base + 3):
        script += f' oifname "wan" ip saddr {PRIVATE} udp sport 7331 meta mark {port} counter snat to {public}:{port}\n'
    # Refresh the *actual* public binding after SNAT/reverse-DNAT. Replies to
    # an inbound EIF flow can reuse its port instead of the classify guess.
    # Learning before NAT would refresh a different port and expire the live one.
    script += f""" }}
 chain remember {{ type filter hook postrouting priority 110; policy accept;
  oifname "wan" ip saddr {public} udp sport {{ {port_base}, {port_base+1}, {port_base+2} }} update @opened {{ udp sport }} update @allowed_ip {{ udp sport . ip daddr }} update @allowed_endpoint {{ udp sport . ip daddr . udp dport }}
 }}
}}
"""
    old = net.ns(name, "nft", "list", "table", "ip", "nat_fixture", check=False)
    if old.returncode == 0:
        script = "delete table ip nat_fixture\n" + script
    path = net.directory / f"{name}.nft"
    path.write_text(script)
    net.ns(name, "nft", "-f", str(path))


def topology(net):
    net.link("r", "w", "wan", "relay", [f"{RELAY}/30", "198.18.0.1/30"])
    for index, node in enumerate(["a", "b"], 1):
        router = "n" + node
        net.link(node, router, "wan", "lan", [f"{PRIVATE}/24", "10.77.0.1/24"])
        net.link(router, "w", "wan", "to_" + node, [f"198.18.{index}.2/30", f"198.18.{index}.1/30"])
        net.ns(node, "ip", "route", "add", "default", "via", "10.77.0.1")
        net.ns(router, "ip", "route", "add", "default", "via", f"198.18.{index}.1")
        net.ns(router, "sysctl", "-qw", "net.ipv4.ip_forward=1")
    net.ns("r", "ip", "route", "add", "default", "via", "198.18.0.1")
    net.ns("w", "sysctl", "-qw", "net.ipv4.ip_forward=1")
    net.ns("r", "ip", "addr", "add", "198.18.99.1/32", "dev", "lo")
    net.ns("w", "ip", "route", "add", "198.18.99.1/32", "via", RELAY)
    # WAN has no route to the overlapping private LANs. Prove only translated
    # addresses can cross it, rather than silently routing the host candidates.
    net.ns("w", "ip", "route", "add", "blackhole", "10.77.0.0/24")


def mapping_probe(net, node):
    client = '''import socket,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.77.0.2',7331));s.settimeout(2)
result=[]
for endpoint in [('198.18.0.2',9001),('198.18.0.2',9002),('198.18.0.1',9001)]:
 s.sendto(b'mapping-probe',endpoint);result.append(json.loads(s.recv(1024)))
print(json.dumps(result))
'''
    import json
    return json.loads(net.ns(node, "python3", "-c", client).stdout)


def probe_servers(net):
    server = '''import socket,select,json,sys
sockets=[]
extra=[]
if sys.argv[1]=='198.18.0.2':
 for address,port in [('198.18.0.2',9003),('198.18.99.1',9004)]:
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((address,port));extra.append(s)
for port in [9001,9002]:
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],port));sockets.append(s)
while True:
 for s in select.select(sockets,[],[])[0]:
  data,peer=s.recvfrom(1024)
  if data==b'filter-probe':
   s.sendto(b'original',peer)
   for outbound,label in zip(extra,[b'other-port',b'other-ip']): outbound.sendto(label,peer)
  else: s.sendto(json.dumps(peer).encode(),peer)
'''
    for node in ["r", "w"]:
        net.spawn(node, ["python3", "-c", server, RELAY if node == "r" else "198.18.0.1"], net.directory / f"probe-{node}.log")
    net.wait(lambda: all(":9001" in net.ns(node, "ss", "-uln").stdout for node in ["r", "w"]), "NAT measurement servers")


def filtering_probe(net, node):
    client = """import socket,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.77.0.2',7331));s.settimeout(0.5)
s.sendto(b'filter-probe',('198.18.0.2',9001));received=[]
while True:
 try: received.append(s.recv(128).decode())
 except socket.timeout: break
print(json.dumps(sorted(received)))
"""
    import json
    return json.loads(net.ns(node, "python3", "-c", client).stdout)

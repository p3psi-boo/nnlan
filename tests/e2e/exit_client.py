"""Unmarked application TCP/DNS traffic; root is only needed for entering netns."""
import ipaddress
import json
import socket
import struct
import sys

mode, host = sys.argv[1:3]
family = socket.AF_INET6 if ":" in host else socket.AF_INET
if mode == "http":
    with socket.create_connection((host, 8080), 1.5) as s:
        s.settimeout(2)
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        data = b""
        while True:
            part = s.recv(65536)
            if not part:
                break
            data += part
    body = json.loads(data.split(b"\r\n\r\n", 1)[1])
    assert body.pop("payload") == "exit-test-" * 4096
    ip = ipaddress.ip_address(body["source"])
    body["source"] = str(ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip)
    print(json.dumps(body))
else:
    qtype = 28 if family == socket.AF_INET6 else 1
    name = sys.argv[3]
    wire_name = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    query = struct.pack("!HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0) + wire_name + struct.pack("!HH", qtype, 1)
    s = socket.socket(family, socket.SOCK_STREAM if mode == "tcp" else socket.SOCK_DGRAM)
    s.settimeout(1.5)
    s.connect((host, 53))
    if mode == "tcp":
        s.sendall(struct.pack("!H", len(query)) + query)
        size = s.recv(2)
        assert len(size) == 2
        size = struct.unpack("!H", size)[0]
        data = b""
        while len(data) < size:
            part = s.recv(size - len(data))
            assert part
            data += part
    else:
        s.send(query)
        data = s.recv(4096)
    s.close()
    ident, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", data[:12])
    assert ident == 0x5678 and flags & 0x8000 and flags & 0xf == 0 and answers == 1
    expected = socket.inet_pton(family, "198.18.0.100" if family == socket.AF_INET else "2001:db8:ffff::100")
    assert data.endswith(expected)
    print(json.dumps(dict(ok=True, tcp=mode == "tcp", name=name)))

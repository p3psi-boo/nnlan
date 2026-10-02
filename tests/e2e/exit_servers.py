"""Dual-stack synthetic internet HTTP/DNS server, only run in fixture namespace."""
import ipaddress
import json
import socket
import struct
import sys
import threading

log = open(sys.argv[1], "a", buffering=1)
lock = threading.Lock()


def record(kind, peer, **fields):
    ip = ipaddress.ip_address(peer[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    with lock:
        log.write(json.dumps(dict(kind=kind, source=str(ip), **fields)) + "\n")


def listen(kind, port, host="::"):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, kind)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0 if host == "::" else 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    if kind == socket.SOCK_STREAM:
        s.listen(64)
    return s


def dns(data, peer, port, tcp):
    index, labels = 12, []
    while data[index]:
        size = data[index]
        labels.append(data[index + 1:index + 1 + size].decode())
        index += size + 1
    end = index + 5
    qtype = struct.unpack("!H", data[index + 1:index + 3])[0]
    name = ".".join(labels).lower()
    record("dns", peer, name=name, port=port, tcp=tcp)
    answer = b""
    flags = 0x8180
    if name in ["large.test", "relay.test"] and not tcp:
        flags |= 0x0200
    elif name == "relay.test":
        if qtype == 1:
            answer = socket.inet_pton(socket.AF_INET, "10.121.0.2")
    elif qtype in [1, 28]:
        answer = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6, "198.18.0.100" if qtype == 1 else "2001:db8:ffff::100")
    header = data[:2] + struct.pack("!HHHHH", flags, 1, int(bool(answer)), 0, 0)
    response = header + data[12:end]
    if answer:
        response += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 1, len(answer)) + answer
    return response


def exact(stream, size):
    data = b""
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise EOFError()
        data += part
    return data


def udp(s, port):
    while True:
        data, peer = s.recvfrom(65535)
        try:
            s.sendto(dns(data, peer, port, False), peer)
        except (ValueError, IndexError, UnicodeError, OSError):
            pass


def tcp_client(c, peer, port):
    try:
        c.settimeout(3)
        if port == 8080:
            c.recv(4096)
            record("http", peer)
            body = json.dumps(dict(source=peer[0], payload="exit-test-" * 4096)).encode()
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        else:
            for _ in range(16):
                data = exact(c, struct.unpack("!H", exact(c, 2))[0])
                response = dns(data, peer, port, True)
                c.sendall(struct.pack("!H", len(response)) + response)
    except (ValueError, IndexError, UnicodeError, OSError, EOFError):
        pass
    finally:
        c.close()


def tcp(s, port):
    while True:
        c, peer = s.accept()
        threading.Thread(target=tcp_client, args=(c, peer, port), daemon=True).start()


hosts = sys.argv[2:] or (["198.18.0.100", "2001:db8:ffff::100"] + [f"10.120.{i}.2" for i in range(3)])
listeners = []
for port in [53, 5353]:
    for host in hosts:
        listeners.append((udp, listen(socket.SOCK_DGRAM, port, host), port))
    # Explicit VM addresses coexist with the OS loopback DNS stub.
    for host in sys.argv[2:] or ["::"]:
        listeners.append((tcp, listen(socket.SOCK_STREAM, port, host), port))
http = listen(socket.SOCK_STREAM, 8080)
# Bind everything before starting workers: a failed DNS listener must fail the
# fixture, not leave an apparently healthy HTTP server with partial coverage.
for target, stream, port in listeners:
    threading.Thread(target=target, args=(stream, port), daemon=True).start()
tcp(http, 8080)

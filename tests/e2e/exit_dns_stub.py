"""Unmarked local stub: models an application's 127.0.0.53 resolver dependency."""
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.53", 53))
while True:
    query, client = s.recvfrom(4096)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
        upstream.settimeout(1.5)
        upstream.connect(("198.18.0.100", 53))
        upstream.send(query)
        try:
            response = upstream.recv(4096)
            s.sendto(response, client)
        except TimeoutError:
            pass

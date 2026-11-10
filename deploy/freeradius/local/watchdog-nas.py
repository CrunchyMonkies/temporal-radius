#!/usr/bin/env python3
"""Minimal RadSec NAS for keepalive tests (stdlib only).

Dials out to the RadSec server like a NAS behind NAT, sends Status-Server watchdogs (RFC 5997)
every --interval seconds (0 = only one, right after connecting), and answers every CoA-Request /
Disconnect-Request that arrives down the connection with an ACK (--ignore-coa: never answers).
Exits after --duration seconds or when the server closes the connection, printing one line per
event.
"""
import argparse
import hashlib
import hmac
import os
import socket
import ssl
import struct
import threading
import time

SECRET = b"radsec"  # fixed shared secret for RADIUS/TLS (RFC 6614)
STATUS_SERVER, ACCESS_ACCEPT = 12, 2
DISCONNECT_REQUEST, COA_REQUEST = 40, 43
MESSAGE_AUTHENTICATOR, OPERATOR_NAME = 80, 126


def log(msg):
    print(f"{time.monotonic() - START:6.1f}s {msg}", flush=True)


def status_server(ident, operator_name=None):
    # Code | Id | Length | Request Authenticator | Message-Authenticator (HMAC-MD5 over the packet with it zeroed)
    auth = os.urandom(16)
    attrs = bytes([MESSAGE_AUTHENTICATOR, 18]) + bytes(16)
    if operator_name:
        value = operator_name.encode()
        attrs += bytes([OPERATOR_NAME, 2 + len(value)]) + value
    pkt = bytearray(struct.pack("!BBH", STATUS_SERVER, ident, 20 + len(attrs)) + auth + attrs)
    pkt[22:38] = hmac.new(SECRET, bytes(pkt), hashlib.md5).digest()
    return bytes(pkt)


def ack(request):
    # RFC 5176 response: Response Authenticator = MD5(Code | Id | Length | Request Authenticator | Attributes | Secret)
    code = request[0] + 1  # 40 -> 41 Disconnect-ACK, 43 -> 44 CoA-ACK
    head = struct.pack("!BBH", code, request[1], 20)
    return head + hashlib.md5(head + request[4:20] + SECRET).digest()


def read_packet(conn):
    buf = b""
    while len(buf) < 4:
        chunk = conn.recv(4 - len(buf))
        if not chunk:
            return None
        buf += chunk
    (length,) = struct.unpack("!H", buf[2:4])
    while len(buf) < length:
        chunk = conn.recv(length - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", default="freeradius")
    p.add_argument("--port", type=int, default=2083)
    p.add_argument("--certs", required=True, help="dir with tls.crt, tls.key, ca.crt")
    p.add_argument("--interval", type=float, default=30)
    p.add_argument("--duration", type=float, default=60)
    p.add_argument("--ignore-coa", action="store_true", help="never answer CoA (an unresponsive NAS)")
    p.add_argument("--operator-name", help='add Operator-Name to watchdogs, e.g. "+nas-03" (hijack attempt)')
    a = p.parse_args()

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{a.certs}/ca.crt")
    ctx.load_cert_chain(f"{a.certs}/tls.crt", f"{a.certs}/tls.key")
    conn = ctx.wrap_socket(socket.create_connection((a.server, a.port), 5), server_hostname=a.server)
    conn.settimeout(None)
    log(f"connected to {a.server}:{a.port} ({conn.version()})")
    lock = threading.Lock()

    def send(pkt):
        with lock:
            conn.sendall(pkt)

    def watchdog():
        ident = 0
        while True:
            send(status_server(ident, a.operator_name))
            log(f"sent Status-Server id={ident}")
            ident = (ident + 1) % 256
            if a.interval <= 0:
                return
            time.sleep(a.interval)

    def reader():
        while True:
            pkt = read_packet(conn)
            if pkt is None:
                log("connection closed by server")
                os._exit(0)
            code = pkt[0]
            if code == ACCESS_ACCEPT:
                log(f"watchdog answered id={pkt[1]}")
            elif code in (COA_REQUEST, DISCONNECT_REQUEST) and a.ignore_coa:
                log(f"ignored {'CoA' if code == COA_REQUEST else 'Disconnect'}-Request id={pkt[1]}")
            elif code in (COA_REQUEST, DISCONNECT_REQUEST):
                send(ack(pkt))
                log(f"answered {'CoA' if code == COA_REQUEST else 'Disconnect'}-Request id={pkt[1]} with ACK")
            else:
                log(f"ignored packet code={code}")

    threading.Thread(target=watchdog, daemon=True).start()
    threading.Thread(target=reader, daemon=True).start()
    time.sleep(a.duration)
    log("duration elapsed, exiting")


START = time.monotonic()
if __name__ == "__main__":
    main()

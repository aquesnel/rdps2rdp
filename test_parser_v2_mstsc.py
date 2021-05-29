
import unittest

from data_model_v2_tpkt import Tpkt
from data_model_v2_x224 import X224
from data_model_v2_mcs import Mcs
from data_model_v2_rdp import Rdp

from parser_v2 import parse, RdpContext

def extract_as_bytes(data):
    result = ''
    for line in data.splitlines():
        if line:
            line = line.split('#')[0]
            result += ''.join(line.lstrip(' ').split(' '))
    return bytes.fromhex(result)

def as_hex_str(b):
    return " ".join("{:02x}".format(x) for x in b)

class TestParsing(unittest.TestCase):

    def test_parse_connect_response_ex_1(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3
        data = b'\x03\x00\x00m\x02\xf0\x80\x7ffc\n\x01\x00\x02\x01\x000\x1a\x02\x01\x16\x02\x01\x03\x02\x01\x00\x02\x01\x01\x02\x01\x00\x02\x01\x01\x02\x03\x00\xff\xf8\x02\x01\x02\x04?\x00\x05\x00\x14|\x00\x01*\x14v\n\x01\x01\x00\x01\xc0\x00McDn\x80(\x01\x0c\x0c\x00\x04\x00\x08\x00\x0b\x00\x00\x00\x03\x0c\x10\x00\xeb\x03\x04\x00\xec\x03\xed\x03\xee\x03\xef\x03\x02\x0c\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        data = extract_as_bytes("""
          03 00 00 6d # TPKT(len=109)
          02 f0 80 # X224(len=2, type=data)
          7f 66 63 # Mcs(len=99, type=Connect-Response)
          0a 01 00 # -> Connect-Response::result = rt-successful (0)
          02 01 00 # -> Connect-Response::calledConnectId = 0
          30 1a #    -> Connect-Response::domainParameters (26 bytes)
          02 01 16 
          02 01 03 
          02 01 00 
          02 01 01 
          02 01 00 
          02 01 01 
          02 03 00 ff f8 
          02 01 02 
          04 3f # -> Connect-Response::userData (63 bytes)
          00 05 # PER encoded GCC Connection Data -> Key::object length = 5 bytes
          00 14 7c 00 01 
          2a # -> ConnectData::connectPDU length = 42 bytes (this should be ignored)
          14 76 0a 01 01 00 01 c0 00 # -> ConnectGCCPDU + stuff
          4d 63 44 6e # -> h221NonStandard (server-to-client H.221 key) = "McDn"
          80 28 # -> UserData::value length = 40 bytes
          01 0c 0c 00 # -> TS_UD_HEADER::type = SC_CORE (0x0c01), length = 12 bytes 
          04 00 08 00 # -> TS_UD_SC_CORE::version = 0x00080004
          0b 00 00 00 # -> TS_UD_SC_CORE::clientRequestedProtocols = b1011 = SSL + HYBRID + EX
          03 0c 10 00 # -> TS_UD_HEADER::type = SC_NET (0x0c03), length = 16 bytes
          eb 03 # -> TS_UD_SC_NET::MCSChannelId = 0x3eb = 1003 (I/O channel)
          04 00 # -> TS_UD_SC_NET::channelCount = 4
          ec 03 ed 03 ee 03 ef 03 
          02 0c 0c 00 # -> TS_UD_HEADER::type = SC_SECURITY, length = 12
          00 00 00 00 # -> TS_UD_SC_SEC1::encryptionMethod = ENCRYPTION_METHOD_NONE
          00 00 00 00 # -> TS_UD_SC_SEC1::encryptionMethod = ENCRYPTION_LEVEL_NONE
          """)
        rdp_context = RdpContext()
        pdu = parse(data, rdp_context)
        
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_INPUT_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 109)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)   

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.CONNECT)
        self.assertEqual(pdu.tpkt.mcs.mcs_connect_header.mcs_connect_type, Mcs.CONNECT_RESPONSE)
        self.assertEqual(pdu.tpkt.mcs.connect_payload.length, 99)
        self.assertEqual(pdu.tpkt.mcs.connect_payload.result.payload, 0)
        
        self.assertEqual(pdu.tpkt.mcs.connect_payload.userData.length, 63)
        self.assertEqual(bytes(pdu.tpkt.mcs.connect_payload.userData.payload.gcc_header[:4]), bytes.fromhex("00 05 00 14"))
        self.assertEqual(bytes(pdu.tpkt.mcs.connect_payload.userData.payload.gcc_header[-4:]), bytes.fromhex("4d 63 44 6e"))
        self.assertEqual(pdu.tpkt.mcs.connect_payload.userData.payload.gcc_userData.length, 40)

        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.header.length, 12)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.header.type, Rdp.UserData.SC_CORE)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.payload.version, 0x00080004)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.payload.clientRequestedProtocols, {Rdp.Protocols.PROTOCOL_RDP, Rdp.Protocols.PROTOCOL_SSL, Rdp.Protocols.PROTOCOL_HYBRID, Rdp.Protocols.PROTOCOL_HYBRID_EX})
        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.payload.earlyCapabilityFlags, None)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.header.length, 16)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.header.type, Rdp.UserData.SC_NET)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.MCSChannelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelCount, 4)
        self.assertEqual(len(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray), 4)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray[0], 1004)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray[1], 1005)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray[2], 1006)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray[2], 1006)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.header.length, 12)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.header.type, Rdp.UserData.SC_SECURITY)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionMethod, Rdp.Security.ENCRYPTION_METHOD_NONE)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionLevel, Rdp.Security.ENCRYPTION_LEVEL_NONE)
        
        self.assertEqual(rdp_context.is_gcc_confrence, True)
        self.assertEqual(rdp_context.encryption_level, Rdp.Security.ENCRYPTION_METHOD_NONE)
        self.assertEqual(rdp_context.encryption_method, Rdp.Security.ENCRYPTION_LEVEL_NONE)

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

    def test_parse_connect_response_ex_2(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3
        # data captured from an MSTSC session with a Win10 datacenter RDP 10? server
        # pdu from server
        data = extract_as_bytes("""
            03 00 00 86 # TPKT(len=134)
            02 f0 80    # X224(len=2, type=data)
            7f 66 7c    # Mcs(len=124, type=Connect-Response)
            0a 01 00 02 01 00 30 1a 02 01 22 02 01 03 02 01 00 02 01 01 02 01 00 02 01 01 02 03 00 ff f8 02 01 02 
            04 58       # -> Connect-Response::userData (88 bytes)
            00 05 00 14 7c 00 01 # PER encoded GCC Connection Data
            2a 14 76 0a 01 01 00 01 c0 00 4d 63 44 6e 
            42 # -> UserData::value length = 66 bytes
            01 0c 10 00 # -> TS_UD_HEADER::type = SC_CORE (0x0c01), length = 16 bytes 
            0b 00 08 00 
            0b 00 00 00 
            06 00 00 00 
            03 0c 18 00 # -> TS_UD_HEADER::type = SC_NET (0x0c03), length = 24 bytes 
            eb 03 
            07 00 
            ec 03 ed 03 ee 03 ef 03 f0 03 f1 03 f2 03 
            00 00 
            02 0c 0c 00 # -> TS_UD_HEADER::type = SC_SECURITY (0x0c02), length = 12 bytes 
            00 00 00 00 00 00 00 00 
            04 0c 06 00 # -> TS_UD_HEADER::type = SC_MCS_MSGCHANNEL (0x0c04), length = 6 bytes 
            f3 03 
            08 0c 08 00 # -> TS_UD_HEADER::type = SC_MULTITRANSPORT (0x0c08), length = 8 bytes 
            01 03 00 00
            """)
        
        rdp_context = RdpContext()
        pdu = parse(data, rdp_context)
        
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_INPUT_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 134)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)   

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.CONNECT)
        self.assertEqual(pdu.tpkt.mcs.mcs_connect_header.mcs_connect_type, Mcs.CONNECT_RESPONSE)
        self.assertEqual(pdu.tpkt.mcs.connect_payload.length, 124)
        self.assertEqual(pdu.tpkt.mcs.connect_payload.result.payload, 0)
        
        self.assertEqual(pdu.tpkt.mcs.connect_payload.userData.length, 88)
        self.assertEqual(bytes(pdu.tpkt.mcs.connect_payload.userData.payload.gcc_header[:4]), bytes.fromhex("00 05 00 14"))
        self.assertEqual(bytes(pdu.tpkt.mcs.connect_payload.userData.payload.gcc_header[-4:]), bytes.fromhex("4d 63 44 6e"))
        self.assertEqual(pdu.tpkt.mcs.connect_payload.userData.payload.gcc_userData.length, 66)

        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.header.length, 16)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.header.type, Rdp.UserData.SC_CORE)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.payload.version, 0x0008000b)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.payload.clientRequestedProtocols, {Rdp.Protocols.PROTOCOL_RDP, Rdp.Protocols.PROTOCOL_SSL, Rdp.Protocols.PROTOCOL_HYBRID, Rdp.Protocols.PROTOCOL_HYBRID_EX})
        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.payload.earlyCapabilityFlags, 0x00000006)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.header.length, 24)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.header.type, Rdp.UserData.SC_NET)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.MCSChannelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelCount, 7)
        self.assertEqual(len(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray), 7)
        # self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray[0], 1004)
        # self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray[1], 1005)
        # self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray[2], 1006)
        # self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray[2], 1006)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.header.length, 12)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.header.type, Rdp.UserData.SC_SECURITY)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionMethod, Rdp.Security.ENCRYPTION_METHOD_NONE)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionLevel, Rdp.Security.ENCRYPTION_LEVEL_NONE)
        
        self.assertEqual(rdp_context.is_gcc_confrence, True)
        self.assertEqual(rdp_context.encryption_level, Rdp.Security.ENCRYPTION_METHOD_NONE)
        self.assertEqual(rdp_context.encryption_method, Rdp.Security.ENCRYPTION_LEVEL_NONE)

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
        
    def test_parse_RDP_BW_RESULTS_ex_2(self):
        # data captured from an MSTSC session with a Win10 datacenter RDP 10? server
        # pdu from client
        data = extract_as_bytes("""
            03 00 00 20 # TPKT(len=32)
            02 f0 80    # X224(len=2, type=data)
            64 00 0b 03 f3 70 12 # Mcs(len=18, type=SEND_DATA_FROM_CLIENT)
            00 20 d1 65 # TS_SECURITY_HEADER(falgs=SEC_AUTODETECT_RSP)
            0e 01 # RDP_BW_RESULTS(len=14, type=TYPE_ID_AUTODETECT_RESPONSE)
            00 00 # sequenceNumber = 0
            0b 00 # responseType 
            00 00 00 00 # timeDelta = 0
            06 00 00 00 # byteCount = 6
            """)
        
        rdp_context = RdpContext()
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_NONE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_NONE
        rdp_context.pre_capability_exchange = False
        rdp_context.is_gcc_confrence = True
        pdu = parse(data, rdp_context)
        

if __name__ == '__main__':
    unittest.main()
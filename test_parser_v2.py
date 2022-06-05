import unittest

from data_model_v2_tpkt import Tpkt
from data_model_v2_x224 import X224
from data_model_v2_mcs import Mcs
from data_model_v2_rdp import Rdp

from parser_v2 import parse, parse_pdu_length
from parser_v2_context import RdpContext
import parser_v2_context

def extract_as_bytes(data):
    result = ''
    for line in data.splitlines():
        if line:
            result += ''.join(line.lstrip(' ').split(' ')[1:17])
    return bytes.fromhex(result)
    
class TestParsing(unittest.TestCase):

    def test_parse_connection_request(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e78db616-689f-4b8a-8a99-525f7a433ee2
        data = extract_as_bytes("""
00000000 03 00 00 2c 27 e0 00 00 00 00 00 43 6f 6f 6b 69     ...,'......Cooki
00000010 65 3a 20 6d 73 74 73 68 61 73 68 3d 65 6c 74 6f     e: mstshash=elto
00000020 6e 73 0d 0a 01 00 08 00 00 00 00 00                 ns..........
        """)
        self.assertEqual(parse_pdu_length(data), 44)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 44)
        
        self.assertEqual(pdu.tpkt.x224.length, 39)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_CONNECTION_REQUEST)
        self.assertEqual(pdu.tpkt.x224.x224_connect.routing_token_or_cookie, 'Cookie: mstshash=eltons')
        self.assertEqual(pdu.tpkt.x224.x224_connect.rdpNegReq_header.type, Rdp.Negotiate.RDP_NEG_REQ)
        self.assertEqual(pdu.tpkt.x224.x224_connect.rdpNegReq.flags, set())
        self.assertEqual(pdu.tpkt.x224.x224_connect.rdpNegReq.length, 8)
        self.assertEqual(pdu.tpkt.x224.x224_connect.rdpNegReq.requestedProtocols, {Rdp.Protocols.PROTOCOL_RDP})
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
        
    def test_parse_connection_confirm(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/49095420-c6ef-4256-a262-3800e1e233a7
        data = extract_as_bytes("""
00000000 03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00 .........4......
00000010 00 00 00                                        ...
        """)
        self.assertEqual(parse_pdu_length(data), 19)
        
        pdu = parse(RdpContext.PduSource.SERVER, data)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 19)
        
        self.assertEqual(pdu.tpkt.x224.length, 14)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_CONNECTION_CONFIRM)

        self.assertEqual(pdu.tpkt.x224.x224_connect.rdpNegReq_header.type, Rdp.Negotiate.RDP_NEG_RSP)
        self.assertEqual(pdu.tpkt.x224.x224_connect.rdpNegRsp.flags, set())
        self.assertEqual(pdu.tpkt.x224.x224_connect.rdpNegRsp.length, 8)
        self.assertEqual(pdu.tpkt.x224.x224_connect.rdpNegRsp.selectedProtocol, Rdp.Protocols.PROTOCOL_RDP)
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

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
        self.assertEqual(parse_pdu_length(data, rdp_context), 416)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data, rdp_context)

        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 416)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.CONNECT)
        self.assertEqual(pdu.tpkt.mcs.mcs_connect_header.mcs_connect_type, Mcs.CONNECT_INITIAL)
        
        self.assertEqual(pdu.tpkt.mcs.connect_payload.length, 404)
        self.assertEqual(pdu.tpkt.mcs.connect_payload.upwardFlag.payload, True)
        self.assertEqual(pdu.tpkt.mcs.connect_payload.userData.length, 307)
        self.assertEqual(bytes(pdu.tpkt.mcs.connect_payload.userData.payload.gcc_header[:4]), bytes.fromhex("00 05 00 14"))
        self.assertEqual(bytes(pdu.tpkt.mcs.connect_payload.userData.payload.gcc_header[-4:]), bytes.fromhex("44 75 63 61"))
        self.assertEqual(pdu.tpkt.mcs.connect_payload.userData.payload.gcc_userData.length, 284)

        # self.assertEqual(bytes(pdu.tpkt.mcs.connect_payload.userData.payload.gcc_userData.payload[:4]), bytes.fromhex("01 c0 d8 00"))
        
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.header.length, 216)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.header.type, Rdp.UserData.CS_CORE)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.version, 0x00080004)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.desktopWidth, 1280)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.desktopHeight, 1024)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.colorDepth, 0xca01)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.SASSequence, 0xaa03)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.keyboardLayout, 1033)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.clientBuild, 3790)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.clientName, 'ELTONS-DEV2')
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.keyboardType, 4)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.keyboardSubType, 0)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.keyboardFunctionKey, 12)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.imeFileName, '')
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.postBeta2ColorDepth, 0xca01)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.clientProductId, 1)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.serialNumber, 0)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.highColorDepth, 24)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.supportedColorDepths, 7)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.earlyCapabilityFlags, {1})
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.clientDigProductId, "69712-783-0357974-42714")
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.serverSelectedProtocol, 0)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.desktopPhysicalWidth, None)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.desktopPhysicalHeight, None)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.desktopOrientation, None)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.desktopScaleFactor, None)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientCoreData.payload.deviceScaleFactor, None)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.clientSecurityData.header.length, 12)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientSecurityData.header.type, Rdp.UserData.CS_SECURITY)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientSecurityData.payload.encryptionMethods, {Rdp.Security.ENCRYPTION_METHOD_NONE, Rdp.Security.ENCRYPTION_METHOD_40BIT, Rdp.Security.ENCRYPTION_METHOD_128BIT, Rdp.Security.ENCRYPTION_METHOD_56BIT, Rdp.Security.ENCRYPTION_METHOD_FIPS})
        self.assertEqual(pdu.tpkt.mcs.rdp.clientSecurityData.payload.extEncryptionMethods, 0)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.clientNetworkData.header.length, 44)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientNetworkData.header.type, Rdp.UserData.CS_NET)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientNetworkData.payload.channelCount, 3)
        self.assertEqual(len(pdu.tpkt.mcs.rdp.clientNetworkData.payload.channelDefArray), 3)
        self.assertEqual(pdu.tpkt.mcs.rdp.clientNetworkData.payload.channelDefArray[0].name, "rdpdr")
        self.assertEqual(pdu.tpkt.mcs.rdp.clientNetworkData.payload.channelDefArray[0].options, {Rdp.Channel.CHANNEL_OPTION_INITIALIZED, Rdp.Channel.CHANNEL_OPTION_COMPRESS_RDP})
        self.assertEqual(pdu.tpkt.mcs.rdp.clientNetworkData.payload.channelDefArray[1].name, "cliprdr")
        self.assertEqual(pdu.tpkt.mcs.rdp.clientNetworkData.payload.channelDefArray[1].options, {Rdp.Channel.CHANNEL_OPTION_INITIALIZED, Rdp.Channel.CHANNEL_OPTION_ENCRYPT_RDP, Rdp.Channel.CHANNEL_OPTION_COMPRESS_RDP, Rdp.Channel.CHANNEL_OPTION_SHOW_PROTOCOL})
        self.assertEqual(pdu.tpkt.mcs.rdp.clientNetworkData.payload.channelDefArray[2].name, "rdpsnd")
        self.assertEqual(pdu.tpkt.mcs.rdp.clientNetworkData.payload.channelDefArray[2].options, {Rdp.Channel.CHANNEL_OPTION_INITIALIZED, Rdp.Channel.CHANNEL_OPTION_ENCRYPT_RDP})
        
        self.assertEqual(rdp_context.is_gcc_confrence, True)

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

        
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
        self.assertEqual(parse_pdu_length(data, rdp_context), 337)
        
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context)
        
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 337)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)   

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.CONNECT)
        self.assertEqual(pdu.tpkt.mcs.mcs_connect_header.mcs_connect_type, Mcs.CONNECT_RESPONSE)
        self.assertEqual(pdu.tpkt.mcs.connect_payload.length, 325)
        self.assertEqual(pdu.tpkt.mcs.connect_payload.result.payload, 0)
        
        self.assertEqual(pdu.tpkt.mcs.connect_payload.userData.length, 287)
        self.assertEqual(bytes(pdu.tpkt.mcs.connect_payload.userData.payload.gcc_header[:4]), bytes.fromhex("00 05 00 14"))
        self.assertEqual(pdu.tpkt.mcs.connect_payload.userData.payload.gcc_userData.length, 264)

        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.header.length, 12)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.header.type, Rdp.UserData.SC_CORE)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.payload.version, 0x00080004)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.payload.clientRequestedProtocols, {Rdp.Protocols.PROTOCOL_RDP})
        self.assertEqual(pdu.tpkt.mcs.rdp.serverCoreData.payload.earlyCapabilityFlags, None)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.header.length, 16)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.header.type, Rdp.UserData.SC_NET)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.MCSChannelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelCount, 3)
        self.assertEqual(len(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray), 3)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray[0], 1004)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray[1], 1005)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverNetworkData.payload.channelIdArray[2], 1006)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.header.length, 236)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.header.type, Rdp.UserData.SC_SECURITY)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionMethod, Rdp.Security.ENCRYPTION_METHOD_128BIT)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.payload.encryptionLevel, Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.payload.serverRandomLen, 32)
        self.assertEqual(pdu.tpkt.mcs.rdp.serverSecurityData.payload.serverCertLen, 184)
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.serverSecurityData.payload.serverRandom[:4]), bytes.fromhex('10 11 77 20'))
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.serverSecurityData.payload.serverCertificate[:4]), bytes.fromhex('01 00 00 00'))
        
        self.assertEqual(rdp_context.is_gcc_confrence, True)
        self.assertEqual(rdp_context.encryption_level, Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE)
        self.assertEqual(rdp_context.encryption_method, Rdp.Security.ENCRYPTION_METHOD_128BIT)

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

    def test_parse_erect_domain(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7afba26d-52a5-4153-b1df-e21eca3b1b4f
        data = extract_as_bytes("""
 00000000 03 00 00 0c 02 f0 80 04 01 00 01 00     ............
        """)
        self.assertEqual(parse_pdu_length(data), 12)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 12)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.ERECT_DOMAIN)
        self.assertEqual(bytes(pdu.tpkt.mcs.payload), bytes.fromhex("01 00 01 00"))
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

    def test_parse_attach_user_request(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5125dd86-1a99-46cd-bcae-d1c3c083eeb0
        data = extract_as_bytes("""
 00000000 03 00 00 08 02 f0 80 28                     .......(
        """)
        self.assertEqual(parse_pdu_length(data), 8)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 8)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.ATTACH_USER_REQUEST)
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
 
    def test_parse_attach_user_confirm(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3a33f738-a023-4178-bcc3-28f953a038fc
        data = extract_as_bytes("""
 00000000 03 00 00 0b 02 f0 80 2e 00 00 06           ...........
        """)
        self.assertEqual(parse_pdu_length(data), 11)
        
        pdu = parse(RdpContext.PduSource.SERVER, data)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 11)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.ATTACH_USER_CONFIRM)
        self.assertEqual(bytes(pdu.tpkt.mcs.payload), bytes.fromhex("00 00 06"))
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

    def test_parse_channel_join_request(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8c14e16a-a556-4bcd-9e8f-5aa6ae360f45
        data = extract_as_bytes("""
 00000000 03 00 00 0c 02 f0 80 38 00 06 03 ef             .......8....
        """)
        self.assertEqual(parse_pdu_length(data), 12)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 12)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.CHANNEL_JOIN_REQUEST)
        self.assertEqual(pdu.tpkt.mcs.channel_join_request.initiator, 1007)
        self.assertEqual(pdu.tpkt.mcs.channel_join_request.channelId, 1007)

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

    def test_parse_channel_join_confirm(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/48bac244-bf30-4df1-8516-6dd31d917128
        data = extract_as_bytes("""
 00000000 03 00 00 0f 02 f0 80 3e 00 00 06 03 ef 03 ef    .......>.......
        """)
        self.assertEqual(parse_pdu_length(data), 15)
        
        pdu = parse(RdpContext.PduSource.SERVER, data)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 15)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.CHANNEL_JOIN_CONFIRM)
        self.assertEqual(bytes(pdu.tpkt.mcs.payload), bytes.fromhex("00 00 06 03 ef 03 ef"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

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
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_NONE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_NONE
        self.assertEqual(parse_pdu_length(data, rdp_context), 94)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data, rdp_context)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 94)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_CLIENT)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1007)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, {Rdp.Security.SEC_EXCHANGE_PKT, Rdp.Security.SEC_LICENSE_ENCRYPT})
        
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SECURITY_PACKET.length, 72)
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.TS_SECURITY_PACKET.encryptedClientRandom[:8]), bytes.fromhex("91 ac 0c 8f 64 8c 39 f4"))

        self.assertEqual(rdp_context.encrypted_client_random[:8], bytes.fromhex("91 ac 0c 8f 64 8c 39 f4"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)


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
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        self.assertEqual(parse_pdu_length(data, rdp_context), 427)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data, rdp_context)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 427)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_CLIENT)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1007)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)

        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, {Rdp.Security.SEC_INFO_PKT, Rdp.Security.SEC_ENCRYPT})
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.sec_header1.dataSignature), bytes.fromhex("45 ca 46 fa 5e a7 be bc"))
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.payload[:4]), bytes.fromhex("74 21 d3 65"))
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.payload[-4:]), bytes.fromhex("a3 b4 0b 29"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

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
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        rdp_context.encrypted_client_random = b'1234'
        self.assertEqual(parse_pdu_length(data, rdp_context), 427)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data, rdp_context)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 427)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_CLIENT)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1007)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)

        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, {Rdp.Security.SEC_INFO_PKT})
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.sec_header1.dataSignature), bytes.fromhex("45 ca 46 fa 5e a7 be bc"))
        
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.CodePage, 0x04090409)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.flags, {
            Rdp.Info.INFO_MOUSE,
            Rdp.Info.INFO_DISABLECTRLALTDEL,
            Rdp.Info.INFO_UNICODE,
            Rdp.Info.INFO_MAXIMIZESHELL,
            Rdp.Info.INFO_COMPRESSION,
            Rdp.Info.INFO_ENABLEWINDOWSKEY,
            Rdp.Info.INFO_FORCE_ENCRYPTED_CS_PDU,
        })
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.compressionType, Rdp.Info.PACKET_COMPR_TYPE_64K)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.cbDomain, 10)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.cbUserName, 12)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.cbPassword, 0)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.cbAlternateShell, 0)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.cbWorkingDir, 0)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.Domain, 'NTDEV')
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.UserName, 'eltons')
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.Password, '')
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.AlternateShell, '')
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.WorkingDir, '')
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.extraInfo.payload_todo[:4]), bytes.fromhex("02 00 1e 00"))
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.extraInfo.payload_todo[-4:]), bytes.fromhex("00 00 00 00"))

        self.assertEqual(rdp_context.auto_logon, False)
        self.assertEqual(rdp_context.rail_enabled, False)
        self.assertEqual(rdp_context.compression_type, Rdp.Info.PACKET_COMPR_TYPE_64K)
        self.assertEqual(rdp_context.domain, 'NTDEV')
        self.assertEqual(rdp_context.user_name, 'eltons')
        self.assertEqual(rdp_context.password, '')
        self.assertEqual(rdp_context.alternate_shell, '')
        self.assertEqual(rdp_context.working_dir, '')

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
        
        # print('pdu modified')
        info_packet_data = bytes(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.as_wire_bytes())
        pdu.tpkt.mcs.rdp.TS_INFO_PACKET.flags.discard(Rdp.Info.INFO_COMPRESSION)
        pdu.tpkt.mcs.rdp.TS_INFO_PACKET.compressionType = Rdp.Info.PACKET_COMPR_TYPE_8K
        
        self.assertEqual(True, Rdp.Info.INFO_COMPRESSION not in pdu.tpkt.mcs.rdp.TS_INFO_PACKET.flags)
        self.assertEqual(True, pdu.tpkt.mcs.rdp.TS_INFO_PACKET._fields_by_name['flags'].is_dirty())
        self.assertEqual(True, pdu.tpkt.mcs.rdp.TS_INFO_PACKET._fields_by_name['compressionType'].is_dirty())
        self.assertEqual(True, pdu.is_dirty())
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.TS_INFO_PACKET.as_wire_bytes())[4:8], b'\x33\x41\x00\x00')
        self.assertNotEqual(bytes(pdu.as_wire_bytes()), data)
        

    @unittest.skip("encrypted license not supported")
    def test_parse_license_valid_encrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/df4cc42d-9a67-4b16-bba1-e3ca1d36d30a
        data = extract_as_bytes("""
 00000000 03 00 00 2a 02 f0 80 68 00 01 03 eb 70 1c 88 02 ...*...h....p...
 00000010 02 03 8d 43 9a ab d5 2a 31 39 62 4d c1 ec 0d 99 ...C...*19bM....
 00000020 88 e6 da ab 2c 02 72 4d 49 90                   ....,.rMI.
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        rdp_context.encrypted_client_random = b'1234'
        self.assertEqual(parse_pdu_length(data, rdp_context), 42)
        
        pdu = parse(RdpContext.PduSource.SERSVER, data, rdp_context)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 42)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_SERVER)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1002)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)

        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, {Rdp.Security.SEC_LICENSE_PKT, Rdp.Security.SEC_ENCRYPT, Rdp.Security.SEC_LICENSE_ENCRYPT_CS})
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.sec_header1.dataSignature), bytes.fromhex("8d 43 9a ab d5 2a 31 39"))
        self.assertEqual(pdu.tpkt.mcs.rdp.payload[:4], bytes.fromhex("62 4d c1 ec"))
        self.assertEqual(pdu.tpkt.mcs.rdp.payload[-4:], bytes.fromhex("72 4d 49 90"))

        self.assertEqual(rdp_context.pre_capability_exchange, False)
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

    def test_parse_license_valid_decrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/df4cc42d-9a67-4b16-bba1-e3ca1d36d30a
        data = extract_as_bytes("""
 00000000 03 00 00 2a 02 f0 80 68 00 01 03 eb 70 1c 80 02 ...*...h....p...
 00000010 02 03 8d 43 9a ab d5 2a 31 39                   ...C...*19
 
 00000000 ff 03 10 00 07 00 00 00 02 00 00 00 04 00 00 00 ................
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        rdp_context.encrypted_client_random = b'1234'
        self.assertEqual(parse_pdu_length(data, rdp_context), 42)
        
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 42)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_SERVER)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1002)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)

        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, {Rdp.Security.SEC_LICENSE_PKT, Rdp.Security.SEC_LICENSE_ENCRYPT_CS})
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.sec_header1.dataSignature), bytes.fromhex("8d 43 9a ab d5 2a 31 39"))

        self.assertEqual(pdu.tpkt.mcs.rdp.LICENSE_VALID_CLIENT_DATA.preamble.bMsgType, Rdp.License.ERROR_ALERT)
        self.assertEqual(pdu.tpkt.mcs.rdp.LICENSE_VALID_CLIENT_DATA.preamble.flags, 0x03)
        self.assertEqual(pdu.tpkt.mcs.rdp.LICENSE_VALID_CLIENT_DATA.preamble.wMsgSize, 16)
        self.assertEqual(len(pdu.tpkt.mcs.rdp.LICENSE_VALID_CLIENT_DATA.validClientMessage), 12)
        self.assertEqual(pdu.tpkt.mcs.rdp.LICENSE_VALID_CLIENT_DATA.validClientMessage[:4], bytes.fromhex("07 00 00 00"))
        self.assertEqual(pdu.tpkt.mcs.rdp.LICENSE_VALID_CLIENT_DATA.validClientMessage[-4:], bytes.fromhex("04 00 00 00"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
        
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
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = False
        self.assertEqual(parse_pdu_length(data, rdp_context), 386)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data, rdp_context)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 386)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_SERVER)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1002)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)

        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, {Rdp.Security.SEC_ENCRYPT})
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.sec_header1.dataSignature), bytes.fromhex("56 02 e1 47 ac 5c 50 d9"))
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.payload[:4]), bytes.fromhex("72 f9 c3 32"))
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.payload[-4:]), bytes.fromhex("99 ad 81 48"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
        
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
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = True
        self.assertEqual(parse_pdu_length(data, rdp_context), 386)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data, rdp_context)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 386)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_SERVER)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1002)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)

        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, set())
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.sec_header1.dataSignature), bytes.fromhex("56 02 e1 47 ac 5c 50 d9"))
        
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.totalLength, 359)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduType, Rdp.ShareControlHeader.PDUTYPE_DEMANDACTIVEPDU)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduVersion, 0x0010)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduSource, 1002)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.shareID, 0x000103ea)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.lengthSourceDescriptor, 4)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.lengthCombinedCapabilities, 337)
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.sourceDescriptor), bytes.fromhex("52 44 50 00"))
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.numberCapabilities, 13)
        self.assertEqual(len(pdu.tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.capabilitySets), 13)

        self.assertEqual(pdu.tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.capabilitySets.virtualChannelCapability.capabilityData.flags, Rdp.Capabilities.VirtualChannel.VCCAPS_COMPR_CS_8K)
        
        self.assertEqual(rdp_context.pre_capability_exchange, False)
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
        
        pdu.tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.capabilitySets.virtualChannelCapability.capabilityData.flags = Rdp.Capabilities.VirtualChannel.VCCAPS_NO_COMPR
        
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.capabilitySets.virtualChannelCapability.capabilityData.flags, Rdp.Capabilities.VirtualChannel.VCCAPS_NO_COMPR)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_DEMAND_ACTIVE_PDU.capabilitySets.virtualChannelCapability.capabilityData._fields_by_name['flags'].is_dirty(), True)
        self.assertNotEqual(bytes(pdu.as_wire_bytes()), data) 
        # TODO: create the PDU bytes with the modified flag value
        

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
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = False
        parser_config = parser_v2_context.ParserConfig(strict_parsing = False)
        self.assertEqual(parse_pdu_length(data, rdp_context, parser_config), 519)
        
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context, parser_config)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 519)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_CLIENT)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1007)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)

        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, {Rdp.Security.SEC_RESET_SEQNO, Rdp.Security.SEC_IGNORE_SEQNO, Rdp.Security.SEC_ENCRYPT})
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.sec_header1.dataSignature), bytes.fromhex("ab 1f 51 e7 93 17 5c 45"))
        
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.payload[:4]), bytes.fromhex("04 36 38 41"))
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.payload[-4:]), bytes.fromhex("ed b5 48 82"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

    # @unittest.skip("refactoring in progress")
    def test_parse_confirm_active_decrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/54765b0a-39d4-4746-92c6-8914934023da
        data = extract_as_bytes("""
 00000000 03 00 02 07 02 f0 80 64 00 06 03 eb 70 81 f8 30 .......d....p..8
 00000010 00 00 00 ab 1f 51 e7 93 17 5c 45                .....Q...\E

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
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = False
        self.assertEqual(parse_pdu_length(data, rdp_context), 519)
        
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 519)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_CLIENT)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1007)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)

        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, {Rdp.Security.SEC_RESET_SEQNO, Rdp.Security.SEC_IGNORE_SEQNO})
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.sec_header1.dataSignature), bytes.fromhex("ab 1f 51 e7 93 17 5c 45"))
        
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.totalLength, 492)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduType, Rdp.ShareControlHeader.PDUTYPE_CONFIRMACTIVEPDU)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduVersion, 0x0010)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduSource, 1007)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_CONFIRM_ACTIVE_PDU.shareID, 0x000103ea)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_CONFIRM_ACTIVE_PDU.originatorID, 1002)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_CONFIRM_ACTIVE_PDU.lengthSourceDescriptor, 6)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_CONFIRM_ACTIVE_PDU.lengthCombinedCapabilities, 470)
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.TS_CONFIRM_ACTIVE_PDU.sourceDescriptor), bytes.fromhex("4d 53 54 53 43 00"))
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_CONFIRM_ACTIVE_PDU.numberCapabilities, 18)
        self.assertEqual(len(pdu.tpkt.mcs.rdp.TS_CONFIRM_ACTIVE_PDU.capabilitySets), 18)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_CONFIRM_ACTIVE_PDU.capabilitySets.virtualChannelCapability.capabilityData.flags, Rdp.Capabilities.VirtualChannel.VCCAPS_COMPR_SC)
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
        
    def test_parse_client_synchronize_encrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/daf2afd3-c864-43b5-90c8-1156df3ca1a9
        data = extract_as_bytes("""
 00000000 03 00 00 30 02 f0 80 64 00 06 03 eb 70 22 28 00 ...0...d....p"(.
 00000010 81 f8 59 ff cb 2f 73 57 2b 42 db 88 2e 23 a9 97 ..Y../sW+B...#..
 00000020 c2 b1 f5 74 bc 49 cc 8a d8 fd 60 8a 7a f6 44 75 ...t.I....`.z.Du
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = False
        self.assertEqual(parse_pdu_length(data, rdp_context), 48)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data, rdp_context)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 48)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_CLIENT)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1007)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)

        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, {Rdp.Security.SEC_IGNORE_SEQNO, Rdp.Security.SEC_ENCRYPT})
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.sec_header1.dataSignature), bytes.fromhex("59 ff cb 2f 73 57 2b 42"))
        
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.payload[:4]), bytes.fromhex("db 88 2e 23"))
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.payload[-4:]), bytes.fromhex("7a f6 44 75"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
    
    def test_parse_client_synchronize_decrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/daf2afd3-c864-43b5-90c8-1156df3ca1a9
        data = extract_as_bytes("""
 00000000 03 00 00 30 02 f0 80 64 00 06 03 eb 70 22 20 00 ...0...d....p"(.
 00000010 81 f8 59 ff cb 2f 73 57 2b 42                   ..Y../sW+B

 00000000 16 00 17 00 ef 03 ea 03 01 00 00 01 08 00 1f 00 ................
 00000010 00 00 01 00 ea 03                               ......
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = False
        self.assertEqual(parse_pdu_length(data, rdp_context), 48)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data, rdp_context)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 48)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_CLIENT)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1007)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)

        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, {Rdp.Security.SEC_IGNORE_SEQNO})
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.sec_header1.dataSignature), bytes.fromhex("59 ff cb 2f 73 57 2b 42"))
        
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.totalLength, 22)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduType, Rdp.ShareControlHeader.PDUTYPE_DATAPDU)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduVersion, 0x0010)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduSource, 1007)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.shareID, 0x000103ea)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.streamID, 1)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.uncompressedLength, 8)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.pduType2, Rdp.ShareDataHeader.PDUTYPE2_SYNCHRONIZE)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.compressionArgs, set())
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.compressionType, Rdp.ShareDataHeader.PACKET_COMPR_TYPE_8K)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.compressedLength, 0)
        
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.payload), bytes.fromhex("01 00 ea 03"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

    def test_parse_client_control_encrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/291d4548-69d0-41fa-92a0-070cbe01167c
        data = extract_as_bytes("""
 00000000 03 00 00 34 02 f0 80 64 00 06 03 eb 70 26 08 00 ...4...d....p&..
 00000010 81 f8 04 03 de f7 91 a3 7c af 3f 7a 62 4e 3b fe ........|.?zbN;.
 00000020 b6 7a 28 bf 0d 4f 31 27 03 b9 4a f1 e6 26 f0 bd .z(..O1'..J..&..
 00000030 c5 71 0a 53                                     .q.S
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = False
        self.assertEqual(parse_pdu_length(data, rdp_context), 52)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data, rdp_context)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 52)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_CLIENT)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1007)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)

        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, {Rdp.Security.SEC_ENCRYPT})
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.sec_header1.dataSignature), bytes.fromhex("04 03 de f7 91 a3 7c af"))
        
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.payload[:4]), bytes.fromhex("3f 7a 62 4e"))
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.payload[-4:]), bytes.fromhex("c5 71 0a 53"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
    
    def test_parse_client_control_decrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/291d4548-69d0-41fa-92a0-070cbe01167c
        data = extract_as_bytes("""
 00000000 03 00 00 34 02 f0 80 64 00 06 03 eb 70 26 00 00 ...4...d....p&..
 00000010 81 f8 04 03 de f7 91 a3 7c af                   ........|.
 
 00000000 1a 00 17 00 ef 03 ea 03 01 00 00 01 0c 00 14 00 ................
 00000010 00 00 04 00 00 00 00 00 00 00                   ..........
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = False
        self.assertEqual(parse_pdu_length(data, rdp_context), 52)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data, rdp_context)
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 52)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_CLIENT)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1007)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1003)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0x70)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0x70)

        self.assertEqual(pdu.tpkt.mcs.rdp.sec_header.flags, set())
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.sec_header1.dataSignature), bytes.fromhex("04 03 de f7 91 a3 7c af"))
        
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.totalLength, 26)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduType, Rdp.ShareControlHeader.PDUTYPE_DATAPDU)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduVersion, 0x0010)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHARECONTROLHEADER.pduSource, 1007)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.shareID, 0x000103ea)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.streamID, 1)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.uncompressedLength, 12)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.pduType2, Rdp.ShareDataHeader.PDUTYPE2_CONTROL)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.compressionArgs, set())
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.compressionType, Rdp.ShareDataHeader.PACKET_COMPR_TYPE_8K)
        self.assertEqual(pdu.tpkt.mcs.rdp.TS_SHAREDATAHEADER.compressedLength, 0)
        
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.payload), bytes.fromhex("04 00 00 00 00 00 00 00"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

    def test_parse_fast_path_input_encrypted(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d8f1be0e-ca81-4caf-a494-3c161d21a7f2
        data = extract_as_bytes("""
 00000000 c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de ..05k[.4.G&.^v..
 00000010 28 
        """)
        rdp_context = RdpContext()
        rdp_context.encryption_level = Rdp.Security.ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
        rdp_context.encryption_method = Rdp.Security.ENCRYPTION_METHOD_128BIT
        rdp_context.encrypted_client_random = b'1234'
        rdp_context.pre_capability_exchange = False
        self.assertEqual(parse_pdu_length(data, rdp_context), 17)
        
        pdu = parse(RdpContext.PduSource.CLIENT, data, rdp_context)
        # print(pdu)
        self.assertEqual(pdu.rdp_fp.header.action, Rdp.FastPath.FASTPATH_ACTION_FASTPATH)
        self.assertEqual(pdu.rdp_fp.header.numEvents, 1)
        self.assertEqual(pdu.rdp_fp.header.flags, {Rdp.FastPath.FASTPATH_FLAG_SECURE_CHECKSUM, Rdp.FastPath.FASTPATH_FLAG_ENCRYPTED})
        self.assertEqual(pdu.rdp_fp.length, 17)
        self.assertEqual(bytes(pdu.rdp_fp.dataSignature), bytes.fromhex("30 35 6b 5b b5 34 c8 47"))
        
        self.assertEqual(bytes(pdu.rdp_fp.fpInputEvents), bytes.fromhex("26 18 5e 76 0e de 28"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)

if __name__ == '__main__':
    unittest.main()

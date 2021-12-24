
import unittest

from data_model_v2_tpkt import Tpkt
from data_model_v2_x224 import X224
from data_model_v2_mcs import Mcs
from data_model_v2_rdp import Rdp

from parser_v2 import parse, RdpContext

from test_utils import extract_as_bytes, extract_as_context


class TestParsing(unittest.TestCase):

    def test_parse_gfx_CAPSCONFIRM(self):
        # data captured from an MSTSC session with a Win10 datacenter RDP 10? server
        # pdu from server
        # OUTPUTPCAP = 'output.win10.rail.no-compression.success.pcap' ; SERVER_PORT = 33930
        # offset = 63
        data = extract_as_bytes("""
            03 00 00 28 # TPKT(len=40)
            02 f0 80 # X224(len=2, type=data)
            68 00 01 03 f2 f0 1a # Mcs(len=26, type=TPDU_DATA)
            12 00 00 00 03 00 00 00 # CHANNEL_PDU_HEADER(len=18, flags=FIRST|LAST)
            38 07 # DYNVC_DATA_FIRST(type=COMMAND_DATA, channel=7)
            e0 # RDP_SEGMENTED_DATA(type=SINGLE)
            24 # RDP8_BULK_ENCODING(flags=COMPRESSED | COMPRESSION_RDP80)
            09 e3 18 0a 44 8c 70 e9 8d d1 44 63 18 00 # compressed bytes
            # RDPGFX_CMDID_CAPSCONFIRM
            # 
            """)
        
        rdp_context = extract_as_context({'domain': '', 'password': 'P@ssw0rd!', 'pdu_source': None, 'encryption_method': 0, 'allow_partial_parsing': False, 'working_dir': '', 'encrypted_client_random': None, 'encryption_level': 0, 'auto_logon': True, 'channel_defs': [{'name': 'rdpdr', 'channel_id': 1004, 'type': 'STATIC', 'options': {2147483648}}, {'name': 'rdpsnd', 'channel_id': 1005, 'type': 'STATIC', 'options': {1073741824, 2147483648}}, {'name': 'rail', 'channel_id': 1006, 'type': 'STATIC', 'options': {1073741824, 2147483648, 1048576, 2097152}}, {'name': 'rail_wi', 'channel_id': 1007, 'type': 'STATIC', 'options': {1073741824, 2147483648, 1048576, 2097152}}, {'name': 'rail_ri', 'channel_id': 1008, 'type': 'STATIC', 'options': {1073741824, 2147483648, 1048576, 2097152}}, {'name': 'cliprdr', 'channel_id': 1009, 'type': 'STATIC', 'options': {1073741824, 2147483648, 2097152}}, {'name': 'drdynvc', 'channel_id': 1010, 'type': 'STATIC', 'options': {1073741824, 2147483648}}, {'name': 'I/O Channel', 'channel_id': 1003, 'type': 'STATIC', 'options': 0}, {'name': 'McsMessageChannel', 'channel_id': 1011, 'type': 'STATIC', 'options': 0}, {'name': 'Microsoft::Windows::RDS::Telemetry', 'channel_id': 5, 'type': 'DYNAMIC', 'options': 0}, {'name': 'Microsoft::Windows::RDS::Graphics', 'channel_id': 7, 'type': 'DYNAMIC', 'options': 0}], 'alternate_shell': 'rdpinit.exe', 'compression_engines': {}, 'rail_enabled': True, 'is_gcc_confrence': True, 'previous_primary_drawing_orders': {}, 'compression_virtual_chan_cs_encoder': None, 'pre_capability_exchange': False, 'compression_type': None, 'user_name': 'runneradmin', 'rdp_gfx_pre_capability_exchange': False} )      
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context)
        # print(pdu)
        
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 40)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_SERVER)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1002)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1010)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 240)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 240)

        self.assertEqual(pdu.tpkt.mcs.rdp.length, 26)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.header.length, 18)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.header.flags, {Rdp.Channel.CHANNEL_FLAG_FIRST, Rdp.Channel.CHANNEL_FLAG_LAST, })

        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.header.cbId, 0)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.header.Pri, 2)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.header.Cmd, Rdp.DynamicVirtualChannels.COMMAND_DATA)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.ChannelId, 7)

        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.descriptor, Rdp.GraphicsPipelineExtention.DataPackaging.DEBLOCK_SINGLE)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.header_CompressionType, Rdp.GraphicsPipelineExtention.Compression.PACKET_COMPR_TYPE_RDP8)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.header_CompressionFlags, {Rdp.GraphicsPipelineExtention.Compression.PACKET_COMPRESSED})

        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.data.header.cmdId, Rdp.GraphicsPipelineExtention.Commands.RDPGFX_CMDID_CAPSCONFIRM)
        
        self.assertEqual(len(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.data.payload), 12)
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.data.payload[:4]), bytes.fromhex("00 06 0a 00"))
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.data.payload[-4:]), bytes.fromhex("00 00 00 00"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
      

    def test_parse_unknown_2(self):
        # data captured from an MSTSC session with a Win10 datacenter RDP 10? server
        # pdu from server
        # OUTPUTPCAP = 'output.win10.rail.no-compression.success.pcap' ; SERVER_PORT = 33930
        # offset = 63
        data = extract_as_bytes("""
            03 00 00 28 # TPKT(len=40)
            02 f0 80 # X224(len=2, type=data)
            68 00 01 03 f2 f0 1a # Mcs(len=26, type=TPDU_DATA)
            12 00 00 00 03 00 00 00 # CHANNEL_PDU_HEADER(len=18, flags=FIRST|LAST)
            38 07 # DYNVC_DATA_FIRST(type=COMMAND_DATA, channel=7)
            e0 # RDP_SEGMENTED_DATA(type=SINGLE)
            24 # RDP8_BULK_ENCODING(flags=COMPRESSED | COMPRESSION_RDP80)
            09 e3 18 0a 44 8c 70 e9 8d d1 44 63 18 00 # compressed bytes
            # RDPGFX_CMDID_CAPSCONFIRM
            # 
            """)
        
        rdp_context = extract_as_context({'domain': '', 'password': 'P@ssw0rd!', 'pdu_source': None, 'encryption_method': 0, 'allow_partial_parsing': False, 'working_dir': '', 'encrypted_client_random': None, 'encryption_level': 0, 'auto_logon': True, 'channel_defs': [{'name': 'rdpdr', 'channel_id': 1004, 'type': 'STATIC', 'options': {2147483648}}, {'name': 'rdpsnd', 'channel_id': 1005, 'type': 'STATIC', 'options': {1073741824, 2147483648}}, {'name': 'rail', 'channel_id': 1006, 'type': 'STATIC', 'options': {1073741824, 2147483648, 1048576, 2097152}}, {'name': 'rail_wi', 'channel_id': 1007, 'type': 'STATIC', 'options': {1073741824, 2147483648, 1048576, 2097152}}, {'name': 'rail_ri', 'channel_id': 1008, 'type': 'STATIC', 'options': {1073741824, 2147483648, 1048576, 2097152}}, {'name': 'cliprdr', 'channel_id': 1009, 'type': 'STATIC', 'options': {1073741824, 2147483648, 2097152}}, {'name': 'drdynvc', 'channel_id': 1010, 'type': 'STATIC', 'options': {1073741824, 2147483648}}, {'name': 'I/O Channel', 'channel_id': 1003, 'type': 'STATIC', 'options': 0}, {'name': 'McsMessageChannel', 'channel_id': 1011, 'type': 'STATIC', 'options': 0}, {'name': 'Microsoft::Windows::RDS::Telemetry', 'channel_id': 5, 'type': 'DYNAMIC', 'options': 0}, {'name': 'Microsoft::Windows::RDS::Graphics', 'channel_id': 7, 'type': 'DYNAMIC', 'options': 0}], 'alternate_shell': 'rdpinit.exe', 'compression_engines': {}, 'rail_enabled': True, 'is_gcc_confrence': True, 'previous_primary_drawing_orders': {}, 'compression_virtual_chan_cs_encoder': None, 'pre_capability_exchange': False, 'compression_type': None, 'user_name': 'runneradmin', 'rdp_gfx_pre_capability_exchange': False} )      
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context)
        # print(pdu)
        
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 40)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_SERVER)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1002)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1010)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 240)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 240)

        self.assertEqual(pdu.tpkt.mcs.rdp.length, 26)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.header.length, 18)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.header.flags, {Rdp.Channel.CHANNEL_FLAG_FIRST, Rdp.Channel.CHANNEL_FLAG_LAST, })

        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.header.cbId, 0)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.header.Pri, 2)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.header.Cmd, Rdp.DynamicVirtualChannels.COMMAND_DATA)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.ChannelId, 7)

        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.descriptor, Rdp.GraphicsPipelineExtention.DataPackaging.DEBLOCK_SINGLE)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.header_CompressionType, Rdp.GraphicsPipelineExtention.Compression.PACKET_COMPR_TYPE_RDP8)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.header_CompressionFlags, {Rdp.GraphicsPipelineExtention.Compression.PACKET_COMPRESSED})

        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.data.header.cmdId, Rdp.GraphicsPipelineExtention.Commands.RDPGFX_CMDID_CAPSCONFIRM)
        
        self.assertEqual(len(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.data.payload), 12)
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.data.payload[:4]), bytes.fromhex("00 06 0a 00"))
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.data.payload[-4:]), bytes.fromhex("00 00 00 00"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
      
    #   """
    #   03 00 06 57 02 f0 80 68 00 01 03 f2 f0 86 48 40 06 00 00 03 00 00 00 24 07 fc 74 e1 02 00 0e 37 01 00 33 33 00 00 24 99 c2 30 28 94 c5 0c 88 f9 8a 7d 69 83 ce 71 3c 62 d3 70 43 18 6a d8 01 44 45 a8 8d 3d b4 04 62 84 a8 c0 82 28 6f 94 b5 80 ec c4 61 01 b8 c1 37 03 34 40 22 28 8b 01 dd 80 84 80 23 8c 24 22 23 08 0d 48 43 74 70 af e1 40 46 28 51 12 88 a2 27 16 88 e2 36 44 4b 84 49 14 74 90 ab b0 0b 38 95 a8 a1 e9 12 95 11 44 48 54 48 44 47 11 21 18 03 64 41 43 d6 26 14 63 f2 4e 91 c6 92 21 84 51 12 01 11 44 4c 15 13 11 44 84 61 44 f9 88 c2 24 e2 24 02 24 23 00 94 80 77 cb 86 12 51 84 c5 51 ac b0 26 3a 89 84 22 28 88 bd 98 a2 26 38 89 58 c2 46 30 a3 5f 11 c4 46 11 2c 11 21 11 23 1e 84 c2 11 41 a9 8e 12 a1 df 49 93 09 10 c2 54 22 70 a8 96 08 97 88 9a 82 25 a2 3a 4c 22 8a 22 38 89 9e 22 44 22 42 30 99 02 24 62 26 88 c2 40 22 42 22 44 30 9b a2 26 60 89 30 88 e2 25 e2 22 88 91 88 92 88 8a 30 91 8e 09 d2 22 55 d3 d1 63 23 1d 12 d1 12 51 01 19 10 ef b0 46 f8 90 88 9b e2 26 b0 89 18 89 68 89 f8 a2 60 08 a7 a1 11 c4 0a a3 0f 3c 57 3e 42 4a 22 48 30 8c 22 61 88 98 c2 24 c2 23 88 9a 02 28 2d 44 71 a4 e9 11 20 11 14 44 d8 11 35 06 11 44 4b 84 4d 31 13 08 45 0d 08 91 88 9a c2 24 23 b0 2d 2d 17 21 1c 93 00 44 ca 11 26 11 21 11 28 11 37 84 49 87 04 84 69 31 06 12 e1 1b a4 43 8e 8a d4 49 84 48 44 4f 51 1a 48 07 3c db 11 4f ba 36 0f 4b d4 4c a5 1d 43 21 90 ce 76 db 6e 8c f5 39 97 2e 66 82 ab 2e 46 4a 73 2e 26 2a 5e 24 25 b2 e1 61 a5 66 4e 8b 04 0a 89 0c d5 9c a5 31 e5 f2 ef 70 65 ec e5 65 65 e8 e0 60 e5 e7 12 1e 4e 06 06 c4 19 af 22 6a 48 a3 5d 13 d6 44 8f 44 a5 45 01 cc 35 94 eb e3 fe b6 db 2b 6f fc 4a d4 6b 8f f5 b6 76 5b 7f c5 91 a4 90 79 09 06 de d9 ff c7 69 14 48 e3 69 2c 44 8f fc 49 24 2d a4 a3 cd 6d c8 c3 1d 92 12 c1 86 65 e3 3c ad a3 c7 69 34 4c 4a 9a e2 26 62 89 8b 22 2f 67 7d 44 56 2a 23 c8 b2 26 48 c3 f2 63 cb e5 d9 20 db cb 6d 21 2f 91 b6 66 3c ce 4c 34 9e c2 26 e8 8e b2 51 bc ea 91 3b 64 49 c4 71 93 0c 26 4c 84 87 6e d9 6d ec db cf 69 83 21 b7 30 82 5f 13 00 67 49 c2 27 a8 89 b7 22 49 22 a2 4c d3 33 00 44 a0 44 96 a6 04 89 80 31 99 52 24 a2 12 0b 64 86 64 e2 36 93 84 ec 49 80 30 d9 03 21 d1 3d 74 4c 9d 11 44 58 31 14 49 f4 4f bd 8c bd 43 f1 e8 ed a5 8d c1 41 fa 24 22 26 22 89 18 8d 24 23 ce 76 4c 4d 13 d1 44 90 44 d9 d8 49 44 4d 1d 1d 25 52 5e 72 09 d3 42 ca 24 52 33 21 1d f2 89 13 02 46 e9 30 87 db ce 55 3a 64 22 26 aa 8d f2 11 84 d4 cd f4 4d 80 f8 a1 42 9a 23 ce c9 40 cd d7 d5 ec ee 73 65 96 be 5a 65 5a 9c 47 47 11 24 98 54 31 22 76 28 a0 e5 2f b7 93 af aa f1 56 a1 cb 8d ba d8 a0 64 da 42 34 a2 75 13 1c 46 92 d1 32 10 92 84 82 46 5f af 57 86 5f 8f 57 7e 5f 8f 47 7c b9 b3 27 11 43 5a 26 9c 89 7c 89 c9 22 28 8a 58 51 35 24 4a 46 32 41 8b da 48 26 41 22 47 30 a8 1f 44 86 47 39 d2 34 7d bc 9d 5d 64 53 07 e4 aa 62 ee cc 8c 71 cf 01 15 13 e8 94 c9 7d 48 c7 2c c1 93 3d c4 54 6e 22 54 22 64 c8 9c 72 24 53 ad dd 32 04 4c 71 01 28 a5 30 64 4c 09 14 10 a6 30 50 fa 89 1c a7 8c c1 1c 8e f9 74 80 ac 84 24 82 26 d0 89 18 e3 74 cc 81 cb 3a 62 44 22 6a 88 ab 07 44 90 44 93 aa 84 53 30 a4 c9 07 2c d6 93 35 c4 ca c4 50 2c c2 48 22 b9 99 13 3e 44 cb 91 30 85 ca c6 72 31 2e fd b4 8f a2 55 b0 9d 5a 03 32 cd 13 ad 43 dd da e4 98 1b 17 f3 ed f1 97 f3 e9 f1 38 d4 4a 34 4b 74 4d 55 13 3b 40 6e 44 39 9f 3a 48 a4 4c 3e 14 c9 86 2e c7 1c 98 67 20 18 d4 20 22 4e 22 64 e8 9e ba 27 9e c3 32 c9 32 29 ab eb 2f e7 db e6 67 e8 91 08 98 fa 26 18 89 70 80 c4 a4 23 88 97 08 91 89 7b 48 c6 8f c7 d4 9e 44 8a 44 e5 51 4d e2 28 65 44 c9 91 1c 61 41 2a 5e ce c7 14 c0 19 3f 1f 7a 3f 9f 8f ad 98 39 a8 fb 6f 34 74 48 d4 54 7f a2 6c cc 24 ea 24 8a 5e ae a7 04 91 63 b3 f9 fd a6 cf e7 ec bc b3 30 14 4c 15 84 c0 51 24 91 14 40 3e 67 a5 50 4a 23 08 98 5a 5e ae 99 20 d7 59 1c eb a0 41 12 49 13 2b 44 b0 44 92 66 df 96 4c b6 7f 67 69 68 4b 2a 40 22 a2 0d 13 8b 44 5e cc 61 12 31 84 c5 11 33 d4 4c 49 2f 47 4c 90 6b 3a 54 48 64 50 9c 89 a3 a2 47 22 28 88 e3 09 1c 89 34 99 c3 a2 47 33 97 c8 91 88 a0 d1 13 02 44 61 01 09 04 97 44 a0 63 1a 44 82 45 00 48 93 48 9a 12 24 33 76 f4 c5 98 6d ba 54 a2 86 d4 48 b4 06 a7 84 d1 e4 e6 6d f5 55 25 d0 f9 7c bd 5e 39 76 b8 1a 92 11 a5 02 c8 98 0a 26 be 97 93 96 42 3a 6a 04 98 03 e6 f2 48 87 4c 78 9d 6a 26 12 8a 17 d8 46 11 39 f4 48 a6 6d a9 6c d6 45 33 99 1a 39 48 a7 89 31 07 54 9e 6d 37 5a 67 0c 26 20 88 bd 90 84 c4 1a 3c 5c b2 21 db 34 44 4c 59 12 31 15 4b c8 98 93 19 18 e3 a1 21 13 c7 44 fa d1 31 44 51 ae 97 8b 91 b3 32 66 b2 52 90 88 93 88 a8 4f 44 84 73 b5 64 02 24 22 27 4e 8a 29 91 21 1d 95 01 28 9d 42 24 23 c0 10 53 66 d2 40 3c c7 74 80 78 d5 49 48 99 82 26 c8 89 84 39 5d ce 09 8e 26 42 30 a3 f9 14 72 22 77 c8 91 88 a8 ad 4c d2 1a 48 85 87 e7 80 48 47 73 85 ad 41 ea 27 c8 8a 92 54 7e 48 27 03 ea 82 a1 de e1 6b 6c 83 94 68 08 55 b0 b7 09 50 d0 89 56 85 da a9 37 97 13 65 a3 4c 88 f6 92 e8 9c 25 9a b2 b4 48 a4 48 26 34 28 a1 fc fa 7b 65 f6 f6 78 48 24 47 91 42 7a 22 88 a8 b8 45 0a 29 92 c8 90 8c 5e ae
    #   """

if __name__ == '__main__':
    unittest.main()


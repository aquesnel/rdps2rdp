
import unittest

from data_model_v2_tpkt import Tpkt
from data_model_v2_x224 import X224
from data_model_v2_mcs import Mcs
from data_model_v2_rdp import Rdp

from parser_v2 import parse, RdpContext
import parser_v2_context

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
            # Rdp_RDPGFX_commands_PDU
            # 13 00 # cmdId = RDPGFX_CMDID_CAPSCONFIRM
            # 00 00 # flags
            # 14 00 00 00 # pduLength = 20
            # RDPGFX_CMDID_CAPSCONFIRM
            # 00 06 0a 00 # version
            # 04 00 00 00 # capsDataLength
            # 00 00 00 00 # capsData
            """)
        
        rdp_context = extract_as_context({'domain': '', 'password': 'P@ssw0rd!', 'pdu_source': None, 'encryption_method': 0, 'allow_partial_parsing': False, 'working_dir': '', 'encrypted_client_random': None, 'encryption_level': 0, 'auto_logon': True, '_channel_defs': [{'name': 'rdpdr', 'channel_id': 1004, 'type': 'STATIC', 'options': {2147483648}}, {'name': 'rdpsnd', 'channel_id': 1005, 'type': 'STATIC', 'options': {1073741824, 2147483648}}, {'name': 'rail', 'channel_id': 1006, 'type': 'STATIC', 'options': {1073741824, 2147483648, 1048576, 2097152}}, {'name': 'rail_wi', 'channel_id': 1007, 'type': 'STATIC', 'options': {1073741824, 2147483648, 1048576, 2097152}}, {'name': 'rail_ri', 'channel_id': 1008, 'type': 'STATIC', 'options': {1073741824, 2147483648, 1048576, 2097152}}, {'name': 'cliprdr', 'channel_id': 1009, 'type': 'STATIC', 'options': {1073741824, 2147483648, 2097152}}, {'name': 'drdynvc', 'channel_id': 1010, 'type': 'STATIC', 'options': {1073741824, 2147483648}}, {'name': 'I/O Channel', 'channel_id': 1003, 'type': 'STATIC', 'options': 0}, {'name': 'McsMessageChannel', 'channel_id': 1011, 'type': 'STATIC', 'options': 0}, {'name': 'Microsoft::Windows::RDS::Telemetry', 'channel_id': 5, 'type': 'DYNAMIC', 'options': 0}, {'name': 'Microsoft::Windows::RDS::Graphics', 'channel_id': 7, 'type': 'DYNAMIC', 'options': 0}], 'alternate_shell': 'rdpinit.exe', 'compression_engines': {}, 'rail_enabled': True, 'is_gcc_confrence': True, 'previous_primary_drawing_orders': {}, 'compression_virtual_chan_cs_encoder': None, 'pre_capability_exchange': False, 'compression_type': None, 'user_name': 'runneradmin', 'rdp_gfx_pre_capability_exchange': False} )      
        parser_config = parser_v2_context.ParserConfig(strict_parsing = False)
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context, parser_config)
        print(pdu)
        
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

        # self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.descriptor, Rdp.GraphicsPipelineExtention.DataPackaging.DEBLOCK_SINGLE)
        # self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.header_CompressionType, Rdp.GraphicsPipelineExtention.Compression.PACKET_COMPR_TYPE_RDP8)
        # self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.bulkData.header_CompressionFlags, {Rdp.GraphicsPipelineExtention.Compression.PACKET_COMPRESSED})

        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.commands[0].header.cmdId, Rdp.GraphicsPipelineExtention.Commands.RDPGFX_CMDID_CAPSCONFIRM)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.commands[0].header.flags, set())
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.commands[0].header.pduLength, 20)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.commands[0].caps_confirm.version, 656896) # bytes.fromhex("00 06 0a 00") little endian
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.commands[0].caps_confirm.capsDataLength, 4)
        self.assertEqual(bytes(pdu.tpkt.mcs.rdp.channel.dyvc.data.GFX_PDU.commands[0].caps_confirm.capsData), bytes.fromhex("00 00 00 00"))

        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
      

if __name__ == '__main__':
    unittest.main()


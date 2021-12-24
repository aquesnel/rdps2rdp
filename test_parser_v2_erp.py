
import unittest

from data_model_v2_tpkt import Tpkt
from data_model_v2_x224 import X224
from data_model_v2_mcs import Mcs
from data_model_v2_rdp import Rdp

from parser_v2 import parse, RdpContext

from test_utils import extract_as_bytes, extract_as_context


class TestParsing(unittest.TestCase):

    def test_parse_rail_handshake_ex(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3
        # data captured from an MSTSC session with a Win10 datacenter RDP 10? server
        # pdu from server
        data = extract_as_bytes("""
            03 00 00 24 # TPKT(len=36)
            02 f0 80    # X224(len=2, type=data)
            68 00 01 03 f2 f0 16 # Mcs(len=22, type=SEND_DATA_FROM_SERVER)
            0e 00 00 00 03 00 00 00 # CHANNEL_PDU_HEADER(len=14, flags=First|Last)
            34 0e       # Dyvc(Cmd=COMMAND_DATA, chan_id_len=1, chan_id=14 [rail])
            13 00 0c 00 # TS_RAIL_PDU_HEADER(type=TS_RAIL_ORDER_HANDSHAKE_EX, len=12)
            00 00 00 00 # TS_RAIL_ORDER_HANDSHAKE_EX.buildNumber
            07 00 00 00 # TS_RAIL_ORDER_HANDSHAKE_EX.railHandshakeFlags 
            """)
        
        rdp_context = extract_as_context({'compression_type': 1536, 'pdu_source': None, 'encryption_level': 0, 'is_gcc_confrence': True, 'password': 'P@ssw0rd!', 'encrypted_client_random': None, 'working_dir': '', 'alternate_shell': 'rdpinit.exe', 'pre_capability_exchange': False, 'domain': '', 'auto_logon': True, 'rail_enabled': True, 'user_name': 'runneradmin', 'channel_defs': [{'name': 'rdpdr', 'type': 'DYNAMIC', 'options': 0, 'channel_id': 12}, {'name': 'rdpsnd', 'type': 'STATIC', 'options': {2147483648, 1073741824}, 'channel_id': 1005}, {'name': 'rail', 'type': 'DYNAMIC', 'options': 0, 'channel_id': 14}, {'name': 'rail_wi', 'type': 'STATIC', 'options': {2147483648, 8388608, 1048576, 1073741824, 2097152}, 'channel_id': 1007}, {'name': 'rail_ri', 'type': 'STATIC', 'options': {2147483648, 8388608, 1048576, 1073741824, 2097152}, 'channel_id': 1008}, {'name': 'cliprdr', 'type': 'STATIC', 'options': {2147483648, 8388608, 1073741824, 2097152}, 'channel_id': 1009}, {'name': 'drdynvc', 'type': 'STATIC', 'options': {2147483648, 8388608, 1073741824}, 'channel_id': 1010}, {'name': 'I/O Channel', 'type': 'STATIC', 'options': 0, 'channel_id': 1003}, {'name': 'McsMessageChannel', 'type': 'STATIC', 'options': 0, 'channel_id': 1011}, {'name': 'Microsoft::Windows::RDS::Graphics', 'type': 'DYNAMIC', 'options': 0, 'channel_id': 7}, {'name': 'AUDIO_PLAYBACK_DVC', 'type': 'DYNAMIC', 'options': 0, 'channel_id': 3}, {'name': 'Microsoft::Windows::RDS::Geometry::v08.01', 'type': 'DYNAMIC', 'options': 0, 'channel_id': 9}, {'name': 'AUDIO_PLAYBACK_LOSSY_DVC', 'type': 'DYNAMIC', 'options': 0, 'channel_id': 10}, {'name': 'Microsoft::Windows::RDS::Input', 'type': 'DYNAMIC', 'options': 0, 'channel_id': 11}], 'encryption_method': 0} ) 
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context)
        
        self.assertEqual(pdu.rdp_fp_header.action, Rdp.FastPath.FASTPATH_ACTION_X224)
        self.assertEqual(pdu.tpkt.length, 36)
        
        self.assertEqual(pdu.tpkt.x224.length, 2)
        self.assertEqual(pdu.tpkt.x224.type, X224.TPDU_DATA)   

        self.assertEqual(pdu.tpkt.mcs.type, Mcs.SEND_DATA_FROM_SERVER)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.initiator, 1002)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.channelId, 1010)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.dataPriority_TODO, 0xf0)
        self.assertEqual(pdu.tpkt.mcs.mcs_user_data.segmentation_TODO, 0xf0)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.header.length, 14)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.header.flags, {Rdp.Channel.CHANNEL_FLAG_FIRST, Rdp.Channel.CHANNEL_FLAG_LAST})
        
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.header.cbId, 0)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.header.Pri, 1)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.header.Cmd, Rdp.DynamicVirtualChannels.COMMAND_DATA)
        
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.TS_RAIL_PDU.header.orderType, Rdp.Rail.TS_RAIL_ORDER_HANDSHAKE_EX)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.TS_RAIL_PDU.header.orderLength, 12)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.TS_RAIL_PDU.payload.buildNumber, 0)
        self.assertEqual(pdu.tpkt.mcs.rdp.channel.dyvc.data.TS_RAIL_PDU.payload.railHandshakeFlags, {Rdp.Rail.TS_RAIL_HANDSHAKE_EX_FLAGS_HIDEF, Rdp.Rail.TS_RAIL_HANDSHAKE_EX_FLAGS_EXTENDED_SPI_SUPPORTED, Rdp.Rail.TS_RAIL_HANDSHAKE_EX_FLAGS_SNAP_ARRANGE_SUPPORTED})
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
        
       
    
if __name__ == '__main__':
    unittest.main()


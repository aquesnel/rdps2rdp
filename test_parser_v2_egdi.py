
import unittest

from data_model_v2_tpkt import Tpkt
from data_model_v2_x224 import X224
from data_model_v2_mcs import Mcs
from data_model_v2_rdp import Rdp

from parser_v2 import parse, RdpContext

from test_utils import extract_as_bytes, extract_as_context


class TestParsing(unittest.TestCase):

    @unittest.skip("unittest not implemented yet")
    def test_parse_primary_drawing_order_unknown_1(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3
        # data captured from an MSTSC session with a Win10 datacenter RDP 10? server
        # pdu from server
        # OUTPUTPCAP = 'output.win10.rail.no-all-compression.no-gfx.failed.pcap' ; SERVER_PORT = 19119 ; offset = 64 ; limit = 1 ;
        data = extract_as_bytes("""
            00 84 0c # FastPath (len=1036)
            00 06 04 # FastPath Update (len=1030, type=FASTPATH_UPDATETYPE_ORDERS)
            0c 01 # Orders (items=268)
            
            # Order 0
            36 00 00 00 00 # Order(type=TS_ALTSEC_FRAME_MARKER, action=TS_FRAME_START)
            
            # Order 1
            49 # DRAWING_ORDER (type=TS_STANDARD, controlFlags: {'TS_PRIMARY_TYPE_CHANGE (8)', 'TS_PRIMARY_ZERO_FIELD_BYTE_BIT0 (64)'}
            0d # PRIMARY_DRAWING_ORDER (orderType= TS_ENC_MEMBLT_ORDER)
            39 # PRIMARY_DRAWING_ORDER (fieldFlags)
            02 00 40 00 40 00 cc # MEMBLT_ORDER fields present
            
            # Order 2
            51 # b'0101 0001' DRAWING_ORDER (type=TS_STANDARD, controlFlags: {TS_DELTA_COORDINATES, 'TS_PRIMARY_ZERO_FIELD_BYTE_BIT0 (64)'}
            # IMPLIED - PRIMARY_DRAWING_ORDER (orderType= TS_ENC_MEMBLT_ORDER)
            02 # PRIMARY_DRAWING_ORDER (fieldFlags)
            40 # MEMBLT_ORDER fields present
            
            # Order 3-21: same as order 2
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            
            # Order 22
            03 1d 00 # DRAWING_ORDER (type=SECONDARY, len=29+13=42)
            22 0d 05 # SECONDARY_DRAWING_ORDER (type=TS_CACHE_BITMAP_COMPRESSED_REV2)
            c7 c9 d2 03 f6 e0 dd 25 14 40 
            40 16 ff ff 10 84 00 00 00 00 
            00 00 00 00 f0 e8 04 84 00 00 
            00 00 00 00 00 00             # TS_CACHE_BITMAP_COMPRESSED_REV2 - compressed data
            
            # Order 23
            11 # b'0001 0001' DRAWING_ORDER (type=TS_STANDARD, controlFlags: {TS_DELTA_COORDINATES}
            # IMPLIED - PRIMARY_DRAWING_ORDER (orderType= TS_ENC_MEMBLT_ORDER)
            0a 01 # PRIMARY_DRAWING_ORDER (fieldFlags)
            40 d4 ff 7f # MEMBLT_ORDER fields present
            
            # Order 24
            01 # b'0001 0001' DRAWING_ORDER (type=TS_STANDARD, controlFlags: {None}
            # IMPLIED - PRIMARY_DRAWING_ORDER (orderType= TS_ENC_MEMBLT_ORDER)
            0e 01 # PRIMARY_DRAWING_ORDER (fieldFlags)
            00 00 40 00 40 00 00 00 # MEMBLT_ORDER fields present
            
            # Order 25-44: same as order 2
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            51 02 40 
            
            # Order 45
            03 1c 00 # DRAWING_ORDER (type=SECONDARY, len=28+13=41)
            22 05 05 # SECONDARY_DRAWING_ORDER (type=TS_CACHE_BITMAP_COMPRESSED_REV2)
            c7 c9 d2 03 f6 e0 dd 25 14 40 40 16 22 10 84 00 00 00 00 00 00 00 00 f0 e8 04 84 00 00 00 00 00 00 00 00 11 0a 01 40 d4 22 00 01 0e 01 00 00 80 00 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 c0 00 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 00 01 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 40 01 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 80 01 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 c0 01 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 00 02 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 40 02 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 80 02 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 01 0e 01 00 00 c0 02 40 00 00 00 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 51 02 40 11 0a 01 40 d4 22 00 36 01 00 00 00
            """)
        
        rdp_context = extract_as_context({'auto_logon': True, 'password': 'P@ssw0rd!', 'channel_defs': [{'options': {2147483648}, 'name': 'rdpdr', 'channel_id': 1004, 'type': 'STATIC'}, {'options': {2147483648, 1073741824}, 'name': 'rdpsnd', 'channel_id': 1005, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152, 1048576}, 'name': 'rail', 'channel_id': 1006, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152, 1048576}, 'name': 'rail_wi', 'channel_id': 1007, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152, 1048576}, 'name': 'rail_ri', 'channel_id': 1008, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152}, 'name': 'cliprdr', 'channel_id': 1009, 'type': 'STATIC'}, {'options': {2147483648, 1073741824}, 'name': 'drdynvc', 'channel_id': 1010, 'type': 'STATIC'}, {'options': 0, 'name': 'I/O Channel', 'channel_id': 1003, 'type': 'STATIC'}, {'options': 0, 'name': 'McsMessageChannel', 'channel_id': 1011, 'type': 'STATIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Telemetry', 'channel_id': 3, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'ECHO', 'channel_id': 8, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Video::Control::v08.01', 'channel_id': 9, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Video::Data::v08.01', 'channel_id': 10, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Geometry::v08.01', 'channel_id': 11, 'type': 'DYNAMIC'}], 'previous_primary_drawing_orders': {}, 'encryption_level': 0, 'domain': '', 'pre_capability_exchange': False, 'encrypted_client_random': None, 'pdu_source': None, 'compression_virtual_chan_cs_encoder': None, 'user_name': 'runneradmin', 'rail_enabled': True, 'encryption_method': 0, 'alternate_shell': 'rdpinit.exe', 'compression_type': None, 'is_gcc_confrence': True, 'working_dir': ''} )      
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context)
        
        self.assertEqual(pdu.rdp_fp.header.action, Rdp.FastPath.FASTPATH_ACTION_FASTPATH)
        self.assertEqual(pdu.rdp_fp.header.numEvents, 0)
        self.assertEqual(pdu.rdp_fp.header.flags, set())
        self.assertEqual(pdu.rdp_fp.length, 1030)
        self.assertEqual(pdu.rdp_fp.fipsInformation, None)
        self.assertEqual(pdu.rdp_fp.dataSignature, None)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateCode, "TODO: implement this test")
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
        
    def test_parse_alt_sec_drawing_order_frame_mark(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/b69a751e-34df-4326-b4e1-0e582ff7ea97
        # data captured from an MSTSC session with a Win10 datacenter RDP 10? server
        # pdu from server
        data = extract_as_bytes("""
            00 11 # FastPath (len=17)
            00 0c 00 # FastPath Update (len=12, type=FASTPATH_UPDATETYPE_ORDERS)
            02 00 # Orders (items=2)
            36 00 00 00 00 # Order(type=TS_ALTSEC_FRAME_MARKER, action=TS_FRAME_START)
            36 01 00 00 00 # Order(type=TS_ALTSEC_FRAME_MARKER, action=TS_FRAME_END)
            """)
        
        rdp_context = extract_as_context({'auto_logon': True, 'password': 'P@ssw0rd!', 'channel_defs': [{'options': {2147483648}, 'name': 'rdpdr', 'channel_id': 1004, 'type': 'STATIC'}, {'options': {2147483648, 1073741824}, 'name': 'rdpsnd', 'channel_id': 1005, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152, 1048576}, 'name': 'rail', 'channel_id': 1006, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152, 1048576}, 'name': 'rail_wi', 'channel_id': 1007, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152, 1048576}, 'name': 'rail_ri', 'channel_id': 1008, 'type': 'STATIC'}, {'options': {2147483648, 1073741824, 2097152}, 'name': 'cliprdr', 'channel_id': 1009, 'type': 'STATIC'}, {'options': {2147483648, 1073741824}, 'name': 'drdynvc', 'channel_id': 1010, 'type': 'STATIC'}, {'options': 0, 'name': 'I/O Channel', 'channel_id': 1003, 'type': 'STATIC'}, {'options': 0, 'name': 'McsMessageChannel', 'channel_id': 1011, 'type': 'STATIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Telemetry', 'channel_id': 3, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'ECHO', 'channel_id': 8, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Video::Control::v08.01', 'channel_id': 9, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Video::Data::v08.01', 'channel_id': 10, 'type': 'DYNAMIC'}, {'options': 0, 'name': 'Microsoft::Windows::RDS::Geometry::v08.01', 'channel_id': 11, 'type': 'DYNAMIC'}], 'previous_primary_drawing_orders': {}, 'encryption_level': 0, 'domain': '', 'pre_capability_exchange': False, 'encrypted_client_random': None, 'pdu_source': None, 'compression_virtual_chan_cs_encoder': None, 'user_name': 'runneradmin', 'rail_enabled': True, 'encryption_method': 0, 'alternate_shell': 'rdpinit.exe', 'compression_type': None, 'is_gcc_confrence': True, 'working_dir': ''} )      
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context)
        
        self.assertEqual(pdu.rdp_fp.header.action, Rdp.FastPath.FASTPATH_ACTION_FASTPATH)
        self.assertEqual(pdu.rdp_fp.header.numEvents, 0)
        self.assertEqual(pdu.rdp_fp.header.flags, set())
        self.assertEqual(pdu.rdp_fp.length, 17)
        self.assertEqual(pdu.rdp_fp.fipsInformation, None)
        self.assertEqual(pdu.rdp_fp.dataSignature, None)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateCode, Rdp.FastPath.FASTPATH_UPDATETYPE_ORDERS)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].fragmentation, Rdp.FastPath.FASTPATH_FRAGMENT_SINGLE)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].compression, 0)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].compressionType, None)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].compressionArgs, None)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].size, 12)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.numberOrders, 2)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[0].header.controlFlags_class, Rdp.DrawingOrders.OrderFlags.TS_SECONDARY)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[0].header.controlFlags, Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_FRAME_MARKER)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[0].orderSpecificData.altSecondaryOrderData.action, 0)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[1].header.controlFlags_class, Rdp.DrawingOrders.OrderFlags.TS_SECONDARY)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[1].header.controlFlags, Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_FRAME_MARKER)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[1].orderSpecificData.altSecondaryOrderData.action, 1)
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
      

    def test_parse_unknown_2(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/b69a751e-34df-4326-b4e1-0e582ff7ea97
        # data captured from an MSTSC session with a Win10 datacenter RDP 10? server
        # OUTPUTPCAP = 'output.win10.rail.no-compression.no-gfx.fail.pcap' ; SERVER_PORT = 33930 ; offset = 180 ;
        # pdu from server
        data = extract_as_bytes("""
            30 81 da # FastPath (num/reserved = 12, len=474)
            a0 03 # FastPath Update (type=FASTPATH_UPDATETYPE_ORDERS, flags=FASTPATH_FRAGMENT_FIRST, FASTPATH_OUTPUT_COMPRESSION_USED, compressionFlags=PACKET_COMPR_TYPE_RDP61)
            02 01 # FastPath Update (size= 258) # I think this is uncompressed or re-assembeled since the remaining bytes in the PDU is 214
            06 # RDP61_COMPRESSED_DATA (Level1ComprFlags= L1_PACKET_AT_FRONT, L1_NO_COMPRESSION)
            a1 # RDP61_COMPRESSED_DATA (Level2ComprFlags= ignored because not L1_INNER_COMPRESSION flag is set)
            # the rest is RDP61 compression literals
            81 d2 30 81 cf 30 81 cc a0 81 c9 04 81 c6 4e 54 4c 4d 53 53 50 00 02 00 00 00 16 00 16 00 38 00 00 00 35 82 8a e2 ea 3e af 3b 6d 95 b8 dc 00 00 00 00 00 00 00 00 78 00 78 00 4e 00 00 00 0a 00 63 45 00 00 00 0f 41 00 50 00 50 00 56 00 45 00 59 00 4f 00 52 00 2d 00 56 00 4d 00 02 00 16 00 41 00 50 00 50 00 56 00 45 00 59 00 4f 00 52 00 2d 00 56 00 4d 00 01 00 16 00 41 00 50 00 50 00 56 00 45 00 59 00 4f 00 52 00 2d 00 56 00 4d 00 04 00 16 00 61 00 70 00 70 00 76 00 65 00 79 00 6f 00 72 00 2d 00 76 00 6d 00 03 00 16 00 61 00 70 00 70 00 76 00 65 00 79 00 6f 00 72 00 2d 00 76 00 6d 00 07 00 08 00 1c 73 6c 9f 14 9e d7 01 00 00 00 00
    
            # 00 11 # FastPath (len=17)
            # 00 0c 00 # FastPath Update (len=12, type=FASTPATH_UPDATETYPE_ORDERS)
            # 02 00 # Orders (items=2)
            # 36 00 00 00 00 # Order(type=TS_ALTSEC_FRAME_MARKER, action=TS_FRAME_START)
            # 36 01 00 00 00 # Order(type=TS_ALTSEC_FRAME_MARKER, action=TS_FRAME_END)
            """)
        
        rdp_context = extract_as_context({'encryption_level': 0, 'channel_defs': [{'options': 0, 'channel_id': 12, 'type': 'DYNAMIC', 'name': 'rdpdr'}, {'options': {1073741824, 2147483648}, 'channel_id': 1005, 'type': 'STATIC', 'name': 'rdpsnd'}, {'options': 0, 'channel_id': 14, 'type': 'DYNAMIC', 'name': 'rail'}, {'options': {2097152, 1073741824, 1048576, 2147483648}, 'channel_id': 1007, 'type': 'STATIC', 'name': 'rail_wi'}, {'options': {2097152, 1073741824, 1048576, 2147483648}, 'channel_id': 1008, 'type': 'STATIC', 'name': 'rail_ri'}, {'options': 0, 'channel_id': 17, 'type': 'DYNAMIC', 'name': 'cliprdr'}, {'options': {1073741824, 2147483648}, 'channel_id': 1010, 'type': 'STATIC', 'name': 'drdynvc'}, {'options': 0, 'channel_id': 1003, 'type': 'STATIC', 'name': 'I/O Channel'}, {'options': 0, 'channel_id': 1011, 'type': 'STATIC', 'name': 'McsMessageChannel'}, {'options': 0, 'channel_id': 3, 'type': 'DYNAMIC', 'name': 'Microsoft::Windows::RDS::Telemetry'}, {'options': 0, 'channel_id': 8, 'type': 'DYNAMIC', 'name': 'ECHO'}, {'options': 0, 'channel_id': 18, 'type': 'DYNAMIC', 'name': 'Microsoft::Windows::RDS::Input'}, {'options': 0, 'channel_id': 10, 'type': 'DYNAMIC', 'name': 'AUDIO_PLAYBACK_DVC'}, {'options': 0, 'channel_id': 11, 'type': 'DYNAMIC', 'name': 'Microsoft::Windows::RDS::DisplayControl'}, {'options': 0, 'channel_id': 18, 'type': 'DYNAMIC', 'name': 'AUDIO_PLAYBACK_LOSSY_DVC'}, {'options': 0, 'channel_id': 9, 'type': 'DYNAMIC', 'name': 'Microsoft::Windows::RDS::Geometry::v08.01'}], 'compression_virtual_chan_cs_encoder': None, 'previous_primary_drawing_orders': {'order_type': 13}, 'working_dir': '', 'pdu_source': None, 'encryption_method': 0, 'compression_type': None, 'user_name': 'runneradmin', 'password': 'P@ssw0rd!', 'domain': '', 'pre_capability_exchange': False, 'auto_logon': True, 'alternate_shell': 'rdpinit.exe', 'encrypted_client_random': None, 'rail_enabled': True, 'allow_partial_parsing': False, 'is_gcc_confrence': True})         
        pdu = parse(RdpContext.PduSource.SERVER, data, rdp_context, allow_partial_parsing = True)
        print(pdu)
        
        self.assertEqual(pdu.rdp_fp.header.action, Rdp.FastPath.FASTPATH_ACTION_FASTPATH)
        self.assertEqual(pdu.rdp_fp.header.numEvents, 12)
        self.assertEqual(pdu.rdp_fp.header.flags, set())
        self.assertEqual(pdu.rdp_fp.length, 474)
        self.assertEqual(pdu.rdp_fp.fipsInformation, None)
        self.assertEqual(pdu.rdp_fp.dataSignature, None)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateCode, Rdp.FastPath.FASTPATH_UPDATETYPE_ORDERS)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].fragmentation, Rdp.FastPath.FASTPATH_FRAGMENT_FIRST)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].compression, 0)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].compressionType, compression_constants.CompressionTypes.RDP_61)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].compressionArgs, set())
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].size, 258)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.numberOrders, 2)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[0].header.controlFlags_class, Rdp.DrawingOrders.OrderFlags.TS_SECONDARY)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[0].header.controlFlags, Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_FRAME_MARKER)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[0].orderSpecificData.altSecondaryOrderData.action, 0)
        
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[1].header.controlFlags_class, Rdp.DrawingOrders.OrderFlags.TS_SECONDARY)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[1].header.controlFlags, Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_FRAME_MARKER)
        self.assertEqual(pdu.rdp_fp.fpOutputUpdates[0].updateData.orderData[1].orderSpecificData.altSecondaryOrderData.action, 1)
        
        self.assertEqual(bytes(pdu.as_wire_bytes()), data)
    
    
if __name__ == '__main__':
    unittest.main()


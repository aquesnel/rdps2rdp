import unittest
import binascii
import json
import os

import data_model_v2_rdp
import data_model_v2_rdp_egdi
import parser_v2
import parser_v2_context
import stream_processors

import compression
import compression_constants
import test_utils
from compression_utils import (
    CompressionArgs,
)

SELF_DIR = os.path.dirname(__file__)

# test data copied from https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/codec/test/TestFreeRDPCodecXCrush.c
# limitations of that test data:
# * the TEST_BELLS_DATA_XCRUSH is 2 bytes short. I don't know how their test can pass
# * the TEST_BELLS_DATA_XCRUSH has L1 and L2 compression skipped
# * the TEST_ISLAND_DATA_XCRUSH has L1 compression skipped and L2 compression performed. So this only exercises the MPPC compression
        

class TestCompressionRdp61(unittest.TestCase):
    
    # @unittest.skip("skip for debugging")
    def test_one_char_at_a_time(self):
        data = b'\x01\x01'
        compressed_data = test_utils.extract_as_bytes("""
                                # match count: 1
                                0100
                                # match details - length
                                0100
                                # match details - output offset
                                0100
                                # match details - history offset
                                00000000
                                # literals
                                01
                                """)

        c = compression.CompressionFactory.new_RDP_61_L1()
        d = compression.CompressionFactory.new_RDP_61_L1()
        
        compression_args = CompressionArgs(data = compressed_data, flags = {compression_constants.CompressionFlags.COMPRESSED}, type = compression_constants.CompressionTypes.RDP_61)
        inflated_1 = d.decompress(compression_args)
        # print("data: %s" % data.hex())
        # print("infa: %s" % inflated_1.hex())
        self.assertEqual(inflated_1, data)
        # self.assertEqual(inflated_1.hex(), data.hex())
        
        # deflated_1 = c.compress(data)
        # self.assertEqual(deflated_1.data.hex(), compressed_data.hex())

    # @unittest.skip("skip for debugging")
    def test_null_compress_L1_and_L2(self):
        data = b"for.whom.the.bell.tolls,.the.bell.tolls.for.thee!"
        # copied from https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/codec/test/TestFreeRDPCodecXCrush.c
        # but the TEST_BELLS_DATA_XCRUSH is 2 bytes short. I don't know how their test can pass
        # note: the first 2 bytes are the L1 and L2 compression flags
        # L1 = L1_INNER_COMPRESSION | L1_NO_COMPRESSION
        # L2 = None
        compressed_data = b"\x12\x00\x66\x6f\x72\x2e\x77\x68\x6f\x6d\x2e\x74\x68\x65\x2e\x62\x65\x6c\x6c\x2e\x74\x6f\x6c\x6c\x73\x2c\x2e\x74\x68\x65\x2e\x62\x65\x6c\x6c\x2e\x74\x6f\x6c\x6c\x73\x2e\x66\x6f\x72\x2e\x74\x68\x65\x65\x21"
        
        c = compression.CompressionFactory.new_RDP_61()
        d = compression.CompressionFactory.new_RDP_61()
        
        inflated_1 = d.decompress(CompressionArgs(data = compressed_data, flags = set(), type = compression_constants.CompressionTypes.RDP_61))
        self.assertEqual(inflated_1, data)
        self.assertEqual(inflated_1.hex(), data.hex())

    # @unittest.skip("skip for debugging")
    def test_compress_L1_only(self):
        data = b"for.whom.the.bell.tolls,.the.bell.tolls.for.thee!"
        compressed_data = test_utils.extract_as_bytes("""
                                # match count
                                0300
                                # MatchTuple(length_of_match=15, output_offset=24, history_offset=8)
                                0f00 1800 08000000
                                # MatchTuple(length_of_match=4, output_offset=40, history_offset=0)
                                0400 2800 00000000
                                # MatchTuple(length_of_match=3, output_offset=44, history_offset=25)
                                0300 2c00 19000000
                                # literals = b'for.whom.the.bell.tolls,.e!'
                                666f722e77686f6d2e7468652e62656c6c2e746f6c6c732c2e6521
                                """)

        d = compression.CompressionFactory.new_RDP_61_L1()
        inflated_1 = d.decompress(CompressionArgs(data = compressed_data, flags = {compression_constants.CompressionFlags.COMPRESSED}, type = compression_constants.CompressionTypes.RDP_61))
        self.assertEqual(inflated_1, data)
        self.assertEqual(inflated_1.hex(), data.hex())
        
        c = compression.CompressionFactory.new_RDP_61_L1()
        d = compression.CompressionFactory.new_RDP_61_L1()
        
        deflated_1 = c.compress(data)
        self.assertEqual(deflated_1.data.hex(), compressed_data.hex())
        inflated_1 = d.decompress(deflated_1)
        self.assertEqual(inflated_1, data)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(deflated_1.data))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))
        
        deflated_2 = c.compress(data)
        # print("data 2    :     ",binascii.hexlify(data))
        # print("deflated 2:     ",binascii.hexlify(deflated_2.data))
        # print("inflated 2:     ",binascii.hexlify(inflated_2))

        inflated_2 = d.decompress(deflated_2)
        self.assertEqual(inflated_2, data)

    # @unittest.skip("skip for debugging")
    def test_compress_ISLAND_L1_NoCompression_L2_Compression(self):
        data = b"""No man is an island entire of itself; every man is a piece of the continent, a part of the main; if a clod be washed away by the sea, Europe is the less, as well as if a promontory were, aswell as any manner of thy friends or of thine own were; any man's death diminishes me, because I am involved in mankind. And therefore never send to know for whom the bell tolls; it tolls for thee."""
        
        # L1 compression flags = b"12" = (L1_INNER_COMPRESSION, L1_NO_COMPRESSION)
        # L2 compression flags = b"61" = (PACKET_COMPR_TYPE_64K, PACKET_COMPRESSED, PACKET_AT_FRONT)
        compressed_data = test_utils.extract_as_bytes("""12614e6f206d616e20697320f8d2d8c2dcc840cadce8d2e4ca40decc40d2e8e6cad8cc7640caeccae4f3fa712070696563fc12e8d0ca40c6dffbcddfd05840c240e0c2e4e9fe63ecc36b0b4b71d9034b37d731b637b2103132903bb0b9b432b21030bbb0bc90313c907e687365612c204575726f7065f2347d386c657373f069cc81dd95b1b08185cfc094e0e4dedbe2b37f924eecae4cbf863f060c2dde5d96e6572f1e53c90333934b2b732399037fd2b696ef381ddbbc2472653bf55bf8493b9903232b0ba34103234b6b4b734f96ce640dbe193132b1b0bab9b290249030b69034b73b37b63b79d4d2ddec186b696e642e2041f733cd47265666ff749bbdbf040e7e31103a379035b737bb907d8103bb437b6fa8e58bd0f0e8ded8d8e7ecf3a7e47ca7e29f01994b80""")

        d = compression.CompressionFactory.new_RDP_61()
        compression_args = CompressionArgs(data = compressed_data, flags = set(), type = compression_constants.CompressionTypes.RDP_61)
        inflated_1 = d.decompress(compression_args)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(compression_args.data))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))
        self.assertEqual(inflated_1, data)

        c = compression.CompressionFactory.new_RDP_61()
        d = compression.CompressionFactory.new_RDP_61()

        deflated_1 = c.compress(data)
        inflated_1 = d.decompress(deflated_1)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(deflated_1.data))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))
        self.assertEqual(inflated_1, data)


    # @unittest.skip("skip for debugging")
    def test_compress_ISLAND_same_packet_twice(self):
        data = b"""No man is an island entire of itself; every man is a piece of the continent, a part of the main; if a clod be washed away by the sea, Europe is the less, as well as if a promontory were, aswell as any manner of thy friends or of thine own were; any man's death diminishes me, because I am involved in mankind. And therefore never send to know for whom the bell tolls; it tolls for thee."""
        # L1 compression flags = b"11" = (L1_INNER_COMPRESSION, L1_COMPRESSED)
        # L2 compression flags = b"21" = (PACKET_COMPR_TYPE_64K, PACKET_COMPRESSED)
        compressed_data = test_utils.extract_as_bytes('1121290005000a000400000009002b0002f900500390019f900300440015f912900029f200800980065f201000a60075f6258fe93f843e002b7e09860017fc8988003efe098c0025fd099080467f44c940187ec4cb8010fe44cc800a7f04ce7f53c3113d008efe89a380157c8030053fc5400000700b00053bf84d9c011bf04db80269fc26e80144fb121602e1f224440671f2249c05cbc312580378fa126e0223f224e80621f225040463f04a280937d094901807a82804dc07e842b809ffc802802f80c3fec4b280cfbf44b700aff9625c805a3f04bc00ab7f097d0160f904e6f206d616e206973206c616e6420656e74697265206f6620697473656c663b206576657279207069656374686520636f6e2c6172746d61696e3b206966636c6f642062652077617368656420617761792062797365612c204575726f70656c657373732077656c6c70726f6d6f77657265616e6ef094333934b2b7323990379037bbb71d93b9903232b0ba34103234b6b4b77938dac4cac6c2eae6ca409240c2da40d2dcecded8ecd2dcd6d2dcc85c4082e4caccdedcde40d6dcdeee4040eed0dedac4e8ded8d8e6e8ca5c0') 

        d = compression.CompressionFactory.new_RDP_61()
        compression_args = CompressionArgs(data = compressed_data, flags = set(), type = compression_constants.CompressionTypes.RDP_61)
        inflated_1 = d.decompress(compression_args)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(compressed_data))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))
        self.assertEqual(inflated_1, data)

        c = compression.CompressionFactory.new_RDP_61()
        d = compression.CompressionFactory.new_RDP_61()
        
        deflated_1 = c.compress(data)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(deflated_1.data))
        # self.assertEqual(deflated_1.data.hex(), compressed_data.hex())

        inflated_1 = d.decompress(deflated_1)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(deflated_1))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))
        self.assertEqual(inflated_1, data)
        
        deflated_2 = c.compress(data)
        # print("data 2    :     ",binascii.hexlify(data))
        # print("deflated 2:     ",binascii.hexlify(deflated_2.data))
        self.assertEqual(deflated_2.data.hex(), '11210100817a55eb0000')

        inflated_2 = d.decompress(deflated_2)
        # print("inflated 2:     ",binascii.hexlify(inflated_2))
        self.assertEqual(inflated_2, data)
    
    @unittest.skip("skip for debugging")
    def test_from_snapshot_split_l1_vs_l2_decompression(self):
        # A PDU from a real connection
        # copied from the output of:
        # ```
        # venv-py3/bin/python3 rdps2rdp_pcap_v2.py print -i traffic-captures/output.win10.rail.no-compression-channels.success.pcap -if pcap -of snapshot -o 106 -l 1 > test_data/output.win10.rail.no-compression-channels.success.pdu-106.json
        # venv-py3/bin/python3 rdps2rdp_pcap_v2.py print -i traffic-captures/output.win10.rail.no-compression-channels.success.pcap -if pcap -of snapshot -o 755 -l 1 > test_data/output.win10.rail.no-compression-channels.success.pdu-755.json
        # ```
        with open(SELF_DIR + '/test_data/output.win10.rail.no-compression-channels.success.pdu-106.json', 'r') as f:
            snapshot = parser_v2_context.RdpStreamSnapshot.from_json(json.load(f))
        # import compression_rdp61; compression_rdp61.DEBUG = True
        # import compression_mppc;  compression_mppc.DEBUG = True
        # import compression_utils; compression_utils.DEBUG = True
        
        # d_l1 = compression.CompressionFactory.new_RDP_61_L1()

        d = snapshot.rdp_context.clone().get_compression_engine(compression_constants.CompressionTypes.RDP_61)
        d_l1 = d._l1_compression_engine
        d_l2 = d._l2_compression_engine
        try:
            pdu = parser_v2.parse(snapshot.pdu_source, snapshot.pdu_bytes, snapshot.rdp_context, parser_config = parser_v2_context.ParserConfig(compression_enabled = False))#, allow_partial_parsing = ALLOW_PARTIAL_PARSING)
        except parser_v2.ParserException as e:
            err = e.__cause__
            pdu = e.pdu
        compressed_data = pdu.rdp_fp.fpOutputUpdates[0].as_field_objects().updateData.get_compressed_bytes()

        compressed_struct = data_model_v2_rdp_egdi.Rdp_RDP61_COMPRESSED_DATA().with_value(compressed_data)
        L1_flags = data_model_v2_rdp.Rdp.Compression61.to_L1_compression_flags(compressed_struct.header.Level1ComprFlags)
        L2_flags = data_model_v2_rdp.Rdp.Compression61.to_L2_compression_flags(compressed_struct.header.Level2ComprFlags)
        
        if compression_constants.CompressionFlags.COMPRESSED in L2_flags:
            compression_args_l2 = CompressionArgs(data = compressed_struct.payload, flags = L2_flags, type = compression_constants.CompressionTypes.RDP_61)
            print("RDP_61 L2 compression:")
            print("flags:          ",L2_flags)
            print("history:        ",binascii.hexlify(d_l2._decompression_history_manager._history[:d_l2._decompression_history_manager._historyOffset]))
            print("compressed_data:",binascii.hexlify(compressed_data))
            data_l2 = d_l2.decompress(compression_args_l2)
        else:
            print("RDP_61 L2 compression: skipped")
            data_l2 = compressed_struct.payload
        print("flags:          ",L2_flags)
        print("compressed_data:",binascii.hexlify(compressed_data))
        print("inflated 1:     ",binascii.hexlify(data_l2))
        
        
        print("RDP_61 L1 compression:")
        print("flags:          ",L1_flags)
        print("history:        ",binascii.hexlify(d_l1._decompression_history_manager._history[:d_l1._decompression_history_manager._historyOffset]))
        print("compressed_data:",binascii.hexlify(data_l2))
        compression_args_l1 = CompressionArgs(data = data_l2, flags = L1_flags, type = compression_constants.CompressionTypes.RDP_61)
        data_l1 = d_l1.decompress(compression_args_l1)
        print("flags:          ",L1_flags)
        print("compressed_data:",binascii.hexlify(data_l2))
        print("inflated 1:     ",binascii.hexlify(data_l1))

        path = SELF_DIR + '/test_data/output.win10.rail.no-compression-channels.success.pdu-106.test_data_61.h'
        path = "/home/ubuntu/dev/freerdp/FreeRDP/libfreerdp/codec/test/output.win10.rail.no-compression-channels.success.pdu-106.test_data_61.h"
        do_write = False
        if do_write:
            with open(path, 'w') as f:
                printer = stream_processors.FreeRdpTestDataPrinter()
                printer.print_freerdp_compression_test_data(output_stream=f, compression_infos = [
                    stream_processors.CompressionInfo(snapshot.pdu_sequence_id, 
                                    "RDP 6.1 compression",
                                    compressed_data, 
                                    data_l1,
                                    compression_constants.CompressionTypes.RDP_61,
                                    set(),
                                    snapshot.pdu_source,
                                    ),
                    stream_processors.CompressionInfo(snapshot.pdu_sequence_id, 
                                    "RDP 6.1 L2 compression",
                                    compressed_data, 
                                    data_l2,
                                    compression_constants.CompressionTypes.RDP_61_L2,
                                    L2_flags,
                                    snapshot.pdu_source,
                                    ),
                    stream_processors.CompressionInfo(snapshot.pdu_sequence_id, 
                                    "RDP 6.1 L1 compression",
                                    data_l2,
                                    data_l1,
                                    compression_constants.CompressionTypes.RDP_61_L1,
                                    L1_flags,
                                    snapshot.pdu_source,
                                    ),
                ])


if __name__ == '__main__':
    unittest.main()

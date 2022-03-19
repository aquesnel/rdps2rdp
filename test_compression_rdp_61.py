import unittest
import binascii

import compression
import compression_constants
import test_utils
from compression_utils import (
    CompressionArgs,
)

# test data copied from https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/codec/test/TestFreeRDPCodecXCrush.c
# limitations of that test data:
# * the TEST_BELLS_DATA_XCRUSH is 2 bytes short. I don't know how their test can pass
# * the TEST_BELLS_DATA_XCRUSH has L1 and L2 compression skipped
# * the TEST_ISLAND_DATA_XCRUSH has L1 compression skipped and L2 compression performed. So this only exercises the MPPC compression
        

class TestCompressionRdp61(unittest.TestCase):
    
    @unittest.skip("not needed anymore")
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

        c = compression.CompressionFactory.new_RDP_61()
        d = compression.CompressionFactory.new_RDP_61()
        
        inflated_1 = d.decompress(compressed_data, l1_compressed = True, l2_compressed = False)
        print("data: %s" % data.hex())
        print("infa: %s" % inflated_1.hex())
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
                                # MatchTuple(length_of_match=4, output_offset=25, history_offset=0)
                                0400 1900 00000000
                                # MatchTuple(length_of_match=3, output_offset=25, history_offset=25)
                                0300 1900 19000000
                                # literals
                                666f722e77686f6d2e7468652e62656c6c2e746f6c6c732c2e6521
                                """)

        c = compression.CompressionFactory.new_RDP_61_L1()
        d = compression.CompressionFactory.new_RDP_61_L1()
        inflated_1 = d.decompress(CompressionArgs(data = compressed_data, flags = set(), type = compression_constants.CompressionTypes.RDP_61))
        # self.assertEqual(inflated_1, data)
        # self.assertEqual(inflated_1.hex(), data.hex())
        
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
    
    def test_compress_ISLAND_same_packet_twice(self):
        data = b"""No man is an island entire of itself; every man is a piece of the continent, a part of the main; if a clod be washed away by the sea, Europe is the less, as well as if a promontory were, aswell as any manner of thy friends or of thine own were; any man's death diminishes me, because I am involved in mankind. And therefore never send to know for whom the bell tolls; it tolls for thee."""
        compressed_data = test_utils.extract_as_bytes('1121290005000a00040000000900260002f9005002b0019f900300310015f912640029f20080067f28000010006c0075f624f80133f84aa002b7e095f002ff916fbf8258c012fe84b480467f44b48030fd896d0043f912dc0053f825c80231e18972008efe8974002af900600770053f900700810053bf84c08011bf04c180269fc260e0144fb13160070f91319009c7c89967829e18897005e3e84cd40047e45c43e44ce40063f04cebd64fa113a00807d0b3701fa1141003ff900500a30043fec4d1c027dfa2699e9a796229a00d1f8269a00adfc269a00c1f209cde40dac2dc40d2e640d8c2dcc840cadce8d2e4ca40decc40d2e8e6cad8cc7640caeccae4f240e0d2cac6e8d0ca40c6dedc58c2e4e8dac2d2dc7640d2ccc6d8dec840c4ca40eec2e6d0cac840c2eec2f240c4f2e6cac258408aeae4dee0cad8cae6e6e640eecad8d8e0e4dedadeeecae4cac2dcdde128667269656e6473206f206f776e3b27732064656174682064696d696ef271b589958d85d5cd9481248185b481a5b9d9bdb1d9a5b9ada5b990b88105c99599bdb9bc81adb9bddc8081dda1bdb589d1bdb1b1cdd194b8') 

        c = compression.CompressionFactory.new_RDP_61()
        d = compression.CompressionFactory.new_RDP_61()
   
        # L1 compression flags(L1_COMPRESSED)
        # 11
        # L2 compression flags (PACKET_COMPR_TYPE_64K, PACKET_COMPRESSED)
        # 21
        
        deflated_1 = c.compress(data)
        self.assertEqual(deflated_1.data.hex(), compressed_data.hex())

        inflated_1 = d.decompress(deflated_1)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(deflated_1.data))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))
        self.assertEqual(inflated_1, data)
        
        deflated_2 = c.compress(data)
        # print("data 2    :     ",binascii.hexlify(data))
        # print("deflated 2:     ",binascii.hexlify(deflated_2.data))
        self.assertEqual(deflated_2.data.hex(), '11210100817a55eb0000')

        inflated_2 = d.decompress(deflated_2)
        # print("inflated 2:     ",binascii.hexlify(inflated_2))
        self.assertEqual(inflated_2, data)
    

if __name__ == '__main__':
    unittest.main()

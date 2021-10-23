import unittest
import binascii

import compression
import test_utils

# test data copied from https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/codec/test/TestFreeRDPCodecXCrush.c
# limitations of that test data:
# * the TEST_BELLS_DATA_XCRUSH is 2 bytes short. I don't know how their test can pass
# * the TEST_BELLS_DATA_XCRUSH has L1 and L2 compression skipped
# * the TEST_ISLAND_DATA_XCRUSH has L1 compression skipped and L2 compression performed. So this only exercises the MPPC compression
        

class TestCompressionRdp61(unittest.TestCase):
    
    #@unittest.skip("not needed anymore")
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
        # self.assertEqual(deflated_1.hex(), compressed_data.hex())

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
        
        inflated_1 = d.decompress(compressed_data[2:], l1_compressed = False, l2_compressed = False)
        self.assertEqual(inflated_1, data)
        self.assertEqual(inflated_1.hex(), data.hex())

    def test_compress_L1_only(self):
        data = b"for.whom.the.bell.tolls,.the.bell.tolls.for.thee!"
        compressed_data = test_utils.extract_as_bytes("""
                                # match count
                                0300
                                # MatchTuple(length_of_match=2, output_offset=17, history_offset=8)
                                0200 1100 08000000
                                # MatchTuple(length_of_match=2, output_offset=20, history_offset=15)
                                0200 1400 0f000000
                                # MatchTuple(length_of_match=15, output_offset=24, history_offset=8)
                                0f00 1800 08000000
                                """)
        # literals
        compressed_data += b'for.whom.the.bellos,.for.thee!'

        c = compression.CompressionFactory.new_RDP_61()
        d = compression.CompressionFactory.new_RDP_61()
        
        inflated_1 = d.decompress(compressed_data, l1_compressed = True, l2_compressed = False)
        self.assertEqual(inflated_1, data)
        self.assertEqual(inflated_1.hex(), data.hex())


    @unittest.skip("compressing not ready yet")
    def test_compress_same_packet_twice(self):
        data = b"for whom the bell tolls, the bell tolls for thee.\xA6\x80"
        data = b"for.whom.the.bell.tolls,.the.bell.tolls.for.thee!"
        compressed_data_50 = b"""\xfb\x1d\x7e\xe4\xda\xc7\x1d\x70\xf8\xa1\x6b\x1f\x7d\xc0\xbe\x6b\xef\xb5\xef\x21\x87\xd0\xc5\xe1\x85\x71\xd4\x10\x16\xe7\xda\xfb\x1d\x7e\xe4\xda\x47\x1f\xb0\xef\xbe\xbd\xff\x2f"""
        # copied from https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/codec/test/TestFreeRDPCodecXCrush.c
        # but the TEST_BELLS_DATA_XCRUSH is 2 bytes short. I don't know how their test can pass
        # note: the first 2 bytes are the L1 and L2 compression flags
        # L1 = L1_INNER_COMPRESSION | L1_NO_COMPRESSION
        # L2 = None
        compressed_data = b"\x12\x00\x66\x6f\x72\x2e\x77\x68\x6f\x6d\x2e\x74\x68\x65\x2e\x62\x65\x6c\x6c\x2e\x74\x6f\x6c\x6c\x73\x2c\x2e\x74\x68\x65\x2e\x62\x65\x6c\x6c\x2e\x74\x6f\x6c\x6c\x73\x2e\x66\x6f\x72\x2e\x74\x68\x65\x65\x21"
        
        c = compression.CompressionFactory.new_RDP_61()
        d = compression.CompressionFactory.new_RDP_61()
        
        # inflated_l2 = compression.CompressionFactory.new_RDP_50().decompress(compressed_data[2:])
        # self.assertEqual(inflated_l2, data)
        # self.assertEqual(inflated_l2.hex(), data.hex())
        
        inflated_1 = d.decompress(compressed_data[2:], l1_compressed = False, l2_compressed = False)
        self.assertEqual(inflated_1, data)
        self.assertEqual(inflated_1.hex(), data.hex())
        
        
        deflated_1 = c.compress(data)
        # self.assertEqual(deflated_1.hex(), compressed_data.hex())
        # self.assertEqual(deflated_1, test_utils.extract_as_bytes("""66 6f 72 20 77 68 6f 6d 20 74 68 65 20 62 65 6c
        #                                                             6c 20 74 6f 6c 6c 73 2c f4 37 20 fa 23 d3 32 97
        #                                                             49 a0 00"""))
        inflated_1 = d.decompress(deflated_1)
        self.assertEqual(inflated_1, data)
        # print("data 1    :     ",binascii.hexlify(data))
        # print("deflated 1:     ",binascii.hexlify(deflated_1))
        # print("inflated 1:     ",binascii.hexlify(inflated_1))
        
        deflated_2 = c.compress(data)
        # print("data 2    :     ",binascii.hexlify(data))
        # print("deflated 2:     ",binascii.hexlify(deflated_2))
        # print("inflated 2:     ",binascii.hexlify(inflated_2))
        self.assertLessEqual(len(deflated_2), 5)
        # self.assertEqual(deflated_2, test_utils.extract_as_bytes("""fc # F[0:4] = 0b1111 = copy-offset with base 0, CF[0:6] = 0b110011 = copy-offset of 0 + 51
        #                                                             fd # FD[2:7] = 0b111101 = length-of-match with base 32
        #                                                             30 # D3[3:8] = 0b10011 = length-of-match of 32 + 19
        #                                                             """))
        
        inflated_2 = d.decompress(deflated_2)
        self.assertEqual(inflated_2, data)
    

if __name__ == '__main__':
    unittest.main()

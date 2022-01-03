import unittest

import compression_constants
import parser_v2_context

class TestParsingContext(unittest.TestCase):

    def test_parsing_context_serialization_when_empty(self):
        rdp_context = parser_v2_context.RdpContext()
        
        serialized_rdp_context = rdp_context.to_json()
        rdp_context_2 = parser_v2_context.RdpContext.from_json(serialized_rdp_context)
        
        self.assertEqual(rdp_context, rdp_context_2)
        
    def test_parsing_context_serialization_withDataChunk(self):
        rdp_context = parser_v2_context.RdpContext()
        chunk = parser_v2_context.DataChunk(10)
        chunk.append_data(b'123')
        rdp_context.set_channel_chunk(2, chunk)
        
        serialized_rdp_context = rdp_context.to_json()
        rdp_context_2 = parser_v2_context.RdpContext.from_json(serialized_rdp_context)
        # print(rdp_context)
        # print(serialized_rdp_context)
        # print(rdp_context_2)
        self.assertEqual(rdp_context, rdp_context_2)
        
    def test_parsing_context_serialization_withChannelDef(self):
        rdp_context = parser_v2_context.RdpContext()
        
        channel = parser_v2_context.ChannelDef('<channel-name>', {1, 2}, 'STATIC', 3, 0)
        rdp_context.add_channel(channel)
        
        serialized_rdp_context = rdp_context.to_json()
        rdp_context_2 = parser_v2_context.RdpContext.from_json(serialized_rdp_context)
        # print(rdp_context)
        # print(serialized_rdp_context)
        # print(rdp_context_2)
        self.assertEqual(rdp_context, rdp_context_2)
        
    def test_parsing_context_serialization_withCompressionEngine(self):
        rdp_context = parser_v2_context.RdpContext()
        
        import array
        a1 = array.array('B')
        a1.fromlist([0] * 2)
        a2 = array.array('B')
        a2.fromlist([0] * 2)
        self.assertEqual(a1, a2)
        
        import compression_utils
        self.assertEqual(compression_utils.BufferOnlyHistoryManager(3), compression_utils.BufferOnlyHistoryManager(3))
        
        import compression
        self.assertEqual(compression.CompressionFactory.new_RDP_40(), compression.CompressionFactory.new_RDP_40())
        
        rdp_context.get_compression_engine(compression_constants.CompressionTypes.RDP_40)

        serialized_rdp_context = rdp_context.to_json()
        rdp_context_2 = parser_v2_context.RdpContext.from_json(serialized_rdp_context)
        print(rdp_context)
        print(serialized_rdp_context)
        print(rdp_context_2)
        self.assertEqual(rdp_context, rdp_context_2)
        

if __name__ == '__main__':
    unittest.main()

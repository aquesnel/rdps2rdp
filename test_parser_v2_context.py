import unittest

import compression_constants
import data_model_v2_rdp
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
        
        rdp_context.get_compression_engine(compression_constants.CompressionTypes.RDP_40)

        serialized_rdp_context = rdp_context.to_json()
        rdp_context_2 = parser_v2_context.RdpContext.from_json(serialized_rdp_context)
        # print(rdp_context)
        # print(serialized_rdp_context)
        # print(rdp_context_2)
        self.assertEqual(rdp_context, rdp_context_2)
        
    def test_parsing_context_serialization_withPrimaryDrawingOrders(self):
        rdp_context = parser_v2_context.RdpContext()
        
        rdp_context.previous_primary_drawing_orders['order_type'] = data_model_v2_rdp.Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_PATBLT_ORDER

        serialized_rdp_context = rdp_context.to_json()
        rdp_context_2 = parser_v2_context.RdpContext.from_json(serialized_rdp_context)
        # print(rdp_context)
        # print(serialized_rdp_context)
        print(rdp_context_2)
        self.assertEqual(rdp_context, rdp_context_2)

    def test_clone_returnsIndependentObjectTree(self):
        rdp_context = parser_v2_context.RdpContext()
        
        rdp_context.previous_primary_drawing_orders['order_type'] = data_model_v2_rdp.Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_PATBLT_ORDER
        
        rdp_context.get_compression_engine(compression_constants.CompressionTypes.RDP_40)
        
        channel = parser_v2_context.ChannelDef('<channel-name>', {1, 2}, 'STATIC', 3, 0)
        rdp_context.add_channel(channel)
        
        chunk = parser_v2_context.DataChunk(10)
        chunk.append_data(b'123')
        rdp_context.set_channel_chunk(2, chunk)

        cloned_rdp_context = rdp_context.clone()

        self.assertNotEqual(
            id(cloned_rdp_context), 
            id(rdp_context))
        self.assertNotEqual(
            id(cloned_rdp_context.previous_primary_drawing_orders), 
            id(rdp_context.previous_primary_drawing_orders))
        self.assertNotEqual(
            id(cloned_rdp_context.get_compression_engine(compression_constants.CompressionTypes.RDP_40)), 
            id(rdp_context.get_compression_engine(compression_constants.CompressionTypes.RDP_40)))
        self.assertNotEqual(
            id(cloned_rdp_context.get_compression_engine(compression_constants.CompressionTypes.RDP_40)._decompression_history_manager), 
            id(rdp_context.get_compression_engine(compression_constants.CompressionTypes.RDP_40)._decompression_history_manager))

        

if __name__ == '__main__':
    unittest.main()

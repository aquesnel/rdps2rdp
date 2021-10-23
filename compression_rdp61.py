import compression_utils
import data_model_v2_rdp_egdi

DEBUG=True

class Rdp61_CompressionEngine():
    def __init__(self):
        self._l1_decompression_engine = Rdp61_L1_CompressionEngine()
        import compression
        self._l2_decompression_engine = compression.CompressionFactory.new_RDP_50()
    
    def resetHistory(self):
        self._decompressionHistoryManager.resetHistory()

    def compress(self, data):
        
        return b''

    def decompress(self, data, l1_compressed, l2_compressed):
        if l2_compressed:
            data = self._l2_decompression_engine.decompress(data)
        if l1_compressed:
            data = self._l1_decompression_engine.decompress(data)
        return data


class Rdp61_L1_CompressionEngine(compression_utils.CompressionEngine):
    def __init__(self):
        self._decompressionHistoryManager = compression_utils.BufferOnlyHistoryManager(2000000)
    
    def resetHistory(self):
        self._decompressionHistoryManager.resetHistory()

    def compress(self, data):
        
        return b''

    def decompress(self, data):
        compress_struct = data_model_v2_rdp_egdi.Rdp_RDP61_COMPRESSED_DATA_L1_content().with_value(data)
        if DEBUG: print("parsed data: %s" % (compress_struct,))
        retval = bytearray()
        literals = memoryview(compress_struct.Literals)
        
        done = False
        literals_index = 0
        for match in compress_struct.MatchDetails:
            output_length = len(retval)
            if output_length > match.MatchOutputOffset:
                raise ValueError("match %s references an offset location that has already been copied to the output. current literals_index = %s" % (match.MatchOutputOffset, literals_index))
            if output_length < match.MatchOutputOffset:
                literals_copy_end = literals_index + (match.MatchOutputOffset - output_length)
                retval.extend(literals[literals_index : literals_copy_end])
                self._decompressionHistoryManager.append_bytes(literals[literals_index : literals_copy_end])
                if DEBUG: print("copying literals to output: len = %s, literals_index = %s, literals = %s" % ((match.MatchOutputOffset - output_length), literals_index, literals[literals_index : literals_copy_end].tobytes()))
                literals_index = literals_copy_end
                
            # assert: len(retval) == match.MatchOutputOffset
            if DEBUG: print("copying match: %s" % (match))
            for i in range(match.MatchLength):
                b = self._decompressionHistoryManager.get_byte(match.MatchHistoryOffset + i, relative = False)
                if DEBUG: print("copying match value: %s = '%s'" % (b, chr(b)))
                retval.append(b)
                self._decompressionHistoryManager.append_byte(b)
        if literals_index < len(literals):
            if DEBUG: print("copying literals to output: len = %s, literals = %s" % ((len(literals[literals_index : ])), literals[literals_index : ].tobytes()))
            retval.extend(literals[literals_index : ])
            self._decompressionHistoryManager.append_bytes(literals[literals_index : ])

        return retval
import compression_constants
import compression_utils
from data_model_v2_rdp import Rdp
import data_model_v2_rdp_egdi
import utils

from compression_utils import (
    SymbolType,
    CopyTuple,
    CopyTupleV2,
    CompressionArgs,
)

DEBUG=False
# DEBUG=True

class Rdp61_L1_CompressionEncoder(compression_utils.Encoder):

    def __init__(self):
        self.matches = []
        self.literals = bytearray()
        self.output_len = 0
    
    def get_encoded_bytes(self):
        compress_struct = data_model_v2_rdp_egdi.Rdp_RDP61_COMPRESSED_DATA_L1_content()
        compress_struct.MatchDetails.extend(self.matches)
        compress_struct.Literals = self.literals
        return compress_struct.as_wire_bytes()

    def encode(self, symbol_type, value):
        if symbol_type == SymbolType.LITERAL:
            self.literals.append(value)
            self.output_len += 1
            if DEBUG: print("encoding literal: '%s' = %d" % (chr(value), value))
        elif symbol_type == SymbolType.END_OF_STREAM:
            if DEBUG: print('encoding end-of-stream')
        elif symbol_type == SymbolType.COPY_OFFSET:
            match_details = data_model_v2_rdp_egdi.Rdp_RDP61_MATCH_DETAILS()
            match_details.MatchLength = value.length_of_match
            match_details.MatchOutputOffset = len(self.literals)
            match_details.MatchHistoryOffset = value.history_absolute_offset
            self.matches.append(match_details)
            self.output_len += value.length_of_match
            if DEBUG: print('encoding match_details: %s' % (match_details,))
        else:
            raise ValueError('Invalid symbol type: %s' % (symbol_type, ))
        

class Rdp61_L1_CompressionDecoder(compression_utils.Decoder):
    
    def __init__(self, data):
        self.__iter = self.decode_iter(data)

    def decode_next(self): # Tuple[SymbolType, Any]
        return next(self.__iter)
    
    def decode_iter(self, data): # Tuple[SymbolType, Any]
        compress_struct = data_model_v2_rdp_egdi.Rdp_RDP61_COMPRESSED_DATA_L1_content().with_value(data)
        if DEBUG: print("parsed data: %s" % (compress_struct,))
        
        match_details = compress_struct.MatchDetails
        literals = memoryview(compress_struct.Literals)
        done = False
        literals_index = 0
        output_length = 0
        for match in match_details:
            if literals_index > match.MatchOutputOffset:
                raise ValueError("match %s references an offset location that has already been copied to the output. current literals_index = %s" % (match, literals_index))
            if literals_index < match.MatchOutputOffset:
                literals_length = match.MatchOutputOffset - literals_index
                literals_copy_end = literals_index + literals_length
                if DEBUG: print("copying literals to output: len = %s, literals_index = %s, literals = %s" % (literals_length, literals_index, literals[literals_index : literals_copy_end].tobytes()))
                yield (SymbolType.LITERAL, literals[literals_index : literals_copy_end])
                output_length += literals_length
                literals_index = literals_copy_end
                
            # assert: output_length == match.MatchOutputOffset
            if DEBUG: print("copying match: %s" % (match))
            yield (SymbolType.COPY_OFFSET, compression_utils.CopyTupleV2(match.MatchHistoryOffset, match.MatchLength, is_relative_offset = False))
            output_length += match.MatchLength

        if literals_index < len(literals):
            if DEBUG: print("copying literals to output: len = %s, literals = %s" % ((len(literals[literals_index : ])), literals[literals_index : ].tobytes()))
            yield (SymbolType.LITERAL, literals[literals_index : ])
        yield (SymbolType.END_OF_STREAM, None)
        

class Rdp61_L1_CompressionEncodingFacotry(compression_utils.EncodingFactory):
    def __init__(self):
        pass
    
    def compression_type(self):
        return compression_constants.CompressionTypes.RDP_61
    
    def make_encoder(self):
        return Rdp61_L1_CompressionEncoder()
    
    def make_decoder(self, compression_args):
        if compression_constants.CompressionFlags.COMPRESSED in compression_args.flags:
            return Rdp61_L1_CompressionDecoder(compression_args.data)
        else:
            return compression_utils.NoOpDecoder(compression_args.data)
    
    
@utils.json_serializable()
class Rdp61_CompressionEngine(compression_utils.CompressionEngine):

    def __init__(self, l1_compression_engine, l2_compression_engine):
        self._l1_compression_engine = l1_compression_engine
        self._l2_compression_engine = l2_compression_engine
    
    def compress(self, data):
        compression_args_l1 = self._l1_compression_engine.compress(data)
        compression_args_l2 = self._l2_compression_engine.compress(compression_args_l1.data)
        
        if compression_constants.CompressionFlags.COMPRESSED in compression_args_l2.flags:
            compression_args_l1.flags.add(compression_constants.CompressionFlags.INNER_COMPRESSION)
        
        compressed_struct = data_model_v2_rdp_egdi.Rdp_RDP61_COMPRESSED_DATA()
        compressed_struct.header.Level1ComprFlags = Rdp.Compression61.from_L1_compression_flags(compression_args_l1.flags)
        compressed_struct.header.Level2ComprFlags = Rdp.Compression61.from_L2_compression_flags(compression_args_l2.flags)
        compressed_struct.header.Level2ComprFlags.add(Rdp.Compression61.PACKET_COMPR_TYPE_64K)
        compressed_struct.payload = compression_args_l2.data
            
        return CompressionArgs(data = compressed_struct.as_wire_bytes(), 
                    flags = set(),
                    type = compression_constants.CompressionTypes.RDP_61)

    def decompress(self, compression_args):
        compressed_struct = data_model_v2_rdp_egdi.Rdp_RDP61_COMPRESSED_DATA().with_value(compression_args.data)
        L1_flags = Rdp.Compression61.to_L1_compression_flags(compressed_struct.header.Level1ComprFlags)
        L2_flags = Rdp.Compression61.to_L2_compression_flags(compressed_struct.header.Level2ComprFlags)
        
        if compression_constants.CompressionFlags.INNER_COMPRESSION in L1_flags:
            compression_args_l2 = CompressionArgs(data = compressed_struct.payload, flags = L2_flags, type = compression_constants.CompressionTypes.RDP_61)
            data_l2 = self._l2_compression_engine.decompress(compression_args_l2)
        else:
            data_l2 = compressed_struct.payload
        
        compression_args_l1 = CompressionArgs(data = data_l2, flags = L1_flags, type = compression_constants.CompressionTypes.RDP_61)
        data = self._l1_compression_engine.decompress(compression_args_l1)
        return data

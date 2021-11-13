import compression_utils
import data_model_v2_rdp_egdi
from data_model_v2_rdp import Rdp

from compression_utils import (
    SymbolType,
    CopyTuple,
    CopyTupleV2,
    CompressionArgs,
)

DEBUG=False
# DEBUG=True

class CompressionFlags_61(object):
    def __init__(self, L1_flags, L2_flags):
        self.L1_flags = L1_flags
        self.L2_flags = L2_flags
    
    def __contains__(self, value):
        return (
            value in self.L1_flags
            or
            value in self.L2_flags
            )

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
        

class Rdp61_L1_CompressionEncodingFacotry(compression_utils.EncodingFacotry):
    def __init__(self):
        pass
        
    def make_encoder(self):
        return Rdp61_L1_CompressionEncoder()
    
    def make_decoder(self, compression_args):
        if Rdp.ShareDataHeader.PACKET_ARG_COMPRESSED in compression_args.flags:
            return Rdp61_L1_CompressionDecoder(compression_args.data)
        else:
            return compression_utils.NoOpDecoder(compression_args.data)
    
    
class Rdp61_CompressionEngine(compression_utils.CompressionEngine):
    L1_FLAG_MAPPING_TO_61 = {
            Rdp.ShareDataHeader.PACKET_ARG_COMPRESSED: Rdp.Compression61.L1_COMPRESSED,
            Rdp.ShareDataHeader.PACKET_ARG_AT_FRONT: Rdp.Compression61.L1_PACKET_AT_FRONT,
            # Rdp.ShareDataHeader.PACKET_ARG_FLUSHED: Rdp.Compression61.,
        }
    L1_FLAG_MAPPING_FROM_61 = {
            Rdp.Compression61.L1_COMPRESSED: Rdp.ShareDataHeader.PACKET_ARG_COMPRESSED,
            Rdp.Compression61.L1_PACKET_AT_FRONT: Rdp.ShareDataHeader.PACKET_ARG_AT_FRONT,
            # Rdp.ShareDataHeader.PACKET_ARG_FLUSHED: Rdp.Compression61.,
        }
    L2_FLAG_MAPPING_TO_61 = {
            Rdp.ShareDataHeader.PACKET_ARG_COMPRESSED: Rdp.Compression61.PACKET_COMPRESSED,
            Rdp.ShareDataHeader.PACKET_ARG_AT_FRONT: Rdp.Compression61.PACKET_AT_FRONT,
            Rdp.ShareDataHeader.PACKET_ARG_FLUSHED: Rdp.Compression61.PACKET_FLUSHED,
        }
    L2_FLAG_MAPPING_FROM_61 = {
            Rdp.Compression61.PACKET_COMPRESSED: Rdp.ShareDataHeader.PACKET_ARG_COMPRESSED,
            Rdp.Compression61.PACKET_AT_FRONT: Rdp.ShareDataHeader.PACKET_ARG_AT_FRONT,
            Rdp.Compression61.PACKET_FLUSHED: Rdp.ShareDataHeader.PACKET_ARG_FLUSHED,
        }

    def __init__(self, l1_compression_engine, l2_compression_engine):
        self._l1_compression_engine = l1_compression_engine
        self._l2_compression_engine = l2_compression_engine
    
    
    def resetHistory(self):
        self._l1_compression_engine.resetHistory()
        self._l2_compression_engine.resetHistory()

    def compress(self, data):
        compression_args_l1 = self._l1_compression_engine.compress(data)
        compression_args_l2 = self._l2_compression_engine.compress(compression_args_l1.data)
        
        # convert from the standard compression flags to 6.1 compression flags
        l1_flags = set()
        for f in compression_args_l1.flags:
            l1_flags.add(self.L1_FLAG_MAPPING_TO_61[f])
        if Rdp.ShareDataHeader.PACKET_ARG_COMPRESSED in compression_args_l2.flags:
            l1_flags.add(Rdp.Compression61.L1_INNER_COMPRESSION)
        
        l2_flags = set()
        for f in compression_args_l2.flags:
            l2_flags.add(self.L2_FLAG_MAPPING_TO_61[f])
            
        return CompressionArgs(data = compression_args_l2.data, 
                    flags = CompressionFlags_61(L1_flags = l1_flags, L2_flags = l2_flags)) 

    def decompress(self, compression_args):
        l1_flags = set()
        for f in compression_args.flags.L1_flags:
            flag = self.L1_FLAG_MAPPING_FROM_61.get(f, None)
            if flag:
                l1_flags.add(flag)
            
        l2_flags = set()
        for f in compression_args.flags.L2_flags:
            l2_flags.add(self.L2_FLAG_MAPPING_FROM_61[f])
        
        compression_args_l2 = CompressionArgs(data = compression_args.data, flags = l2_flags)
        data_l2 = self._l2_compression_engine.decompress(compression_args_l2)
        
        compression_args_l1 = CompressionArgs(data = data_l2, flags = l1_flags)
        data = self._l1_compression_engine.decompress(compression_args_l1)
        return data

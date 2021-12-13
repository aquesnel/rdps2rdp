
import compression_constants
import compression_utils
import compression_mppc
import compression_rdp60
import compression_rdp61
import compression_rdp80


class CompressionFactory(object):
    
    @classmethod
    def new_engine(cls, compression_type):
        if compression_type == compression_constants.CompressionTypes.NO_OP:
            return cls.new_NoOp()
        elif compression_type == compression_constants.CompressionTypes.RDP_40:
            return cls.new_RDP_40()
        elif compression_type == compression_constants.CompressionTypes.RDP_50:
            return cls.new_RDP_50()
        elif compression_type == compression_constants.CompressionTypes.RDP_60:
            return cls.new_RDP_60()
        elif compression_type == compression_constants.CompressionTypes.RDP_61:
            return cls.new_RDP_61()
        elif compression_type == compression_constants.CompressionTypes.RDP_80:
            return cls.new_RDP_80()
        else:
            raise AssertionError("Unknown compression type: %s" % compression_type)

    @classmethod
    def new_NoOp(cls):
        class NoOpCompressionEngine(compression_utils.CompressionEngine):
            def compress(self, data):
                return compression_utils.CompressionArgs(data = data, flags = set())
            
            def decompress(self, compression_args):
                return compression_args.data
        
        return NoOpCompressionEngine()
    
    @classmethod
    def new_RDP_40(cls):
        compression_config = compression_mppc.MccpCompressionConfig.RDP_40
        return compression_mppc.MPPC(
                                    compression_utils.BruteForceHistoryManager(compression_config.history_size),
                                    compression_utils.BufferOnlyHistoryManager(compression_config.history_size),
                                    compression_mppc.MppcEncodingFacotry(compression_config))
    
    @classmethod
    def new_RDP_50(cls):
        compression_config = compression_mppc.MccpCompressionConfig.RDP_50
        return compression_mppc.MPPC(
                                    compression_utils.BruteForceHistoryManager(compression_config.history_size),
                                    compression_utils.BufferOnlyHistoryManager(compression_config.history_size),
                                    compression_mppc.MppcEncodingFacotry(compression_config))
    
    @classmethod
    def new_RDP_60(cls):
        history_size = 65536
        return compression_mppc.MPPC(#TODO: change this to use the RDP 6.0 slide-back-by-half reset behaviour
                                    compression_utils.BruteForceHistoryManager(history_size),
                                    compression_utils.BufferOnlyHistoryManager(history_size),
                                    compression_rdp60.Rdp60CompressionEncodingFacotry())

    @classmethod
    def new_RDP_61_L1(cls):
        history_size_l1 = 2000000
        return compression_mppc.MPPC(
                                    compression_utils.BruteForceHistoryManager(history_size_l1),
                                    compression_utils.BufferOnlyHistoryManager(history_size_l1),
                                    compression_rdp61.Rdp61_L1_CompressionEncodingFacotry()
                                    )
    
    @classmethod
    def new_RDP_61(cls):
        l1_compression = CompressionFactory.new_RDP_61_L1()
        l2_compression = CompressionFactory.new_RDP_50()
        # l2_compression = CompressionFactory.new_NoOp()
        
        return compression_rdp61.Rdp61_CompressionEngine(l1_compression, l2_compression)

    @classmethod
    def new_RDP_80(cls):
        history_size = 2500000
        return compression_mppc.MPPC(
                                    compression_utils.BruteForceHistoryManager(history_size),
                                    compression_utils.BufferOnlyHistoryManager(history_size),
                                    compression_rdp80.Rdp80_CompressionEncodingFacotry()
                                    )
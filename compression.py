
import compression_utils
import compression_mppc
import compression_rdp60


class CompressionFactory(object):
    
    @classmethod
    def new_RDP_40(cls):
        compression_config = compression_mppc.MccpCompressionConfig.RDP_40
        return compression_mppc.MPPC(#compression_config,
                                    compression_mppc.BruteForceHistoryManager(compression_config.history_size),
                                    compression_utils.BufferOnlyHistoryManager(compression_config.history_size),
                                    compression_mppc.MccpCompressionEncoder(compression_config), 
                                    compression_mppc.MccpCompressionDecoder(compression_config))
    
    @classmethod
    def new_RDP_50(cls):
        compression_config = compression_mppc.MccpCompressionConfig.RDP_50
        return compression_mppc.MPPC(#compression_config,
                                    compression_mppc.BruteForceHistoryManager(compression_config.history_size),
                                    compression_utils.BufferOnlyHistoryManager(compression_config.history_size),
                                    compression_mppc.MccpCompressionEncoder(compression_config), 
                                    compression_mppc.MccpCompressionDecoder(compression_config))
    
    @classmethod
    def new_RDP_60(cls):
        history_size = 65536
        return compression_mppc.MPPC(#TODO: change this to use the RDP 6.0 slide-back-by-half reset behaviour
                                    compression_mppc.BruteForceHistoryManager(history_size),
                                    compression_utils.BufferOnlyHistoryManager(history_size),
                                    compression_rdp60.Rdp60CompressionEncoder(), 
                                    compression_rdp60.Rdp60CompressionDecoder())
    
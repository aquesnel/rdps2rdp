
import compression_constants
import compression_utils
import compression_mppc
import compression_rdp60
import compression_rdp61
import compression_rdp80
import utils


class CompressionFactory(object):
    
    @classmethod
    def new_engine(cls, compression_type, **kwargs):
        if compression_type == compression_constants.CompressionTypes.NO_OP:
            return cls.new_NoOp(**kwargs)
        elif compression_type == compression_constants.CompressionTypes.RDP_40:
            return cls.new_RDP_40(**kwargs)
        elif compression_type == compression_constants.CompressionTypes.RDP_50:
            return cls.new_RDP_50(**kwargs)
        elif compression_type == compression_constants.CompressionTypes.RDP_60:
            return cls.new_RDP_60(**kwargs)
        elif compression_type == compression_constants.CompressionTypes.RDP_61:
            return cls.new_RDP_61(**kwargs)
        elif compression_type == compression_constants.CompressionTypes.RDP_80:
            return cls.new_RDP_80(**kwargs)
        elif compression_type == compression_constants.CompressionTypes.RDP_80_LITE:
            return cls.new_RDP_80_lite(**kwargs)
        else:
            raise AssertionError("Unknown compression type: %s" % ((compression_type.__class__.__name__, compression_type),))

    @classmethod
    def new_NoOp(cls, **kwargs):
        @utils.json_serializable()
        class NoOpCompressionEngine(compression_utils.CompressionEngine):
            def __init__(self, **kwargs):
                self._compression_type = compression_constants.CompressionTypes.NO_OP
            
            def compress(self, data):
                return compression_utils.CompressionArgs(data = data, flags = set())
            
            def decompress(self, compression_args):
                return compression_args.data
        
        return NoOpCompressionEngine()
    
    @classmethod
    def new_RDP_40(cls, **kwargs):
        compression_config = compression_mppc.MppcCompressionConfig.RDP_40
        return compression_mppc.MPPC(
                                    compression_constants.CompressionTypes.RDP_40,
                                    compression_history_manager = 
                                        compression_utils.BruteForceHistoryManager(
                                            **{**compression_mppc.MPPC.get_field_from_json('compression_history_manager', kwargs, {}),
                                                **{'historyLength': compression_config.history_size}}),
                                    decompression_history_manager = 
                                        compression_utils.BufferOnlyHistoryManager(
                                            **{**compression_mppc.MPPC.get_field_from_json('decompression_history_manager', kwargs, {}),
                                                **{'historyLength': compression_config.history_size}}),
                                    encoder_factory = compression_mppc.MppcEncodingFacotry(compression_config),
                                    add_non_compressed_data_to_history = False,
                                    **kwargs
                                    )
    
    # goal:
    # * re-hydrate the compression engine object with the history manager state.
    # problem:
    # * the state json shema is defined by the MPPC class, but the history manager is created 
    #   before the compression engine is created, and the history manager is injected into the
    #   compression engine. 
    # from_json options:
    # 1. have the history managers support re-init
    #   * CON: this is a special case solution, but the problem is general: injected class with state
    # 2. have the factory method extract the fields for the history manager state
    #   * CON: the factory must know the internals of the compression engine json representation
    # 3. have the compression engine support extracting the history manager state field
    #   * CON: something smells bad but I'm not sure what
    
    @classmethod
    def new_RDP_50(cls, **kwargs):
        compression_config = compression_mppc.MppcCompressionConfig.RDP_50
        return compression_mppc.MPPC(
                                    compression_constants.CompressionTypes.RDP_50,
                                    compression_history_manager = 
                                        compression_utils.BruteForceHistoryManager(
                                            **{**compression_mppc.MPPC.get_field_from_json('compression_history_manager', kwargs, {}),
                                                **{'historyLength': compression_config.history_size}}),
                                    decompression_history_manager = 
                                        compression_utils.BufferOnlyHistoryManager(
                                            **{**compression_mppc.MPPC.get_field_from_json('decompression_history_manager', kwargs, {}),
                                                **{'historyLength': compression_config.history_size}}),
                                    encoder_factory = compression_mppc.MppcEncodingFacotry(compression_config),
                                    add_non_compressed_data_to_history = False,
                                    **kwargs
                                    )
    
    @classmethod
    def new_RDP_60(cls, **kwargs):
        history_size = 65536
        return compression_mppc.MPPC(#TODO: change this to use the RDP 6.0 slide-back-by-half reset behaviour
                                    compression_constants.CompressionTypes.RDP_60,
                                    compression_history_manager = 
                                        compression_utils.BruteForceHistoryManager(
                                            **{**compression_mppc.MPPC.get_field_from_json('compression_history_manager', kwargs, {}),
                                                **{'historyLength': history_size}}),
                                    decompression_history_manager = 
                                        compression_utils.BufferOnlyHistoryManager(
                                            **{**compression_mppc.MPPC.get_field_from_json('decompression_history_manager', kwargs, {}),
                                                **{'historyLength': history_size}}),
                                    encoder_factory = compression_rdp60.Rdp60CompressionEncodingFacotry(),
                                    add_non_compressed_data_to_history = False,
                                    **kwargs
                                    )

    @classmethod
    def new_RDP_61_L1(cls, **kwargs):
        history_size_l1 = 2000000
        return compression_mppc.MPPC(
                                    compression_constants.CompressionTypes.RDP_61,
                                    compression_history_manager = 
                                        compression_utils.BruteForceHistoryManager(
                                            **{**compression_mppc.MPPC.get_field_from_json('compression_history_manager', kwargs, {}),
                                                **{'historyLength': history_size_l1}}),
                                    decompression_history_manager = 
                                        compression_utils.BufferOnlyHistoryManager(
                                            **{**compression_mppc.MPPC.get_field_from_json('decompression_history_manager', kwargs, {}),
                                                **{'historyLength': history_size_l1}}),
                                    encoder_factory = compression_rdp61.Rdp61_L1_CompressionEncodingFacotry(),
                                    add_non_compressed_data_to_history = False,
                                    **kwargs
                                    )
    
    @classmethod
    def new_RDP_61(cls, **kwargs):
        l1_compression = CompressionFactory.new_RDP_61_L1(
            **compression_rdp61.Rdp61_CompressionEngine.get_field_from_json('l1_compression_engine', kwargs, {}))
        l2_compression = CompressionFactory.new_RDP_50(
            **compression_rdp61.Rdp61_CompressionEngine.get_field_from_json('l2_compression_engine', kwargs, {}))
        # l2_compression = CompressionFactory.new_NoOp()
        
        return compression_rdp61.Rdp61_CompressionEngine(
                l1_compression_engine = l1_compression, 
                l2_compression_engine = l2_compression)

    @classmethod
    def new_RDP_80(cls, **kwargs):
        history_size = 2500000
        return compression_rdp80.Rdp80_CompressionEngine(
                    compression_mppc.MPPC(
                        compression_constants.CompressionTypes.RDP_80,
                        compression_history_manager = 
                            compression_utils.BruteForceHistoryManager(
                                **{**compression_mppc.MPPC.get_field_from_json('compression_history_manager', kwargs, {}),
                                    **{'historyLength': history_size}}),
                        decompression_history_manager = 
                            compression_utils.BufferOnlyHistoryManager(
                                **{**compression_mppc.MPPC.get_field_from_json('decompression_history_manager', kwargs, {}),
                                    **{'historyLength': history_size}}),
                        encoder_factory = compression_rdp80.Rdp80_CompressionEncodingFacotry(),
                        add_non_compressed_data_to_history = True,
                        **kwargs
                        ))

    @classmethod
    def new_RDP_80_lite(cls, **kwargs):
        history_size = 8192
        return compression_rdp80.Rdp80_CompressionEngine(
                    compression_mppc.MPPC(
                        compression_constants.CompressionTypes.RDP_80,
                        compression_history_manager = 
                            compression_utils.BruteForceHistoryManager(
                                **{**compression_mppc.MPPC.get_field_from_json('compression_history_manager', kwargs, {}),
                                    **{'historyLength': history_size}}),
                        decompression_history_manager = 
                            compression_utils.BufferOnlyHistoryManager(
                                **{**compression_mppc.MPPC.get_field_from_json('decompression_history_manager', kwargs, {}),
                                    **{'historyLength': history_size}}),
                        encoder_factory = compression_rdp80.Rdp80_CompressionEncodingFacotry(),
                        add_non_compressed_data_to_history = True,
                        **kwargs
                        ))

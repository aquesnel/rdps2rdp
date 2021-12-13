import collections
import contextlib
from enum import Enum, unique

import compression
from data_model_v2_rdp import Rdp

# ChannelDef = collections.namedtuple('ChannelDef', ['name', 'options'])
class ChannelDef(object):
    def __init__(self, name, options, type, channel_id = None):
        self.name = name
        self.options = options
        if isinstance(type, str):
            type = Rdp.Channel.ChannelType[type]
        self.type = type # Rdp.Channel.ChannelType
        self.channel_id = channel_id

    def __repr__(self):
        return str({k:(v if not isinstance(v, Rdp.Channel.ChannelType) else v.name) for k,v in self.__dict__.items() if not callable(v)})

    @staticmethod
    def from_repr(repr):
        return ChannelDef(**repr)

class RdpContext(object):
    @unique
    class PduSource(Enum):
        CLIENT = 'Client'
        SERVER = 'Server'
    def __init__(self):
        self.allow_partial_parsing = False # hack, this should be in SerializationContext
        
        self.is_gcc_confrence = False
        self.encryption_level = None
        self.encryption_method = None
        self.encrypted_client_random = None
        self.pre_capability_exchange = True
        self.rdp_gfx_pre_capability_exchange = True
        
        self.auto_logon = False
        self.rail_enabled = False
        self.compression_type = None
        self.compression_virtual_chan_cs_encoder = None
        self.compression_engines = {}
        self.domain = None
        self.user_name = None
        self.password = None
        self.alternate_shell = None
        self.working_dir = None
        
        self.channel_defs = []
        
        self.pdu_source = None
        
        self.previous_primary_drawing_orders = {}
        
    def get_channel_ids(self):
        return [channel.channel_id for channel in self.channel_defs]
        
    def get_channel_names(self):
        return [channel.name for channel in self.channel_defs]
        
    def get_channel_by_id(self, id, default = None):
        for channel in self.channel_defs:
            if channel.channel_id == id:
                return channel
        if default:
            return default
        else:
            raise ValueError('Unknown channel id: %s' % str(id))
        
    def get_channel_by_name(self, name, default = None):
        for channel in self.channel_defs:
            if channel.name == name:
                return channel
        if default:
            return default
        else:
            raise ValueError('Unknown channel name: %s' % str(name))
    
    def remove_channel_by_id(self, id):
        for i, channel in enumerate(self.channel_defs):
            if channel.channel_id == id:
                del self.channel_defs[i]
                break
    
    def clone(self):
        import copy
        return copy.deepcopy(self)
        
    def __repr__(self):
        return str({k:v for k,v in self.__dict__.items() if (not callable(v) or v != 'channels_by_name')})
        
    @staticmethod
    def from_repr(repr):
        rdp_context = RdpContext()
        for k,v in repr.items():
            setattr(rdp_context, k, v)
        channel_defs = []
        for v in rdp_context.channel_defs:
            channel_defs.append(ChannelDef.from_repr(v))
        rdp_context.channel_defs = channel_defs
        return rdp_context
        
    @contextlib.contextmanager
    def set_pdu_source(self, pdu_source):
        if pdu_source not in RdpContext.PduSource:
            raise ValueError('Invalid pdu_source: %s' % str(pdu_source))
        orig_pdu_source = self.pdu_source
        self.pdu_source = pdu_source
        try:
            yield self
        finally:
            self.pdu_source = orig_pdu_source

    def get_compression_engine(self, compression_type = None):
        if compression_type is None:
            compression_type = self.compression_type
        if compression_type not in self.compression_engines:
            self.compression_engines[compression_type] = compression.CompressionFactory.new_engine(compression_type)
        return self.compression_engines[compression_type]

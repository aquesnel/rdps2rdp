import ast
import collections
import collections.abc
import contextlib
from enum import Enum, unique
import json
import operator
import functools

import utils
import compression
import compression_constants
import compression_utils
from data_model_v2_rdp import Rdp

# ChannelDef = collections.namedtuple('ChannelDef', ['name', 'options'])
@utils.json_serializable()
class ChannelDef(object):
    def __init__(self, name, options, type, channel_id = None, channel_index = None):
        self.channel_index = channel_index
        self.name = name
        if not isinstance(options, collections.abc.Iterable):
            options = {options}
        if not isinstance(options, set):
            options = {v for v in options}
        self.options = options
        if isinstance(type, str):
            type = Rdp.Channel.ChannelType[type]
        self.type = type # Rdp.Channel.ChannelType
        self.channel_id = channel_id

DataChunkKey = collections.namedtuple('DataChunkKey', ['channel_id', 'pdu_source'])
DataChunkKey.to_json_key = lambda self: '%s__%s' % self
DataChunkKey.from_json_key = staticmethod(lambda s: DataChunkKey(*[cast(v) for cast,v in zip((int, lambda x: utils.from_json_value(RdpContext.PduSource, x)), s.split('__'))]))

@utils.json_serializable()
class DataChunk(object):
    def __init__(self, expected_total_len, **kwargs):
        self._expected_total_len = expected_total_len
        self._data = bytearray(kwargs.get('_data', []))

    def __str__(self):
        length = len(self._data)
        if length < 10:
            s = "b'%s'" % utils.as_hex_str(self._data)
        else:
            s = "b'%s...%s'" % (utils.as_hex_str(self._data[:4]), utils.as_hex_str(self._data[-4:]))
        return '<DataChunk(len %d of %d): %s>' % (length, self._expected_total_len, s)

    def __len__(self):
        return len(self._data)

    def get_expected_length(self):
        return self._expected_total_len

    def append_data(self, next_chunk):
        if len(self._data) + len(next_chunk) > self._expected_total_len:
            raise ValueError('Appending data chunk makes the total chunk grow beyond the expected data size. Expected %d, acctual %d' % (self._expected_total_len, len(self._data) + len(next_chunk)))
        self._data += next_chunk

    def is_full(self):
        return len(self._data) == self._expected_total_len

    def get_data(self):
        if len(self._data) != self._expected_total_len:
            raise ValueError('The data chunk is not the expected size. Expected %d, acctual %d' % (self._expected_total_len, len(self._data)))
        return self._data

@utils.json_serializable()
class RdpContext(object):
    @unique
    class PduSource(Enum):
        CLIENT = 'Client'
        SERVER = 'Server'
        
    def __init__(self, **kwargs):
        self.allow_partial_parsing = kwargs.get('allow_partial_parsing', False) # hack, this should be in SerializationContext
        
        self.is_gcc_confrence = kwargs.get('is_gcc_confrence', False)
        self.encryption_level = kwargs.get('encryption_level', None)
        self.encryption_method = kwargs.get('encryption_method', None)
        self.encrypted_client_random = kwargs.get('encrypted_client_random', None)
        self.pre_capability_exchange = kwargs.get('pre_capability_exchange', True)
        self.rdp_gfx_pre_capability_exchange = kwargs.get('rdp_gfx_pre_capability_exchange', True)
        
        self.auto_logon = kwargs.get('auto_logon', False)
        self.rail_enabled = kwargs.get('rail_enabled', False)
        self.compression_type = kwargs.get('compression_type', None)
        self.compression_virtual_chan_cs_encoder = kwargs.get('compression_virtual_chan_cs_encoder', None)
        self.domain = kwargs.get('domain', None)
        self.user_name = kwargs.get('user_name', None)
        self.password = kwargs.get('password', None)
        self.alternate_shell = kwargs.get('alternate_shell', None)
        self.working_dir = kwargs.get('working_dir', None)
        self.pdu_source = kwargs.get('pdu_source', None)
        
        self._compression_engines = utils.from_json_dict(compression_constants.CompressionTypes, compression_utils.CompressionEngine, kwargs.get('_compression_engines', {}))
        self.previous_primary_drawing_orders = kwargs.get('previous_primary_drawing_orders', {})
        self._channel_defs = utils.from_json_list(ChannelDef, kwargs.get('_channel_defs', []))
        self._channel_data_chunk_by_id_and_source = utils.from_json_dict(DataChunkKey, DataChunk, kwargs.get('_channel_data_chunk_by_id_and_source', {}))

    def clone(self):
        import copy
        return copy.deepcopy(self)
    
    def add_channel(self, channel):
        self._channel_defs.append(channel)
    
    def remove_channel_by_id(self, id, pdu_source = None):
        if pdu_source is None:
            pdu_source = self.pdu_source
        if (id, pdu_source) in self._channel_data_chunk_by_id_and_source:
            del self._channel_data_chunk_by_id_and_source[(id, pdu_source)]
        for i, channel in enumerate(self._channel_defs):
            if channel.channel_id == id:
                del self._channel_defs[i]
                break
    
    def get_channel_ids(self):
        return [channel.channel_id for channel in self._channel_defs]
        
    def get_channel_names(self):
        return [channel.name for channel in self._channel_defs]
    
    def get_channels_by_index(self):
        return sorted([channel for channel in self._channel_defs if channel.channel_index is not None], key = lambda c: c.channel_index)

    def get_channel_by_id(self, id, default = None):
        for channel in self._channel_defs:
            if channel.channel_id == id:
                return channel
        if default:
            return default
        else:
            raise ValueError('Unknown channel id: %s' % str(id))
        
    def get_channel_by_name(self, name, default = None):
        for channel in self._channel_defs:
            if channel.name == name:
                return channel
        if default:
            return default
        else:
            raise ValueError('Unknown channel name: %s' % str(name))
    
    def has_channel_chunk(self, id, pdu_source = None):
        if pdu_source is None:
            pdu_source = self.pdu_source
        return DataChunkKey(id, pdu_source) in self._channel_data_chunk_by_id_and_source
        
    def get_channel_chunk(self, id, pdu_source = None):
        if pdu_source is None:
            pdu_source = self.pdu_source
        return self._channel_data_chunk_by_id_and_source[DataChunkKey(id, pdu_source)]
    
    def set_channel_chunk(self, id, chunk, pdu_source = None):
        if not isinstance(chunk, DataChunk) and not chunk is None:
            raise ValueError('chunk must be of type DataChunk. Found: %s' % chunk.__class__.__name__)
        if pdu_source is None:
            pdu_source = self.pdu_source
        if chunk is not None:
            self._channel_data_chunk_by_id_and_source[DataChunkKey(id, pdu_source)] = chunk
        elif DataChunkKey(id, pdu_source) in self._channel_data_chunk_by_id_and_source:
            del self._channel_data_chunk_by_id_and_source[DataChunkKey(id, pdu_source)]
    
    
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
        if compression_type not in self._compression_engines:
            self._compression_engines[compression_type] = compression.CompressionFactory.new_engine(compression_type)
        return self._compression_engines[compression_type]

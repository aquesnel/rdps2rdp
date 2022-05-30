import ast
import binascii
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
DataChunkKey.to_json_key = lambda self: '%s__%s' % (self.channel_id, utils.to_json_value(self.pdu_source))
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

@unique
class PduSource(Enum):
    CLIENT = 'Client'
    SERVER = 'Server'
    
@utils.json_serializable(field_filter = lambda field_path: field_path.split('.')[-1] not in {'parser_config'})
class RdpContext(object):
    PduSource = PduSource
    def __init__(self, parser_config = None, **kwargs):
        self.allow_partial_parsing = kwargs.get('allow_partial_parsing', False) # hack, this should be in SerializationContext
        
        self.is_gcc_confrence = kwargs.get('is_gcc_confrence', False)
        self.encryption_level = kwargs.get('encryption_level', None)
        self.encryption_method = kwargs.get('encryption_method', None)
        self.encrypted_client_random = kwargs.get('encrypted_client_random', None)
        self.pre_capability_exchange = kwargs.get('pre_capability_exchange', True)
        
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
        
        if parser_config is None:
            parser_config = ParserConfig()
        self.parser_config = parser_config

        # HACK: this is a parsing setting not a rdp context value, but I don't have another place to put it at the moment
        self.compression_enabled = kwargs.get('compression_enabled', True)

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
        if chunk is None: # this means remove the chuck
            if DataChunkKey(id, pdu_source) in self._channel_data_chunk_by_id_and_source:
                del self._channel_data_chunk_by_id_and_source[DataChunkKey(id, pdu_source)]
        else:
            self._channel_data_chunk_by_id_and_source[DataChunkKey(id, pdu_source)] = chunk
    
    
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

    @contextlib.contextmanager
    def set_parser_config(self, parser_config):
        if parser_config is not None and not isinstance(parser_config, ParserConfig):
            raise ValueError('Expected an ParserConfig, but got %s' % (parser_config.__class__.__name__ if parser_config else parser_config))
        if parser_config is None:
            parser_config = self.parser_config
        orig_parser_config = self.parser_config
        self.parser_config = parser_config
        try:
            yield self
        finally:
            self.parser_config = orig_parser_config

    def get_compression_engine(self, compression_type = None):
        if compression_type is None:
            compression_type = self.compression_type
        if compression_type not in self._compression_engines:
            self._compression_engines[compression_type] = compression.CompressionFactory.new_engine(compression_type)
        return self._compression_engines[compression_type]

@utils.json_serializable(field_filter = lambda path: path.split('.')[-1] not in {'pdu_bytes'})
class RdpStreamSnapshot(object):
    def __init__(self, pdu_source: PduSource, pdu_bytes: bytes = None, pdu_timestamp = None, pdu_sequence_id = None, rdp_context: RdpContext = None, pdu_bytes_hex: str = None):
        self.pdu_source = utils.from_json_value(RdpContext.PduSource, pdu_source)
        self.pdu_bytes = pdu_bytes
        self.pdu_bytes_hex = pdu_bytes_hex
        self.rdp_context = utils.from_json_value(RdpContext, rdp_context, RdpContext())
        self.pdu_timestamp = pdu_timestamp
        self.pdu_sequence_id = pdu_sequence_id
        
        if self.pdu_bytes is None:
            if pdu_bytes_hex is None:
                raise ValueError('Either pdu_bytes or pdu_bytes_hex must be non-null')
            self.pdu_bytes = bytes.fromhex(pdu_bytes_hex)
        else:
            if pdu_bytes_hex is None:
                self.pdu_bytes_hex = binascii.hexlify(self.pdu_bytes).decode('ascii')
            else:
                if bytes.fromhex(self.pdu_bytes_hex) != self.pdu_bytes:
                    raise ValueError('pdu_bytes_hex must be equal to pdu_bytes. pdu_bytes_hex: %s, pdu_bytes = %s' % (bytes.fromhex(self.pdu_bytes_hex), self.pdu_bytes))

class ParserConfig(object):
    def __init__(self, compression_enabled = True, debug_pdu_paths = None):
        self.compression_enabled = compression_enabled

        if debug_pdu_paths is None:
            debug_pdu_paths = []
        self._debug_pdu_paths = debug_pdu_paths

    def is_debug_enabled(self, pdu_path):
        return any(pdu_path.endswith(debug_path) for debug_path in self._debug_pdu_paths)

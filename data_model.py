import struct
from functools import lru_cache as memoized
import functools

UINT_8  = '<B'
UINT_16_BE = '>H'
UINT_16_LE = '<H'
UINT_32_LE = '<I'
PAD = 'x'

def lazy_get_field(self, name):
    return functools.partial(self.__getattr__, name)

def no_op(x):
    pass

def traverse_object_graph(value, path):
    for field_name in path.split("."):
        value = getattr(value, field_name)
    return value

class LengthDependency(object):
    def __init__(self, length_getter = len):
        self._length_getter = length_getter
        
    def get_length(self, value):
        return self._length_getter(value)

class ValueDependency(object):
    def __init__(self, value_getter):
        self._value_getter = value_getter
        
    def get_value(self, value):
        return self._value_getter(value)

class BaseField(object):

    def get_length(self, value):
        raise NotImplementedError()
        
    def unpack_from(self, raw_data, offset):
        raise NotImplementedError()
    
    def pack_into(self, buffer, offset, value):
        raise NotImplementedError()

class StaticField(BaseField):
    def __init__(self, name, static_value):
        self._static_value = static_value
        self.name = name
    
    def get_length(self, value):
        return len(self._static_value)
        
    def unpack_from(self, raw_data, offset):
        return self._static_value
    
    def pack_into(self, buffer, offset, value):
        buffer[offset : offset + len(self._static_value)] = self._static_value

class StructEncodedField(BaseField):
    def __init__(self, name, struct_format):
        self._struct = struct.Struct(struct_format)
        self.name = name
    
    def get_length(self, value):
        return self._struct.size
        
    def unpack_from(self, raw_data, offset):
        value = self._struct.unpack_from(raw_data, offset)
        if len(value) == 0:
            return None
        elif len(value) == 1:
            return value[0]
        else:
            raise ValueError('unexpected number of values unpacked')
    
    def pack_into(self, buffer, offset, value):
        if value is not None:
            self._struct.pack_into(buffer, offset, value)

class BerEncodedLengthField(BaseField):
    def __init__(self, name):
        self.name = name
    
    def get_length(self, value):
        if value < 0x80:
            return 1
        else:
            length = 1
            while value > 0:
                value >>= 8
                length += 1
            return length
        
    def unpack_from(self, raw_data, offset):
        payload_length = raw_data[offset]
        if (payload_length & 0x80 == 0x80):
            length_length = payload_length & 0x7f
            payload_length = 0
            for j in range(length_length):
                payload_length <<= 8
                payload_length += raw_data[offset + 1 + j]
        return payload_length
    
    def pack_into(self, buffer, offset, value):
        if value < 0x80:
            struct.pack_into(UINT_8, buffer, offset, value)
        else:
            value_bytes = []
            while value > 0:
                value_bytes.append(value & 0xff)
                value >>= 8
            struct.pack_into(UINT_8, buffer, offset, len(value_bytes) | 0x80)
            i = 1
            for b in reversed(value_bytes):
                struct.pack_into(UINT_8, buffer, offset + i, b)
                i += 1

class PerEncodedLengthField(BaseField):
    def __init__(self, name):
        self.name = name
    
    def get_length(self, value):
        if value < 0x80:
            return 1
        else:
            return 2
        
    def unpack_from(self, raw_data, offset):
        payload_length = raw_data[offset]
        if payload_length & 0xC0 == 0x80: # see https://github.com/neutrinolabs/xrdp/blob/feb8ef33f53b951714fc2dca5b4d09cd7a8b277e/libxrdp/xrdp_mcs.c#L222
            payload_length &= 0x3f
            payload_length <<= 8
            payload_length += raw_data[offset + 1]
        return payload_length
    
    def pack_into(self, buffer, offset, value):
        if value < 0x80:
            struct.pack_into(UINT_8, buffer, offset, value)
        elif value < 2**14:
            struct.pack_into(UINT_8, buffer, offset +1 , value & 0xff)
            struct.pack_into(UINT_8, buffer, offset, (value >> 8) | 0x80)
        else:
            raise ValueError('value too large: %d' % value)

class DependentFieldDecorator(BaseField):
    def __init__(self, field, dependency):
        self._field = field
        self._dependency = dependency
        
    @property
    def name(self):
        return self._field.name
    
    def get_length(self, value):
        return self._field.get_length(value)
        
    def unpack_from(self, raw_data, offset):
        return self._field.unpack_from(raw_data, offset)
    
    def pack_into(self, buffer, offset, value):
        dependent_value = self._dependency.get_value(value)
        self._field.pack_into(buffer, offset, dependent_value)

class RawLengthField(BaseField):
    def __init__(self, name, length_dependency = LengthDependency()):
        self.name = name
        self._length_dependency = length_dependency
        
    def get_length(self, value):
        return self._length_dependency.get_length(value)

    def unpack_from(self, raw_data, offset):
        return raw_data[offset : offset + self.get_length(raw_data)]
    
    def pack_into(self, buffer, offset, value):
        buffer[offset : offset + self.get_length(value)] = value[:self.get_length(value)]

class NonSerializingReferenceField(BaseField):
    def __init__(self, name, value_getter):
        self.name = name
        self._value_getter = value_getter
        
    def get_referenced_value(self):
        return self._value_getter()
    
    def get_length(self, value):
        return 0

    def unpack_from(self, raw_data, offset):
        return None
    
    def pack_into(self, buffer, offset, value):
        pass

class ReinterpretedField(BaseField):
    def __init__(self, name, original_field, new_field):
        self.name = name
        self._original_field = original_field
        self._new_field = new_field
        self._remaining_field = RawLengthField(
                name + "_remaining", 
                LengthDependency(lambda x: self._original_field.get_length(x) - self._new_field.get_length(x)))
        
    def get_original_field(self):
        return self._original_field
    
    def get_remaining_field(self):
        return self._original_field
    
    def clear_remaining_field(self):
        self._remaining_field = RawLengthField(
                self._remaining_field.name, 
                LengthDependency(lambda x: 0))
    
    def get_length(self, value):
        return self._new_field.get_length(value)

    def unpack_from(self, raw_data, offset):
        return self._new_field.unpack_from(raw_data, offset)
    
    def pack_into(self, buffer, offset, value):
        self._new_field.pack_into(buffer, offset, value)
        raise ValueError("TODO: how do I pack the original remaining value if it has not been reinterpreted?")
        # length = self._new_field.get_length(value)
        # self._remaining_field.pack_into(buffer, offset + length, value)
        

class StructuredDataUnitField(BaseField):
    def __init__(self, name, data_unit_factory):
        self.name = name
        self._data_unit_factory = data_unit_factory

    def get_length(self, value):
        return len(value)
        
    def unpack_from(self, data, offset):
        return self._data_unit_factory(data[offset:])
    
    def pack_into(self, buffer, offset, value):
        wire_bytes = value.as_wire_bytes()
        buffer[offset : offset + len(wire_bytes)] = wire_bytes

class BaseDataUnit(object):
    def __init__(self, raw_data, fields):
        self._fields = fields
        self._field_values = {}
        self._fields_dirty = False
        self._raw_data = raw_data # we need to populate _raw_data in case there is a DynamicField in fields when we calculate the length
        self._raw_data = raw_data[:self.get_length()]
        
    def __getattr__(self, name):
        if len(self._field_values) == 0:
            self._unpack()
        if name in self._field_values:
            return self._get_value(name)
        else:
            raise AttributeError(name)
        
    def __setattr__(self, name, value):
        if name in {'_field_values', '_fields', '_fields_dirty', '_raw_data'}:
            super(BaseDataUnit, self).__setattr__(name, value)
            return
        if len(self._field_values) == 0:
            self._unpack()
        if name in self._field_values:
            self._field_values[name] = value
            self._fields_dirty = True
        else:
            super(BaseDataUnit, self).__setattr__(name, value)
    
    # problem:
    # how to reference length for a field that is split?
    #  > create a field which is a split field and a reference field, then split the field and add a ref in the parent to the new child and replace the 
    # how to keep field names short while still having a single clear place to lookup field names?
    #  > use aliasing of fields
    def reinterpret_field(self, name_to_reinterpret, new_name, cls):
    # def reinterpret_field(self, name_to_reinterpret, new_field):
        if len(self._field_values) == 0:
            self._unpack()
        offset = 0
        for i, f in enumerate(self._fields):
            value = self._get_value(f.name)
            length = f.get_length(value)
            if f.name == name_to_reinterpret:
                raise ValueError("TODO: how do I support reinterpreting the remaining value of this reinterpreted field?")
                # can I reinterpret an alias?
                # fields are only used for serialization and deserialization. once deserialized all of the 
                # values are the object representation only. Maybe I should make this more explicit by renaming 
                # field to "serializationSpec"/UnMarshaller and then having a seperate object which handles 
                # marshalling which only does serialization
                # Maybe I change the field definition to hold a sede and a value.
                #
                # problem: reinterpretation means doing multiple things that are seperate:
                # * use a new deserializer on the old raw bytes
                # * split the old raw bytes into the new object and the remaining bytes (eg. split off a header)
                #   * consuming all of the bytes is easy and does not have the problem of remaining bytes
                # * replace the old value with the new value
                # * install a serializer for the new value
                # * store the remaining bytes for future use (eg. payload that will next be reinterpreted)
                # 
                # problem: can I make deserialization lazy?
                
                
                # attemp 2:
                # reinterperted_field = ReinterpretedField(name_to_reinterpret, f, new_field)
                # self._fields[i] = reinterperted_field
                # new_value = reinterperted_field.unpack_from(memoryview(self._raw_data[offset : offset + length]), 0)
                # self._field_values[name_to_reinterpret] = new_value
                # raise ValueError('TODO: this is broken because the ReinterpretedField dosen't expose it's remaining_field via a property for object graph traversal. This can be fixed with a structured field (maybe? but maybe not since it dosen't make sense to reference a field via a name and expect to get a value from it. Maybe I can change this by having Unbound and Bound fields.))
                # self.alias_field(name_to_reinterpret + "_remaining", name_to_reinterpret + "." + )

                # Orig:
                new_value = cls(memoryview(self._raw_data[offset : offset + length]))
                # raise ValueError('TODO: fixup the replaced field so it can add the structured field')
                self._field_values[new_name] = new_value
                self._fields[i] = StructuredDataUnitField(new_name, cls)
                remaining_length = length - new_value.get_length()
                if remaining_length < 0:
                    raise ValueError("new field is bigger than old field")
                else:
                    self._fields.insert(i + 1, 
                            RawLengthField(name_to_reinterpret, LengthDependency(lambda x: remaining_length)))
                break
            else:
                offset += length
    
    def alias_field(self, new_name, path):
        self._fields.append(NonSerializingReferenceField(new_name, lambda: traverse_object_graph(self, path)))
    
    def __len__(self):
        return self.get_length()
        
    def get_length(self):
        if len(self._field_values) == 0:
            self._unpack()
        length = 0
        for f in self._fields:
            length += f.get_length(self._get_value(f.name))
        return length
        
    def _unpack(self):
        self._field_values = {}
        offset = 0
        for f in self._fields:
            value = f.unpack_from(self._raw_data, offset)
            self._field_values[f.name] = value
            offset += f.get_length(value)
    
    def _get_value(self, name):
        value = self._field_values[name]
        if value is not None:
            return value
        for f in self._fields:
            if name == f.name and hasattr(f, 'get_referenced_value'):
                return f.get_referenced_value()
        return None
            
    
    def is_dirty(self):
        if self._fields_dirty:
            return True
        elif len(self._field_values) == 0:
            return False
        else:
            for v in self._field_values.values():
                if hasattr(v, 'is_dirty') and v.is_dirty():
                    return True
            return False
        
    def as_wire_bytes(self):
        if not self.is_dirty():
            return self._raw_data
        elif len(self._field_values) == 0:
            return self._raw_data
        else:
            buffer = bytearray(self.get_length())
            offset = 0
            for f in self._fields:
                value = self._get_value(f.name)
                f.pack_into(buffer, offset, value)
                offset += f.get_length(value)
            return memoryview(buffer)

class RawDataUnit(BaseDataUnit):
    def __init__(self, raw_data):
        super(RawDataUnit, self).__init__(raw_data, fields = [
            RawLengthField('payload'),
        ])

class BerEncodedDataUnit(BaseDataUnit):
    def __init__(self, raw_data):
        super(BerEncodedDataUnit, self).__init__(raw_data, fields = [
            StructEncodedField('type', UINT_8),
            DependentFieldDecorator(
                BerEncodedLengthField('length'),
                ValueDependency(lambda x: len(self))
                ),
            RawLengthField('payload', 
                LengthDependency(lambda x: self.length))
        ])
        
class PerEncodedDataUnit(BaseDataUnit):
    def __init__(self, raw_data):
        super(PerEncodedDataUnit, self).__init__(raw_data, fields = [
            DependentFieldDecorator(
                PerEncodedLengthField('length'),
                ValueDependency(lambda x: len(self))
                ),
            RawLengthField('payload', 
                LengthDependency(lambda x: self.length))
        ])

class TpktDataUnit(BaseDataUnit):
    def __init__(self, raw_data):
        super(TpktDataUnit, self).__init__(raw_data, fields = [
            StructEncodedField('version', UINT_8),
            StructEncodedField('_', PAD),
            DependentFieldDecorator(
                StructEncodedField('length', UINT_16_BE),
                ValueDependency(lambda x: len(self))
                ),
            RawLengthField('tpktUserData', 
                LengthDependency(lambda x: self.length - 4)),
        ])
        
    FAST_PATH = 'FastPath'
    SLOW_PATH = 'SlowPath'
    TPKT_VERSION = {
        0x03: SLOW_PATH,
    }
    def get_tpkt_version(self):
        return self.TPKT_VERSION.get(self.version, self.FAST_PATH)
    

class X224HeaderDataUnit(BaseDataUnit):
    def __init__(self, raw_data):
        super(X224HeaderDataUnit, self).__init__(raw_data, fields = [
            StructEncodedField('length', UINT_8),
            StructEncodedField('x224_type', UINT_8),
            StaticField('x224_EOT', b'\x08'),
            RawLengthField('x224UserData'),
        ])
    
    TPDU_DATA = 'Data'
    TPDU_CONNECTION_REQUEST = 'Connection Request'
    TPDU_CONNECTION_CONFIRM = 'Connection Confirm'
    TPDU_TYPE = {
        0xE0: TPDU_CONNECTION_REQUEST,
        0xD0: TPDU_CONNECTION_CONFIRM,
        0xF0: TPDU_DATA
    }

    def get_x224_type(self):
        return self.TPDU_TYPE.get(self.x224_type, 'unknown (%d)' % self.x224_type)


class McsHeaderDataUnit(BaseDataUnit):
    SEND_DATA_CLIENT = 'send data request'
    SEND_DATA_SERVER = 'send data indication'
    CONNECT = 'Connect'
    ERECT_DOMAIN = 'Erect Domain'
    ATTACH_USER_REQUEST = 'Attach user request'
    ATTACH_USER_CONFIRM = 'Attach user confirm'
    CHANNEL_JOIN_REQUEST = 'channel join request'
    CHANNEL_JOIN_CONFIRM = 'channel join confirm'
    MCS_TYPE = {
        0x7f: CONNECT,
        0x04: ERECT_DOMAIN,
        0x28: ATTACH_USER_REQUEST,
        0x2c: ATTACH_USER_CONFIRM, # only uses high 6 bits
        0x38: CHANNEL_JOIN_REQUEST,
        0x3c: CHANNEL_JOIN_CONFIRM, # only uses high 6 bits
        0x64: SEND_DATA_CLIENT,
        0x68: SEND_DATA_SERVER,
    }
    
    def __init__(self, raw_data):
        super(McsHeaderDataUnit, self).__init__(raw_data, fields = [
            StructEncodedField('mcs_type', UINT_8),
            RawLengthField('mcs_payload'),
        ])
    
    def get_mcs_type(self):
        mcs_type = self.MCS_TYPE.get(self.mcs_type, None)
        if mcs_type is None:
            mcs_type = self.MCS_TYPE[self.mcs_type & 0xfc] # for high 6 bits
        return mcs_type

class McsConnectHeaderDataUnit(BaseDataUnit):
    CONNECT_INITIAL = 'Connect Initial'
    CONNECT_RESPONSE = 'Connect Response'
    MCS_CONNECT_TYPE = {
        0x65: CONNECT_INITIAL,
        0x66: CONNECT_RESPONSE,
    }
    
    def __init__(self, raw_data):
        super(McsConnectHeaderDataUnit, self).__init__(raw_data, fields = [
            StructEncodedField('mcs_connect_type', UINT_8),
        ])
        
    def get_mcs_connect_type(self):
        return self.MCS_CONNECT_TYPE.get(self.mcs_connect_type, None)


class McsConnectDataUnit(BaseDataUnit):
    def __init__(self, raw_data):
        super(McsConnectDataUnit, self).__init__(raw_data, fields = [
            DependentFieldDecorator(
                BerEncodedLengthField('length'),
                ValueDependency(lambda x: len(self))
                ),
            RawLengthField('mcs_connect_parameters', LengthDependency(lambda x: 93)),
            StructuredDataUnitField('userData', BerEncodedDataUnit),
        ])

class McsGccConnectionDataUnit(BaseDataUnit):
    def __init__(self, raw_data): 
        super(McsGccConnectionDataUnit, self).__init__(raw_data, fields = [
            RawLengthField('gcc_header', LengthDependency(lambda x: 21)),
            StructuredDataUnitField('gcc_userData', PerEncodedDataUnit),
        ])
        
class McsSendDataUnit(BaseDataUnit):
    def __init__(self, raw_data):
        super(McsSendDataUnit, self).__init__(raw_data, fields = [
            RawLengthField('mcs_data_parameters', LengthDependency(lambda x: 6)),
            DependentFieldDecorator(
                PerEncodedLengthField('length'),
                ValueDependency(lambda x: len(self.payload))
                ),
            RawLengthField('payload', LengthDependency(lambda x: self.payload_length)),
        ])
        
    # @property
    # def payload(self):
        
    #     payload = None
    #     if self.mcs_type in (Mcs.CONNECT_INITIAL):
    #         payload_length, i = parse_ber_length(self._raw_data, 2)
    #         # payload = self._raw_data[i:i + payload_length]
            
    #         callingDomainSelector, i = parse_ber(self._raw_data, i)
    #         calledDomainSelector, i = parse_ber(self._raw_data, i)
    #         upwardFlag, i = parse_ber(self._raw_data, i)
    #         targetParameters, i = parse_ber(self._raw_data, i)
    #         minimumParameters, i = parse_ber(self._raw_data, i)
    #         maximumParameters, i = parse_ber(self._raw_data, i)
    #         connectionInitial_userData, i = parse_ber(self._raw_data, i)
            
    #         # assume userData[:6] == b'00 05 00 14 7c 00' # = GCC Connection Data
    #         #connectionInitial_userData_length, i = parse_ber_length(connectionInitial_userData, 6)
    #         # assume connectionInitial header is 23 byte, xrdp does this https://github.com/neutrinolabs/xrdp/blob/feb8ef33f53b951714fc2dca5b4d09cd7a8b277e/libxrdp/xrdp_sec.c#L2478
    #         gccConnectionData_userData = connectionInitial_userData[23:]
    #         payload = gccConnectionData_userData
        
    #     elif self.mcs_type in (Mcs.CONNECT_RESPONSE):
    #         payload_length, i = parse_ber_length(self._raw_data, 2)
    #         # payload = self._raw_data[i:i + payload_length]
            
    #         result, i = parse_ber(self._raw_data, i)
    #         calledConnectId, i = parse_ber(self._raw_data, i)
    #         domainParameters, i = parse_ber(self._raw_data, i)
    #         connectionResponse_userData, i = parse_ber(self._raw_data, i)
            
    #         # assume userData[:6] == b'00 05 00 14 7c 00' # = GCC Connection Data
    #         #connectionInitial_userData_length, i = parse_ber_length(connectionInitial_userData, 6)
    #         # assume connectionInitial header is 23 byte, xrdp does this https://github.com/neutrinolabs/xrdp/blob/feb8ef33f53b951714fc2dca5b4d09cd7a8b277e/libxrdp/xrdp_sec.c#L2478
    #         gccConnectionData_userData = connectionResponse_userData[23:]
    #         payload = gccConnectionData_userData
            
    #     elif self.mcs_type in (Mcs.SEND_DATA_CLIENT, Mcs.SEND_DATA_SERVER):
    #         # type = self._raw_data[0]
    #         # initiator = self._raw_data[1] << 8 + self._raw_data[2] + 1001
    #         # channel_id = self._raw_data[3] << 8 + self._raw_data[4]
    #         # segmentation = self._raw_data[5]
            
    #         payload_length, i = parse_per_length(self._raw_data, 6)
    #         payload = self._raw_data[i:i + payload_length]

    #     elif self.mcs_type in (
    #             Mcs.ATTACH_USER_REQUEST, 
    #             Mcs.ATTACH_USER_CONFIRM, 
    #             Mcs.ERECT_DOMAIN,
    #             Mcs.CHANNEL_JOIN_REQUEST,
    #             Mcs.CHANNEL_JOIN_CONFIRM,
    #             ):
    #         payload = self._raw_data

    #     return payload

class Rdp_TS_UD_HEADER(BaseDataUnit):
    def __init__(self, raw_data):
        super(Rdp_TS_UD_HEADER, self).__init__(raw_data, fields = [
            StructEncodedField('type', UINT_16_LE),
            DependentFieldDecorator(
                StructEncodedField('length', UINT_16_LE),
                ValueDependency(lambda x: len(self.payload) + 4)
                ),
            RawLengthField('UD_array', LengthDependency(lambda x: self.length - 4)),
        ])
        
class Rdp_TS_UD_CS_CORE(BaseDataUnit):
    def __init__(self, raw_data):
        super(Rdp_TS_UD_CS_CORE, self).__init__(raw_data, fields = [
            RawLengthField('payload'),
        ])
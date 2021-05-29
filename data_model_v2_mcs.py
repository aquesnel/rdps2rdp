from data_model_v2 import (
    BaseDataUnit,
    BerEncodedDataUnit,
    PerEncodedDataUnit,
    
    PrimitiveField,
    DataUnitField,   
    
    add_constants_names_mapping,
    lookup_name_in,
)
from data_model_v2_rdp import RdpUserDataBlock
from serializers import (
    RawLengthSerializer,
    DependentValueSerializer,
    StaticSerializer,
    ValueTransformSerializer,
    BerEncodedLengthSerializer,
    PerEncodedLengthSerializer,
    ArraySerializer,
    DataUnitSerializer,
    
    StructEncodedSerializer,
    UINT_8, 
    UINT_16_BE,
    UINT_16_LE,
    UINT_32_LE,
    PAD,
    
    ValueTransformer,
    ValueDependency,
    LengthDependency,
)

class Mcs(object):
    CONNECT = 0x7f
    ERECT_DOMAIN = 0x04
    ATTACH_USER_REQUEST = 0x28
    ATTACH_USER_CONFIRM = 0x2c # only uses high 6 bits
    CHANNEL_JOIN_REQUEST = 0x38
    CHANNEL_JOIN_CONFIRM = 0x3c # only uses high 6 bits
    SEND_DATA_FROM_CLIENT = 0x64
    SEND_DATA_FROM_SERVER = 0x68
    MCS_TYPE = {
        CONNECT: 'CONNECT',
        ERECT_DOMAIN: 'ERECT_DOMAIN',
        ATTACH_USER_REQUEST: 'ATTACH_USER_REQUEST',
        ATTACH_USER_CONFIRM: 'ATTACH_USER_CONFIRM',
        CHANNEL_JOIN_REQUEST: 'CHANNEL_JOIN_REQUEST',
        CHANNEL_JOIN_CONFIRM: 'CHANNEL_JOIN_CONFIRM',
        SEND_DATA_FROM_CLIENT: 'SEND_DATA_FROM_CLIENT',
        SEND_DATA_FROM_SERVER: 'SEND_DATA_FROM_SERVER',
    }
    
    CONNECT_INITIAL = 0x65
    CONNECT_RESPONSE = 0x66
    MCS_CONNECT_TYPE = {
        CONNECT_INITIAL: 'CONNECT_INITIAL',
        CONNECT_RESPONSE: 'CONNECT_RESPONSE',
    }
    
class McsHeaderDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsHeaderDataUnit, self).__init__(fields = [
            PrimitiveField('type', 
                ValueTransformSerializer(
                    StructEncodedSerializer(UINT_8),
                    ValueTransformer(
                        to_serialized = lambda x: x,
                        from_serialized = lambda x: Mcs.CONNECT if x == Mcs.CONNECT else x & 0xfc)), # use the high 6 bits for all types except CONNECT
                to_human_readable = lookup_name_in(Mcs.MCS_TYPE)),
            PrimitiveField('payload', RawLengthSerializer()),
        ])

class McsConnectHeaderDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsConnectHeaderDataUnit, self).__init__(fields = [
            PrimitiveField('mcs_connect_type', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Mcs.MCS_CONNECT_TYPE)),
        ])

class McsConnectInitialDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsConnectInitialDataUnit, self).__init__(fields = [
            PrimitiveField('length',
                DependentValueSerializer(
                    BerEncodedLengthSerializer(),
                    ValueDependency(lambda x: len(self)))),
            DataUnitField('callingDomainSelector', BerEncodedDataUnit()),
            DataUnitField('calledDomainSelector', BerEncodedDataUnit()),
            DataUnitField('upwardFlag', BerEncodedDataUnit()),
            DataUnitField('targetParameters', BerEncodedDataUnit()),
            DataUnitField('minimumParameters', BerEncodedDataUnit()),
            DataUnitField('maximumParameters', BerEncodedDataUnit()),
            DataUnitField('userData', 
                BerEncodedDataUnit(McsGccConnectionDataUnit())),
        ])


class McsConnectResponseDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsConnectResponseDataUnit, self).__init__(fields = [
            PrimitiveField('length',
                DependentValueSerializer(
                    BerEncodedLengthSerializer(),
                    ValueDependency(lambda x: len(self)))),
            DataUnitField('result', BerEncodedDataUnit()),
            DataUnitField('calledConnectId', BerEncodedDataUnit()),
            DataUnitField('domainParameters', BerEncodedDataUnit()),
            DataUnitField('userData', 
                BerEncodedDataUnit(McsGccConnectionDataUnit())),
        ])

class McsGccConnectionDataUnit(BaseDataUnit):
    def __init__(self): 
        super(McsGccConnectionDataUnit, self).__init__(fields = [
            PrimitiveField('gcc_header', RawLengthSerializer(LengthDependency(lambda x: 21))),
            DataUnitField('gcc_userData', 
                PerEncodedDataUnit(
                    PerEncodedLengthSerializer.RANGE_0_64K,
                    ArraySerializer(
                        DataUnitSerializer(RdpUserDataBlock),
                        length_dependency = LengthDependency()))),
        ])
        
class McsSendDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsSendDataUnit, self).__init__(fields = [
            PrimitiveField('mcs_data_parameters', RawLengthSerializer(LengthDependency(lambda x: 5))),
            DataUnitField('mcs_data', PerEncodedDataUnit(PerEncodedLengthSerializer.RANGE_VALUE_DEFINED)),
        ])

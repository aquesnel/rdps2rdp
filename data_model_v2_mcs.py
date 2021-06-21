from data_model_v2 import (
    BaseDataUnit,
    ArrayDataUnit,
    BerEncodedDataUnit,
    PerEncodedDataUnit,
    
    PrimitiveField,
    DataUnitField,
    UnionField,
    
    ArrayAutoReinterpret,
    AutoReinterpretConfig,
    
    add_constants_names_mapping,
    lookup_name_in,
)
from data_model_v2_rdp import (
    Rdp,
    RdpUserDataBlock,
    
    Rdp_TS_UD_CS_CORE,
    Rdp_TS_UD_CS_SEC,
    Rdp_TS_UD_CS_NET,
    
    Rdp_TS_UD_SC_CORE,
    Rdp_TS_UD_SC_NET,
    Rdp_TS_UD_SC_SEC1,
    Rdp_TS_UD_SC_MCS_MSGCHANNEL,
)
from serializers import (
    RawLengthSerializer,
    DependentValueSerializer,
    StaticSerializer,
    ValueTransformSerializer,
    BerEncodedLengthSerializer,
    PerEncodedLengthSerializer,
    
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

    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append('MCS')
        retval.append(str(self._fields_by_name['type'].get_human_readable_value()))
        retval.extend(super(McsHeaderDataUnit, self).get_pdu_types(rdp_context))
        return retval

class McsConnectHeaderDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsConnectHeaderDataUnit, self).__init__(
            fields = [
                PrimitiveField('mcs_connect_type', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Mcs.MCS_CONNECT_TYPE)),
            ])

    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(str(self._fields_by_name['mcs_connect_type'].get_human_readable_value()))
        retval.extend(super(McsConnectHeaderDataUnit, self).get_pdu_types(rdp_context))
        return retval

class McsConnectInitialDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsConnectInitialDataUnit, self).__init__(
            use_class_as_pdu_name = True,
            fields = [
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
        super(McsConnectResponseDataUnit, self).__init__(
            use_class_as_pdu_name = True,
            fields = [
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
        super(McsGccConnectionDataUnit, self).__init__(
            fields = [
                PrimitiveField('gcc_header', RawLengthSerializer(LengthDependency(lambda x: 21))),
                DataUnitField('gcc_userData', 
                    PerEncodedDataUnit(
                        PerEncodedLengthSerializer.RANGE_0_64K,
                        ArrayDataUnit(RdpUserDataBlock, 
                            length_dependency = LengthDependency(),
                            alias_hinter = ValueDependency(lambda rdp_user_data_block: {
                                    Rdp.UserData.CS_CORE: 'clientCoreData',
                                    Rdp.UserData.CS_SECURITY: 'clientSecurityData',
                                    Rdp.UserData.CS_NET: 'clientNetworkData',
                                    
                                    Rdp.UserData.SC_CORE: 'serverCoreData',
                                    Rdp.UserData.SC_NET: 'serverNetworkData',
                                    Rdp.UserData.SC_SECURITY: 'serverSecurityData',
                                    Rdp.UserData.SC_MCS_MSGCHANNEL: 'serverMessageChannelData',
                                }.get(rdp_user_data_block.header.type, None))))),
            ])
        
class McsSendDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsSendDataUnit, self).__init__(fields = [
            # PrimitiveField('mcs_data_parameters', RawLengthSerializer(LengthDependency(lambda x: 5))),
            PrimitiveField('initiator', 
                ValueTransformSerializer(
                    StructEncodedSerializer(UINT_16_BE),
                    ValueTransformer( # initiator is in the range 1001..65535
                        to_serialized = lambda x: x - 1001,
                        from_serialized = lambda x: x + 1001))),
            PrimitiveField('channelId', StructEncodedSerializer(UINT_16_BE)),
            UnionField(fields = [
                PrimitiveField('dataPriority_TODO', StructEncodedSerializer(UINT_8)), # TODO: add bit mask
                PrimitiveField('segmentation_TODO', StructEncodedSerializer(UINT_8)), # TODO: add bit mask
            ]),
            DataUnitField('mcs_data', PerEncodedDataUnit(PerEncodedLengthSerializer.RANGE_VALUE_DEFINED)),
        ])

    def get_pdu_types(self, rdp_context):
        channel_id = self._fields_by_name['channelId'].get_human_readable_value()
        if channel_id in rdp_context.get_channel_ids():
            channel_name = "%s (%d)" % (rdp_context.get_channel_by_id(channel_id).name, channel_id)
        else:
            channel_name = str(channel_id)
        retval = []
        retval.append('channelId')
        retval.append(channel_name)
        retval.extend(super(McsSendDataUnit, self).get_pdu_types(rdp_context))
        return retval

class McsChannelJoinRequestDataUnit(BaseDataUnit):
    def __init__(self):
        super(McsChannelJoinRequestDataUnit, self).__init__(fields = [
            PrimitiveField('initiator', 
                ValueTransformSerializer(
                    StructEncodedSerializer(UINT_16_BE),
                    ValueTransformer(
                        to_serialized = lambda x: x - 1001,
                        from_serialized = lambda x: x + 1001))),
            PrimitiveField('channelId', StructEncodedSerializer(UINT_16_BE)),
        ])

    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append('channelId')
        retval.append(str(self._fields_by_name['channelId'].get_human_readable_value()))
        retval.extend(super(McsChannelJoinRequestDataUnit, self).get_pdu_types(rdp_context))
        return retval

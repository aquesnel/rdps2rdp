import functools

from data_model_v2 import (
    BaseDataUnit,
    
    PrimitiveField,
    DataUnitField,
    UnionField,
    OptionalField,
    ConditionallyPresentField,
    
    ArrayAutoReinterpret,
    AutoReinterpretConfig,
    
    add_constants_names_mapping,
    lookup_name_in,
    PduLayerSummary,
)
from serializers import (
    RawLengthSerializer,
    DependentValueSerializer,
    BitFieldEncodedSerializer,
    BitMaskSerializer,
    
    StructEncodedSerializer,
    VariableLengthIntSerializer,
    UINT_8, 
    UINT_16_BE,
    UINT_16_LE,
    UINT_32_LE,
    PAD,
    
    EncodedStringSerializer,
    DelimitedEncodedStringSerializer,
    
    ValueTransformSerializer,
    ValueTransformer,
    
    ValueDependency,
    LengthDependency,
)
from data_model_v2_rdp import (
    Rdp,
)

CBID_FROM_SERIALIZED_MAPPING = {
    0x00: 1,
    0x01: 2,
    0x02: 4,
}
CBID_TO_SERIALIZED_MAPPING = {v:k for k,v in CBID_FROM_SERIALIZED_MAPPING.items()}

class Rdp_DYNVC_Header(BaseDataUnit):
    def __init__(self):
        super(Rdp_DYNVC_Header, self).__init__(fields = [
            UnionField([
                PrimitiveField('cbId', BitMaskSerializer(Rdp.DynamicVirtualChannels.HEADER_MASK_CBID, StructEncodedSerializer(UINT_8))),
                PrimitiveField('Pri', ValueTransformSerializer(
                        BitMaskSerializer(Rdp.DynamicVirtualChannels.HEADER_MASK_PRI, StructEncodedSerializer(UINT_8)),
                        ValueTransformer(
                            to_serialized = lambda x: x << 2,
                            from_serialized = lambda x: x >> 2))),
                PrimitiveField('Cmd', ValueTransformSerializer(
                        BitMaskSerializer(Rdp.DynamicVirtualChannels.HEADER_MASK_CMD, StructEncodedSerializer(UINT_8)),
                        ValueTransformer(
                            to_serialized = lambda x: x << 4,
                            from_serialized = lambda x: x >> 4)),
                    to_human_readable = lookup_name_in(Rdp.DynamicVirtualChannels.COMMAND_NAMES)),
            ]),
        ])
        
    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(self._fields_by_name['Cmd'].get_human_readable_value())
        retval.extend(super(Rdp_DYNVC_Header, self).get_pdu_types(rdp_context))
        return retval

    def _get_pdu_summary_layers(self, rdp_context):
        return [PduLayerSummary('RDP-DYNVC', self._fields_by_name['Cmd'].get_human_readable_value())]

class Rdp_DYNVC_CAPS_VERSION(BaseDataUnit):
    def __init__(self):
        super(Rdp_DYNVC_CAPS_VERSION, self).__init__(fields = [
            PrimitiveField('Pad', StructEncodedSerializer(PAD)),
            PrimitiveField('Version', StructEncodedSerializer(UINT_16_LE)),
            ConditionallyPresentField(
                lambda: self.Version in {2, 3},
                PrimitiveField('PriorityCharge0', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: self.Version in {2, 3},
                PrimitiveField('PriorityCharge1', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: self.Version in {2, 3},
                PrimitiveField('PriorityCharge2', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: self.Version in {2, 3},
                PrimitiveField('PriorityCharge3', StructEncodedSerializer(UINT_16_LE))),
        ])

class Rdp_DYNVC_CAPS_RSP(BaseDataUnit):
    def __init__(self):
        super(Rdp_DYNVC_CAPS_RSP, self).__init__(fields = [
            PrimitiveField('Pad', StructEncodedSerializer(PAD)),
            PrimitiveField('Version', StructEncodedSerializer(UINT_16_LE)),
        ])


def _get_channel_name(self, rdp_context):
    channel_id = self._fields_by_name['ChannelId'].get_human_readable_value()
    if channel_id in rdp_context.get_channel_ids():
        channel_name = "%s (%d)" % (rdp_context.get_channel_by_id(channel_id).name, channel_id)
    else:
        channel_name = str(channel_id)
    return channel_name

def _get_pdu_types_with_channel(self, rdp_context):
    retval = []
    retval.append('channelId')
    retval.append(self._get_channel_name(rdp_context))
    retval.extend(super(self.__class__, self).get_pdu_types(rdp_context))
    return retval
    
def _get_pdu_summary_layers_with_channel(rdp_dynvc_data_unit, rdp_context, command):
    return [PduLayerSummary('RDP-DYNVC', envelope_extra = 'channel %s' % rdp_dynvc_data_unit._get_channel_name(rdp_context), command = command)]


class Rdp_DYNVC_CREATE_REQ(BaseDataUnit):
    def __init__(self, dynvc_header):
        super(Rdp_DYNVC_CREATE_REQ, self).__init__(fields = [
            PrimitiveField('ChannelId', VariableLengthIntSerializer(LengthDependency(lambda x: CBID_FROM_SERIALIZED_MAPPING[dynvc_header.cbId]))),
            PrimitiveField('ChannelName', DelimitedEncodedStringSerializer(EncodedStringSerializer.WINDOWS_1252, '\0')),
        ])
    
    _get_channel_name = _get_channel_name
    get_pdu_types = _get_pdu_types_with_channel
    
    def _get_pdu_summary_layers(self, rdp_context):
        return _get_pdu_summary_layers_with_channel(self, rdp_context, 'CREATE_REQ')


class Rdp_DYNVC_CREATE_RSP(BaseDataUnit):
    def __init__(self, dynvc_header):
        super(Rdp_DYNVC_CREATE_RSP, self).__init__(fields = [
            PrimitiveField('ChannelId', VariableLengthIntSerializer(LengthDependency(lambda x: CBID_FROM_SERIALIZED_MAPPING[dynvc_header.cbId]))),
            PrimitiveField('CreationStatus', StructEncodedSerializer(UINT_32_LE), to_human_readable = lookup_name_in(Rdp.HResult.HRESULT_NAMES)),
        ])
        
    _get_channel_name = _get_channel_name
    # get_pdu_types = _get_pdu_types_with_channel
    def get_pdu_types(self, rdp_context):
        retval = _get_pdu_types_with_channel(self, rdp_context)
        retval.append('CreationStatus')
        retval.append(self._fields_by_name['CreationStatus'].get_human_readable_value())
        retval.extend(super(Rdp_DYNVC_CREATE_RSP, self).get_pdu_types(rdp_context))
        return retval

    def _get_pdu_summary_layers(self, rdp_context):
        return _get_pdu_summary_layers_with_channel(self, rdp_context, 'CREATE_RSP')

class Rdp_DYNVC_CLOSE(BaseDataUnit):
    def __init__(self, dynvc_header):
        super(Rdp_DYNVC_CLOSE, self).__init__(fields = [
            PrimitiveField('ChannelId', VariableLengthIntSerializer(LengthDependency(lambda x: CBID_FROM_SERIALIZED_MAPPING[dynvc_header.cbId]))),
        ])
        
    _get_channel_name = _get_channel_name
    get_pdu_types = _get_pdu_types_with_channel

    def _get_pdu_summary_layers(self, rdp_context):
        return _get_pdu_summary_layers_with_channel(self, rdp_context, 'CLOSE')

class Rdp_DYNVC_DATA_FIRST(BaseDataUnit):
    def __init__(self, dynvc_header):
        super(Rdp_DYNVC_DATA_FIRST, self).__init__(fields = [
            PrimitiveField('ChannelId', VariableLengthIntSerializer(LengthDependency(lambda x: CBID_FROM_SERIALIZED_MAPPING[dynvc_header.cbId]))),
            # Length = total length across PDUs
            PrimitiveField('Length', VariableLengthIntSerializer(LengthDependency(lambda x: CBID_FROM_SERIALIZED_MAPPING[dynvc_header.Pri]))),
            PrimitiveField('Data', RawLengthSerializer(LengthDependency(lambda x: self.Length))),
        ])
        
    _get_channel_name = _get_channel_name
    get_pdu_types = _get_pdu_types_with_channel

    def _get_pdu_summary_layers(self, rdp_context):
        return _get_pdu_summary_layers_with_channel(self, rdp_context, 'DATA_FIRST')

class Rdp_DYNVC_DATA(BaseDataUnit):
    def __init__(self, dynvc_header):
        super(Rdp_DYNVC_DATA, self).__init__(fields = [
            PrimitiveField('ChannelId', VariableLengthIntSerializer(LengthDependency(lambda x: CBID_FROM_SERIALIZED_MAPPING[dynvc_header.cbId]))),
            PrimitiveField('Data', RawLengthSerializer()),
        ])
        
    _get_channel_name = _get_channel_name
    get_pdu_types = _get_pdu_types_with_channel

    def _get_pdu_summary_layers(self, rdp_context):
        return _get_pdu_summary_layers_with_channel(self, rdp_context, 'DATA')


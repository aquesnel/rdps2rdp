import functools

from data_model_v2 import (
    BaseDataUnit,
    
    PrimitiveField,
    DataUnitField,
    UnionField,
    OptionalField,
    ConditionallyPresentField,
    
    AutoReinterpret,
    ArrayAutoReinterpret,
    AutoReinterpretConfig,
    
    add_constants_names_mapping,
    lookup_name_in,
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
    Utf16leEncodedStringSerializer,
    FixedLengthUtf16leEncodedStringSerializer,
    
    ValueTransformSerializer,
    ValueTransformer,
    
    ValueDependency,
    LengthDependency,
)
from data_model_v2_rdp import (
    Rdp,
)

class Rdp_TS_RAIL_PDU(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_PDU, self).__init__(fields = [
            DataUnitField('header', Rdp_TS_RAIL_PDU_HEADER()),
            PrimitiveField('payload', RawLengthSerializer(LengthDependency(lambda x: self.header.orderLength))),
        ],
        auto_reinterpret_configs = [
            AutoReinterpret(
                field_to_reinterpret_name = 'payload',
                type_getter = ValueDependency(lambda x: self.header.orderType),
                config_by_type = {
                    Rdp.Rail.TS_RAIL_ORDER_EXEC: AutoReinterpretConfig('', Rdp_TS_RAIL_ORDER_EXEC),
                    Rdp.Rail.TS_RAIL_ORDER_EXEC_RESULT: AutoReinterpretConfig('', Rdp_TS_RAIL_ORDER_EXEC_RESULT),
                    Rdp.Rail.TS_RAIL_ORDER_HANDSHAKE: AutoReinterpretConfig('', Rdp_TS_RAIL_ORDER_HANDSHAKE),
                    Rdp.Rail.TS_RAIL_ORDER_HANDSHAKE_EX: AutoReinterpretConfig('', Rdp_TS_RAIL_ORDER_HANDSHAKE_EX),
                    Rdp.Rail.TS_RAIL_ORDER_GET_APPID_REQ: AutoReinterpretConfig('', Rdp_TS_RAIL_ORDER_GET_APPID_REQ),
                    Rdp.Rail.TS_RAIL_ORDER_GET_APPID_RESP: AutoReinterpretConfig('', Rdp_TS_RAIL_ORDER_GET_APPID_RESP),
                    Rdp.Rail.TS_RAIL_ORDER_GET_APPID_RESP_EX: AutoReinterpretConfig('', Rdp_TS_RAIL_ORDER_GET_APPID_RESP_EX),
                    Rdp.Rail.TS_RAIL_ORDER_MINMAXINFO: AutoReinterpretConfig('', Rdp_TS_RAIL_ORDER_MINMAXINFO),
                    Rdp.Rail.TS_RAIL_ORDER_CLOAK: AutoReinterpretConfig('', Rdp_TS_RAIL_ORDER_CLOAK),
                }),
        ])

    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(self.header._fields_by_name['orderType'].get_human_readable_value())
        retval.extend(super(Rdp_TS_RAIL_PDU, self).get_pdu_types(rdp_context))
        return retval
        
class Rdp_TS_RAIL_PDU_HEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_PDU_HEADER, self).__init__(fields = [
            PrimitiveField('orderType', StructEncodedSerializer(UINT_16_LE), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_ORDER_NAMES)),
            PrimitiveField('orderLength', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_TS_RAIL_ORDER_HANDSHAKE(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_HANDSHAKE, self).__init__(fields = [
            PrimitiveField('buildNumber', StructEncodedSerializer(UINT_32_LE)),
        ])
    
class Rdp_TS_RAIL_ORDER_HANDSHAKE_EX(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_HANDSHAKE_EX, self).__init__(fields = [
            PrimitiveField('buildNumber', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('railHandshakeFlags', BitFieldEncodedSerializer(UINT_32_LE, Rdp.Rail.TS_RAIL_HANDSHAKE_EX_FLAGS_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_HANDSHAKE_EX_FLAGS_NAMES)),
        ])

class Rdp_TS_RAIL_ORDER_CLIENTSTATUS(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_CLIENTSTATUS, self).__init__(fields = [
            PrimitiveField('Flags', BitFieldEncodedSerializer(UINT_32_LE, Rdp.Rail.TS_RAIL_CLIENTSTATUS_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLIENTSTATUS_NAMES)),
        ])


class Rdp_TS_RAIL_ORDER_EXEC(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_EXEC, self).__init__(fields = [
            PrimitiveField('Flags', BitFieldEncodedSerializer(UINT_16_LE, Rdp.Rail.TS_RAIL_EXEC_FLAG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_EXEC_FLAG_NAMES)),
            PrimitiveField('ExeOrFileLength', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('WorkingDirLength', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('ArgumentsLen', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('ExeOrFile', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.ExeOrFileLength))),
            PrimitiveField('WorkingDir', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.WorkingDirLength))),
            PrimitiveField('Arguments', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.ArgumentsLen))),
        ])
        
class Rdp_TS_RAIL_ORDER_EXEC_RESULT(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_EXEC_RESULT, self).__init__(fields = [
            PrimitiveField('Flags', BitFieldEncodedSerializer(UINT_16_LE, Rdp.Rail.TS_RAIL_EXEC_FLAG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_EXEC_FLAG_NAMES)),
            PrimitiveField('ExecResult', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('RawResult', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('Padding1', StructEncodedSerializer(PAD)),
            PrimitiveField('Padding2', StructEncodedSerializer(PAD)),
            PrimitiveField('ExeOrFileLength', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('ExeOrFile', Utf16leEncodedStringSerializer(LengthDependency(lambda x: self.ExeOrFileLength))),
        ])
        
class Rdp_TS_RAIL_ORDER_GET_APPID_REQ(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_GET_APPID_REQ, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
        ])

class Rdp_TS_RAIL_ORDER_GET_APPID_RESP(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_GET_APPID_RESP, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('ApplicationId', FixedLengthUtf16leEncodedStringSerializer(520)),
        ])
        
class Rdp_TS_RAIL_ORDER_GET_APPID_RESP_EX(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_GET_APPID_RESP_EX, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('ApplicationId', FixedLengthUtf16leEncodedStringSerializer(520)),
            PrimitiveField('ProcessId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('ProcessImageName', FixedLengthUtf16leEncodedStringSerializer(520)),
        ])

class Rdp_TS_RAIL_ORDER_MINMAXINFO(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_MINMAXINFO, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('MaxWidth', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MaxHeight', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MaxPosX', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MaxPosY', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MinTrackWidth', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MinTrackHeight', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MaxTrackWidth', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MaxTrackHeight', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_TS_RAIL_ORDER_CLOAK(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_RAIL_ORDER_CLOAK, self).__init__(fields = [
            PrimitiveField('WindowId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('Cloaked', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLOAKED_NAMES)),
        ])
        
class Rdp_TS_WINDOW_ORDER_HEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_WINDOW_ORDER_HEADER, self).__init__(fields = [
            PrimitiveField('OrderSize', StructEncodedSerializer(UINT_16_LE)),
            # UnionField([
            #     PrimitiveField('FieldsPresentFlags_type',
            #         BitMaskSerializer(Rdp.DrawingOrders.OrderFlags.ALT_SECAONDARY_FLAG_MASK_offscreenBitmapId, StructEncodedSerializer(UINT_8)),
            #         to_human_readable = lookup_name_in(Rdp.Rail.TS_RAIL_CLOAKED_NAMES)),
            #     PolymophicField('FieldsPresentFlags_flags',
            #         type_getter = ValueDependency(lambda x: self.FieldsPresentFlags_type), 
            #         fields_by_type = {
            #             False: PrimitiveField('BitmapSize_2byte', StructEncodedSerializer(UINT_16_LE)),
            #             True: PrimitiveField('BitmapSize_4byte', StructEncodedSerializer(UINT_32_LE)),
            #     }),
            # ])),
            # PrimitiveField('FieldsPresentFlags', StructEncodedSerializer(UINT_8)),
            PrimitiveField('payload', RawLengthSerializer(LengthDependency(lambda x: self.OrderSize - 3))),
        ])

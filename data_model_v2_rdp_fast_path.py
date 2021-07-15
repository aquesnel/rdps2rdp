from typing import Tuple
import functools

from data_model_v2 import (
    BaseDataUnit,
    ArrayDataUnit,
    
    PrimitiveField,
    DataUnitField,
    UnionField,
    OptionalField,
    ConditionallyPresentField,
    
    AutoReinterpret,
    AutoReinterpretConfig,
    
    add_constants_names_mapping,
    lookup_name_in,
)
from serializers import (
    BaseSerializer,
    RawLengthSerializer,
    DependentValueSerializer,
    ValueTransformSerializer,
    BitFieldEncodedSerializer,
    BitMaskSerializer,
    
    StructEncodedSerializer,
    UINT_8, 
    UINT_16_BE,
    UINT_16_LE,
    UINT_32_LE,
    PAD,
    
    EncodedStringSerializer,
    FixedLengthEncodedStringSerializer,
    FixedLengthUtf16leEncodedStringSerializer,
    Utf16leEncodedStringSerializer,
    
    ValueTransformer,
    ValueDependency,
    LengthDependency,
)

from data_model_v2_rdp import Rdp



class Rdp_TS_FP_HEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_FP_HEADER, self).__init__(fields = [
            UnionField([
                PrimitiveField('action', BitMaskSerializer(Rdp.FastPath.FASTPATH_ACTIONS_MASK, StructEncodedSerializer(UINT_8)), to_human_readable = lookup_name_in(Rdp.FastPath.FASTPATH_ACTION_NAMES)),
                PrimitiveField('numEvents', 
                    ValueTransformSerializer(
                        BitMaskSerializer(Rdp.FastPath.FASTPATH_NUM_EVENTS_MASK, StructEncodedSerializer(UINT_8)),
                        ValueTransformer(
                            to_serialized = lambda x: x << 2,
                            from_serialized = lambda x: x >> 2))),
                PrimitiveField('flags', BitFieldEncodedSerializer(UINT_8, Rdp.FastPath.FASTPATH_FLAG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.FastPath.FASTPATH_FLAG_NAMES)),
            ]),
        ])

    def get_pdu_types(self, rdp_context):
        packet_type = 'Unknown'
        if self.action == Rdp.FastPath.FASTPATH_ACTION_X224:
            packet_type = 'TPKT'
        elif self.action == Rdp.FastPath.FASTPATH_ACTION_FASTPATH:
            packet_type = 'FastPath'
        retval = []
        retval.append(packet_type)
        retval.extend(super(Rdp_TS_FP_HEADER, self).get_pdu_types(rdp_context))
        return retval

class TS_FP_LengthSerializer(BaseSerializer[int]):
    # TS_FP_INPUT_PDU.length1 and TS_FP_INPUT_PDU.length2 fields
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133
    def __init__(self):
        pass
    
    def get_serialized_length(self, value: int) -> int:
        if value < 0x80:
            return 1
        else:
            return 2
        
    def unpack_from(self, raw_data: bytes, offset: int) -> Tuple[int, int]:
        length = 1
        value = raw_data[offset]
        # if value > 0x7fff:
        #     raise ValueError('value too large: %d' % value)
        if value & 0x80 == 0x80:
            value &= 0x7f
            value <<= 8
            value += raw_data[offset + 1]
            length += 1
        return value, length
    
    def pack_into(self, buffer: bytes, offset: int, value: int) -> None:
        if value < 0x80:
            struct.pack_into(UINT_8, buffer, offset, value)
        elif value <= 0x7fff:
            struct.pack_into(UINT_16_BE, buffer, offset, value | 0x8000)
        else:
            raise ValueError('value too large: %d' % value)

class Rdp_TS_FP_length_only(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_FP_length_only, self).__init__(fields = [
            PrimitiveField('length', TS_FP_LengthSerializer()),
            ])

            
class Rdp_TS_FP_INPUT_PDU(BaseDataUnit):
    def __init__(self, is_fips_present = False):
        super(Rdp_TS_FP_INPUT_PDU, self).__init__(fields = [
            DataUnitField('header', Rdp_TS_FP_HEADER()),
            PrimitiveField('length', TS_FP_LengthSerializer()),
            ConditionallyPresentField(
                lambda:  is_fips_present,
                PrimitiveField('fipsInformation', RawLengthSerializer(LengthDependency(lambda x: 4)))),
            ConditionallyPresentField(
                lambda:  Rdp.FastPath.FASTPATH_FLAG_SECURE_CHECKSUM in self.header.flags,
                PrimitiveField('dataSignature', RawLengthSerializer(LengthDependency(lambda x: 8)))),
            ConditionallyPresentField(
                lambda:  self.header.numEvents == 0,
                PrimitiveField('numEvents', StructEncodedSerializer(UINT_8))),
            PrimitiveField('fpInputEvents', 
                RawLengthSerializer(
                    LengthDependency(
                        lambda x: (self.length
                                    - self._fields_by_name['header'].get_length()
                                    - self._fields_by_name['length'].get_length()
                                    - self._fields_by_name['fipsInformation'].get_length()
                                    - self._fields_by_name['dataSignature'].get_length()
                                    - self._fields_by_name['numEvents'].get_length())))),
        ])

class Rdp_TS_FP_UPDATE_PDU(BaseDataUnit):
    def __init__(self, is_fips_present = False):
        super(Rdp_TS_FP_UPDATE_PDU, self).__init__(fields = [
            DataUnitField('header', Rdp_TS_FP_HEADER()),
            PrimitiveField('length', TS_FP_LengthSerializer()),
            ConditionallyPresentField(
                lambda:  is_fips_present,
                PrimitiveField('fipsInformation', RawLengthSerializer(LengthDependency(lambda x: 4)))),
            ConditionallyPresentField(
                lambda:  Rdp.FastPath.FASTPATH_FLAG_SECURE_CHECKSUM in self.header.flags,
                PrimitiveField('dataSignature', RawLengthSerializer(LengthDependency(lambda x: 8)))),
            DataUnitField('fpOutputUpdates',
                ArrayDataUnit(Rdp_TS_FP_UPDATE,
                    length_dependency = LengthDependency(
                        lambda x: (self.length
                                    - self._fields_by_name['header'].get_length()
                                    - self._fields_by_name['length'].get_length()
                                    - self._fields_by_name['fipsInformation'].get_length()
                                    - self._fields_by_name['dataSignature'].get_length())))),
        ])
        
        
class Rdp_TS_FP_UPDATE(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_FP_UPDATE, self).__init__(fields = [
            UnionField([
                PrimitiveField('updateCode', BitMaskSerializer(Rdp.FastPath.FASTPATH_UPDATE_CODE_MASK, StructEncodedSerializer(UINT_8)), to_human_readable = lookup_name_in(Rdp.FastPath.FASTPATH_UPDATETYPE_NAMES)),
                PrimitiveField('fragmentation', BitMaskSerializer(Rdp.FastPath.FASTPATH_FRAGMENTATION_MASK, StructEncodedSerializer(UINT_8)), to_human_readable = lookup_name_in(Rdp.FastPath.FASTPATH_FRAGMENT_NAMES)),
                PrimitiveField('compression', BitMaskSerializer(Rdp.FastPath.FASTPATH_COMPRESSION_MASK, StructEncodedSerializer(UINT_8)), to_human_readable = lookup_name_in(Rdp.FastPath.FASTPATH_OUTPUT_COMPRESSION_NAMES)),
            ]),
            ConditionallyPresentField(
                lambda:  self.compression == Rdp.FastPath.FASTPATH_OUTPUT_COMPRESSION_USED,
                PrimitiveField('compressionFlags', StructEncodedSerializer(UINT_8))),
            PrimitiveField('size', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('updateData', RawLengthSerializer(LengthDependency(lambda x: self.size))),
        ],
        auto_reinterpret_configs = [
            AutoReinterpret('updateData',
                type_getter = ValueDependency(lambda x: self.updateCode), 
                config_by_type = {
                    Rdp.FastPath.FASTPATH_UPDATETYPE_SURFCMDS: AutoReinterpretConfig('', functools.partial(ArrayDataUnit, Rdp_TS_SURFCMD, length_dependency = LengthDependency(lambda x: self.size))),
                    Rdp.FastPath.FASTPATH_UPDATETYPE_ORDERS: AutoReinterpretConfig('', Rdp_FASTPATH_UPDATETYPE_ORDERS),
                }),
        ])
        
    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(str(self._fields_by_name['updateCode'].get_human_readable_value()))
        retval.extend(super(Rdp_TS_FP_UPDATE, self).get_pdu_types(rdp_context))
        return retval

class Rdp_TS_SURFCMD(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_SURFCMD, self).__init__(fields = [
            PrimitiveField('cmdType', StructEncodedSerializer(UINT_16_LE), to_human_readable = lookup_name_in(Rdp.Surface.CMDTYPE_NAMES)),
            PolymophicField('cmdData',
                type_getter = ValueDependency(lambda x: self.cmdType), 
                field_by_type = {
                    Rdp.Surface.CMDTYPE_SET_SURFACE_BITS: DataUnitField('cmdData_setSurfaceBits', Rdp_TS_SURFCMD_SET_SURF_BITS()),
                    Rdp.Surface.CMDTYPE_FRAME_MARKER: DataUnitField('cmdData_frameMarker', Rdp_TS_FRAME_MARKER()),
                    Rdp.Surface.CMDTYPE_STREAM_SURFACE_BITS: DataUnitField('cmdData_streamSurfaceBits', Rdp_TS_SURFCMD_STREAM_SURF_BITS()),
                }),
        ])
    
    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(str(self._fields_by_name['cmdType'].get_human_readable_value()))
        retval.extend(super(Rdp_TS_SURFCMD, self).get_pdu_types(rdp_context))
        return retval

class Rdp_TS_FRAME_MARKER(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_FP_UPDATE, self).__init__(fields = [
            PrimitiveField('frameAction', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.Frame.SURFACECMD_FRAMEACTION_NAMES)),
            PrimitiveField('frameId', StructEncodedSerializer(UINT_8)),
        ])

class Rdp_TS_SURFCMD_SET_SURF_BITS(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_SURFCMD_SET_SURF_BITS, self).__init__(fields = [
            PrimitiveField('destLeft', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('destTop', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('destRight', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('destBottom', StructEncodedSerializer(UINT_16_LE)),
            DataUnitField('bitmapData', Rdp_TS_BITMAP_DATA_EX()),
        ])

class Rdp_TS_SURFCMD_STREAM_SURF_BITS(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_SURFCMD_STREAM_SURF_BITS, self).__init__(fields = [
            PrimitiveField('destLeft', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('destTop', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('destRight', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('destBottom', StructEncodedSerializer(UINT_16_LE)),
            DataUnitField('bitmapData', Rdp_TS_BITMAP_DATA_EX()),
        ])
        
class Rdp_TS_BITMAP_DATA_EX(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_BITMAP_DATA_EX, self).__init__(fields = [
            PrimitiveField('bpp', StructEncodedSerializer(UINT_8)),
            PrimitiveField('flags', BitFieldEncodedSerializer(UINT_8, Rdp.Bitmap.BITMAP_FLAG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.Bitmap.BITMAP_FLAG_NAMES)),
            PrimitiveField('reserved', StructEncodedSerializer(PAD)),
            PrimitiveField('codecID', StructEncodedSerializer(UINT_8)),
            PrimitiveField('width', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('height', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('bitmapDataLength', StructEncodedSerializer(UINT_32_LE)),
            ConditionallyPresentField(
                lambda:  Rdp.Bitmap.EX_COMPRESSED_BITMAP_HEADER_PRESENT in self.flags,
                DataUnitField('exBitmapDataHeader', Rdp_TS_COMPRESSED_BITMAP_HEADER_EX())),
            PrimitiveField('bitmapData', RawLengthSerializer(LengthDependency(lambda x: self.bitmapDataLength))),
        ])

class Rdp_TS_COMPRESSED_BITMAP_HEADER_EX(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_COMPRESSED_BITMAP_HEADER_EX, self).__init__(fields = [
            PrimitiveField('highUniqueId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('lowUniqueId', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('tmMilliseconds', StructEncodedSerializer(UINT_64_LE)),
            PrimitiveField('tmSeconds', StructEncodedSerializer(UINT_64_LE)),
        ])

class Rdp_FASTPATH_UPDATETYPE_ORDERS(BaseDataUnit):
    def __init__(self):
        super(Rdp_FASTPATH_UPDATETYPE_ORDERS, self).__init__(fields = [
            PrimitiveField('numberOrders', StructEncodedSerializer(UINT_16_LE)),
            DataUnitField('orderData',
                ArrayDataUnit(Rdp_DRAWING_ORDER,
                    item_count_dependency = ValueDependency(lambda x: self.numberOrders))),
        ])

class Rdp_DRAWING_ORDER(BaseDataUnit):
    def __init__(self):
        super(Rdp_DRAWING_ORDER, self).__init__(fields = [
            DataUnitField('header', Rdp_DRAWING_ORDER_header()),
            PolymophicField('orderSpecificData',
                type_getter = ValueDependency(lambda x: self.header.class),
                field_by_type = {
                    Rdp.DrawingOrders.ORDERS_PRIMARY: DataUnitField('orderSpecificData_primary', Rdp_PRIMARY_DRAWING_ORDER(self)),
                    Rdp.DrawingOrders.ORDERS_SECONDARY: ,
                    Rdp.DrawingOrders.ORDERS_SECONDARY_ALTERNATE: ,
                }),
        # ],
        # auto_reinterpret_configs = [
        #     AutoReinterpret('orderSpecificData',
        #         type_getter = ValueDependency(lambda x: (self.controlFlags & Rdp.DrawingOrders.ORDERS_MASK)), 
        #         config_by_type = {
        #             # Rdp.DrawingOrders.ORDERS_PRIMARY: AutoReinterpretConfig('', functools.partial(Rdp_PRIMARY_DRAWING_ORDER, self)),
        #         }),
        ])

# This class is a hack to get the header to reinterpret it'self before any of the other fields in the Rdp_DRAWING_ORDER
class Rdp_DRAWING_ORDER_header(BaseDataUnit):
    def __init__(self):
        super(Rdp_DRAWING_ORDER_header, self).__init__(fields = [
            # DataUnitField('payload', Rdp_DRAWING_ORDER_header_unknown()),
            UnionField([
                PrimitiveField('class', # in the spec: this is named "class"
                    BitMaskSerializer(Rdp.DrawingOrders.ORDER_TYPE_MASK, 
                        BitFieldEncodedSerializer(UINT_8, Rdp.DrawingOrders.OrderFlags.ORDER_FLAG_NAMES.keys()), 
                    to_human_readable = lookup_name_in(Rdp.DrawingOrders.OrderFlags.ORDER_FLAG_NAMES))),
                PolymophicField('controlFlags',
                    type_getter = ValueDependency(lambda x: self.class), 
                    field_by_type = {
                        Rdp.DrawingOrders.ORDERS_PRIMARY: 
                            PrimitiveField('controlFlags_primary', 
                                BitMaskSerializer(Rdp.DrawingOrders.OrderFlags.PRIMARY_ORDER_FLAG_MASK, 
                                    BitFieldEncodedSerializer(UINT_8, Rdp.DrawingOrders.OrderFlags.PRIMARY_ORDER_FLAG_NAMES.keys())), 
                                to_human_readable = lookup_name_in(Rdp.DrawingOrders.OrderFlags.PRIMARY_ORDER_FLAG_NAMES)),
                        Rdp.DrawingOrders.ORDERS_SECONDARY: 
                            PrimitiveField('controlFlags_secondary', 
                                BitMaskSerializer(Rdp.DrawingOrders.OrderFlags.SECONDARY_ORDER_FLAG_MASK, StructEncodedSerializer(UINT_8))),
                        Rdp.DrawingOrders.ORDERS_SECONDARY_ALTERNATE: 
                            PrimitiveField('controlFlags_secondaryAlt_orderType', 
                                ValueTransformSerializer(
                                    BitMaskSerializer(Rdp.DrawingOrders.SecondaryAlternateOrderTypes.ORDER_TYPE_MASK, StructEncodedSerializer(UINT_8)),
                                    ValueTransformer(
                                        to_serialized = lambda x: x << 2,
                                        from_serialized = lambda x: x >> 2)),
                                to_human_readable = lookup_name_in(Rdp.DrawingOrders.SecondaryAlternateOrderTypes.TS_ALTSEC_NAMES)),
                }),
            ])
        ])

# class Rdp_DRAWING_ORDER_header_unknown(BaseDataUnit):
#     def __init__(self):
#         super(Rdp_DRAWING_ORDER, self).__init__(fields = [
#             PrimitiveField('controlFlags', BitMaskSerializer(Rdp.DrawingOrders.ORDER_TYPE_MASK, StructEncodedSerializer(UINT_8)), to_human_readable = lookup_name_in(Rdp.DrawingOrders.ORDERS_NAMES)),
#         ])

# class Rdp_DRAWING_ORDER_header_primary(BaseDataUnit):
#     def __init__(self):
#         super(Rdp_DRAWING_ORDER, self).__init__(fields = [
#             PrimitiveField('controlFlags', BitFieldEncodedSerializer(UINT_8, Rdp.DrawingOrders.OrderFlags.PRIMARY_ORDER_FLAG_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.DrawingOrders.OrderFlags.PRIMARY_ORDER_FLAG_NAMES)),
#         ])

# class Rdp_DRAWING_ORDER_header_secondary(BaseDataUnit):
#     def __init__(self):
#         super(Rdp_DRAWING_ORDER, self).__init__(fields = [
#             PrimitiveField('controlFlags', BitFieldEncodedSerializer(UINT_8, Rdp.DrawingOrders.ORDERS_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.DrawingOrders.OrderFlags.ORDER_FLAG_NAMES)),
#         ])

# class Rdp_DRAWING_ORDER_header_secondary_alternate(BaseDataUnit):
#     def __init__(self):
#         super(Rdp_DRAWING_ORDER, self).__init__(fields = [
#             UnionField([
#                 PrimitiveField('controlFlags', # in the spec: this is named "class"
#                     BitMaskSerializer(Rdp.DrawingOrders.ORDER_TYPE_MASK, 
#                         BitFieldEncodedSerializer(UINT_8, Rdp.DrawingOrders.OrderFlags.ORDER_FLAG_NAMES.keys()), 
#                     to_human_readable = lookup_name_in(Rdp.DrawingOrders.OrderFlags.ORDER_FLAG_NAMES)),
#                 PrimitiveField('orderType', 
#                     ValueTransformSerializer(
#                         BitMaskSerializer(Rdp.DrawingOrders.SecondaryAlternateOrderTypes.ORDER_TYPE_MASK, StructEncodedSerializer(UINT_8)),
#                         ValueTransformer(
#                             to_serialized = lambda x: x << 2,
#                             from_serialized = lambda x: x >> 2)),
#                     to_human_readable = lookup_name_in(Rdp.DrawingOrders.SecondaryAlternateOrderTypes.TS_ALTSEC_NAMES)),
#             ]),
#         ])

# class Rdp_DRAWING_ORDER(BaseDataUnit):
#     def __init__(self):
#         super(Rdp_DRAWING_ORDER, self).__init__(fields = [
#             PrimitiveField('controlFlags', StructEncodedSerializer(UINT_8)),
#             PrimitiveField('orderSpecificData', RawLengthSerializer()), TODO this raw length is of undetermined length, and is only known by parsing the order
#             PolymophicField('cmdData',
#                 type_getter = ValueDependency(lambda x: self.cmdType), 
#                 field_by_type = {
#                     Rdp.Surface.CMDTYPE_SET_SURFACE_BITS: DataUnitField('cmdData_setSurfaceBits', Rdp_TS_SURFCMD_SET_SURF_BITS()),
#                     Rdp.Surface.CMDTYPE_FRAME_MARKER: DataUnitField('cmdData_frameMarker', Rdp_TS_FRAME_MARKER()),
#                     Rdp.Surface.CMDTYPE_STREAM_SURFACE_BITS: DataUnitField('cmdData_streamSurfaceBits', Rdp_TS_SURFCMD_STREAM_SURF_BITS()),
#                 }),
#         ],
#         auto_reinterpret_configs = [
#             AutoReinterpret('orderSpecificData',
#                 type_getter = ValueDependency(lambda x: (self.controlFlags & Rdp.DrawingOrders.ORDERS_MASK)), 
#                 config_by_type = {
#                     # Rdp.DrawingOrders.ORDERS_PRIMARY: AutoReinterpretConfig('', functools.partial(Rdp_PRIMARY_DRAWING_ORDER, self)),
#                 }),
#         ])

class PRIMARY_DRAWING_ORDER_fieldFlagsSerializer(BaseSerializer[set[int]]):
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272
    
    @staticmethod
    def field_count_to_flags_length(numberOfOrderFields):
        import math
        return math.ceil((numberOfOrderFields + 1) / 8)

    FIELD_COUNT_BY_ORDER = {
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_DSTBLT_ORDER: 5,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_PATBLT_ORDER: 12,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_SCRBLT_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_DRAWNINEGRID_ORDER: 5,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTI_DRAWNINEGRID_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_LINETO_ORDER: 10,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_OPAQUERECT_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_SAVEBITMAP_ORDER: 6,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MEMBLT_ORDER: 9,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MEM3BLT_ORDER: 16,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTIDSTBLT_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTIPATBLT_ORDER: 14,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTISCRBLT_ORDER: 9,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_MULTIOPAQUERECT_ORDER: 9,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_FAST_INDEX_ORDER: 15,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_POLYGON_SC_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_POLYGON_CB_ORDER: 13,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_POLYLINE_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_FAST_GLYPH_ORDER: 15,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_ELLIPSE_SC_ORDER: 7,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_ELLIPSE_CB_ORDER: 13,
        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_INDEX_ORDER: 22,
    }
    FIELD_FLAG_LENGTH_BY_ORDER = {k: PRIMARY_DRAWING_ORDER_fieldFlagsSerializer.field_count_to_flags_length(v) for k,v in PRIMARY_DRAWING_ORDER_fieldFlagsSerializer.FIELD_COUNT_BY_ORDER}
    STRUCT_1BYTE = struct.Struct(UINT_8)

    def __init__(self, zero_field_byte_dependency, orderType_dependency):
        self._zero_field_byte = zero_field_byte_dependency
        self._orderType = orderType_dependency
    
    def get_serialized_length(self, value: set[int]) -> int:
        return self.FIELD_FLAG_LENGTH_BY_ORDER[self._orderType.get_value()] - self._zero_field_byte.get_value()
        
    def unpack_from(self, raw_data: bytes, offset: int) -> Tuple[set[int], int]:
        length = self.get_serialized_length(None)
        value = set()
        max_field_count = self.FIELD_COUNT_BY_ORDER[self._orderType.get_value()]
        field_count = 1
        for i in range(length):
            b = self.STRUCT_1BYTE.unpack_from(raw_data, offset+i)
            for _ in range(8):
                if b & 0x01 == 1:
                    value.add(field_count)
                field_count += 1
                b >>= 1
                if field_count >= max_field_count:
                    return value, length
        return value, length
    
    def pack_into(self, buffer: bytes, offset: int, value: set[int]) -> None:
        raise NotImplementedError('TODO')
   
class Rdp_PRIMARY_DRAWING_ORDER(BaseDataUnit): TODO finish this class
    def __init__(self, drawing_order, previous_primary_drawing_order_type):
        super(Rdp_PRIMARY_DRAWING_ORDER, self).__init__(fields = [
            ConditionallyPresentField( # Note: when the orderType is not present then the orderType value is equal to the previous order type sent
                lambda: Rdp.DrawingOrders.OrderFlags.TS_TYPE_CHANGE in drawing_order.header.controlFlags,
                PrimitiveField('orderType', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_NAMES))),
            PrimitiveField('fieldFlags', 
                PRIMARY_DRAWING_ORDER_fieldFlagsSerializer(
                    zero_field_byte_dependency = ValueDependency(lambda x: get_zero_field_bytes(drawing_order)),
                    orderType_dependency = ValueDependency(lambda x: self.orderType if self.orderType is not None else previous_primary_drawing_order_type))),
            ConditionallyPresentField(
                lambda: (Rdp.DrawingOrders.OrderFlags.TS_BOUNDS in drawing_order.header.controlFlags 
                        and not Rdp.DrawingOrders.OrderFlags.TS_ZERO_BOUNDS_DELTAS in drawing_order.header.controlFlags),
                DataUnitField('bounds', Rdp_TS_BOUNDS()),
            PrimitiveField('primaryOrderData', RawLengthSerializer()), TODO this raw length is determined by the orderType and fieldFlags value
            PolymophicField('primaryOrderData',
                    type_getter = ValueDependency(lambda x: self.orderType), 
                    field_by_type = {
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_DSTBLT_ORDER: 
                            DataUnitField('primaryOrderData_DSTBLT_ORDER', Rdp_DSTBLT_ORDER(drawing_order)),
                        Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_PATBLT_ORDER: 
                            DataUnitField('primaryOrderData_PATBLT_ORDER', Rdp_PATBLT_ORDER(drawing_order)),
                        TODO: add the other types
                        
                }),
        ])
        
    @staticmethod
    def get_zero_field_bytes(drawing_order):
        retval = 0
        if Rdp.DrawingOrders.OrderFlags.TS_PRIMARY_ZERO_FIELD_BYTE_BIT0 in drawing_order.header.controlFlags:
            retval |= 0x01
        if Rdp.DrawingOrders.OrderFlags.TS_PRIMARY_ZERO_FIELD_BYTE_BIT1 in drawing_order.header.controlFlags:
            retval |= 0x02
        return retval

class Rdp_TS_BOUNDS(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_BOUNDS, self).__init__(fields = [
            PrimitiveField('boundsDescription', BitFieldEncodedSerializer(UINT_8, Rdp.DrawingOrders.Bounds.TS_BOUND_NAMES.keys()), to_human_readable = lookup_name_in(Rdp.DrawingOrders.Bounds.TS_BOUND_NAMES)),
            ConditionallyPresentField(
                lambda: (Rdp.DrawingOrders.Bounds.TS_BOUND_LEFT in self.boundsDescription
                        and not Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_LEFT in self.boundsDescription),
                PrimitiveField('left', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_LEFT in self.boundsDescription,
                PrimitiveField('left_delta', StructEncodedSerializer(SINT_8))),
            
            ConditionallyPresentField(
                lambda: (Rdp.DrawingOrders.Bounds.TS_BOUND_TOP in self.boundsDescription
                        and not Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_TOP in self.boundsDescription),
                PrimitiveField('top', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_TOP in self.boundsDescription,
                PrimitiveField('top_delta', StructEncodedSerializer(SINT_8))),
            
            ConditionallyPresentField(
                lambda: (Rdp.DrawingOrders.Bounds.TS_BOUND_RIGHT in self.boundsDescription
                        and not Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_RIGHT in self.boundsDescription),
                PrimitiveField('right', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_RIGHT in self.boundsDescription,
                PrimitiveField('right_delta', StructEncodedSerializer(SINT_8))),
            
            ConditionallyPresentField(
                lambda: (Rdp.DrawingOrders.Bounds.TS_BOUND_BOTTOM in self.boundsDescription
                        and not Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_LEFT in self.boundsDescription),
                PrimitiveField('bottom', StructEncodedSerializer(UINT_16_LE))),
            ConditionallyPresentField(
                lambda: Rdp.DrawingOrders.Bounds.TS_BOUND_DELTA_BOTTOM in self.boundsDescription,
                PrimitiveField('bottom_delta', StructEncodedSerializer(SINT_8))),
        ])


class Rdp_COORD_FIELD(BaseDataUnit):
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/870b982c-9abe-40cb-99d0-2c3f0cc5fb74
    def __init__(self, drawing_order):
        super(Rdp_TS_BOUNDS, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: Rdp.DrawingOrders.OrderFlags.TS_PRIMARY_DELTA_COORDINATES in drawing_order.header.controlFlags,
                PrimitiveField('signedValue_delta', StructEncodedSerializer(SINT_8))),
            ConditionallyPresentField(
                lambda: Rdp.DrawingOrders.OrderFlags.TS_PRIMARY_DELTA_COORDINATES not in drawing_order.header.controlFlags,
                PrimitiveField('signedValue_absolute', StructEncodedSerializer(SINT_16_LE))),
        ])

class Rdp_DSTBLT_ORDER(BaseDataUnit):
    def __init__(self, drawing_order):
        super(Rdp_DSTBLT_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nWidth', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nHeight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop', StructEncodedSerializer(UINT_8))),
        ])

class Rdp_TS_COLOR(BaseDataUnit):
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/f99c616b-876d-4371-99fe-cc656d0a610b
    def __init__(self, caps_preferredBitsPerPixel):
        super(Rdp_TS_COLOR, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: caps_preferredBitsPerPixel <= 8,
                PrimitiveField('PaletteIndex', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: caps_preferredBitsPerPixel > 8,
                PrimitiveField('Red', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: caps_preferredBitsPerPixel > 8,
                PrimitiveField('Green', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: caps_preferredBitsPerPixel > 8,
                PrimitiveField('Blue', StructEncodedSerializer(UINT_8))),
        ])

class Rdp_PATBLT_ORDER(BaseDataUnit):
    def __init__(self, drawing_order):
        super(Rdp_PATBLT_ORDER, self).__init__(fields = [
            ConditionallyPresentField(
                lambda: 1 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nLeftRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 2 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nTopRect', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 3 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nWidth', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 4 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('nHeight', Rdp_COORD_FIELD(drawing_order))),
            ConditionallyPresentField(
                lambda: 5 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('bRop', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 6 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('BackColor', Rdp_TS_COLOR(TODO))),
            ConditionallyPresentField(
                lambda: 7 in drawing_order.orderSpecificData.fieldFlags,
                DataUnitField('ForeColor', Rdp_TS_COLOR(TODO))),
            ConditionallyPresentField(
                lambda: 8 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgX', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 9 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushOrgY', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 10 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushStyle', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.BrushStyle.TODO)),
            ConditionallyPresentField(
                lambda: 11 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushHatch', StructEncodedSerializer(UINT_8))),
            ConditionallyPresentField(
                lambda: 12 in drawing_order.orderSpecificData.fieldFlags,
                PrimitiveField('BrushExtra', RawLengthSerializer(LengthDependency(lambda x: 7)))),  
        ])

from typing import Tuple
import functools

from data_model_v2 import (
    BaseDataUnit,
    ArrayDataUnit,
    RawDataUnit,
    
    PrimitiveField,
    DataUnitField,
    UnionField,
    OptionalField,
    ConditionallyPresentField,
    PolymophicField,
    
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

from data_model_v2_rdp_egdi_primary_order import (
    Rdp_PRIMARY_DRAWING_ORDER,
)
from data_model_v2_rdp_egdi import (
    Rdp_SECONDARY_DRAWING_ORDER,
    Rdp_ALT_SECONDARY_DRAWING_ORDER,
)



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
    def __init__(self, rdp_context, is_fips_present = False):
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
                ArrayDataUnit(functools.partial(Rdp_TS_FP_UPDATE, rdp_context),
                    length_dependency = LengthDependency(
                        lambda x: (self.length
                                    - self._fields_by_name['header'].get_length()
                                    - self._fields_by_name['length'].get_length()
                                    - self._fields_by_name['fipsInformation'].get_length()
                                    - self._fields_by_name['dataSignature'].get_length())))),
        ])
        
        
class Rdp_TS_FP_UPDATE(BaseDataUnit):
    def __init__(self, rdp_context):
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
                    Rdp.FastPath.FASTPATH_UPDATETYPE_ORDERS: AutoReinterpretConfig('', functools.partial(Rdp_FASTPATH_UPDATETYPE_ORDERS, rdp_context)),
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
    def __init__(self, rdp_context):
        super(Rdp_FASTPATH_UPDATETYPE_ORDERS, self).__init__(fields = [
            PrimitiveField('numberOrders', StructEncodedSerializer(UINT_16_LE)),
            DataUnitField('orderData',
                ArrayDataUnit(functools.partial(Rdp_DRAWING_ORDER, rdp_context),
                    item_count_dependency = ValueDependency(lambda x: self.numberOrders))),
        ])

class Rdp_DRAWING_ORDER(BaseDataUnit):
    def __init__(self, rdp_context):
        super(Rdp_DRAWING_ORDER, self).__init__(fields = [
            DataUnitField('header', Rdp_DRAWING_ORDER_header()),
            PolymophicField('orderSpecificData',
                type_getter = ValueDependency(lambda x: self.header.controlFlags_class),
                fields_by_type = {
                    Rdp.DrawingOrders.ORDERS_PRIMARY: DataUnitField('orderSpecificData_primary', Rdp_PRIMARY_DRAWING_ORDER(rdp_context, self)),
                    Rdp.DrawingOrders.ORDERS_SECONDARY: DataUnitField('orderSpecificData_secondary', Rdp_SECONDARY_DRAWING_ORDER()),
                    Rdp.DrawingOrders.ORDERS_SECONDARY_ALTERNATE: DataUnitField('orderSpecificData_altSecondary', Rdp_ALT_SECONDARY_DRAWING_ORDER(self)),
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
                PrimitiveField('controlFlags_class', # in the spec: this is named "class"
                    BitMaskSerializer(Rdp.DrawingOrders.ORDER_TYPE_MASK, StructEncodedSerializer(UINT_8)),
                    to_human_readable = lookup_name_in(Rdp.DrawingOrders.OrderFlags.ORDER_FLAG_NAMES)),
                PolymophicField('controlFlags',
                    type_getter = ValueDependency(lambda x: self.controlFlags_class), 
                    fields_by_type = {
                        Rdp.DrawingOrders.ORDERS_PRIMARY: 
                            PrimitiveField('controlFlags_primary',
                                BitFieldEncodedSerializer(UINT_8, Rdp.DrawingOrders.OrderFlags.PRIMARY_ORDER_FLAG_NAMES.keys()),
                                to_human_readable = lookup_name_in(Rdp.DrawingOrders.OrderFlags.PRIMARY_ORDER_FLAG_NAMES)),
                        Rdp.DrawingOrders.ORDERS_SECONDARY: 
                            PrimitiveField('controlFlags_secondary', 
                                BitMaskSerializer(Rdp.DrawingOrders.OrderFlags.SECONDARY_ORDER_FLAG_MASK, StructEncodedSerializer(UINT_8))),
                        Rdp.DrawingOrders.ORDERS_SECONDARY_ALTERNATE: 
                            PrimitiveField('controlFlags_secondaryAlt_orderType', 
                                ValueTransformSerializer(
                                    BitMaskSerializer(Rdp.DrawingOrders.OrderFlags.ALT_SECAONDARY_ORDER_TYPE_MASK, StructEncodedSerializer(UINT_8)),
                                    ValueTransformer(
                                        to_serialized = lambda x: x << 2,
                                        from_serialized = lambda x: x >> 2)),
                                to_human_readable = lookup_name_in(Rdp.DrawingOrders.AltSecondaryOrderTypes.ALT_SECONDARY_ORDER_NAMES)),
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

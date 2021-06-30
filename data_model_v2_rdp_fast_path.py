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
                    # Rdp.FastPath.FASTPATH_UPDATETYPE_SURFCMDS: AutoReinterpretConfig('', functools.partial(ArrayDataUnit, Rdp_TS_SURFCMD, length_dependency = LengthDependency(lambda x: self.size))),
                    # Rdp.FastPath.FASTPATH_UPDATETYPE_ORDERS: AutoReinterpretConfig('', Rdp_FASTPATH_UPDATETYPE_ORDERS),
                }),
        ])
        
    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(str(self._fields_by_name['updateCode'].get_human_readable_value()))
        retval.extend(super(Rdp_TS_FP_UPDATE, self).get_pdu_types(rdp_context))
        return retval

# class Rdp_TS_SURFCMD(BaseDataUnit):
#     def __init__(self):
#         super(Rdp_TS_FP_UPDATE, self).__init__(fields = [
#             PrimitiveField('cmdType', StructEncodedSerializer(UINT_16_LE), to_human_readable = lookup_name_in(Rdp.Surface.CMDTYPE_NAMES)),
#             PrimitiveField('cmdData ', RawLengthSerializer()), TODO: the raw length is determined by the cmdType
#         ],
#         auto_reinterpret_configs = [
#             AutoReinterpret('cmdData',
#                 type_getter = ValueDependency(lambda x: self.cmdType), 
#                 config_by_type = {
#                     # Rdp.Surface.CMDTYPE_SET_SURFACE_BITS: AutoReinterpretConfig('', Rdp_TS_SURFCMD_SET_SURF_BITS),
#                 }),
#         ])
    
#     def get_pdu_types(self, rdp_context):
#         retval = []
#         retval.append(str(self._fields_by_name['cmdType'].get_human_readable_value()))
#         retval.extend(super(Rdp_TS_SURFCMD, self).get_pdu_types(rdp_context))
#         return retval

# class Rdp_FASTPATH_UPDATETYPE_ORDERS(BaseDataUnit):
#     def __init__(self):
#         super(Rdp_FASTPATH_UPDATETYPE_ORDERS, self).__init__(fields = [
#             PrimitiveField('numberOrders', StructEncodedSerializer(UINT_16_LE)),
#             DataUnitField('orderData',
#                 ArrayDataUnit(Rdp_DRAWING_ORDER,
#                     item_count_dependency = ValueDependency(lambda x: self.numberOrders))),
#         ])

# class Rdp_DRAWING_ORDER(BaseDataUnit):
#     def __init__(self):
#         super(Rdp_DRAWING_ORDER, self).__init__(fields = [
#             PrimitiveField('controlFlags', StructEncodedSerializer(UINT_8)),
#             PrimitiveField('orderSpecificData', RawLengthSerializer()), TODO this raw length is of undetermined length, and is only known by parsing the order
#         ],
#         auto_reinterpret_configs = [
#             AutoReinterpret('orderSpecificData',
#                 type_getter = ValueDependency(lambda x: (self.controlFlags & Rdp.DrawingOrders.ORDERS_MASK)), 
#                 config_by_type = {
#                     # Rdp.DrawingOrders.ORDERS_PRIMARY: AutoReinterpretConfig('', functools.partial(Rdp_PRIMARY_DRAWING_ORDER, self)),
#                 }),
#         ])
        
# class Rdp_PRIMARY_DRAWING_ORDER(BaseDataUnit): TODO finish this class
#     def __init__(self, drawing_order):
#         super(Rdp_PRIMARY_DRAWING_ORDER, self).__init__(fields = [
#             ConditionallyPresentField( # Note: when the orderType is not present then the orderType value is equal to the previous order type sent
#                 lambda: Rdp.DrawingOrders.OrderFlags.TS_TYPE_CHANGE in drawing_order.controlFlags,
#                 PrimitiveField('orderType', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_NAMES))),
#             ConditionallyPresentField(
#                 lambda: raise NotImplementedError('The fieldFlags is complicated see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272'),
#                 PrimitiveField('fieldFlags', StructEncodedSerializer(UINT_8))),
#             ConditionallyPresentField(
#                 lambda: (Rdp.DrawingOrders.OrderFlags.TS_BOUNDS in drawing_order.controlFlags 
#                         and not Rdp.DrawingOrders.OrderFlags.TS_ZERO_BOUNDS_DELTAS in drawing_order.controlFlags),
#                 DataUnitField('bounds', Rdp_TS_BOUNDS()),
#             PrimitiveField('primaryOrderData', RawLengthSerializer()), TODO this raw length is determined by the orderType and fieldFlags value
#         ])

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
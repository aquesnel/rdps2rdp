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
    CompressedField,
    
    AutoReinterpret,
    AutoReinterpretConfig,
    
    add_constants_names_mapping,
    lookup_name_in,
    PduLayerSummary,
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
    ValueDependencyWithSideEffect,
    LengthDependency,
    
    SerializationContext,
)

from data_model_v2_rdp import Rdp

from data_model_v2_rdp_bcgr_output import (
    Rdp_TS_POINTERATTRIBUTE,
    Rdp_TS_CACHEDPOINTERATTRIBUTE,
)
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
                PrimitiveField('action', 
                    BitMaskSerializer(Rdp.FastPath.FASTPATH_ACTIONS_MASK, StructEncodedSerializer(UINT_8)), 
                    to_human_readable = lookup_name_in(Rdp.FastPath.FASTPATH_ACTION_NAMES)),
                PrimitiveField('numEvents', 
                    ValueTransformSerializer(
                        BitMaskSerializer(Rdp.FastPath.FASTPATH_NUM_EVENTS_MASK, StructEncodedSerializer(UINT_8)),
                        ValueTransformer(
                            to_serialized = lambda x: x << 2,
                            from_serialized = lambda x: x >> 2))),
                PrimitiveField('flags', 
                    BitFieldEncodedSerializer(UINT_8, Rdp.FastPath.FASTPATH_FLAG_NAMES.keys()), 
                    to_human_readable = lookup_name_in(Rdp.FastPath.FASTPATH_FLAG_NAMES)),
            ]),
        ])

    def _get_packet_type(self):
        packet_type = 'Unknown'
        if self.action == Rdp.FastPath.FASTPATH_ACTION_X224:
            packet_type = 'TPKT'
        elif self.action == Rdp.FastPath.FASTPATH_ACTION_FASTPATH:
            packet_type = 'FastPath'
        return packet_type
    
    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(self._get_packet_type())
        retval.extend(super(Rdp_TS_FP_HEADER, self).get_pdu_types(rdp_context))
        return retval

    def _get_pdu_summary_layers(self, rdp_context):
        return [PduLayerSummary(self._get_packet_type(), 'None')]
        
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
        
    def unpack_from(self, raw_data: bytes, offset: int, serde_context: SerializationContext) -> Tuple[int, int]:
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
    
    def pack_into(self, buffer: bytes, offset: int, value: int, serde_context: SerializationContext) -> None:
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
                lambda:  Rdp.FastPath.FASTPATH_FLAG_ENCRYPTED in self.header.flags,
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
                PrimitiveField('fragmentation',
                    ValueTransformSerializer(
                        BitMaskSerializer(Rdp.FastPath.FASTPATH_FRAGMENTATION_MASK, StructEncodedSerializer(UINT_8)),
                        ValueTransformer(
                            to_serialized = lambda x: x << 4,
                            from_serialized = lambda x: x >> 4)),
                    to_human_readable = lookup_name_in(Rdp.FastPath.FASTPATH_FRAGMENT_NAMES)),
                PrimitiveField('compression',
                    ValueTransformSerializer(
                        BitMaskSerializer(Rdp.FastPath.FASTPATH_COMPRESSION_MASK, StructEncodedSerializer(UINT_8)),
                        ValueTransformer(
                            to_serialized = lambda x: x << 6,
                            from_serialized = lambda x: x >> 6)),
                    to_human_readable = lookup_name_in(Rdp.FastPath.FASTPATH_OUTPUT_COMPRESSION_NAMES)),
            ]),
            ConditionallyPresentField(
                lambda:  self.compression == Rdp.FastPath.FASTPATH_OUTPUT_COMPRESSION_USED,
                # PrimitiveField('compressionFlags', StructEncodedSerializer(UINT_8))),
                UnionField(name = 'compressionFlags', fields = [
                    PrimitiveField('compressionArgs', 
                        DependentValueSerializer(
                            BitFieldEncodedSerializer(UINT_8, Rdp.ShareDataHeader.PACKET_ARG_NAMES.keys()), 
                            ValueDependencyWithSideEffect(lambda x, serde_context: Rdp.ShareDataHeader.from_compression_flags(self.as_field_objects().updateData.compress_field(serde_context).flags))),
                        to_human_readable = lookup_name_in(Rdp.ShareDataHeader.PACKET_ARG_NAMES)),
                    PrimitiveField('compressionType', 
                        DependentValueSerializer(
                            BitMaskSerializer(Rdp.ShareDataHeader.PACKET_COMPR_TYPE_MASK, StructEncodedSerializer(UINT_8)), 
                            ValueDependency(lambda x: Rdp.ShareDataHeader.from_compression_type(self.as_field_objects().updateData.get_compression_type()))),
                        to_human_readable = lookup_name_in(Rdp.ShareDataHeader.PACKET_COMPR_TYPE_NAMES)),
                ])),
            # TODO: is the size field the compressed or uncompressed size? or is it the fragmented re-assembled size
            # uncompressed size: ValueDependency(lambda x: self.as_field_objects().updateData.get_inner_field().get_length())
            # looks like size is the compressed size
            PrimitiveField('size', StructEncodedSerializer(UINT_16_LE)),
            CompressedField(
                decompression_type = ValueDependency(lambda x: Rdp.ShareDataHeader.to_compression_type(self.compressionType)),
                decompression_flags = ValueDependency(lambda x: Rdp.ShareDataHeader.to_compression_flags(self.compressionArgs)),
                compressed_length = LengthDependency(lambda x: self.size),
                field = PolymophicField('updateData',
                    type_getter = ValueDependency(lambda x: self.updateCode), 
                    fields_by_type = {
                        Rdp.FastPath.FASTPATH_UPDATETYPE_SURFCMDS: 
                            DataUnitField('updateData_surfaceCmd', 
                                ArrayDataUnit(Rdp_TS_SURFCMD, 
                                    length_dependency = LengthDependency(lambda x: self.as_field_objects().updateData.get_decompressed_length()))),
                        Rdp.FastPath.FASTPATH_UPDATETYPE_ORDERS: 
                            DataUnitField('updateData_orders', Rdp_TS_FP_UPDATE_ORDERS(rdp_context)),
                        Rdp.FastPath.FASTPATH_UPDATETYPE_POINTER:
                            DataUnitField('updateData_pointer', Rdp_TS_FP_POINTERATTRIBUTE(LengthDependency(lambda x: self.as_field_objects().updateData.get_decompressed_length()))),
                        Rdp.FastPath.FASTPATH_UPDATETYPE_CACHED:
                            DataUnitField('updateData_cached', Rdp_TS_FP_CACHEDPOINTERATTRIBUTE()),
                    }
                )
            ),
        ])
        
    def get_pdu_types(self, rdp_context):
        retval = []
        if Rdp.ShareDataHeader.PACKET_ARG_COMPRESSED in self.compressionArgs:
            retval.append('(compressed %s)' % (Rdp.ShareDataHeader.to_compression_type(self.compressionType).name,))
        retval.append(str(self._fields_by_name['updateCode'].get_human_readable_value()))
        retval.extend(super(Rdp_TS_FP_UPDATE, self).get_pdu_types(rdp_context))
        return retval

    def _get_pdu_summary_layers(self, rdp_context):
        retval = [
            PduLayerSummary('FastPath-Update', str(self._fields_by_name['updateCode'].get_human_readable_value())),
        ]
        if self.compression == Rdp.FastPath.FASTPATH_OUTPUT_COMPRESSION_USED:
            retval.append(PduLayerSummary('FastPath-Update', 'compressed', command_extra = str(self._fields_by_name['compressionType'].get_human_readable_value())))
        return retval
        
class Rdp_TS_SURFCMD(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_SURFCMD, self).__init__(fields = [
            PrimitiveField('cmdType', StructEncodedSerializer(UINT_16_LE), to_human_readable = lookup_name_in(Rdp.Surface.CMDTYPE_NAMES)),
            PolymophicField('cmdData',
                type_getter = ValueDependency(lambda x: self.cmdType), 
                fields_by_type = {
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

    def _get_pdu_summary_layers(self, rdp_context):
        return [PduLayerSummary('SURFCMD', str(self._fields_by_name['cmdType'].get_human_readable_value()))]
        
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

class Rdp_TS_FP_UPDATE_ORDERS(BaseDataUnit):
    def __init__(self, rdp_context):
        super(Rdp_TS_FP_UPDATE_ORDERS, self).__init__(fields = [
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
        ])

# This class is a hack to get the header to reinterpret it'self before any of the other fields in the Rdp_DRAWING_ORDER
class Rdp_DRAWING_ORDER_header(BaseDataUnit):
    def __init__(self):
        super(Rdp_DRAWING_ORDER_header, self).__init__(fields = [
            UnionField([
                PrimitiveField('controlFlags_class', # in the spec: this is named "class"
                    BitMaskSerializer(Rdp.DrawingOrders.ORDER_TYPE_MASK, StructEncodedSerializer(UINT_8)),
                    to_human_readable = lookup_name_in(Rdp.DrawingOrders.DRAWING_ORDER_TYPE_NAMES)),
                PolymophicField('controlFlags',
                    type_getter = ValueDependency(lambda x: self.controlFlags_class), 
                    length_dependency = LengthDependency(lambda x: 1), # = UINT_8.get_length()
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

    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(str(Rdp.DrawingOrders.DRAWING_ORDER_TYPE_NAMES.get(self.controlFlags_class, 'unknown (%s)' % self.controlFlags_class)))
        if self.controlFlags_class == Rdp.DrawingOrders.ORDERS_SECONDARY_ALTERNATE:
            retval.append(str(self._fields_by_name['controlFlags'].get_human_readable_value()))
        retval.extend(super(Rdp_DRAWING_ORDER_header, self).get_pdu_types(rdp_context))
        return retval

    def _get_pdu_summary_layers(self, rdp_context):
        if self.controlFlags_class == Rdp.DrawingOrders.ORDERS_SECONDARY_ALTERNATE:
            return [PduLayerSummary('ALTERNATE_SECONDARY_DRAWING_ORDER', str(self._fields_by_name['controlFlags'].get_human_readable_value()))]
        else:
            return []


class Rdp_TS_FP_POINTERATTRIBUTE(BaseDataUnit):
    def __init__(self, field_size: LengthDependency):
        super(Rdp_TS_FP_POINTERATTRIBUTE, self).__init__(fields = [
            DataUnitField('newPointerUpdateData', Rdp_TS_POINTERATTRIBUTE(field_size)),
        ])

class Rdp_TS_FP_CACHEDPOINTERATTRIBUTE(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_FP_CACHEDPOINTERATTRIBUTE, self).__init__(fields = [
            DataUnitField('cachedPointerUpdateData', Rdp_TS_CACHEDPOINTERATTRIBUTE()),
        ])

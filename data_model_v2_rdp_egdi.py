from typing import Tuple, Set
import functools
import struct

from data_model_v2 import (
    BaseDataUnit,
    ArrayDataUnit,
    
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
    SINT_8,
    UINT_8, 
    SINT_16_LE,
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
from data_model_v2_rdp_erp import (
    Rdp_ALTSEC_WINDOW_ORDER,
)


class Rdp_RDP61_COMPRESSED_DATA(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP61_COMPRESSED_DATA, self).__init__(fields = [
            DataUnitField('header', Rdp_RDP61_COMPRESSED_DATA_header()),
            PrimitiveField('payload', RawLengthSerializer()),
        ])

class Rdp_RDP61_COMPRESSED_DATA_header(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP61_COMPRESSED_DATA_header, self).__init__(fields = [
            PrimitiveField('Level1ComprFlags', 
                BitFieldEncodedSerializer(UINT_8, Rdp.Compression61.L1_COMPRESSION_NAMES.keys()), 
                to_human_readable = lookup_name_in(Rdp.Compression61.L1_COMPRESSION_NAMES)),
            PrimitiveField('Level2ComprFlags', 
                BitFieldEncodedSerializer(UINT_8, Rdp.Compression61.L2_COMPRESSION_NAMES.keys()), 
                to_human_readable = lookup_name_in(Rdp.Compression61.L2_COMPRESSION_NAMES)),
        ])

class Rdp_RDP61_COMPRESSED_DATA_L1_content(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP61_COMPRESSED_DATA_L1_content, self).__init__(fields = [
            PrimitiveField('MatchCount', 
                DependentValueSerializer(
                    StructEncodedSerializer(UINT_16_LE),
                    ValueDependency(lambda x: len(self.MatchDetails)))),
            DataUnitField('MatchDetails', 
                ArrayDataUnit(Rdp_RDP61_MATCH_DETAILS,
                    item_count_dependency = ValueDependency(lambda x: self.MatchCount))),
            PrimitiveField('Literals', RawLengthSerializer()), 
        ])

class Rdp_RDP61_MATCH_DETAILS(BaseDataUnit):
    def __init__(self):
        super(Rdp_RDP61_MATCH_DETAILS, self).__init__(fields = [
            PrimitiveField('MatchLength', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MatchOutputOffset', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('MatchHistoryOffset', StructEncodedSerializer(UINT_32_LE)),
        ])

class Rdp_SECONDARY_DRAWING_ORDER(BaseDataUnit):
    def __init__(self):
        super(Rdp_SECONDARY_DRAWING_ORDER, self).__init__(fields = [
            DataUnitField('header', Rdp_SECONDARY_DRAWING_ORDER_HEADER()),
            PrimitiveField('secondaryOrderData', RawLengthSerializer(LengthDependency(lambda x: self.header.orderLength))),

            # PolymophicField('primaryOrderData',
            #         type_getter = ValueDependency(lambda x: self.orderType), 
            #         fields_by_type = {
            #             Rdp.DrawingOrders.PrimaryOrderTypes.TS_ENC_DSTBLT_ORDER: 
            #                 DataUnitField('primaryOrderData_DSTBLT_ORDER', Rdp_DSTBLT_ORDER(drawing_order)),
            #     }),
        ])

class Rdp_SECONDARY_DRAWING_ORDER_HEADER(BaseDataUnit):
    def __init__(self):
        super(Rdp_SECONDARY_DRAWING_ORDER_HEADER, self).__init__(fields = [
            PrimitiveField('orderLength',
                ValueTransformSerializer(
                    StructEncodedSerializer(UINT_16_LE), 
                    ValueTransformer(
                        # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/c54e2667-335d-4a59-a6e2-7dc9744dbe79
                        to_serialized = lambda x: x - 13 + 6,
                        from_serialized = lambda x: x + 13 - 6))),
            PrimitiveField('extraFlags', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('orderType', StructEncodedSerializer(UINT_8), to_human_readable = lookup_name_in(Rdp.DrawingOrders.SecondaryOrderTypes.SECONDARY_ORDER_NAMES)),
        ])

    def get_pdu_types(self, rdp_context):
        retval = []
        retval.append(str(self._fields_by_name['orderType'].get_human_readable_value()))
        retval.extend(super(Rdp_SECONDARY_DRAWING_ORDER_HEADER, self).get_pdu_types(rdp_context))
        return retval

    def _get_pdu_summary_layers(self, rdp_context):
        return [PduLayerSummary('SECONDARY_DRAWING_ORDER', str(self._fields_by_name['orderType'].get_human_readable_value()))]


class Rdp_ALT_SECONDARY_DRAWING_ORDER(BaseDataUnit):
    def __init__(self, drawing_order):
        super(Rdp_ALT_SECONDARY_DRAWING_ORDER, self).__init__(fields = [
            PolymophicField('altSecondaryOrderData',
                    type_getter = ValueDependency(lambda x: drawing_order.header.controlFlags), 
                    fields_by_type = {
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_SWITCH_SURFACE: 
                            DataUnitField('altSecondaryOrderData_SWITCH_SURFACE', Rdp_SWITCH_SURFACE()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_CREATE_OFFSCR_BITMAP: 
                            DataUnitField('altSecondaryOrderData_CREATE_OFFSCR_BITMAP', Rdp_CREATE_OFFSCR_BITMAP_ORDER()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_STREAM_BITMAP_FIRST: 
                            DataUnitField('altSecondaryOrderData_STREAM_BITMAP_FIRST', Rdp_STREAM_BITMAP_FIRST_ORDER()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_STREAM_BITMAP_NEXT: 
                            DataUnitField('altSecondaryOrderData_STREAM_BITMAP_NEXT', Rdp_STREAM_BITMAP_NEXT_ORDER()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_CREATE_NINEGRID_BITMAP: 
                            DataUnitField('altSecondaryOrderData_CREATE_NINEGRID_BITMAP', Rdp_CREATE_NINEGRID_BITMAP_ORDER()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_GDIP_FIRST: 
                            DataUnitField('altSecondaryOrderData_GDIP_FIRST', Rdp_DRAW_GDIPLUS_CACHE_FIRST_ORDER()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_GDIP_NEXT: 
                            DataUnitField('altSecondaryOrderData_GDIP_NEXT', Rdp_DRAW_GDIPLUS_CACHE_NEXT_ORDER()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_GDIP_END: 
                            DataUnitField('altSecondaryOrderData_GDIP_END', Rdp_DRAW_GDIPLUS_CACHE_END_ORDER()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_GDIP_CACHE_FIRST: 
                            DataUnitField('altSecondaryOrderData_GDIP_CACHE_FIRST', Rdp_DRAW_GDIPLUS_CACHE_FIRST_ORDER()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_GDIP_CACHE_NEXT: 
                            DataUnitField('altSecondaryOrderData_GDIP_CACHE_NEXT', Rdp_DRAW_GDIPLUS_CACHE_NEXT_ORDER()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_GDIP_CACHE_END: 
                            DataUnitField('altSecondaryOrderData_GDIP_CACHE_END', Rdp_DRAW_GDIPLUS_CACHE_END_ORDER()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_WINDOW: 
                            DataUnitField('altSecondaryOrderData_WINDOW', Rdp_ALTSEC_WINDOW_ORDER()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_COMPDESK_FIRST: 
                            DataUnitField('altSecondaryOrderData_COMPDESK_FIRST', Rdp_TS_COMPDESK_TOGGLE()),
                        Rdp.DrawingOrders.AltSecondaryOrderTypes.TS_ALTSEC_FRAME_MARKER: 
                            DataUnitField('altSecondaryOrderData_FRAME_MARKER', Rdp_FRAME_MARKER()),
                }),
        ])

class Rdp_SWITCH_SURFACE(BaseDataUnit):
    def __init__(self):
        super(Rdp_SWITCH_SURFACE, self).__init__(fields = [
            PrimitiveField('bitmapId', StructEncodedSerializer(UINT_16_LE)),
        ])

class Rdp_CREATE_OFFSCR_BITMAP_ORDER(BaseDataUnit):
    def __init__(self):
        super(Rdp_CREATE_OFFSCR_BITMAP_ORDER, self).__init__(fields = [
            PrimitiveField('bitmapId', StructEncodedSerializer(UINT_16_LE)),
            UnionField([
                PrimitiveField('offscreenBitmapId',
                    BitMaskSerializer(Rdp.DrawingOrders.OrderFlags.ALT_SECAONDARY_FLAG_MASK_offscreenBitmapId, StructEncodedSerializer(UINT_8))),
                PrimitiveField('deleteList_present', 
                    ValueTransformSerializer(
                        BitMaskSerializer(Rdp.DrawingOrders.OrderFlags.ALT_SECAONDARY_FLAG_MASK_deleteList, StructEncodedSerializer(UINT_8)), 
                        ValueTransformer(
                            to_serialized = lambda x: Rdp.DrawingOrders.OrderFlags.ALT_SECAONDARY_FLAG_MASK_deleteList if x else 0,
                            from_serialized = lambda x: x > 0))),
            ]),
            PrimitiveField('cx', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('cy', StructEncodedSerializer(UINT_16_LE)),
            ConditionallyPresentField(
                lambda: self.deleteList_present,
                DataUnitField('deleteList', Rdp_OFFSCR_DELETE_LIST())),
        ])

class Rdp_OFFSCR_DELETE_LIST(BaseDataUnit):
    def __init__(self):
        super(Rdp_OFFSCR_DELETE_LIST, self).__init__(fields = [
            PrimitiveField('cIndices', StructEncodedSerializer(UINT_16_LE)),
            DataUnitField('indices',
                ArrayDataUnit(Rdp_BitmapCacheIndex,
                    item_count_dependency = ValueDependency(lambda x: self.cIndices))),
        ])

class Rdp_BitmapCacheIndex(BaseDataUnit):
    def __init__(self):
        super(Rdp_BitmapCacheIndex, self).__init__(fields = [
            PrimitiveField('index', StructEncodedSerializer(UINT_16_LE)),
        ])


class Rdp_STREAM_BITMAP_FIRST_ORDER(BaseDataUnit):
    def __init__(self):
        super(Rdp_STREAM_BITMAP_FIRST_ORDER, self).__init__(fields = [
            PrimitiveField('BitmapFlags', 
                BitFieldEncodedSerializer(UINT_8, Rdp.DrawingOrders.BitmapFlags.BITMAP_FLAG_NAMES.keys()), 
                to_human_readable = lookup_name_in(Rdp.DrawingOrders.BitmapFlags.BITMAP_FLAG_NAMES)),
            PrimitiveField('BitmapBpp', StructEncodedSerializer(UINT_8)),
            PrimitiveField('BitmapType', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('BitmapWidth', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('BitmapHeight', StructEncodedSerializer(UINT_16_LE)),
            PolymophicField('BitmapSize',
                    type_getter = ValueDependency(lambda x: Rdp.DrawingOrders.BitmapFlags.STREAM_BITMAP_REV2 in self.BitmapFlags), 
                    fields_by_type = {
                        False: PrimitiveField('BitmapSize_2byte', StructEncodedSerializer(UINT_16_LE)),
                        True: PrimitiveField('BitmapSize_4byte', StructEncodedSerializer(UINT_32_LE)),
            }),
            PrimitiveField('BitmapBlockSize', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('BitmapBlock', RawLengthSerializer(LengthDependency(lambda x: self.BitmapBlockSize))),
        ])

class Rdp_STREAM_BITMAP_NEXT_ORDER(BaseDataUnit):
    def __init__(self):
        super(Rdp_STREAM_BITMAP_NEXT_ORDER, self).__init__(fields = [
            PrimitiveField('BitmapFlags', 
                BitFieldEncodedSerializer(UINT_8, Rdp.DrawingOrders.BitmapFlags.BITMAP_FLAG_NAMES.keys()), 
                to_human_readable = lookup_name_in(Rdp.DrawingOrders.BitmapFlags.BITMAP_FLAG_NAMES)),
            PrimitiveField('BitmapType', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('BitmapBlockSize', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('BitmapBlock', RawLengthSerializer(LengthDependency(lambda x: self.BitmapBlockSize))),
        ])

class Rdp_CREATE_NINEGRID_BITMAP_ORDER(BaseDataUnit):
    def __init__(self):
        super(Rdp_CREATE_NINEGRID_BITMAP_ORDER, self).__init__(fields = [
            PrimitiveField('BitmapBpp', StructEncodedSerializer(UINT_8)),
            PrimitiveField('BitmapId', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('cx', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('cy', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('nineGridInfo', RawLengthSerializer(LengthDependency(lambda x: 16))), # should be NINEGRID_BITMAP_INFO
        ])        

class Rdp_DRAW_GDIPLUS_CACHE_FIRST_ORDER(BaseDataUnit):
    def __init__(self):
        super(Rdp_DRAW_GDIPLUS_CACHE_FIRST_ORDER, self).__init__(fields = [
            PrimitiveField('Flags', StructEncodedSerializer(UINT_8)),
            PrimitiveField('CacheType', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('CacheIndex', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('cbSize', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('cbTotalSize', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('emfRecords', RawLengthSerializer(LengthDependency(lambda x: self.cbSize))), # should be https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-emfplus/229f98d8-c19a-464e-80cc-2cb96aba1d71
        ])

class Rdp_DRAW_GDIPLUS_CACHE_NEXT_ORDER(BaseDataUnit):
    def __init__(self):
        super(Rdp_DRAW_GDIPLUS_CACHE_NEXT_ORDER, self).__init__(fields = [
            PrimitiveField('Flags', StructEncodedSerializer(UINT_8)),
            PrimitiveField('CacheType', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('CacheIndex', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('cbSize', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('emfRecords', RawLengthSerializer(LengthDependency(lambda x: self.cbSize))), # should be https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-emfplus/229f98d8-c19a-464e-80cc-2cb96aba1d71
        ])

class Rdp_DRAW_GDIPLUS_CACHE_END_ORDER(BaseDataUnit):
    def __init__(self):
        super(Rdp_DRAW_GDIPLUS_CACHE_END_ORDER, self).__init__(fields = [
            PrimitiveField('Flags', StructEncodedSerializer(UINT_8)),
            PrimitiveField('CacheType', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('CacheIndex', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('cbSize', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('cbTotalSize', StructEncodedSerializer(UINT_32_LE)),
            PrimitiveField('emfRecords', RawLengthSerializer(LengthDependency(lambda x: self.cbSize))), # should be https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-emfplus/229f98d8-c19a-464e-80cc-2cb96aba1d71
        ])

class Rdp_TS_COMPDESK_TOGGLE(BaseDataUnit):
    def __init__(self):
        super(Rdp_TS_COMPDESK_TOGGLE, self).__init__(fields = [
            PrimitiveField('operation', StructEncodedSerializer(UINT_8)),
            PrimitiveField('size', StructEncodedSerializer(UINT_16_LE)),
            PrimitiveField('eventType', StructEncodedSerializer(UINT_8)),
        ])

class Rdp_FRAME_MARKER(BaseDataUnit):
    def __init__(self):
        super(Rdp_FRAME_MARKER, self).__init__(fields = [
            PrimitiveField('action', StructEncodedSerializer(UINT_32_LE)),
        ])

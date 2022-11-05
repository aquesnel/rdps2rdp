import collections
import textwrap
import sys

import data_model_v2
import utils

DEBUG = False
# DEBUG = True

class StreamProcessor(object):
    def process_pdu(self, pdu, rdp_context, pdu_sequence_id):
        pass

    def finalize_processing(self):
        pass

CompressionInfo = collections.namedtuple('CompressionInfo', 
                                        ['pdu_sequence_id', 
                                            'pdu_path', 
                                            'compressed_bytes', 
                                            'decompressed_bytes', 
                                            'compression_type', 
                                            'compression_flags',
                                            'pdu_source',
                                        ])

class FreerdpCompressionTestDataWriter(StreamProcessor):
    def __init__(self, compression_type = None):
        self._compression_info = []
        self._compression_type = compression_type

    def process_pdu(self, pdu, rdp_context, pdu_sequence_id):
        for path, field in pdu.walk_fields():
            if DEBUG: print("Processing path %s = %s" % (path, str(field.__class__)))
            if isinstance(field, data_model_v2.CompressedField):
                if self._compression_type is None or self._compression_type == field.get_compression_type():
                    self._compression_info.append(
                        CompressionInfo(pdu_sequence_id, 
                            path,
                            field.get_compressed_bytes(), 
                            field.get_decompressed_bytes(),
                            field.get_compression_type(),
                            field.get_compression_flags(),
                            rdp_context.pdu_source,
                            ))

    def finalize_processing(self):
        FreeRdpTestDataPrinter().print_freerdp_compression_test_data(self._compression_info)

class FreeRdpTestDataPrinter(object):
    def print_freerdp_compression_test_data(self, compression_infos, output_stream=sys.stdout):
        freerdp_compressed_test_data = ""
        compression_info_by_type = collections.defaultdict(list)
        for compression_info in compression_infos:
            compression_info_by_type[compression_info.compression_type].append(compression_info)
        for compression_type, compression_infos in compression_info_by_type.items():
            freerdp_compressed_test_structs = ""
            for compression_info in compression_infos:
                freerdp_compressed_test_structs += textwrap.dedent("""
                    { // PDU %d from %s with path '%s' and compression %s with flags %s
                        0, %d,
                        (BYTE*) %s,
                        %d, %d,
                        (BYTE*) %s,
                    },
                    """) % (
                        compression_info.pdu_sequence_id,
                        compression_info.pdu_source,
                        compression_info.pdu_path,
                        compression_info.compression_type,
                        compression_info.compression_flags,

                        len(compression_info.compressed_bytes), 
                        (utils.as_hex_cstr(compression_info.compressed_bytes) if compression_info.compressed_bytes else "NULL"),

                        len(compression_info.decompressed_bytes) if compression_info.decompressed_bytes is not None else 0, 
                        len(compression_info.decompressed_bytes) if compression_info.decompressed_bytes is not None else 0,
                        (utils.as_hex_cstr(compression_info.decompressed_bytes) if compression_info.decompressed_bytes else "NULL"),
                    )
            freerdp_compressed_test_data += textwrap.dedent("""
                static const Test_Data COMPRESSION_TEST_DATA_%s[] =
                {
                    %s
                };
            """) % (compression_type.value, freerdp_compressed_test_structs)

        print(textwrap.dedent("""
            #ifndef RDP_INSPECTOR_COMPRESSION_TEST_DATA_H
            #define RDP_INSPECTOR_COMPRESSION_TEST_DATA_H

            #include <winpr/wtypes.h>

            typedef struct _test_data 
            {
                UINT32 compressedBytesExpectedSize;
                UINT32 compressedBytesSize;
                const BYTE* compressedBytes;
                UINT32 plaintextBytesExpectedSize;
                UINT32 plaintextBytesSize;
                const BYTE* plaintextBytes;
            } Test_Data;

            %s

            #endif /* RDP_INSPECTOR_COMPRESSION_TEST_DATA_H */
            """) % (freerdp_compressed_test_data,),
            file=output_stream)

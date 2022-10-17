import collections

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
        freerdp_compressed_test_data = ""
        for compression_info in self._compression_info:
            freerdp_compressed_test_data += """
                { // PDU %d from %s with path '%s' and compression %s with flags %s
                    0, %d,
                    (BYTE*) %s,
                    %d, %d,
                    (BYTE*) %s,
                },
                """ % (
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

        print("""
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

            static const Test_Data COMPRESSION_TEST_DATA[] =
                {
                    %s
                };

            #endif /* RDP_INSPECTOR_COMPRESSION_TEST_DATA_H */
            """ % freerdp_compressed_test_data)

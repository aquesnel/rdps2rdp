import data_model_v2
import utils

class StreamProcessor(object):
    def process_pdu(self, pdu, rdp_context, pdu_sequence_id):
        pass

    def finalize_processing(self):
        pass

class FreerdpCompressionTestDataWriter(StreamProcessor):
    def __init__(self, compression_type):
        self._compression_pairs = []
        self._compression_type = compression_type

    def process_pdu(self, pdu, rdp_context, pdu_sequence_id):
        for path, field in pdu.walk_fields():
            if isinstance(field, data_model_v2.CompressedField):
                if self._compression_type == field.get_compression_type():
                    self._compression_pairs.append(
                        (pdu_sequence_id, 
                        path,
                        field.get_compressed_bytes(), 
                        field.get_decompressed_bytes())
                        )

    def finalize_processing(self):
        freerdp_compressed_test_data = ""
        for pdu_sequence_id, pdu_path, compressed_bytes, decompressed_bytes in self._compression_pairs:
            freerdp_compressed_test_data += """
                { // PDU %d with path '%s'
                    0, %d,
                    (BYTE*) %s,
                    %d, %d,
                    (BYTE*) %s,
                },
                """ % (pdu_sequence_id,
                    pdu_path,

                    len(compressed_bytes), 
                    (utils.as_hex_cstr(compressed_bytes) if compressed_bytes else "NULL"),

                    len(decompressed_bytes), 
                    len(decompressed_bytes),
                    (utils.as_hex_cstr(decompressed_bytes) if decompressed_bytes else "NULL"),
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

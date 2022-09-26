import data_model_v2
import parser_v2
import parser_v2_context

def file_parser_from_snapshot(input_file_name):
    with open(input_file_name, 'r') as f:
        pdu_bytes = bytes()
        for line in f:
            rdp_stream_snapshot = parser_v2_context.RdpStreamSnapshot.from_json(json.loads(line))

            pdu_source = rdp_stream_snapshot.pdu_source
            rdp_context = rdp_stream_snapshot.rdp_context.clone()
            pdu_bytes += rdp_stream_snapshot.pdu_bytes
            err = None
            try:
                # parse and update the rdp_context
                pdu = parser_v2.parse(
                    rdp_stream_snapshot.pdu_source, 
                    pdu_bytes, 
                    parser_config = parser_config, 
                    rdp_context = rdp_context)
                
            except parser_v2.NotEnoughBytesException as e:
                continue
            except parser_v2.ParserException as e:
                err = e.__cause__
                pdu = e.pdu
            except Exception as e:
                err = e
                pdu = data_model_v2.RawDataUnit().with_value(pdu_bytes)

            pdu_bytes = bytes()
            yield rdp_stream_snapshot, pdu, err, rdp_context

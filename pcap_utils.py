import data_model_v2
import data_model_v2_x224
import parser_v2
import parser_v2_context
from scapy.all import (
    rdpcap,
    Raw,
    TCP,
)

def parse_packets_as_raw(pcap_file, server_port = None, parser_config = None):
    private_rdp_context = parser_v2_context.RdpContext()
    pkt_list = rdpcap(pcap_file)
    i = 0
    partial_pdu_history = {
        parser_v2_context.RdpContext.PduSource.CLIENT: bytes(),
        parser_v2_context.RdpContext.PduSource.SERVER: bytes(),
    }
    for pkt in pkt_list:
        if server_port is None:
            # assume that the first packet is the client connection request PDU
            pdu_source = parser_v2_context.RdpContext.PduSource.CLIENT
        else:
            if pkt[TCP].sport == server_port:
                pdu_source = parser_v2_context.RdpContext.PduSource.SERVER
            else:
                pdu_source = parser_v2_context.RdpContext.PduSource.CLIENT
        
        pre_parsing_rdp_context = private_rdp_context.clone()
        pdu_bytes = partial_pdu_history[pdu_source]
        pdu_bytes += pkt[Raw].load
        
        try:
            err = None
            # parse and update the rdp_context
            pdu = parser_v2.parse(pdu_source, pdu_bytes, private_rdp_context, parser_config = parser_config)
        except parser_v2.NotEnoughBytesException as e:
            partial_pdu_history[pdu_source] = pdu_bytes
            continue
        except parser_v2.ParserException as e:
            err = e.__cause__
            pdu = e.pdu
        except Exception as e:
            err = e
            pdu = data_model_v2.RawDataUnit().with_value(pdu_bytes)
        
        if server_port is None:
            if pdu.has_path('tpkt.x224.type') and pdu.tpkt.x224.type == data_model_v2_x224.X224.TPDU_CONNECTION_REQUEST:
                server_port = pkt[TCP].dport
            else:
                raise ValueError('The PDU is not a known PDU type') from err

        yield parser_v2_context.RdpStreamSnapshot(
                    pdu_source, 
                    pdu_bytes = pdu_bytes,
                    pdu_timestamp = float(pkt.time), 
                    pdu_sequence_id = i,
                    rdp_context = pre_parsing_rdp_context
                ), pdu, err, private_rdp_context.clone()
        
        partial_pdu_history[pdu_source] = bytes()
        i += 1
            
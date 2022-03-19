import data_model_v2
import data_model_v2_x224
import parser_v2
import parser_v2_context
from scapy.all import (
    rdpcap,
    Raw,
    TCP,
)

def parse_packets_as_raw(pcap_file, server_port = None):
    rdp_context = parser_v2_context.RdpContext()
    pkt_list = rdpcap(pcap_file)
    i = 0
    for pkt in pkt_list:
        if server_port is None:
            # assume that the first packet is the client connection request PDU
            pdu_source = parser_v2_context.RdpContext.PduSource.CLIENT
        else:
            if pkt[TCP].sport == server_port:
                pdu_source = parser_v2_context.RdpContext.PduSource.SERVER
            else:
                pdu_source = parser_v2_context.RdpContext.PduSource.CLIENT
        
        raw_pdu = data_model_v2.RawDataUnit().with_value(pkt[Raw].load)
        # yield pdu_source, rdp_context, raw_pdu
        yield parser_v2_context.RdpStreamSnapshot(
                    pdu_source, 
                    pdu_bytes = pkt[Raw].load,
                    pdu_timestamp = float(pkt.time), 
                    pdu_sequence_id = i,
                    rdp_context = rdp_context
                )
        
        pdu = parser_v2.parse(pdu_source, pkt[Raw].load, rdp_context)
        
        if server_port is None:
            if pdu.has_path('tpkt.x224.type') and pdu.tpkt.x224.type == data_model_v2_x224.X224.TPDU_CONNECTION_REQUEST:
                server_port = pkt[TCP].dport
            else:
                raise ValueError('The PDU is not a known PDU type')
        i += 1
            
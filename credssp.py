

from requests_credssp.credssp import CredSSPContext
from requests_credssp.asn_structures import TSRequest


from pyasn1.type.univ import Sequence, SequenceOf, OctetString, Integer
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.codec.der.decoder import decode

# the last 4 bytes of this PDU is the RDP_NEG_REQ.requestedProtocols  field
RDP_NEG_REQ_TLS = "\x03\x00\x00\x2f\x2a\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d\x72\x75\x6e\x6e\x65\x72\x61\x64\x6d\x0d\x0a\x01\x00\x08\x00\x01\x00\x00\x00"
RDP_NEG_REQ_CREDSSP = "\x03\x00\x00\x2f\x2a\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d\x72\x75\x6e\x6e\x65\x72\x61\x64\x6d\x0d\x0a\x01\x00\x08\x00\x03\x00\x00\x00"
RDP_NEG_RSP_TLS = "\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x1f\x08\x00\x01\x00\x00\x00"
RDP_NEG_RSP_CREDSSP = "\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x1f\x08\x00\x08\x00\x00\x00"
# clientConnectionRequest
#           Msg from Client: '03 00 00 2f 2a e0 00 00 00 00 00 43 6f 6f 6b 69 65 3a 20 6d 73 74 73 68 61 73 68 3d 72 75 6e 6e 65 72 61 64 6d 0d 0a 01 00 08 00 0b 00 00 00'
# serverConnectionConfirm
#           Msg from Server: '03 00 00 13 0e d0 00 00 12 34 00 02 1f 08 00 08 00 00 00'
# clientSpnego
#           Msg from Client: '30 37 a0 03 02 01 06 a1 30 30 2e 30 2c a0 2a 04 28 4e 54 4c 4d 53 53 50 00 01 00 00 00 b7 82 08 e2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 61 4a 00 00 00 0f'
                # TSRequest:
                #  version=6
                #  negoTokens=NegoData:
                #   NegoToken:
                #   negoToken=0x4e544c4d5353500001000000b78208e2000000000000000000000000000000000a00614a0000000f
clientSpnego_negotiate_raw = '\x30\x37\xa0\x03\x02\x01\x06\xa1\x30\x30\x2e\x30\x2c\xa0\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\xb7\x82\x08\xe2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x61\x4a\x00\x00\x00\x0f'

SPNEGO_CHALLENGE_WINDC = '\x30\x81\xda\xa0\x03\x02\x01\x06\xa1\x81\xd2\x30\x81\xcf\x30\x81\xcc\xa0\x81\xc9\x04\x81\xc6\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00\x16\x00\x16\x00\x38\x00\x00\x00\x35\x82\x8a\xe2\x02\xe7\x30\x83\x57\x22\xf8\xdf\x00\x00\x00\x00\x00\x00\x00\x00\x78\x00\x78\x00\x4e\x00\x00\x00\x0a\x00\x63\x45\x00\x00\x00\x0f\x66\x00\x76\x00\x2d\x00\x61\x00\x7a\x00\x34\x00\x31\x00\x2d\x00\x36\x00\x33\x00\x37\x00\x02\x00\x16\x00\x66\x00\x76\x00\x2d\x00\x61\x00\x7a\x00\x34\x00\x31\x00\x2d\x00\x36\x00\x33\x00\x37\x00\x01\x00\x16\x00\x66\x00\x76\x00\x2d\x00\x61\x00\x7a\x00\x34\x00\x31\x00\x2d\x00\x36\x00\x33\x00\x37\x00\x04\x00\x16\x00\x66\x00\x76\x00\x2d\x00\x61\x00\x7a\x00\x34\x00\x31\x00\x2d\x00\x36\x00\x33\x00\x37\x00\x03\x00\x16\x00\x66\x00\x76\x00\x2d\x00\x61\x00\x7a\x00\x34\x00\x31\x00\x2d\x00\x36\x00\x33\x00\x37\x00\x07\x00\x08\x00\x0e\xd2\xb1\xed\x70\x03\xd7\x01\x00\x00\x00\x00'
SPNEGO_CHALLENGE_MITM  = '\x30\x82\x01\x09\xa0\x03\x02\x01\x06\xa1\x82\x01\x00\x30\x81\xfd\x30\x81\xfa\xa0\x81\xf7\x04\x81\xf4\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00\x14\x00\x14\x00\x30\x00\x00\x00\x35\x82\x8a\xe2\x8c\xd3\xad\xe7\xf9\x61\x5b\xbd\x00\x00\x00\x00\x00\x00\x00\x00\xb0\x00\xb0\x00\x44\x00\x00\x00\x41\x00\x57\x00\x53\x00\x2d\x00\x43\x00\x4c\x00\x4f\x00\x55\x00\x44\x00\x39\x00\x01\x00\x14\x00\x41\x00\x57\x00\x53\x00\x2d\x00\x43\x00\x4c\x00\x4f\x00\x55\x00\x44\x00\x39\x00\x02\x00\x16\x00\x57\x00\x4f\x00\x52\x00\x4b\x00\x53\x00\x54\x00\x41\x00\x54\x00\x49\x00\x4f\x00\x4e\x00\x03\x00\x6a\x00\x61\x00\x77\x00\x73\x00\x2d\x00\x63\x00\x6c\x00\x6f\x00\x75\x00\x64\x00\x39\x00\x2e\x00\x75\x00\x73\x00\x2d\x00\x63\x00\x65\x00\x6e\x00\x74\x00\x72\x00\x61\x00\x6c\x00\x31\x00\x2d\x00\x62\x00\x2e\x00\x63\x00\x2e\x00\x65\x00\x6c\x00\x69\x00\x74\x00\x65\x00\x2d\x00\x62\x00\x69\x00\x72\x00\x64\x00\x2d\x00\x31\x00\x38\x00\x37\x00\x38\x00\x31\x00\x39\x00\x2e\x00\x69\x00\x6e\x00\x74\x00\x65\x00\x72\x00\x6e\x00\x61\x00\x6c\x00\x07\x00\x08\x00\x88\x8b\xc5\xed\x70\x03\xd7\x01\x00\x00\x00\x00'
# MitM as server PUD 1:
mitm_pdu_1 = '\x30\x59\xa0\x03\x02\x01\x06\xa1\x52\x30\x50\x30\x4e\xa0\x4c\x04\x4a\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa3\x2a\x30\x28\xa0\x26\x1b\x24\x6e\x6f\x74\x5f\x64\x65\x66\x69\x6e\x65\x64\x5f\x69\x6e\x5f\x52\x46\x43\x34\x31\x37\x38\x40\x70\x6c\x65\x61\x73\x65\x5f\x69\x67\x6e\x6f\x72\x65'
# client response to pdu 1
client_pdu1_resp = '\x30\x37\xa0\x03\x02\x01\x06\xa1\x30\x30\x2e\x30\x2c\xa0\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\xb7\x82\x08\xe2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x61\x4a\x00\x00\x00\x0f'
mitm_pdu_2 = '\x30\x82\x01\x09\xa0\x03\x02\x01\x06\xa1\x82\x01\x00\x30\x81\xfd\x30\x81\xfa\xa0\x81\xf7\x04\x81\xf4\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00\x14\x00\x14\x00\x30\x00\x00\x00\x35\x82\x8a\xe2\xa2\xdd\xd8\x08\x5d\x41\xa0\xfa\x00\x00\x00\x00\x00\x00\x00\x00\xb0\x00\xb0\x00\x44\x00\x00\x00\x41\x00\x57\x00\x53\x00\x2d\x00\x43\x00\x4c\x00\x4f\x00\x55\x00\x44\x00\x39\x00\x01\x00\x14\x00\x41\x00\x57\x00\x53\x00\x2d\x00\x43\x00\x4c\x00\x4f\x00\x55\x00\x44\x00\x39\x00\x02\x00\x16\x00\x57\x00\x4f\x00\x52\x00\x4b\x00\x53\x00\x54\x00\x41\x00\x54\x00\x49\x00\x4f\x00\x4e\x00\x03\x00\x6a\x00\x61\x00\x77\x00\x73\x00\x2d\x00\x63\x00\x6c\x00\x6f\x00\x75\x00\x64\x00\x39\x00\x2e\x00\x75\x00\x73\x00\x2d\x00\x63\x00\x65\x00\x6e\x00\x74\x00\x72\x00\x61\x00\x6c\x00\x31\x00\x2d\x00\x62\x00\x2e\x00\x63\x00\x2e\x00\x65\x00\x6c\x00\x69\x00\x74\x00\x65\x00\x2d\x00\x62\x00\x69\x00\x72\x00\x64\x00\x2d\x00\x31\x00\x38\x00\x37\x00\x38\x00\x31\x00\x39\x00\x2e\x00\x69\x00\x6e\x00\x74\x00\x65\x00\x72\x00\x6e\x00\x61\x00\x6c\x00\x07\x00\x08\x00\xaa\x18\x75\x0e\x60\x03\xd7\x01\x00\x00\x00\x00'

"""
(venv-py2) rsa-key-20171202-gcp-aws-cloud9@aws-cloud9:~/aws-cloud9-root/rdps2rdp/rdps2rdp$ NTLM_USER_FILE=ntlm_credentials.txt ./rdps2rdp_pcap.py
/home/rsa-key-20171202-gcp-aws-cloud9/aws-cloud9-root/rdps2rdp/rdps2rdp/venv-py2/local/lib/python2.7/site-packages/scapy/config.py:411: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in a future release.
  import cryptography
waiting for connection...
('...connected from:', ('108.49.117.183', 53095))
RDP: clientConnectionRequest
Client receive: waiting
           Msg from Client [len(msg) = 47] : '03 00 00 2f 2a e0 00 00 00 00 00 43 6f 6f 6b 69 65 3a 20 6d 73 74 73 68 61 73 68 3d 72 75 6e 6e 65 72 61 64 6d 0d 0a 01 00 08 00 0b 00 00 00'
Forwarding Msg from Client [len(msg) = 47] : '03 00 00 2f 2a e0 00 00 00 00 00 43 6f 6f 6b 69 65 3a 20 6d 73 74 73 68 61 73 68 3d 72 75 6e 6e 65 72 61 64 6d 0d 0a 01 00 08 00 0b 00 00 00'
RDP: serverConnectionConfirm
Server receive: waiting
           Msg from Server [len(msg) = 19] : '03 00 00 13 0e d0 00 00 12 34 00 02 1f 08 00 08 00 00 00'
Server requested Hybrid security (CredSSP) with version 08
Forwarding Msg from Server [len(msg) = 19] : '03 00 00 13 0e d0 00 00 12 34 00 02 1f 08 00 08 00 00 00'
Intercepting rdp session from 108.49.117.183
CredSSP: MitM with Server
CredSSP: Step 2. Authenticate
Forwarding Msg from MitM [len(msg) = 49] : '30 2f a0 03 02 01 06 a1 28 30 26 30 24 a0 22 04 20 4e 54 4c 4d 53 53 50 00 01 00 00 00 37 82 08 e0 00 00 00 00 20 00 00 00 00 00 00 00 20 00 00 00'
TSRequest:
 version=6
 negoTokens=NegoData:
  NegoToken:
   negoToken=0x4e544c4d5353500001000000378208e000000000200000000000000020000000


<class 'spnego._ntlm_raw.messages.Negotiate'>:
    MESSAGE_TYPE: MessageType.negotiate
    MINIMUM_LENGTH: 32
    _data: <memory at 0x7f1c5024bf28>
    _encoding: windows-1252
    _payload_offset: 32
    domain_name: None
    flags: 3758654007
    pack: <bound method Negotiate.pack of <spnego._ntlm_raw.messages.Negotiate object at 0x7f1c4fb91250>>
    signature: NTLMSSP
    unpack: <function unpack at 0x7f1c50766b18>
    version: None
    workstation: None
Server receive: waiting
           Msg from Server [len(msg) = 221] : '30 81 da a0 03 02 01 06 a1 81 d2 30 81 cf 30 81 cc a0 81 c9 04 81 c6 4e 54 4c 4d 53 53 50 00 02 00 00 00 16 00 16 00 38 00 00 00 35 82 8a e2 02 e7 30 83 57 22 f8 df 00 00 00 00 00 00 00 00 78 00 78 00 4e 00 00 00 0a 00 63 45 00 00 00 0f 66 00 76 00 2d 00 61 00 7a 00 34 00 31 00 2d 00 36 00 33 00 37 00 02 00 16 00 66 00 76 00 2d 00 61 00 7a 00 34 00 31 00 2d 00 36 00 33 00 37 00 01 00 16 00 66 00 76 00 2d 00 61 00 7a 00 34 00 31 00 2d 00 36 00 33 00 37 00 04 00 16 00 66 00 76 00 2d 00 61 00 7a 00 34 00 31 00 2d 00 36 00 33 00 37 00 03 00 16 00 66 00 76 00 2d 00 61 00 7a 00 34 00 31 00 2d 00 36 00 33 00 37 00 07 00 08 00 0e d2 b1 ed 70 03 d7 01 00 00 00 00'
TSRequest:
 version=6
 negoTokens=NegoData:
  NegoToken:
   negoToken=0x4e544c4d5353500002000000160016003800000035828ae202e730835722f8df0000000000000000780078004e0000000a0063450000000f660076002d0061007a00340031002d0036003300370002001600660076002d0061007a00340031002d0036003300370001001600660076002d0061007a00340031002d0036003300370004001600660076002d0061007a00340031002d0036003300370003001600660076002d0061007a00340031002d00360033003700070008000ed2b1ed7003d70100000000


<class 'spnego._ntlm_raw.messages.Challenge'>:
    MESSAGE_TYPE: MessageType.challenge
    MINIMUM_LENGTH: 48
    _data: <memory at 0x7f1c5024bf28>
    _encoding: utf-16-le
    _payload_offset: 56
    flags: 3800728117
    pack: <bound method Challenge.pack of <spnego._ntlm_raw.messages.Challenge object at 0x7f1c4fb91310>>
    server_challenge: W"
                            signature: NTLMSSP
    target_info: TargetInfo([(<AvId.nb_domain_name: 2>, u'fv-az41-637'), (<AvId.nb_computer_name: 1>, u'fv-az41-637'), (<AvId.dns_domain_name: 4>, u'fv-az41-637'), (<AvId.dns_computer_name: 3>, u'fv-az41-637'), (<AvId.timestamp: 7>, FileTime(2021, 2, 15, 8, 2, 38, 979329)), (<AvId.eol: 0>, '')])
    target_name: fv-az41-637
    unpack: <function unpack at 0x7f1c50766b18>
    version: 10.0.17763.15
CredSSP: Step 3. Server Authentication
Forwarding Msg from MitM [len(msg) = 499] : '30 82 01 ef a0 03 02 01 06 a1 82 01 8e 30 82 01 8a 30 82 01 86 a0 82 01 82 04 82 01 7e 4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00 58 00 00 00 d4 00 d4 00 70 00 00 00 00 00 00 00 44 01 00 00 16 00 16 00 44 01 00 00 14 00 14 00 5a 01 00 00 10 00 10 00 6e 01 00 00 35 82 8a e2 00 01 05 00 00 00 00 0f 6e 6a 38 a8 6b 6a 4b ce 47 f8 2c 6a a4 59 35 e6 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e8 60 79 93 92 28 7a 83 49 4d b3 a8 08 db ff 78 01 01 00 00 00 00 00 00 0e d2 b1 ed 70 03 d7 01 0e 62 76 b3 0d 90 08 34 00 00 00 00 02 00 16 00 66 00 76 00 2d 00 61 00 7a 00 34 00 31 00 2d 00 36 00 33 00 37 00 01 00 16 00 66 00 76 00 2d 00 61 00 7a 00 34 00 31 00 2d 00 36 00 33 00 37 00 04 00 16 00 66 00 76 00 2d 00 61 00 7a 00 34 00 31 00 2d 00 36 00 33 00 37 00 03 00 16 00 66 00 76 00 2d 00 61 00 7a 00 34 00 31 00 2d 00 36 00 33 00 37 00 07 00 08 00 0e d2 b1 ed 70 03 d7 01 09 00 20 00 48 00 4f 00 53 00 54 00 2f 00 33 00 2e 00 32 00 32 00 2e 00 35 00 33 00 2e 00 31 00 36 00 31 00 06 00 04 00 02 00 00 00 00 00 00 00 00 00 00 00 72 00 75 00 6e 00 6e 00 65 00 72 00 61 00 64 00 6d 00 69 00 6e 00 41 00 57 00 53 00 2d 00 43 00 4c 00 4f 00 55 00 44 00 39 00 06 6b c4 c1 9c 93 97 af 45 ac de d5 13 2e f4 6d a3 32 04 30 01 00 00 00 a4 2c 86 b3 70 f1 61 9d 00 00 00 00 d0 b7 0a 54 02 64 9b e7 1b 0c 8c 52 7f 4c 1d 04 4d f6 7e fc 58 fc 54 e2 6c 12 ad 02 87 30 00 cd a5 22 04 20 01 fe cd 07 db 13 9f 47 58 79 99 0d ec a6 58 66 b7 33 8e a5 6c 6c 96 72 90 e9 a7 cc f3 43 e2 ec'
TSRequest:
 version=6
 negoTokens=NegoData:
  NegoToken:
   negoToken=0x4e544c4d53535000030000001800180058000000d400d4007000000000000000440100001600160044010000140014005a010000100010006e01000035828ae2000105000000000f6e6a38a86b6a4bce47f82c6aa45935e6000000000000000000000000000000000000000000000000e860799392287a83494db3a808dbff7801010000000000000ed2b1ed7003d7010e6276b30d9008340000000002001600660076002d0061007a00340031002d0036003300370001001600660076002d0061007a00340031002d0036003300370004001600660076002d0061007a00340031002d0036003300370003001600660076002d0061007a00340031002d00360033003700070008000ed2b1ed7003d7010900200048004f00530054002f0033002e00320032002e00350033002e0031003600310006000400020000000000000000000000720075006e006e0065007200610064006d0069006e004100570053002d0043004c004f00550044003900066bc4c19c9397af45acded5132ef46d

 pubKeyAuth=0x01000000a42c86b370f1619d00000000d0b70a5402649be71b0c8c527f4c1d044df67efc58fc54e26c12ad02873000cd
 clientNonce=0x01fecd07db139f475879990deca65866b7338ea56c6c967290e9a7ccf343e2ec

<class 'spnego._ntlm_raw.messages.Authenticate'>:
    MESSAGE_TYPE: MessageType.authenticate
    MINIMUM_LENGTH: 64
    _data: <memory at 0x7f1c5024bf28>
    _encoding: utf-16-le
    _get_mic_offset: <bound method Authenticate._get_mic_offset of <spnego._ntlm_raw.messages.Authenticate object at 0x7f1c4fb91990>>
    _payload_offset: 88
    domain_name: None
    encrypted_random_session_key: kE.
    flags: 3800728117
    lm_challenge_response: 
    mic: nj8kjK,jY5
4fv-az41-637fv-az41-637fv-az41-637fv-az41-63\xd2 y( HOST/3.22.53.161
    pack: <bound method Authenticate.pack of <spnego._ntlm_raw.messages.Authenticate object at 0x7f1c4fb91990>>
    signature: NTLMSSP
    unpack: <function unpack at 0x7f1c50766b18>
    user_name: runneradmin
    version: 0.1.5.15
    workstation: AWS-CLOUD9
Server receive: waiting
           Msg from Server [len(msg) = 59] : '30 39 a0 03 02 01 06 a3 32 04 30 01 00 00 00 37 e5 b3 2d 9a c8 6e 1f 00 00 00 00 54 1b 5b bc d7 62 75 b4 aa 24 ac 83 2f 95 77 96 1b 36 c2 95 b6 1a a8 0e 0b 37 da 1b b7 0d a8 4f'
TSRequest:
 version=6
 pubKeyAuth=0x0100000037e5b32d9ac86e1f00000000541b5bbcd76275b4aa24ac832f9577961b36c295b61aa80e0b37da1bb70da84f

CredSSP: Step 5. Delegate Credentials
Forwarding Msg from MitM [len(msg) = 92] : '30 5a a0 03 02 01 06 a2 53 04 51 01 00 00 00 87 1b ea fe 5c 0c 5d 47 01 00 00 00 be ce 1d 99 03 59 32 3c 77 b7 38 6f 46 c7 45 8a cf 7a a0 8f a1 08 0d 4e 8e 2a 3c 4c 59 5a c8 a1 17 ea 75 1b 07 16 4c 6a e5 71 bc f7 bb ea cd 10 9d c7 62 6a f6 3e 10 78 a3 aa 66 9d 43 3b 60 03 98'
TSRequest:
 version=6
 authInfo=0x01000000871beafe5c0c5d4701000000bece1d990359323c77b7386f46c7458acf7aa08fa1080d4e8e2a3c4c595ac8a117ea751b07164c6ae571bcf7bbeacd109dc7626af63e1078a3aa669d433b600398

Server receive: waiting
           Msg from Server [len(msg) = 4] : '00 00 00 00'
CredSSP: MitM with Client
Client receive: waiting
           Msg from Client [len(msg) = 57] : '30 37 a0 03 02 01 06 a1 30 30 2e 30 2c a0 2a 04 28 4e 54 4c 4d 53 53 50 00 01 00 00 00 b7 82 08 e2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 61 4a 00 00 00 0f'
TSRequest:
 version=6
 negoTokens=NegoData:
  NegoToken:
   negoToken=0x4e544c4d5353500001000000b78208e2000000000000000000000000000000000a00614a0000000f


<class 'spnego._ntlm_raw.messages.Negotiate'>:
    MESSAGE_TYPE: MessageType.negotiate
    MINIMUM_LENGTH: 32
    _data: <memory at 0x7f1c5024bf28>
    _encoding: windows-1252
    _payload_offset: 40
    domain_name: None
    flags: 3792208567
    pack: <bound method Negotiate.pack of <spnego._ntlm_raw.messages.Negotiate object at 0x7f1c5022ab10>>
    signature: NTLMSSP
    unpack: <function unpack at 0x7f1c50766b18>
    version: 10.0.19041.15
    workstation: None
CredSSP: Step 2. Authenticate
Forwarding Msg from MitM [len(msg) = 269] : '30 82 01 09 a0 03 02 01 06 a1 82 01 00 30 81 fd 30 81 fa a0 81 f7 04 81 f4 4e 54 4c 4d 53 53 50 00 02 00 00 00 14 00 14 00 30 00 00 00 35 82 8a e2 8c d3 ad e7 f9 61 5b bd 00 00 00 00 00 00 00 00 b0 00 b0 00 44 00 00 00 41 00 57 00 53 00 2d 00 43 00 4c 00 4f 00 55 00 44 00 39 00 01 00 14 00 41 00 57 00 53 00 2d 00 43 00 4c 00 4f 00 55 00 44 00 39 00 02 00 16 00 57 00 4f 00 52 00 4b 00 53 00 54 00 41 00 54 00 49 00 4f 00 4e 00 03 00 6a 00 61 00 77 00 73 00 2d 00 63 00 6c 00 6f 00 75 00 64 00 39 00 2e 00 75 00 73 00 2d 00 63 00 65 00 6e 00 74 00 72 00 61 00 6c 00 31 00 2d 00 62 00 2e 00 63 00 2e 00 65 00 6c 00 69 00 74 00 65 00 2d 00 62 00 69 00 72 00 64 00 2d 00 31 00 38 00 37 00 38 00 31 00 39 00 2e 00 69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 07 00 08 00 88 8b c5 ed 70 03 d7 01 00 00 00 00'
TSRequest:
 version=6
 negoTokens=NegoData:
  NegoToken:
   negoToken=0x4e544c4d5353500002000000140014003000000035828ae28cd3ade7f9615bbd0000000000000000b000b000440000004100570053002d0043004c004f00550044003900010014004100570053002d0043004c004f005500440039000200160057004f0052004b00530054004100540049004f004e0003006a006100770073002d0063006c006f007500640039002e00750073002d00630065006e007400720061006c0031002d0062002e0063002e0065006c006900740065002d0062006900720064002d003100380037003800310039002e0069006e007400650072006e0061006c0007000800888bc5ed7003d70100000000


<class 'spnego._ntlm_raw.messages.Challenge'>:
    MESSAGE_TYPE: MessageType.challenge
    MINIMUM_LENGTH: 48
    _data: <memory at 0x7f1c4fbac050>
    _encoding: utf-16-le
    _payload_offset: 48
    flags: 3800728117
    pack: <bound method Challenge.pack of <spnego._ntlm_raw.messages.Challenge object at 0x7f1c5022ae10>>
    server_challenge: \xd3a[
    signature: NTLMSSP
    target_info: TargetInfo([(<AvId.nb_computer_name: 1>, u'AWS-CLOUD9'), (<AvId.nb_domain_name: 2>, u'WORKSTATION'), (<AvId.dns_computer_name: 3>, u'aws-cloud9.us-central1-b.c.elite-bird-187819.internal'), (<AvId.timestamp: 7>, FileTime(2021, 2, 15, 8, 2, 39, 108596)), (<AvId.eol: 0>, '')])
    target_name: AWS-CLOUD9
    unpack: <function unpack at 0x7f1c50766b18>
    version: None
Client receive: waiting
Client receive: [Errno 104] Connection reset by peer
           Msg from Client [len(msg) = 0] : ''
Traceback (most recent call last):
  File "./rdps2rdp_pcap.py", line 229, in handler
    negotiate_credssp_as_server(sslclientsock)
  File "./rdps2rdp_pcap.py", line 113, in negotiate_credssp_as_server
    out_token, step_name = credssp_gen.send(in_token)
  File "./rdps2rdp_pcap.py", line 339, in credssp_generator_as_server
    ts_request = decoder.decode(in_token, asn1Spec=TSRequest())[0]
  File "/home/rsa-key-20171202-gcp-aws-cloud9/aws-cloud9-root/rdps2rdp/rdps2rdp/venv-py2/local/lib/python2.7/site-packages/pyasn1/codec/ber/decoder.py", line 1338, in __call__
    'Short octet stream on tag decoding'
SubstrateUnderrunError: Short octet stream on tag decoding
waiting for connection...
('...connected from:', ('108.49.117.183', 53096))
RDP: clientConnectionRequest
Client receive: waiting
           Msg from Client [len(msg) = 47] : '03 00 00 2f 2a e0 00 00 00 00 00 43 6f 6f 6b 69 65 3a 20 6d 73 74 73 68 61 73 68 3d 72 75 6e 6e 65 72 61 64 6d 0d 0a 01 00 08 00 01 00 00 00'
Forwarding Msg from Client [len(msg) = 47] : '03 00 00 2f 2a e0 00 00 00 00 00 43 6f 6f 6b 69 65 3a 20 6d 73 74 73 68 61 73 68 3d 72 75 6e 6e 65 72 61 64 6d 0d 0a 01 00 08 00 01 00 00 00'
RDP: serverConnectionConfirm
Server receive: waiting
           Msg from Server [len(msg) = 19] : '03 00 00 13 0e d0 00 00 12 34 00 03 00 08 00 05 00 00 00'
Traceback (most recent call last):
  File "./rdps2rdp_pcap.py", line 186, in handler
    raise ValueError('Server rejected the connection with reason: %s' % str(serverConnectionConfirm[15]).encode('hex'))
ValueError: Server rejected the connection with reason: 05
waiting for connection...
^CTraceback (most recent call last):
  File "./rdps2rdp_pcap.py", line 614, in <module>
    clientsock, addr = serversock.accept()
  File "/usr/lib/python2.7/socket.py", line 206, in accept
    sock, addr = self._sock.accept()
KeyboardInterrupt
"""


def print_ts_request(pdu):
    try:
        ts_request, rest_of_substrate = decode(pdu, asn1Spec=TSRequest())
    except:
        return
    print("%s" % ts_request)
    from spnego._spnego import unpack_token
    if len(ts_request['negoTokens']) > 0:
        negoToken = unpack_token(ts_request['negoTokens'][0]['negoToken'].asOctets(), unwrap=True)
        print("%s:" % (negoToken.__class__))
        for k in [attr for attr in dir(negoToken) if not attr.startswith('__')]:
            # if isinstance(v, property):
            v = getattr(negoToken, k)
            if callable(v):
                continue
            elif k in  {"server_challenge"}:
                v = binascii.hexlify(v)
            elif k in {'flags'}:
                from spnego._kerberos import (
                    parse_flags,
                )
                from spnego._ntlm_raw.messages import (
                    NegotiateFlags,
                )
                import pprint
                v = pprint.pformat(parse_flags(v, enum_type=NegotiateFlags)['flags'])
            try:
                print("    %s: %s" % (k, v))
            except:
                pass


# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import binascii
import hashlib
import logging
import os
import re
import spnego
import struct
import warnings

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from OpenSSL import SSL
from pyasn1.codec.der import encoder, decoder
from requests.auth import AuthBase

from requests_credssp.asn_structures import NegoToken, TSCredentials, \
    TSPasswordCreds, TSRequest
from requests_credssp.exceptions import AuthenticationException, InvalidConfigurationException

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

log = logging.getLogger(__name__)


class CredSSPContext(object):
    BIO_BUFFER_SIZE = 8192

    def __init__(self, hostname, username, password, auth_mechanism='auto',
                 disable_tlsv1_2=False, minimum_version=2):
        self.hostname = hostname
        self.username = username
        self.password = password

        if auth_mechanism == 'auto':
            auth_mechanism = 'negotiate'
        elif auth_mechanism not in ['ntlm', 'kerberos']:
            raise InvalidConfigurationException("Invalid auth_mechanism supplied %s, must be auto, ntlm, or kerberos"
                                                % auth_mechanism)
        self.auth_mechanism = auth_mechanism
        self.minimum_version = minimum_version

        # if disable_tlsv1_2:
        #     """
        #     Windows 7 and Server 2008 R2 uses TLSv1 by default which is
        #     considered insecure. Microsoft have released a KB that adds support
        #     for TLSv1.2 https://support.microsoft.com/en-us/kb/3080079 which
        #     can be installed. Once installed the relevant reg keys need to be
        #     configured as show by this page
        #     https://technet.microsoft.com/en-us/library/dn786418.aspx
        #     If you do not wish to do this you can set the disable_tlsv1_2 flag
        #     to true when calling CredSSP (NOT RECOMMENDED).
        #     """
        #     log.debug("disable_tlsv1_2 is set to False, disabling TLSv1.2"
        #               "support and reverting back to TLSv1")
        #     self.tls_context = SSL.Context(SSL.TLSv1_METHOD)

        #     # Revert OpenSSL fix to CBC ciphers due to incompatibility with
        #     # MS TLS 1.0 implementation SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
        #     # 0x00000800 - SSL_OP_TLS_BLOCK_PADDING_BUG 0x00000200
        #     self.tls_context.set_options(0x00000800 | 0x00000200)
        # else:
        #     self.tls_context = SSL.Context(SSL.TLSv1_2_METHOD)

        # self.tls_context.set_cipher_list(b'ALL')
        # self.tls_connection = None

    def credssp_generator_as_server(self, ssl_sock):
        context = spnego.server(hostname=self.hostname, protocol=self.auth_mechanism)

        in_token = yield None, None
        while True:
            in_token = self.unwrap(in_token)
            
            ts_request = decoder.decode(in_token, asn1Spec=TSRequest())[0] 
            ts_request.check_error_code()
            out_token = context.step(bytes(ts_request['negoTokens'][0]['negoToken']))
            if context.complete:
                break
            nego_token = NegoToken()
            nego_token['negoToken'] = out_token

            ts_request = TSRequest()
            ts_request['negoTokens'].append(nego_token)
            ts_request_token = encoder.encode(ts_request)

            in_token = yield self.wrap(ts_request_token), "Step 2. Authenticate"
            
        from cryptography import x509
        from cryptography.hazmat import backends
        with open('cert.pem', 'r') as f:
            cert = x509.load_pem_x509_certificate(f.read(), backends.default_backend())
        cryptographic_key = cert.public_key()
        server_public_key = cryptographic_key.public_bytes(Encoding.DER, PublicFormat.PKCS1)
        # server_public_key = self._get_subject_public_key(ssl_sock)
        version = min(int(ts_request['version']), TSRequest.CLIENT_VERSION)
        log.debug("Starting public key verification process at version %d" % version)
        if version > 4:
            nonce = bytes(ts_request['clientNonce'])
        else:
            nonce = None

        pub_key_auth = self._build_server_pub_key_auth(context, nonce, None, server_public_key)
        log.debug("Step 3. Server Authentication, returning token: %s" % binascii.hexlify(pub_key_auth))
        in_token = yield self.wrap(pub_key_auth), "Step 3. Server Authentication"
        

    def credssp_generator_as_client(self, ssl_sock):
        """
        [MS-CSSP] 3.1.5 Processing Events and Sequencing Rules
        https://msdn.microsoft.com/en-us/library/cc226791.aspx
        Generator function that yields each CredSSP token to sent to the
        server. CredSSP has multiple steps that must be run for the client to
        successfully authenticate with the server and delegate the credentials.
        """
        # log.debug("Starting TLS handshake process")
        # self.tls_connection = SSL.Connection(self.tls_context)
        # self.tls_connection.set_connect_state()

        # while True:
        #     try:
        #         self.tls_connection.do_handshake()
        #     except SSL.WantReadError:
        #         out_token = self.tls_connection.bio_read(self.BIO_BUFFER_SIZE)

        #         log.debug("Step 1. TLS Handshake, returning token: %s" % binascii.hexlify(out_token))
        #         in_token = yield out_token, "Step 1. TLS Handshake"
        #         log.debug("Step 1. TLS Handshake, received token: %s" % binascii.hexlify(in_token))

        #         self.tls_connection.bio_write(in_token)
        #     else:
        #         break
        # log.debug("TLS Handshake complete. Protocol: %s, Cipher: %s"
        #           % (self.tls_connection.get_protocol_version_name(), self.tls_connection.get_cipher_name()))

        # server_certificate = self.tls_connection.get_peer_certificate()
        # server_public_key = self._get_subject_public_key(server_certificate)

        log.debug("Starting Authentication process")
        context = spnego.client(self.username, self.password, hostname=self.hostname,
                            protocol=self.auth_mechanism)

        out_token = context.step()
        while True:
            nego_token = NegoToken()
            nego_token['negoToken'] = out_token

            ts_request = TSRequest()
            ts_request['negoTokens'].append(nego_token)
            ts_request_token = encoder.encode(ts_request)

            log.debug("Step 2. Authenticate, returning token: %s" % binascii.hexlify(ts_request_token))
            in_token = yield self.wrap(ts_request_token), "Step 2. Authenticate"
            in_token = self.unwrap(in_token)
            log.debug("Step 3. Authenticate, received token: %s" % binascii.hexlify(in_token))

            ts_request = decoder.decode(in_token, asn1Spec=TSRequest())[0]
            ts_request.check_error_code()
            version = int(ts_request['version'])
            out_token = context.step(bytes(ts_request['negoTokens'][0]['negoToken']))

            # Special edge case, we need to include the final NTLM token in the pubKeyAuth step but the context won't
            # be seen as complete at that stage so check if the known header is present.
            if context.complete or b"NTLMSSP\x00\x03\x00\x00\x00" in out_token:
                break

        server_public_key = self._get_subject_public_key(ssl_sock)
        version = min(version, TSRequest.CLIENT_VERSION)
        log.debug("Starting public key verification process at version %d" % version)
        if version < self.minimum_version:
            raise AuthenticationException("The reported server version was %d and did not meet the minimum "
                                          "requirements of %d" % (version, self.minimum_version))
        if version > 4:
            nonce = os.urandom(32)
        else:
            log.warning("Reported server version was %d, susceptible to MitM attacks and should be patched - "
                        "CVE 2018-0886" % version)
            nonce = None

        pub_key_auth = self._build_pub_key_auth(context, nonce, out_token, server_public_key)
        log.debug("Step 3. Server Authentication, returning token: %s" % binascii.hexlify(pub_key_auth))
        in_token = yield self.wrap(pub_key_auth), "Step 3. Server Authentication"
        in_token = self.unwrap(in_token)
        log.debug("Step 3. Server Authentication, received token: %s" % binascii.hexlify(in_token))

        log.debug("Starting server public key response verification")
        ts_request = decoder.decode(in_token, asn1Spec=TSRequest())[0]
        ts_request.check_error_code()
        if not ts_request['pubKeyAuth'].isValue:
            raise AuthenticationException("The server did not response with pubKeyAuth info, authentication was "
                                          "rejected")
        if len(ts_request['negoTokens']) > 0:
            # SPNEGO auth returned the mechListMIC for us to verify
            context.step(bytes(ts_request['negoTokens'][0]['negoToken']))

        response_key = context.unwrap(bytes(ts_request['pubKeyAuth'])).data
        self._verify_public_keys(nonce, response_key, server_public_key)

        log.debug("Sending encrypted credentials")
        enc_credentials = self._get_encrypted_credentials(context)

        yield self.wrap(enc_credentials), "Step 5. Delegate Credentials"

    def _build_pub_key_auth(self, context, nonce, auth_token, public_key):
        """
        [MS-CSSP] 3.1.5 Processing Events and Sequencing Rules - Step 3
        https://msdn.microsoft.com/en-us/library/cc226791.aspx
        This step sends the final SPNEGO token to the server if required and
        computes the value for the pubKeyAuth field for the protocol version
        negotiated.
        The format of the pubKeyAuth field depends on the version that the
        server supports.
        For version 2 to 4:
        The pubKeyAuth field is just wrapped using the authenticated context
        For versions 5 to 6:
        The pubKeyAuth is a sha256 hash of the server's public key plus a nonce
        and a magic string value. This hash is wrapped using the authenticated
        context and the nonce is added to the TSRequest alongside the nonce
        used in the hash calcs.
        :param context: The authenticated context
        :param nonce: If versions 5+, the nonce to use in the hash
        :param auth_token: If NTLM, this is the last msg (authenticate msg) to
            send in the same request
        :param public_key: The server's public key
        :return: The TSRequest as a byte string to send to the server
        """
        ts_request = TSRequest()

        if auth_token is not None:
            nego_token = NegoToken()
            nego_token['negoToken'] = auth_token
            ts_request['negoTokens'].append(nego_token)

        if nonce is not None:
            ts_request['clientNonce'] = nonce
            hash_input = b"CredSSP Client-To-Server Binding Hash\x00" + nonce + public_key
            pub_value = hashlib.sha256(hash_input).digest()
        else:
            pub_value = public_key

        enc_public_key = context.wrap(pub_value).data
        ts_request['pubKeyAuth'] = enc_public_key

        return encoder.encode(ts_request)

    def _build_server_pub_key_auth(self, context, nonce, auth_token, public_key):
        ts_request = TSRequest()

        if nonce is not None:
            hash_input = b"CredSSP Server-To-Client Binding Hash\x00" + nonce + public_key
            pub_value = hashlib.sha256(hash_input).digest()
        else:
            raise ValueError("unsupported")
            pub_value = public_key

        enc_public_key = context.wrap(pub_value).data
        ts_request['pubKeyAuth'] = enc_public_key

        return encoder.encode(ts_request)

    def _verify_public_keys(self, nonce, server_key, public_key):
        """
        [MS-CSSP] 3.1.5 Processing Events and Sequencing Rules - Step 4
        https://msdn.microsoft.com/en-us/library/cc226791.aspx
        The rules vary depending on the server version
        For version 2 to 4:
        After the server received the public key in Step 3 it verifies the key
        with what was in the handshake. After the verification it then adds 1
        to the first byte representing the public key and encrypts the bytes
        result by using the authentication protocol's encryption services.
        This method does the opposite where it will decrypt the public key
        returned from the server and subtract the first byte by 1 to compare
        with the public key we sent originally.
        For versions 5 to 6:
        A hash is calculated with the magic string value, the nonce that was
        sent to the server and the public key that was used. This is verified
        against the returned server public key.
        :param nonce: If version 5+, the nonce used in the hash calculations
        :param server_key: The unwrapped value returned in the
            TSRequest['pubKeyAuth'] field.
        :param public_key: The actual public key of the server
        """
        if nonce is not None:
            hash_input = b"CredSSP Server-To-Client Binding Hash\x00" + nonce + public_key
            actual = hashlib.sha256(hash_input).digest()
            expected = server_key
        else:
            first_byte = struct.unpack("B", server_key[0:1])[0]
            actual_first_byte = struct.pack("B", first_byte - 1)

            actual = actual_first_byte + server_key[1:]
            expected = public_key

        if actual != expected:
            raise AuthenticationException("Could not verify key sent from the server, potential man in the middle "
                                          "attack")

    def _get_encrypted_credentials(self, context):
        """
        [MS-CSSP] 3.1.5 Processing Events and Sequencing Rules - Step 5
        https://msdn.microsoft.com/en-us/library/cc226791.aspx
        After the client has verified the server's authenticity, it encrypts
        the user's credentials with the authentication protocol's encryption
        services. The resulting value is encapsulated in the authInfo field of
        the TSRequest structure and sent over the encrypted TLS channel to the
        server
        :param context: The authenticated security context
        :return: The encrypted TSRequest that contains the user's credentials
        """
        domain = u""
        if "\\" in context.username:
            domain, username = context.username.split('\\', 1)
        else:
            username = context.username

        ts_password = TSPasswordCreds()
        ts_password['domainName'] = domain.encode('utf-16-le')
        ts_password['userName'] = username.encode('utf-16-le')
        ts_password['password'] = context.password.encode('utf-16-le')

        ts_credentials = TSCredentials()
        ts_credentials['credType'] = ts_password.CRED_TYPE
        ts_credentials['credentials'] = encoder.encode(ts_password)

        ts_request = TSRequest()
        enc_credentials = context.wrap(encoder.encode(ts_credentials)).data
        ts_request['authInfo'] = enc_credentials

        return encoder.encode(ts_request)

    def wrap(self, data):
        return data

    def unwrap(self, encrypted_data):
        return encrypted_data

    # @staticmethod
    # def _get_subject_public_key(cert):
    #     """
    #     Returns the SubjectPublicKey asn.1 field of the SubjectPublicKeyInfo
    #     field of the server's certificate. This is used in the server
    #     verification steps to thwart MitM attacks.
    #     :param cert: X509 certificate from pyOpenSSL .get_peer_certificate()
    #     :return: byte string of the asn.1 DER encoded SubjectPublicKey field
    #     """
    #     public_key = cert.get_pubkey()
    #     cryptographic_key = public_key.to_cryptography_key()
    #     subject_public_key = cryptographic_key.public_bytes(Encoding.DER, PublicFormat.PKCS1)
    #     return subject_public_key

    @staticmethod
    def _get_subject_public_key(ssl_sock):
        """
        Returns the SubjectPublicKey asn.1 field of the SubjectPublicKeyInfo
        field of the server's certificate. This is used in the server
        verification steps to thwart MitM attacks.
        :param cert: X509 certificate from pyOpenSSL .get_peer_certificate()
        :return: byte string of the asn.1 DER encoded SubjectPublicKey field
        """
        """
        Extract an X.509 certificate from a socket connection.
        """
        certificate = ssl_sock.getpeercert(binary_form=True) # must be from ssl.wrap_socket()
        from cryptography import x509
        from cryptography.hazmat import backends
        cert = x509.load_der_x509_certificate(certificate, backends.default_backend())
        cryptographic_key = cert.public_key()
        subject_public_key = cryptographic_key.public_bytes(Encoding.DER, PublicFormat.PKCS1)
        return subject_public_key

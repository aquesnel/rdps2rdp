import enum

@enum.unique
class CompressionFlags(enum.Enum):
    COMPRESSED = 'compressed'
    FLUSHED = 'flushed'
    AT_FRONT = 'at_front'
    INNER_COMPRESSION = 'inner_compression'
    
@enum.unique
class CompressionTypes(enum.Enum):
    NO_OP       = 'NO_OP'
    RDP_40      = 'RDP_40'
    RDP_50      = 'RDP_50'
    RDP_60      = 'RDP_60'
    RDP_61      = 'RDP_61'
    RDP_61_L1   = 'RDP_61_L1'
    RDP_61_L2   = 'RDP_61_L2'
    RDP_80      = 'RDP_80'
    RDP_80_LITE = 'RDP_80_LITE' # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedyc/b0a9b542-0221-429d-b18e-07bded361435

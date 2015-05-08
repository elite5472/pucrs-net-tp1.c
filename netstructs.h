typedef uint8_t MacAddress[6];

typedef struct
{
    MacAddress 	Destination;
    MacAddress 	Source;
    uint16_t 	Type;
} __attribute__((packed)) EthernetHeader;

typedef struct
{
    uint16_t    HardwareType;
    uint16_t    ProtocolType;

    uint8_t     HardwareAddressLength;
    uint8_t     ProtocolAddressLength;
    uint16_t    Operation;

    MacAddress  SenderHardwareAddress;
    uint32_t    SenderProtocolAddress;
    MacAddress  TargetHardwareAddress;
    uint32_t    TargetProtocolAddress;
} __attribute__((packed)) ArpHeader;

typedef struct
{
    uint8_t		VersionIhl;
    uint8_t		DscpEcn;
    uint16_t	Length;

    uint16_t    Id;
    uint16_t    FlagsOffset;

    uint8_t		Ttl;
    uint8_t		Protocol;
    uint16_t	Checksum;

    uint32_t	Source;
    uint32_t	Destination;

} __attribute__((packed)) IpHeader;

typedef struct
{
    uint8_t		Type;
    uint8_t		Code;
    uint16_t	Checksum;
} __attribute__((packed)) IcmpHeader;

typedef struct
{
	uint16_t	SourcePort;
	uint16_t	DestPort;

	uint32_t	SequenceNum;

	uint32_t	AckNum;

	uint16_t	Flags;
	uint16_t	WindowSize;

	uint16_t	Checksum;
	uint16_t	UrgentPointer;
} __attribute__((packed)) TcpHeader;

typedef struct
{
	uint16_t	SourcePort;
	uint16_t	DestPort;

	uint16_t	Length;
	uint16_t	Checksum;
} __attribute__((packed)) UdpHeader;
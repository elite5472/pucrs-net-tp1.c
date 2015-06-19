#ifndef NETSTRUCTS

#include <iostream>
#include <unordered_map>
#include <string>
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include "netstructs.cpp"

#define NETSTRUCTS
#endif

typedef uint8_t MacAddress[6];

typedef struct
{
    MacAddress  Destination;
    MacAddress  Source;
    uint16_t    Type;
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
    uint8_t VersionIhl;
    uint8_t DscpEcn;
    uint16_t    Length;

    uint16_t    Id;
    uint16_t    FlagsOffset;

    uint8_t Ttl;
    uint8_t Protocol;
    uint16_t    Checksum;

    uint32_t    Source;
    uint32_t    Destination;

} __attribute__((packed)) IpHeader;

typedef struct
{
    uint8_t     Type;
    uint8_t     Code;
    uint16_t    Checksum;
} __attribute__((packed)) IcmpHeader;

typedef struct
{
    uint16_t    SourcePort;
    uint16_t    DestPort;

    uint32_t    SequenceNum;

    uint32_t    AckNum;

    uint16_t    Flags;
    uint16_t    WindowSize;

    uint16_t    Checksum;
    uint16_t    UrgentPointer;
} __attribute__((packed)) TcpHeader;

typedef struct
{
    uint16_t    SourcePort;
    uint16_t    DestPort;

    uint16_t    Length;
    uint16_t    Checksum;
} __attribute__((packed)) UdpHeader;

typedef struct
{
    uint8_t opcode;
    uint8_t htype;
        uint8_t hlen;
        uint8_t hops;
        uint32_t xid;
        uint16_t secs;
        uint16_t flags;
        uint32_t ciaddr;
        uint32_t yiaddr;
        uint32_t siaddr;
        uint32_t giaddr;
        MacAddress chaddr;
        char sname[64];
        char file[128];
        uint8_t options[512];
} __attribute__((packed)) DhcpHeader;
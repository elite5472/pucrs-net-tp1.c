//Compile with g++ -pthread -std=c++11 main.c
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

#define ETHERTYPE_LEN 2
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define BUFFER_LEN 1518
#define ARP_LEN 28

using namespace std;

typedef unsigned char EtherType[ETHERTYPE_LEN];
typedef unsigned char MacAddress[MAC_ADDR_LEN];

typedef unsigned char DataType2[2];
typedef unsigned char DataType3[3];
typedef unsigned char DataType8[8];
extern int errno;

typedef uint8_t MacAddress[6];

typedef struct
{
    MacAddress Destination;
    MacAddress Source;
    uint16_t Type;
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
    uint8_t	VersionIhl;
    uint8_t	DscpEcn;
    uint16_t	Length;
    uint16_t    Id;
    uint16_t    FlagsOffset;
    uint8_t	Ttl;
    uint8_t	Protocol;
    uint16_t	Checksum;
    uint32_t	Source;
    uint32_t	Destination;
  
} __attribute__((packed)) IpHeader;

typedef struct
{
    uint8_t	Type;
    uint8_t	Code;
    uint16_t	Checksum;
} __attribute__((packed)) IcmpHeader;

int stats_frame_count;
int stats_frame_size_min;
int stats_frame_size_max;

int stats_arp_request_count;
int stats_arp_reply_count;

int stats_ip_count;
unordered_map<uint32_t, int> stats_ip_access_count;

int stats_ip_icmp_count;
int stats_ip_icmp_echo_request_count;
int stats_ip_icmp_echo_reply_count;

int stats_ip_udp_count;
int stats_ip_tcp_count;

unordered_map<uint16_t, int> stats_ip_tcp_access_count;
unordered_map<uint16_t, int> stats_ip_udp_access_count;

int stats_ip_tcp_http_count;
int stats_ip_tcp_dns_count;
int stats_ip_tcp_other1_count;
int stats_ip_tcp_other2_count;

unordered_map<string, int> stats_ip_tcp_http_access_count;

void print_mac(MacAddress s)
{
	printf("%x:%x:%x:%x:%x:%x", s[0],s[1],s[2],s[3],s[4],s[5]);
}

void print_ip(uint32_t ip)
{
	unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;	
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]); 
}

int thread_listener_socket = 0;
struct ifreq ifr;
void* thread_listener(void * arg)
{
    //Setup monitoring to grab everything. (I don't know how this works!)
    if(ioctl(thread_listener_socket, SIOCGIFINDEX, &ifr) < 0)
        printf("Error: Monitor failed to start \n");
    ioctl(thread_listener_socket, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(thread_listener_socket, SIOCSIFFLAGS, &ifr);


    unsigned char buffer[BUFFER_LEN];
    //Do actual monitoring!
    while (true)
    {
        recv(thread_listener_socket,(char *) &buffer, BUFFER_LEN, 0x0);

		EthernetHeader* ethheader = (EthernetHeader*)buffer;

        printf("Package Captured From ");
		print_mac(ethheader->Source);
        printf(" to ");
		print_mac(ethheader->Destination);
        printf("\n");

		if (ntohs(ethheader->Type) == 0x0806 /*ARP*/)
		{
			ArpHeader* arpheader = (ArpHeader*)(buffer+14);
			printf("ARP IP Requested: ");
		 	print_ip(ntohl(arpheader->TargetProtocolAddress));
			printf("\n");
		}
    }
}

void* thread_cmd(void * arg)
{
}

int main(int argc, char *argv[])
{

    if(argc >= 2)
    {
		strcpy(ifr.ifr_name, argv[1]);
    }
	else
	{
		strcpy(ifr.ifr_name, "eth0");
	}

	if((thread_listener_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("Error: Socket did not initialize. \n");
		exit(1);
	}

	pthread_t cmd, listener;
	pthread_create(&cmd, NULL, &thread_cmd, NULL);
	pthread_create(&listener, NULL, &thread_listener, NULL);
	pthread_join(listener, NULL);
	pthread_join(cmd, NULL);

	return 0;
}

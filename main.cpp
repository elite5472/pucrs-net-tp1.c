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

#include "netstructs.h"

#define BUFFER_LEN 1518

using namespace std;

extern int errno;

MacAddress host_mac;

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
    while (true)
    {
        recv(thread_listener_socket,(char *) &buffer, BUFFER_LEN, 0x0);

		int i = 0;
		EthernetHeader* ethheader = (EthernetHeader*)buffer;
		i = i + sizeof(EthernetHeader);
		if(mac_equal(host_mac, ethheader->Destination) && ntohs(ethheader->Type) == 0x0800)
		{
			
		}
    }
}

unsigned short in_cksum(unsigned short *addr,int len)
{
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

int make_dhcp(DhcpHeader* frame_dhcp, uint32_t source_ip, uint16_t source_port, MacAddress source_mac, uint32_t dest_ip, uint16_t dest_port, MacAddress dest_mac,uint8_t* buffer)
{
	EthernetHeader* frame_ethernet;
	frame_ethernet->Destination[0] = dest_mac[0];
	frame_ethernet->Destination[1] = dest_mac[1];
	frame_ethernet->Destination[2] = dest_mac[2];
	frame_ethernet->Destination[3] = dest_mac[3];
	frame_ethernet->Destination[4] = dest_mac[4];
	frame_ethernet->Destination[5] = dest_mac[5];
	frame_ethernet->Source[0] = source_mac[0];
	frame_ethernet->Source[1] = source_mac[1];
	frame_ethernet->Source[2] = source_mac[2];
	frame_ethernet->Source[3] = source_mac[3];
	frame_ethernet->Source[4] = source_mac[4];
	frame_ethernet->Source[5] = source_mac[5];
	frame_ethernet->Type = 0x0800;
	
	IpHeader* frame_ip;
	frame_ip->VersionIhl = 0x4;
	frame_ip->DscpEcn = 0x00;
	frame_ip->Length = 0x14;
	frame_ip->Id = 0x01;
	frame_ip->FlagsOffset = 0x00;
	frame_ip->Ttl = 0x80;
	frame_ip->Protocol = 0x11;
	frame_ip->Source = source_ip;
	frame_ip->Destination = dest_ip;
	frame_ip->Checksum = in_cksum((uint16_t*)(frame_ip), sizeof(frame_ip));

	UdpHeader* frame_udp;
	frame_udp->SourcePort = source_port;
	frame_udp->DestPort = dest_port;
	frame_udp->Length = 0x0134;
	frame_udp->Checksum = 0x00;	

	int i = 0;
	memcpy(buffer + i, frame_ethernet, sizeof(EthernetHeader)); i += sizeof(EthernetHeader);
	memcpy(buffer + i, frame_ip, sizeof(IpHeader)); i += sizeof(IpHeader);
	memcpy(buffer + i, frame_udp, sizeof(UdpHeader)); i += sizeof(UdpHeader);
	memcpy(buffer + i, frame_dhcp, sizeof(DhcpHeader)); i += sizeof(DhcpHeader);

	return i;

}

int main(int argc, char *argv[])
{

	if(argc < 3)
    {
        printf("usage: %s local_mac adapter ip \n", argv[0]);
        exit(1);
    }

    //Config
    sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &host_mac[0], &host_mac[1], &host_mac[2], &host_mac[3], &host_mac[4], &host_mac[5]);

    if(argc >= 2)
    {
		strcpy(ifr.ifr_name, argv[2]);
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

	pthread_t listener;
	pthread_create(&listener, NULL, &thread_listener, NULL);
	pthread_join(listener, NULL);

	return 0;
}

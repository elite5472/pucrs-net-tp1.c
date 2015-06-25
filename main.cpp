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
int sender_socket = 0;
int listener_socket = 0;

uint32_t sender_ip = 0;


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
	EthernetHeader* frame_ethernet = (EthernetHeader*) malloc(sizeof(EthernetHeader));
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
	

	IpHeader* frame_ip = (IpHeader*) malloc(sizeof(IpHeader));
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

	UdpHeader* frame_udp = (UdpHeader*) malloc(sizeof(UdpHeader)); 
	frame_udp->SourcePort = source_port;
	frame_udp->DestPort = dest_port;
	frame_udp->Length = 0x0134;
	frame_udp->Checksum = 0x00;	

	frame_dhcp->opcode = 0x02;
	frame_dhcp->htype = 0x01;
	frame_dhcp->hlen = 0x06;
	frame_dhcp->hops = 0x00;
	frame_dhcp->id = 0xc7d44645;
	frame_dhcp->secs = 0x0000;
	frame_dhcp->flags = 0x0000;
	frame_dhcp->ciaddr = 0x16208FC0;
	frame_dhcp->yiaddr = 0xC0A80164;
	frame_dhcp->siaddr = 0x00000000;
	frame_dhcp->giaddr = 0x00000000;

	frame_dhcp->magic[0] == 0x63;
	frame_dhcp->magic[1] == 0x82;
	frame_dhcp->magic[2] == 0x53;
	frame_dhcp->magic[3] == 0x63;

	frame_dhcp->options[0] == 53;
	frame_dhcp->options[1] == 1;
	frame_dhcp->options[2] == 2;
	frame_dhcp->options[3] == 1;
	frame_dhcp->options[4] == 4;
	frame_dhcp->options[5] == 255;
	frame_dhcp->options[6] == 255;
	frame_dhcp->options[7] == 255;
	frame_dhcp->options[8] == 0;
	frame_dhcp->options[9] == 3;
	frame_dhcp->options[10] == 4;
	frame_dhcp->options[11] == 10;
	frame_dhcp->options[12] == 32;
	frame_dhcp->options[13] == 143;
	frame_dhcp->options[14] == 1;
	frame_dhcp->options[15] == 54;
	frame_dhcp->options[16] == 4;
	frame_dhcp->options[17] == 10;
	frame_dhcp->options[18] == 32;
	frame_dhcp->options[19] == 143;
	frame_dhcp->options[20] == 193;

	frame_dhcp->options[21] == 6;
	frame_dhcp->options[22] == 4;
	frame_dhcp->options[23] == 192;
	frame_dhcp->options[24] == 168;
	frame_dhcp->options[25] == 25;
	frame_dhcp->options[26] == 203;

	frame_dhcp->options[27] == 51;
	frame_dhcp->options[28] == 4;
	frame_dhcp->options[29] == 10;
	frame_dhcp->options[30] == 10;
	frame_dhcp->options[31] == 10;
	frame_dhcp->options[32] == 10;

	frame_dhcp->options[33] == 255;
	frame_dhcp->options[34] == 255;
	//uint8_t options[251];

	int i = 0;
	memcpy(buffer + i, frame_ethernet, sizeof(EthernetHeader)); i += sizeof(EthernetHeader);
	memcpy(buffer + i, frame_ip, sizeof(IpHeader)); i += sizeof(IpHeader);
	memcpy(buffer + i, frame_udp, sizeof(UdpHeader)); i += sizeof(UdpHeader);
	memcpy(buffer + i, frame_dhcp, sizeof(DhcpHeader)); i += sizeof(DhcpHeader);
	return i;

}

struct ifreq ifr;
void* thread_listener(void * arg)
{
    //Setup monitoring to grab everything. (I don't know how this works!)
    if(ioctl(listener_socket, SIOCGIFINDEX, &ifr) < 0)
        printf("Error: Monitor failed to start \n");
    ioctl(listener_socket, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(listener_socket, SIOCSIFFLAGS, &ifr);


    unsigned char buffer[BUFFER_LEN];
    while (true)
    {
        recv(listener_socket,(char *) &buffer, BUFFER_LEN, 0x0);

		int i = 0;
		EthernetHeader* ethheader = (EthernetHeader*)buffer;
		i = i + sizeof(EthernetHeader);
	    IpHeader* ipheader = (IpHeader*)(buffer + i);
		i = i + sizeof(IpHeader);
		UdpHeader* udpheader = (UdpHeader*)(buffer + i);
		i = i + sizeof(UdpHeader);
		if(mac_equal(ethheader->Destination, host_mac) && ntohs(ethheader->Type) == 0x0800)
		{
			print_ip(ipheader->Source);
			printf(", sending back.\n");
			EthernetHeader out_ethheader;
			memcpy(out_ethheader.Source, ethheader->Destination, sizeof(MacAddress));
			memcpy(out_ethheader.Destination, ethheader->Source, sizeof(MacAddress));
			out_ethheader.Type = htons(0x0800);
			
			IpHeader out_ipheader;
			out_ipheader.VersionIhl = 0x45;
			out_ipheader.DscpEcn = 0x00;
			out_ipheader.Length = htons(20);
			out_ipheader.Id = 0x00;
			out_ipheader.FlagsOffset = 0x00;
			out_ipheader.Ttl = 64;
			out_ipheader.Protocol = 0xFD;
			out_ipheader.Source = ntohl(sender_ip);
			out_ipheader.Destination = ipheader->Source;
			out_ipheader.Checksum = in_cksum((uint16_t*)(&out_ipheader), sizeof(IpHeader));
			
			uint8_t out_buffer[BUFFER_LEN];
			int i = 0;
			
			memcpy(out_buffer + i, &out_ethheader, sizeof(EthernetHeader)); i += sizeof(EthernetHeader);
			memcpy(out_buffer + i, &out_ipheader, sizeof(IpHeader)); i += sizeof(IpHeader);
			
			send_packet(out_buffer, i, sender_socket, host_mac);
		}
		
		if(ntohs(udpheader->SourcePort) == 67)
		{			
			
		}
    }
}

int main(int argc, char *argv[])
{

	if(argc < 3)
    {
        printf("usage: %s ip local_mac adapter \n", argv[0]);
        exit(1);
    }

    //Config
    sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &host_mac[0], &host_mac[1], &host_mac[2], &host_mac[3], &host_mac[4], &host_mac[5]);

	struct in_addr addr_buffer;
	inet_aton(argv[1], &addr_buffer);
    unsigned int sender_ip = addr_buffer.s_addr;
	strcpy(ifr.ifr_name, argv[3]);

	if((listener_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("Error: Socket did not initialize. \n");
		exit(1);
	}
	
	if((sender_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        printf("Error: Socket did not initialize. \n");
        exit(1);
    }
    
    printf("Started. IP is "); print_ip(sender_ip);
    printf("\nMac is "); print_mac(host_mac);
    printf("\n");

	pthread_t listener;
	pthread_create(&listener, NULL, &thread_listener, NULL);
	pthread_join(listener, NULL);

	return 0;
}

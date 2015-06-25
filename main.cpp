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
uint32_t gateway_ip = 0;
uint32_t subnet_mask = 0;
uint32_t dns_ip = 0;
uint32_t lease_ip = 0;


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

int make_ip(MacAddress source_mac, uint32_t source_ip, MacAddress dest_mac, uint32_t dest_ip, uint8_t protocol, uint8_t* data, int data_len, uint8_t* buffer, int buffer_offset)
{
	EthernetHeader eth;
	memcpy(eth.Source, source_mac, sizeof(MacAddress));
	memcpy(eth.Destination, dest_mac, sizeof(MacAddress));
	eth.Type = htons(0x0800);
	
	IpHeader ip;
	ip.VersionIhl = 0x45;
	ip.DscpEcn = 0x00;
	ip.Length = htons(20 + data_len);
	ip.Id = 0x00;
	ip.FlagsOffset = 0x00;
	ip.Ttl = 64;
	ip.Protocol = protocol;
	ip.Source = sender_ip;
	ip.Destination = dest_ip;
	ip.Checksum = 0;
	ip.Checksum = in_cksum((uint16_t*)(&ip), sizeof(IpHeader));
	
	int i = buffer_offset;
	memcpy(buffer + i, &eth, sizeof(EthernetHeader)); i += sizeof(EthernetHeader);
	memcpy(buffer + i, &ip, sizeof(IpHeader)); i += sizeof(IpHeader);
	if(data_len > 0)
	{
		memcpy(buffer + i, data, data_len); i += data_len;
	}
	
	return i;
}

int make_udp(MacAddress source_mac, uint32_t source_ip, uint16_t source_port, MacAddress dest_mac, uint32_t dest_ip, uint16_t dest_port, uint8_t* data, int data_len, uint8_t* buffer, int buffer_offset)
{
	UdpHeader udp;
	udp.SourcePort = source_port;
	udp.DestPort = dest_port;
	udp.Length = htons(8 + data_len);
	udp.Checksum = 0;
	
	int i = make_ip(source_mac, source_ip, dest_mac, dest_ip, 0x11, (uint8_t*)(&udp), 8 + data_len, buffer, buffer_offset);
	memcpy(buffer + i, &udp, 8); i += 8;
	if(data_len > 0)
	{
		memcpy(buffer + i, data, data_len); i += data_len;
	}
	
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
		EthernetHeader* eth = (EthernetHeader*)buffer;
		i = i + sizeof(EthernetHeader);
	    IpHeader* ip = (IpHeader*)(buffer + i);
		i = i + sizeof(IpHeader);
		UdpHeader* udp = (UdpHeader*)(buffer + i);
		i = i + sizeof(UdpHeader);
		
		if(ntohs(eth->Type) == 0x0800 && ip->Protocol == 0x11 && ntohs(udp->SourcePort) == 68)
		{			
			print_ip(ip->Source);
			printf(": DHCP Discovery/Request\n");
			
			DhcpHeader* i_dhcp = (DhcpHeader*)(buffer+i); i += sizeof(DhcpHeader);
			
			DhcpHeader o_dhcp;
			o_dhcp.Op = 2;
			o_dhcp.HType = 1;
			o_dhcp.HLength = 6;
			o_dhcp.Id = i_dhcp->Id;
			o_dhcp.Flags = ntohs(0x8000);
			o_dhcp.Yiaddr = lease_ip;
			o_dhcp.Siaddr = sender_ip;
			memcpy(o_dhcp.Chaddr, eth->Source, 6);
			o_dhcp.Magic = i_dhcp->Magic;
			
			uint8_t options[BUFFER_LEN];
			memcpy(options, &o_dhcp, sizeof(DhcpHeader));
			int j = sizeof(DhcpHeader);
			bool cont = false;
			
			for(int x = 0; x < j; x++)
			{
				printf("%hhx ", options[x]);
			}
			printf("\n");
			
			if(false && buffer[i + 2] == 1) //DHCP Discover
			{
				//Message Type
				options[j+0] = 53;
				options[j+1] = 1;
				options[j+2] = 2;
				j += 3;
				cont = true;
			}
			else if(false && buffer[i + 2] == 3) //DHCP Request
			{
				//Message Type
				options[j+0] = 53;
				options[j+1] = 1;
				options[j+2] = 5;
				j += 3;
				cont = true;
			}
				
			if(false)
			{
				int aux;
				
				//Server Identifier
				options[j+0] = 54;
				options[j+1] = 4;
				memcpy(options + (j + 2), &sender_ip, 4);
				j += 6;
				
				//Lease Time (One Day)
				aux = htonl(0x15180);
				options[j+0] = 58;
				options[j+1] = 4;
				memcpy(options + (j + 2), &aux, 4);
				j += 6;
				
				//Rebinding Time Value (21 Hours)
				aux = htonl(0x127550);
				options[j+0] = 59;
				options[j+1] = 4;
				memcpy(options + (j + 2), &aux, 4);
				j += 6;
				
				//Subnet Mask
				options[j+0] = 1;
				options[j+1] = 4;
				memcpy(options + (j + 2), &subnet_mask, 4);
				j += 6;
				
				//Broadcast Address
				aux = (sender_ip & subnet_mask) + (0xFFFFFFFF & ~subnet_mask);
				options[j+0] = 28;
				options[j+1] = 4;
				memcpy(options + (j + 2), &aux, 4);
				j += 6;
				
				//Subnet Mask
				options[j+0] = 6;
				options[j+1] = 4;
				memcpy(options + (j + 2), &dns_ip, 4);
				j += 6;
				
				//Router
				options[j+0] = 3;
				options[j+1] = 4;
				memcpy(options + (j + 2), &gateway_ip, 4);
				j += 6;
			}
			
			MacAddress broadcast;
			for (int k = 0; k < 6; k++) broadcast[k] = 0xFF;
			
			uint8_t out_buffer[BUFFER_LEN];
			i = make_udp(host_mac, sender_ip, htons(67), broadcast, 0xFFFFFFFF, htons(68), options, j, out_buffer, 0);
			printf("PacketSize: %d bytes\n", i);
			
			send_packet(out_buffer, i, sender_socket, host_mac);
		}
    }
}

int main(int argc, char *argv[])
{

	if(argc < 7)
    {
        printf("usage: %s ip local_mac adapter gateway_ip subnet_mask lease_ip dns_ip \n", argv[0]);
        exit(1);
    }

    //Config
    sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &host_mac[0], &host_mac[1], &host_mac[2], &host_mac[3], &host_mac[4], &host_mac[5]);

	struct in_addr addr_buffer;
	
	inet_aton(argv[1], &addr_buffer);
    sender_ip = addr_buffer.s_addr;
	
	inet_aton(argv[4], &addr_buffer);
    gateway_ip = addr_buffer.s_addr;
    
    inet_aton(argv[5], &addr_buffer);
    subnet_mask = addr_buffer.s_addr;
    
    inet_aton(argv[6], &addr_buffer);
    lease_ip = addr_buffer.s_addr;
    
    inet_aton(argv[7], &addr_buffer);
    dns_ip = addr_buffer.s_addr;
	
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

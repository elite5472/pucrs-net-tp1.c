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

#define ETHERTYPE_LEN 2
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define BUFFER_LEN 1518
#define ARP_LEN 28

using namespace std;

extern int errno;

int stats_frame_count = 0;

int stats_ip_count = 0;

int stats_ip_udp_count = 0;

int stats_ip_port_dhcp_count = 0;

bool mac_equal(MacAddress a, MacAddress b)
{
    for(int i = 0; i < 6; i++)
    {
        if(a[i] != b[i]) return false;
    }

    return true;
}

void print_ip(uint32_t ip)
{
	unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}

void print_mac(MacAddress* mac)
{
//    for(int i = 0; i < 6; ++i)
//        cout << mac[i];
}

void make_dhcp_discovery(DhcpHeader* frame_dhcp_discovery)
{
	frame_dhcp_discovery->opcode = 0x01;
	frame_dhcp_discovery->htype = 0x01;
	frame_dhcp_discovery->hlen = 0x06;
	frame_dhcp_discovery->hops = 0x00;
	frame_dhcp_discovery->xid = 0x01;
	frame_dhcp_discovery->secs = 0x00;
	frame_dhcp_discovery->flags = 0x1;
	frame_dhcp_discovery->ciaddr = 0x00;
	frame_dhcp_discovery->yiaddr = 0x00;
	frame_dhcp_discovery->siaddr = 0x00;
	frame_dhcp_discovery->giaddr = 0x00;
//	frame_dhcp_discovery->chaddr = 0xa41f72f5908f;
	frame_dhcp_discovery->chaddr[0] = 0x00;
	frame_dhcp_discovery->chaddr[1] = 0x00;
	frame_dhcp_discovery->chaddr[2] = 0x00;
	frame_dhcp_discovery->chaddr[3] = 0x00;
	frame_dhcp_discovery->chaddr[4] = 0x00;
	frame_dhcp_discovery->chaddr[5] = 0x01;
}

void make_dhcp_offer(DhcpHeader* frame_dhcp_offer, DhcpHeader* frame_dhcp_discover)
{
	frame_dhcp_offer->opcode = 0x02;
	frame_dhcp_offer->htype = 0x01;
	frame_dhcp_offer->hlen = 0x06;
	frame_dhcp_offer->hops = 0x00;
	frame_dhcp_offer->xid = frame_dhcp_discover->xid;
	frame_dhcp_offer->secs = 0x00;
	frame_dhcp_offer->flags = 0x00;
	frame_dhcp_offer->ciaddr = 0x00;
	frame_dhcp_offer->yiaddr = 0x01010101;
	frame_dhcp_offer->siaddr = 0x00;
	frame_dhcp_offer->giaddr = 0x00;
	frame_dhcp_offer->chaddr[0] = frame_dhcp_discover->chaddr[0];
	frame_dhcp_offer->chaddr[1] = frame_dhcp_discover->chaddr[1];
	frame_dhcp_offer->chaddr[2] = frame_dhcp_discover->chaddr[2];
	frame_dhcp_offer->chaddr[3] = frame_dhcp_discover->chaddr[3];
	frame_dhcp_offer->chaddr[4] = frame_dhcp_discover->chaddr[4];
	frame_dhcp_offer->chaddr[5] = frame_dhcp_discover->chaddr[5];
}

void make_udp(UdpHeader* frame_udp)
{
	frame_udp->SourcePort = 0x44;
	frame_udp->DestPort = 0x43;
	frame_udp->Length = 0x0134;
	frame_udp->Checksum = 0x00;
}

void make_ip(IpHeader* frame_ip)
{
	frame_ip->VersionIhl = 0x4;
	frame_ip->DscpEcn = 0x00;
	frame_ip->Length = 0x14;
	frame_ip->Id = 0x01;
	frame_ip->FlagsOffset = 0x00;
	frame_ip->Ttl = 0x80;
	frame_ip->Protocol = 0x11;
	frame_ip->Checksum = 0x00;
	frame_ip->Source = 0x00;
	frame_ip->Destination = 0xFFFFFFFF;
}

void make_ethernet(EthernetHeader* frame_ethernet)
{
	frame_ethernet->Destination[0] = 0xFF;
	frame_ethernet->Destination[1] = 0xFF;
	frame_ethernet->Destination[2] = 0xFF;
	frame_ethernet->Destination[3] = 0xFF;
	frame_ethernet->Destination[4] = 0xFF;
	frame_ethernet->Destination[5] = 0xFF;
	frame_ethernet->Source[0] = 0x00;
	frame_ethernet->Source[1] = 0x00;
	frame_ethernet->Source[2] = 0x00;
	frame_ethernet->Source[3] = 0x00;
	frame_ethernet->Source[4] = 0x00;
	frame_ethernet->Source[5] = 0x01;
	frame_ethernet->Type = 0x0800;
}

struct ifreq ifr;
void* thread_listener(void * arg)
{
    int thread_listener_socket = 0;
    struct ifreq ifr;
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

        stat_ethernet(ethheader, buffer);
    }
}

int sender_socket = 0;
MacAddress sender_host_mac;
bool send_packet(uint8_t buffer, int buffer_len)
{
	if(sender_socket == 0 && (sender_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0))
    {
        return false;
    }

	struct sockaddr_ll socket_header;
	socket_header.sll_family = htons(PF_PACKET);
	socket_header.sll_protocol = htons(ETH_P_ALL);
	socket_header.sll_halen = 6;
	socket_header.sll_ifindex = 2;
	memcpy(&(socket_header.sll_addr), sender_host_mac, 6);

	int result = 0;
    if((result = sendto(sender_socket, buffer, buffer_len, 0, (struct sockaddr *)&(socket_header), sizeof(struct sockaddr_ll))) < 0)
    {
    	return false;
    }
   	else
   	{
   		return true;
   	}
}

MacAddress* GetMacAddress()
{
	struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    unsigned char mac_address[6];

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
}

void* thread_flooder(void * arg)
{
		int sock, i;
		char buff[1518];
		struct sockaddr_ll to;
		socklen_t len;
		unsigned char addr[6];
		addr[0] = 0xFF;
		addr[1] = 0xFF;
		addr[2] = 0xFF;
		addr[3] = 0xFF;
		addr[4] = 0xFF;
		addr[5] = 0xFF;
		memcpy(to.sll_addr, addr, 6);

		memset(&ifr, 0, sizeof(ifr));
		if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
			printf("Erro na criacao do socket.\n");
			exit(1);
	 	}
//		to.sll_protocol= htons(ETH_P_ALL);
//		to.sll_ifindex = 1;

		EthernetHeader* frame_ethernet;
		IpHeader* frame_ip;
		UdpHeader* frame_udp;
		DhcpHeader* frame_dhcp;

		int i = 0;
		uint8_t buffer[BUFFER_LEN];
		memcpy(buffer + i, &frame_ethernet, sizeof(&frame_ethernet));
		i += sizeof(&frame_ethernet);
		

}

int main(int argc, char *argv[])
{

	if(argc < 3)
    {
        printf("usage: %s local_mac adapter \n", argv[0]);
        exit(1);
    }

    //Config
    MacAddress localhost;
    sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &localhost[0], &localhost[1], &localhost[2], &localhost[3], &localhost[4], &localhost[5]);

    sender_host_mac = localhost;

    if(argc >= 2)
    {
		strcpy(ifr.ifr_name, argv[1]);
    }
	else
	{
		strcpy(ifr.ifr_name, "eth0");
	}

/*	if((thread_listener_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("Error: Socket did not initialize. \n");
		exit(1);
	}
*/
	pthread_t flooder, listener;
	pthread_create(&flooder, NULL, &thread_flooder, NULL);
	pthread_create(&listener, NULL, &thread_listener, NULL);
	pthread_join(listener, NULL);
	pthread_join(flooder, NULL);

	return 0;
}

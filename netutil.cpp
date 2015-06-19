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

void print_mac(MacAddress a)
{
    printf("%x:%x:%x:%x:%x:%x", a[0], a[1], a[2], a[3], a[4], a[5]);
}

bool send_packet(uint8_t* buffer, int buffer_len, int sender_socket, MacAddress host_mac)
{
	if(sender_socket == 0 && (sender_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        return false;
    }

	struct sockaddr_ll socket_header;
	socket_header.sll_family = htons(PF_PACKET);
	socket_header.sll_protocol = htons(ETH_P_ALL);
	socket_header.sll_halen = 6;
	socket_header.sll_ifindex = 2;
	memcpy(&(socket_header.sll_addr), host_mac, 6);

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
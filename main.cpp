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

#include "netutil.cpp"

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

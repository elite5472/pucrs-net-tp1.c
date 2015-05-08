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

extern int errno;

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

int stats_frame_count = 0;
int stats_frame_size_min = 0;
int stats_frame_size_max = 0;
int stats_frame_size_total = 0;

int stats_arp_count = 0;
int stats_arp_request_count = 0;
int stats_arp_reply_count = 0;

int stats_ip_count = 0;
unordered_map<uint32_t, int> stats_ip_access_count = {};

int stats_ip_icmp_count = 0;
int stats_ip_icmp_echo_request_count = 0;
int stats_ip_icmp_echo_reply_count = 0;

int stats_ip_udp_count = 0;
int stats_ip_tcp_count = 0;

unordered_map<uint16_t, int> stats_ip_tcp_access_count = {};
unordered_map<uint16_t, int> stats_ip_udp_access_count = {};

int stats_ip_tcp_initiated_count = 0; // tcp connections initiated count

int stats_ip_port_http_count = 0;
int stats_ip_port_https_count = 0;
int stats_ip_port_dns_count = 0;
int stats_ip_port_ftp_count = 0;

unordered_map<uint32_t, int> stats_ip_website_access_count;

void print_mac(MacAddress s)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x", s[0],s[1],s[2],s[3],s[4],s[5]);
}

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

void stat_arp(ArpHeader* frame)
{
    MacAddress zero = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    stats_arp_count++;
    if (mac_equal(frame->TargetHardwareAddress, zero))
        stats_arp_request_count++;
    else
        stats_arp_reply_count++;
}

void stat_icmp(IcmpHeader* frame)
{
    stats_ip_icmp_count++;
    if(ntohs(frame->Type) == 0x0000)
        stats_ip_icmp_echo_reply_count++;
    if(ntohs(frame->Type) == 0x0800)
        stats_ip_icmp_echo_request_count++;
}

void stat_tcp(TcpHeader* frame_tcp, IpHeader* frame_ip)
{
    stats_ip_tcp_count++;
    
    unordered_map<uint16_t, int>::const_iterator got = stats_ip_tcp_access_count.find(frame_tcp->DestPort);
    if(got == stats_ip_tcp_access_count.end())
        stats_ip_tcp_access_count[frame_tcp->DestPort] = 1;
    else
        stats_ip_tcp_access_count[frame_tcp->DestPort] += 1;

    if(ntohs(frame_tcp->DestPort) == 80)
    {
        stats_ip_port_http_count++;
    }
    
    if(ntohs(frame_tcp->DestPort) == 443)
    {
        stats_ip_port_https_count++;
    }
    
    if(ntohs(frame_tcp->DestPort) == 80 || ntohs(frame_tcp->DestPort) == 443)
    {
        unordered_map<uint32_t, int>::const_iterator got = stats_ip_website_access_count.find(frame->Destination);
        if(got == stats_ip_website_access_count.end())
            stats_ip_website_access_count[frame_ip->Destination] = 1;
        else
            stats_ip_website_access_count[frame_ip->Destination] = stats_ip_website_access_count[frame_ip->Destination] + 1;
    }
    
    if(ntohs(frame_tcp->DestPort) == 21)
    {
        stats_ip_port_ftp_count++;
    }

    int ack = (frame_tcp->Flags >> 4) & 1;
    int syn = frame_tcp->Flags & 1;
    if(ack == 1 && syn == 0)                // canal tcp - 1 passo: ack = 0 e syn = 1, 2 passo: ack = 1 e syn = 1, 3 passo: ack = 1 e syn = 0
        ++stats_ip_tcp_initiated_count;
}

void stat_udp(UdpHeader* frame)
{
    stats_ip_udp_count++;
    unordered_map<uint16_t, int>::const_iterator got = stats_ip_udp_access_count.find(frame->DestPort);
    
    if(got == stats_ip_udp_access_count.end())
        stats_ip_udp_access_count[frame->DestPort] = 1;
    else
        stats_ip_udp_access_count[frame->DestPort] += 1;
        
    if(ntohs(frame->DestPort) == 53)
    {
        stats_ip_port_dns_count++;
    }
    
    if(ntohs(frame->DestPort) == 21)
    {
        stats_ip_port_ftp_count++;
    }

}

void stat_ip(IpHeader* frame, unsigned char* buffer)
{
    stats_ip_count++;
    stats_ip_access_count[frame->Destination] = stats_ip_access_count[frame->Destination] + 1;

	
    unordered_map<uint32_t, int>::const_iterator got = stats_ip_access_count.find(frame->Destination);
    if(got == stats_ip_access_count.end())
        stats_ip_access_count[frame->Destination] = 1;
    else
        stats_ip_access_count[frame->Destination] = stats_ip_access_count[frame->Destination] + 1;

    if(ntohs(frame->Protocol) == 0x0100)
        stat_icmp((IcmpHeader*)(buffer+20));

    if(ntohs(frame->Protocol) == 0x0600)
        stat_tcp((TcpHeader*)(buffer+20), frame);

    if(ntohs(frame->Protocol) == 0x1100)
        stat_udp((UdpHeader*)(buffer+20));

    //printf("To: "); print_ip(ntohl(frame->Destination));
}

void stat_ethernet(EthernetHeader* frame, unsigned char* buffer)
{
    //112 (14)
    stats_frame_count++;

    if(ntohs(frame->Type) == 0x0806)
    {
        int size = 42;
        if(stats_frame_size_min > size || stats_frame_size_min == 0) stats_frame_size_min = size;
        if(stats_frame_size_max < size) stats_frame_size_max = size;
        stats_frame_size_total += size;

        ArpHeader* frame = (ArpHeader*)(buffer +14);
        stat_arp(frame);
    }

    else if(ntohs(frame->Type) == 0x0800)
    {
        IpHeader* ip = (IpHeader*)(buffer + 14);
        int size = 14 + ntohs(ip->Length);
        if(stats_frame_size_min > size || stats_frame_size_min == 0) stats_frame_size_min = size;
        if(stats_frame_size_max < size) stats_frame_size_max = size;
        stats_frame_size_total += size;

        stat_ip(ip, (buffer+14));
    }
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

        stat_ethernet(ethheader, buffer);
    }
}

void printMenu(){
    int i = 1;
	cout << endl << "Geral:" << endl;
	cout << "\t" << i++ << ") Apresentar min/max/média do tamanho dos pacotes recebidos" << endl;

	cout << endl << "Nível de Enlace:" << endl;
	cout << "\t" << i++ << ") Quantidade e porcentagem de ARP Requests e ARP Reply" << endl;

	cout << endl << "Nível de Rede:" << endl;
	cout << "\t" << i++ << ") Quantidade e porcentagem de pacotes ICMP" << endl;
	cout << "\t" << i++ << ") Quantidade e porcentagem de ICMP Echo Request e ICMP Echo Reply" << endl;
	cout << "\t" << i++ << ") Lista com os 5 IPs mais acessados na rede" << endl;

	cout << endl << "Nível de Transporte:" << endl;
	cout << "\t" << i++ << ") Quantidade e porcentagem de pacotes UDP" << endl;
	cout << "\t" << i++ << ") Quantidade e porcentagem de pacotes TCP" << endl;
	cout << "\t" << i++ << ") Número de conexões TCP iniciadas" << endl;
	cout << "\t" << i++ << ") Lista com as 5 portas TCP mais acessadas" << endl;
	cout << "\t" << i++ << ") Lista com as 5 portas UDP mais acessadas" << endl;

	cout << endl << "Nível de Aplicação:" << endl;
	cout << "\t" << i++ << ") Quantidade e porcentagem de pacotes HTTP" << endl;
    cout << "\t" << i++ << ") Quantidade e porcentagem de pacotes HTTPS" << endl;
	cout << "\t" << i++ << ") Quantidade e porcentagem de pacotes DNS" << endl;
	cout << "\t" << i++ << ") Quantidade e porcentagem de pacotes FTP" << endl;
	cout << "\t" << i++ << ") Lista com os 5 sites mais acessados" << endl << endl;
}

int get_lowest_i(int* a, int len)
{
    int lowest_i = 0;
    int lowest_val = a[0];
    for(int i = 1; i < len; i++)
    {
        if(a[i] < lowest_val)
        {
            lowest_i = i;
            lowest_val = a[i];
        }
    }
    return lowest_i;
}

void* thread_cmd(void * arg)
{
 
	int cod;
    printMenu();
    
    while(true)
    {
        cout << endl << "Escolha uma opção: ";
        cin >> cod;
        
        if(stats_frame_count == 0)
        {
            cout << "Nemum pacote foi interceptado, tente de novo." << endl;
            continue;
        }
        
        switch(cod)
        {
        	case 1:
            {
        		cout << "Min: " << stats_frame_size_min << " bytes" << endl;
        		cout << "Max: " << stats_frame_size_max << " bytes" << endl;
        		cout << "Média: " << stats_frame_size_total/stats_frame_count << " bytes" << endl;
        		break;
        	}
        	case 2:
            {
        		cout << "Quantidade e Porcentagem ARP Request: " << stats_arp_request_count;
                    printf(", %.2f%%\n", (stats_arp_request_count * 100.0)/ stats_frame_count);
        		cout << "Quantidade e Porcentagem ARP Reply: " << stats_arp_reply_count;
        			printf(", %.2f%%\n", (stats_arp_reply_count * 100.0)/ stats_frame_count);
        		break;
        	}
        	case 3:
            {
        		cout << "Quantidade e porcentagem de pacotes ICMP: " << stats_ip_icmp_count;
                    printf(", %.2f%%\n", (stats_ip_icmp_count * 100.0)/ stats_frame_count);
        		break;
        	}
        	case 4:
            {
        		cout << "Quantidade e porcentagem de ICMP Echo Request: " << stats_ip_icmp_echo_request_count;
                    printf(", %.2f%%\n", (stats_ip_icmp_echo_request_count * 100.0)/ stats_frame_count);
        		cout << "Quantidade e porcentagem de ICMP Echo Reply: " << stats_ip_icmp_echo_reply_count;
                    printf(", %.2f%%\n", (stats_ip_icmp_echo_reply_count * 100.0)/ stats_frame_count);
        		break;
        	}
        	case 5:
            {
        		cout << "Lista com os 5 IPs mais acessados na rede:" << endl;
        
        		int amount[5] = {0,0,0,0,0};
        		uint32_t dest[5] = {0,0,0,0,0};
        		for(auto it = stats_ip_access_count.begin(); it != stats_ip_access_count.end(); it++)
                {
                    int key = it->first;
                    int val = it->second;
                    int i = get_lowest_i(amount, 5);
                    if (val > amount[i])
                    {
                        dest[i] = key;
                        amount[i] = val;
                    }
                }

                for( int i = 0; i < 5; i++ ) if (dest[i] != 0)
                {
                    print_ip(dest[i]);
                    cout << ", " << amount[i] << " vezes." << endl;
                }
        		break;
        	}
        	case 6:
            {
        		cout << "Quantidade e porcentagem de pacotes UDP: " << stats_ip_udp_count;
        			printf(", %.2f%%\n", (stats_ip_udp_count * 100.0)/ stats_frame_count);
        		break;
        	}
        	case 7:
            {
        		cout << "Quantidade e porcentagem de pacotes TCP: " << stats_ip_tcp_count;
        			printf(", %.2f%%\n", (stats_ip_tcp_count * 100.0)/ stats_frame_count);
        		break;
        	}
        	case 8:
            {
        		cout << "Número de conexões TCP iniciadas: " << stats_ip_tcp_initiated_count;
        		break;
        	}
        	case 9:
            {
        		cout << "Lista com as 5 portas TCP mais acessadas: " << endl;
                
                int amount[5] = {0,0,0,0,0};
        		uint16_t dest[5] = {0,0,0,0,0};
        		for(auto it = stats_ip_tcp_access_count.begin(); it != stats_ip_tcp_access_count.end(); it++)
                {
                    int key = it->first;
                    int val = it->second;
                    int i = get_lowest_i(amount, 5);
                    if (val > amount[i])
                    {
                        dest[i] = key;
                        amount[i] = val;
                    }
                }

                for( int i = 0; i < 5; i++ ) if (dest[i] != 0)
                {
                    cout << ntohs(dest[i]) << ", " << amount[i] << " vezes." << endl;
                }
        		break;
        	}
        	case 10:{
        		cout << "Lista com as 5 portas UDP mais acessadas" << endl;
                
                int amount[5] = {0,0,0,0,0};
        		uint16_t dest[5] = {0,0,0,0,0};
        		for(auto it = stats_ip_udp_access_count.begin(); it != stats_ip_udp_access_count.end(); it++)
                {
                    int key = it->first;
                    int val = it->second;
                    int i = get_lowest_i(amount, 5);
                    if (val > amount[i])
                    {
                        dest[i] = key;
                        amount[i] = val;
                    }
                }

                for( int i = 0; i < 5; i++ ) if (dest[i] != 0)
                {
                    cout << ntohs(dest[i]) << ", " << amount[i] << " vezes." << endl;
                }
        		break;
        	}
        	case 11:
            {
                cout << "Quantidade e porcentagem de pacotes HTTP: " << stats_ip_port_http_count;
                    printf(", %.2f%%\n", (stats_ip_port_http_count * 100.0)/ stats_frame_count);
        		break;
        	}
            case 12:
            {
                cout << "Quantidade e porcentagem de pacotes HTTPS: " << stats_ip_port_https_count;
                    printf(", %.2f%%\n", (stats_ip_port_https_count * 100.0)/ stats_frame_count);
        		break;
        	}
        	case 13:
            {
        		cout << "Quantidade e porcentagem de pacotes DNS: " << stats_ip_port_dns_count;
                    printf(", %.2f%%\n", (stats_ip_port_dns_count * 100.0)/ stats_frame_count);
        		break;
        	}
        	case 14:
            {
        		cout << "Quantidade e porcentagem de pacotes FTP: " << stats_ip_port_ftp_count;
                    printf(", %.2f%%\n", (stats_ip_port_ftp_count * 100.0)/ stats_frame_count);
        		break;
        	}
        	case 15:
            {
        		cout << "Lista com os 5 sites mais acessados: " << endl;
        		int amount[5] = {0,0,0,0,0};
        		uint32_t dest[5] = {0,0,0,0,0};
        		for(auto it = stats_ip_website_access_count.begin(); it != stats_ip_website_access_count.end(); it++)
                {
                    int key = it->first;
                    int val = it->second;
                    int i = get_lowest_i(amount, 5);
                    if (val > amount[i])
                    {
                        dest[i] = key;
                        amount[i] = val;
                    }
                }

                for( int i = 0; i < 5; i++ ) if (dest[i] != 0)
                {
                    print_ip(dest[i]);
                    cout << ", " << amount[i] << " vezes." << endl;
                }
        		break;
        	 }
        }
    }
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

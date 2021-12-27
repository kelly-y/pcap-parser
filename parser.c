#include<stdio.h>
#include<time.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<net/if.h>
#include<net/ethernet.h>
#include<netinet/if_ether.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<arpa/inet.h>
#include<pcap.h>

typedef unsigned char u_char;
#define PCAP_BUFSIZE 1024

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    struct ether_header* ethernetHeader;
    struct ip* ipHeader;
    struct tcphdr* tcpHeader;
    struct udphdr* udpHeader;
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;

    // Time stamp
    printf("[Time]: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));
    
    // Ethernet 欄位，MAC 位址
    ethernetHeader = (struct ether_header*)packet;
    u_char *sMac = ethernetHeader->ether_shost;
    u_char *dMac = ethernetHeader->ether_dhost;
    printf("[MAC Address]\nSoruce: %02x-%02x-%02x-%02x-%02x-%02x\n", sMac[0], sMac[1], sMac[2], sMac[3], sMac[4], sMac[5]);
    printf("Destination: %02x-%02x-%02x-%02x-%02x-%02x\n\n", dMac[0], dMac[1], dMac[2], dMac[3], dMac[4], dMac[5]);

    if( ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP ) {   // IP protocol
        printf("[Ether Type]: Internet Protocol version 4 (IPv4)\n");

        // IP 來源位址 & 目的地位址
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
        printf("Source IP Address: %s\n", sourceIP);
        printf("Destination IP Address: %s\n\n", destIP);

        // TCP or UDP
        if( ipHeader->ip_p == IPPROTO_TCP ) {
            tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);
            printf("[Transmission Control Protocol (TCP)]\nSource Port: %u\n", sourcePort);
            printf("Destination Port: %u\n\n", destPort);
        } else if( ipHeader->ip_p == IPPROTO_UDP ) {
            udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(udpHeader->source);
            destPort = ntohs(udpHeader->dest);
            printf("[User Datagram Protocol (UDP)]\nSoruce Port: %u\n", sourcePort);
            printf("Destination Port: %u\n\n", destPort);
        }

    } else if( ntohs(ethernetHeader->ether_type) == 0x08DD ) {
        printf("[Ether Type]: Internet Protocol version 6 (IPv6)\n\n");
    } else if( ntohs(ethernetHeader->ether_type) == ETHERTYPE_PUP ) {
        printf("[Ether Type]: PUP Protocol\n\n");
    } else if( ntohs(ethernetHeader->ether_type) == ETHERTYPE_ARP ) {
        printf("[Ether Type]: Address Resolution Protocol\n\n");
    }

    printf("------------------------------------------------------\n\n");
    return;
}

int main(int argc, char *argv[])
{
    // Illegal filename
    if(argc != 2) {
        printf("Please enter legal pcap fileneme.\n");
        return 0;
    }

    pcap_t *pfp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUFSIZE];

    // 開啟 pcap 檔案
    pfp = pcap_open_offline_with_tstamp_precision(argv[1], PCAP_TSTAMP_PRECISION_MICRO, errbuf);
    if( !pfp ) {
        fprintf(stderr, "\npcap_open_offline_with_tstamp_precision() failed: %s\n", errbuf);
        return 0;
    }

    // 迴圈讀取 pcap 檔案
    if( pcap_loop(pfp, 0, packetHandler, NULL) < 0 ) {
        fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(pfp));
        return 0;
    }

    pcap_close(pfp);
    return 0;
}
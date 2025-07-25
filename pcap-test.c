#include "pcap-test.h"
#include <stdio.h>
#include <arpa/inet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test eth0\n");
}

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]){
    if(argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_packet(const struct pcap_pkthdr* header, const u_char* packet) {

    const struct Ethernet *ethernet;
    const struct IP *ip;
    const struct TCP *tcp;

    ethernet = (struct Ethernet *)packet;
    ip = (struct IP *)(packet + sizeof(struct Ethernet));
    tcp = (struct TCP *)(packet + (sizeof(struct Ethernet)) + (ip->ihl * 4));

    if(ip->protocol == 0x06 && ntohs(ethernet->ether_type) == 0x0800) {
        printf("[Ethernet]\n");

        printf("Source Mac: ");
        for(int i = 0; i < 6; i++) {
            printf("%02X", ethernet->ether_src[i]);
            if(i < 5)
                printf(" : ");
            else
                printf("\n");
        }

        printf("Destination Mac: ");
        for(int i = 0; i < 6; i++) {
            printf("%02X", ethernet->ether_dst[i]);
            if(i < 5)
                printf(" : ");
            else
                printf("\n");
        }

        printf("[IP]\n");

        printf("Source IP: %s\n", inet_ntoa(ip->iph_src));

        printf("Destination IP: %s\n", inet_ntoa(ip->iph_dst));

        printf("[TCP]\n");

        printf("Source Port: %d\n", ntohs(tcp->tcp_srcp));

        printf("Destination Port: %d\n", ntohs(tcp->tcp_dstp));

        int tcp_header_len = ((tcp->reserved & 0xF0) >> 4) * 4;
        int payload_offset = sizeof(struct Ethernet) + (ip->ihl * 4) + tcp_header_len;
        int payload_len = header->caplen - payload_offset;
        const uint8_t* payload = packet + payload_offset;

        printf("TCP Payload: ");
        for(int i = 0; i < payload_len && i < 20; i++) {
            printf("%02X ", payload[i]);
        }

        printf("\n---------------------------------------------------\n");
    }
}

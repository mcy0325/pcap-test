#pragma once
#include <pcap.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

struct Ethernet {
    uint8_t ether_dst[6];
    uint8_t ether_src[6];
    uint16_t ether_type;
} __attribute__ ((__packed__));

struct IP {
    uint8_t ihl:4;
    uint8_t ver:4;
    uint8_t service;
    uint16_t ip_total_length;
    uint16_t identification;
    uint16_t flags_fragOffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    struct in_addr iph_src;
    struct in_addr iph_dst;
}__attribute__ ((__packed__));

struct TCP {
    uint16_t tcp_srcp;
    uint16_t tcp_dstp;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t reserved;
}__attribute__ ((__packed__));

void usage();

typedef struct {
    char* dev_;
} Param;

extern Param param;

bool parse(Param* param, int argc, char* argv[]);

void print_packet(const struct pcap_pkthdr* header, const u_char* packet);

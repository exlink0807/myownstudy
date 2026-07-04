#ifndef MYHEADER_H
#define MYHEADER_H

#include <stdint.h>

/* ===================== Ethernet Header (14 bytes, 고정 길이) ===================== */
#define ETHER_ADDR_LEN 6

struct ethheader {
    u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host MAC address */
    u_char  ether_shost[ETHER_ADDR_LEN]; /* source host MAC address */
    u_short ether_type;                  /* protocol type (IP, ARP, ...) */
};

/* ===================== IP Header (가변 길이: ip_hl * 4) ===================== */
struct ipheader {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char iph_ihl:4,   /* IP header length (단위: 4바이트) */
                  iph_ver:4;   /* IP version */
#else
    unsigned char iph_ver:4,
                  iph_ihl:4;
#endif
    unsigned char  iph_tos;      /* Type of service */
    unsigned short iph_len;      /* IP Packet length (data + header) */
    unsigned short iph_ident;    /* Identification */
    unsigned short iph_flag:3,   /* Fragmentation flags */
                   iph_offset:13;/* Flags offset */
    unsigned char  iph_ttl;      /* Time to Live */
    unsigned char  iph_protocol; /* Protocol type (TCP=6, UDP=17, ...) */
    unsigned short iph_chksum;   /* IP datagram checksum */
    struct  in_addr iph_sourceip;/* Source IP address */
    struct  in_addr iph_destip;  /* Destination IP address */
};

/* ===================== TCP Header (가변 길이: tcp_offx2 >> 4 * 4) ===================== */
struct tcpheader {
    unsigned short tcp_sport;    /* source port */
    unsigned short tcp_dport;    /* destination port */
    unsigned int   tcp_seq;      /* sequence number */
    unsigned int   tcp_ack;      /* acknowledgement number */
    unsigned char  tcp_offx2;    /* data offset(상위 4bit), reserved(하위 4bit) */
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    unsigned char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
    unsigned short tcp_win;      /* window */
    unsigned short tcp_sum;      /* checksum */
    unsigned short tcp_urp;      /* urgent pointer */
};

#endif

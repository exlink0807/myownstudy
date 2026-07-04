/*
 * sniff_improved.c
 * -----------------------------------------------------------
 * libpcap 기반 TCP 패킷 스니퍼
 *  - Ethernet Header : src mac / dst mac
 *  - IP Header       : src ip / dst ip
 *  - TCP Header      : src port / dst port
 *  - Application(HTTP) Message 출력
 *
 * 컴파일:  gcc -o sniff_improved sniff_improved.c -lpcap
 * 실행:    sudo ./sniff_improved <interface>      (실시간 캡처)
 *          sudo ./sniff_improved -r <file.pcap>   (pcap 파일 읽기)
 * -----------------------------------------------------------
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <endian.h>
#include <ctype.h>
#include "myheader.h"

/* MAC 주소를 "aa:bb:cc:dd:ee:ff" 형태 문자열로 출력 */
void print_mac(const char *label, const u_char *mac) {
    printf("%s %02x:%02x:%02x:%02x:%02x:%02x\n", label,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    /* ---------- 1. Ethernet Header ---------- */
    struct ethheader *eth = (struct ethheader *)packet;

    /* IP 패킷이 아니면 무시 (0x0800 = IPv4) */
    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }

    printf("\n========================= Packet Captured (%d bytes) =========================\n",
           header->len);

    printf("[Ethernet Header]\n");
    print_mac("  Src MAC: ", eth->ether_shost);
    print_mac("  Dst MAC: ", eth->ether_dhost);

    /* ---------- 2. IP Header (가변 길이 처리) ---------- */
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    int ip_header_len = ip->iph_ihl * 4;      /* ihl 단위: 4바이트 -> 실제 바이트 길이 */
    if (ip_header_len < 20) {
        printf("Invalid IP header length\n");
        return;
    }

    printf("[IP Header] (length: %d bytes)\n", ip_header_len);
    printf("  Src IP : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Dst IP : %s\n", inet_ntoa(ip->iph_destip));

    /* TCP가 아니면 무시 (protocol 6 = TCP) */
    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    /* ---------- 3. TCP Header (가변 길이 처리) ---------- */
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

    int tcp_header_len = TH_OFF(tcp) * 4;     /* data offset 단위: 4바이트 -> 실제 바이트 길이 */
    if (tcp_header_len < 20) {
        printf("Invalid TCP header length\n");
        return;
    }

    printf("[TCP Header] (length: %d bytes)\n", tcp_header_len);
    printf("  Src Port : %d\n", ntohs(tcp->tcp_sport));
    printf("  Dst Port : %d\n", ntohs(tcp->tcp_dport));

    /* ---------- 4. Application Layer Data (HTTP Message) ---------- */
    int ethernet_header_len = sizeof(struct ethheader);
    int total_header_len = ethernet_header_len + ip_header_len + tcp_header_len;

    /* 실제 캡처된 IP 전체 길이(iph_len)를 이용해 payload 길이 계산 */
    int ip_total_len = ntohs(ip->iph_len);
    int payload_len = ip_total_len - (ip_header_len + tcp_header_len);

    const u_char *payload = packet + total_header_len;

    if (payload_len > 0) {
        printf("[HTTP Message] (%d bytes)\n", payload_len);
        /* 캡처된 실제 바이트 수를 넘어서 읽지 않도록 방어 */
        int available = header->caplen - total_header_len;
        int print_len = (payload_len < available) ? payload_len : available;
        if (print_len > 0) {
            for (int i = 0; i < print_len; i++) {
                /* 출력 가능한 아스키 문자만 그대로, 나머지는 '.' 처리 */
                putchar(isprint(payload[i]) ? payload[i] : '.');
            }
            printf("\n");
        }
    } else {
        printf("[HTTP Message] (no payload / flags only, e.g. SYN/ACK/FIN)\n");
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";   /* TCP protocol만 대상으로 진행 (UDP 무시) */
    bpf_u_int32 net = 0, mask = 0;

    if (argc == 3 && strcmp(argv[1], "-r") == 0) {
        /* pcap 파일에서 읽기 모드 */
        handle = pcap_open_offline(argv[2], errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[2], errbuf);
            return 1;
        }
    } else if (argc == 2) {
        /* 실시간 캡처 모드: 인터페이스 이름 지정 (예: eth0, en0) */
        pcap_lookupnet(argv[1], &net, &mask, errbuf);
        handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
            return 1;
        }
    } else {
        printf("Usage:\n");
        printf("  %s <interface>       : 실시간 캡처 (관리자 권한 필요)\n", argv[0]);
        printf("  %s -r <file.pcap>    : pcap 파일 분석\n", argv[0]);
        return 1;
    }

    /* TCP만 캡처하도록 BPF 필터 적용 */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    printf("Start capturing TCP packets...\n");
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}

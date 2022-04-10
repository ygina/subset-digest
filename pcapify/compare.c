#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

char errbuf[PCAP_ERRBUF_SIZE];

const uint32_t SRC_IP_ADDR = 604783275,
               DST_IP_ADDR = 4270877056;

void pip(const void *bytes) {
    for (size_t i = 0; i < 4; i++) {
        printf("%u%c", ((const uint8_t*)bytes)[i], i == 3 ? ' ' : '.');
    }
    printf("= %u", *(const uint32_t*)bytes);
}

int cmptimeval(struct timeval t1, struct timeval t2) {
    if (t1.tv_sec != t2.tv_sec)
        return t1.tv_sec < t2.tv_sec ? -1 : +1;
    return t1.tv_usec < t2.tv_usec ? -1 : +1;
}

int is_sync(struct pcap_pkthdr h, const u_char *bytes) {
    if (h.len < (42 + strlen("HI MASOT") + 8)) return -1;
    if (strncmp("HI MASOT", bytes + 42, strlen("HI MASOT"))) {
        return -1;
    }
    // for (size_t i = 42; i < h.len; i++) {
    //     printf("\t%u = %c\n", bytes[i], bytes[i]);
    // }
    bytes += 42 + strlen("HI MASOT");
    uint32_t count = ntohl(*(int32_t*)(bytes + 4));
    return count;
}

void process_pkt(struct pcap_pkthdr h, const u_char *bytes) {
    int which_sync = 0;
    if ((which_sync = is_sync(h, bytes)) > -1) {
        printf("\tSYNC! %8d\n", which_sync);
        return;
    }
    printf("\tTime %lus:%luus\n", h.ts.tv_sec, h.ts.tv_usec);
    printf("\tN bytes: %u\n", h.len);
    struct ether_header *eth = (typeof(eth))(bytes);
    printf("\tEth type: 0x%x\n", eth->ether_type);
    struct ip *ip = (typeof(ip))(bytes + 14);
    printf("\tIP src: "); pip(&(ip->ip_src)); printf("\n");
    printf("\tIP dst: "); pip(&(ip->ip_dst)); printf("\n");
}

const u_char *pcap_next_real(pcap_t *p, struct pcap_pkthdr *h, int is_dst) {
    for (const u_char *bytes; bytes = pcap_next(p, h); ) {
        struct ip *ip = (typeof(ip))(bytes + 14);
        if (is_dst && *((uint32_t*)(&(ip->ip_src))) == SRC_IP_ADDR)    return bytes;
        if (!is_dst && *((uint32_t*)(&(ip->ip_dst))) == DST_IP_ADDR)   return bytes;
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: compare {src} {dst}\n");
        return -1;
    }
    pcap_t *p_src = pcap_open_offline(argv[1], errbuf),
           *p_dst = pcap_open_offline(argv[2], errbuf);
    struct pcap_pkthdr head_src, head_dst;
    const u_char *head_src_bytes = pcap_next_real(p_src, &head_src, 0),
                 *head_dst_bytes = pcap_next_real(p_dst, &head_dst, 1);
    while (head_src_bytes || head_dst_bytes) {
        // Process the packet that arrived first.
        if (!head_dst_bytes || (head_src_bytes && cmptimeval(head_src.ts, head_dst.ts) < 0)) {
            printf("Source sent packet...\n");
            process_pkt(head_src, head_src_bytes);
            head_src_bytes = pcap_next_real(p_src, &head_src, 0);
        } else {
            printf("Dst received packet...\n");
            process_pkt(head_dst, head_dst_bytes);
            head_dst_bytes = pcap_next_real(p_dst, &head_dst, 1);
        }
    }
}

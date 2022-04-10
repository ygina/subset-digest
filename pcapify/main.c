#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#define DUMP 0

pcap_t *p;
pcap_dumper_t *d = 0;

void phex(const void *bytes, int n_bytes) {
    printf("0x");
    for (size_t i = 0; i < n_bytes; i++) {
        printf("%02x", ((const uint8_t*)bytes)[i]);
    }
}

void plhex(const void *bytes, int n_bytes) {
    for (size_t i = 0; i < n_bytes; i++) {
        printf("%02x:", ((const uint8_t*)bytes)[i]);
    }
}

void pip(const void *bytes) {
    for (size_t i = 0; i < 4; i++) {
        printf("%u%c", ((const uint8_t*)bytes)[i], i == 3 ? ' ' : '.');
    }
}

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    static size_t n_found = 0;
#if DUMP
    if (d == 0) d = pcap_dump_open(p, "out.pcap");
    if (d == 0) { printf("%s\n", pcap_geterr(p)); exit(-1); }
    pcap_dump(d, h, bytes);
#endif
    if (n_found++ > 10) {
        pcap_breakloop(p);
        return;
    }
    printf("Got packet: %u %u\n", h->caplen, h->len);
    plhex(bytes, h->caplen);
    struct ether_header *eth = (typeof(eth))(bytes);
    // printf("Destination address: ");
    // plhex(&(eth->ether_dhost), 6);
    // printf("\n");
    // printf("Source address: ");
    // plhex(&(eth->ether_shost), 6);
    // printf("\n");
    // printf("EtherType: ");
    // plhex(&(eth->ether_type), 2);
    // printf("\n");

    struct ip *ip = (typeof(ip))(bytes + 14);
    printf("IP:\n");
    plhex(ip, sizeof(*ip));
    printf("\n");

    printf("IP src: ");
    pip(&(ip->ip_src));
    printf("\n");

    printf("IP dst: ");
    pip(&(ip->ip_dst));
    printf("\n");
}

const char *filter = "!broadcast";

char errbuf[PCAP_ERRBUF_SIZE];
int main() {
    pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
    p = pcap_create("wlp3s0", errbuf);

    pcap_activate(p);

    pcap_set_promisc(p, 0);
    pcap_setdirection(p, PCAP_D_OUT);

    struct bpf_program fp;
    pcap_compile(p, &fp, filter, 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(p, &fp);

    pcap_loop(p, -1, callback, NULL);

#if DUMP
    pcap_dump_flush(d);
    pcap_dump_close(d);
#endif

    return 0;
}

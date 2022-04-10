#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

// const char *filter = "src host 10.34.160.201 and !broadcast";
const char *filter = "!broadcast";
const char *dev = "wlp3s0";
const pcap_direction_t direction = PCAP_D_OUT;

pcap_t *p;
pcap_dumper_t *d = 0;

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    static size_t n_found = 0;
    if (d == 0) d = pcap_dump_open(p, "dump.pcap");
    if (d == 0) exit(-1);

    pcap_dump((void*)d, h, bytes);

    if ((n_found++) % 10 == 0) {
        pcap_dump_flush(d);
        return;
    }

    printf("Got packet: %u %u\n", h->caplen, h->len);
}

char errbuf[PCAP_ERRBUF_SIZE];
int main() {
    pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
    p = pcap_create(dev, errbuf);

    pcap_activate(p);

    pcap_set_promisc(p, 0);
    pcap_setdirection(p, direction);

    struct bpf_program fp;
    pcap_compile(p, &fp, filter, 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(p, &fp);

    pcap_loop(p, -1, callback, NULL);

    pcap_dump_flush(d);
    pcap_dump_close(d);

    return 0;
}

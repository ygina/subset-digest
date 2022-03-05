#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glpk.h>
#include "options.h"
#include "iblt.h"

int ilp_list(struct bloom_cell *iblt, size_t *options, size_t *keys, size_t *n_keys);

int main() {
    srand(24);

#if DISJOINT_BUCKET_RANGES
    assert(!(n_buckets % n_hashes));
#endif

    size_t *packets = malloc(n_packets * sizeof(packets[0]));
    for (size_t i = 0; i < n_packets; i++) packets[i] = rand();
    qsort(packets, n_packets, sizeof(packets[0]), compare_size_ts);

    size_t *dropped = malloc(n_dropped * sizeof(dropped[0]));
    for (size_t i = 0; i < n_dropped; i++) {
redrop: dropped[i] = rand() % n_packets;
        for (size_t j = 0; j < i; j++)
            if (dropped[j] == dropped[i])
                goto redrop;
        VERBOSE_DO(printf("Dropping %lu\n", dropped[i]);)
    }
    qsort(dropped, n_dropped, sizeof(dropped[0]), compare_size_ts);

    struct bloom_cell *src_table = calloc(n_buckets, sizeof(src_table[0])),
                      *dst_table = calloc(n_buckets, sizeof(dst_table[0]));
    // Insert the packets.
    size_t drop_idx = 0;
    for (size_t i = 0; i < n_packets; i++) {
        iblt_modify(src_table, packets[i], IBLT_INSERT);

        int is_dropped = drop_idx < n_dropped && dropped[drop_idx] == i;
        if (is_dropped) drop_idx++;
        else            iblt_modify(dst_table, packets[i], IBLT_INSERT);
    }

    // Find an IBLT for the dropped packets.
    struct bloom_cell *delta_table = iblt_subtract(src_table, dst_table);

    // List out the contents until fixedpoint.
    size_t *found_dropped = calloc(n_packets, sizeof(dropped[0])),
           n_found_dropped = 0;
    int any_left = iblt_list(delta_table, found_dropped, &n_found_dropped);
    if (any_left)  ilp_list(delta_table, packets, found_dropped, &n_found_dropped);

    for (size_t i = 0; i < n_found_dropped; i++) {
        size_t packet = found_dropped[i];
        if (!bsearch(&packet, packets, n_packets, sizeof(packets[0]), compare_size_ts)) {
            printf("[Error] Recovered packet was not sent --- malicious!\n");
            return 1;
        }
        VERBOSE_DO(printf("[Solver] Dropped packet: %4lu\n", packet);)
    }

    printf("Successfully solved for the dropped packets.\n");

    return 0;
}

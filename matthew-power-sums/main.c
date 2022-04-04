#include <stdlib.h>
#include <stdint.h>
#include "bn.h"
#include "bn.c"

int main() {
    srand(24);

    unsigned n_packets = 1000, n_threshold = 10;

    struct bn *packets = calloc(n_packets, sizeof(packets[0]));
    for (size_t i = 0; i < n_packets; i++) {
        for (size_t j = 0; j < BN_ARRAY_SIZE; j++) {
            packets[i].array[j] = (uint32_t)rand();
        }
    }

    struct bn prime;
    for (size_t j = 0; j < BN_ARRAY_SIZE; j++) {
        prime.array[j] = (uint32_t)rand();
    }

    struct bn tmp;

    struct bn *power_sums = calloc(n_threshold, sizeof(power_sums[0]));
    for (size_t i = 0; i < n_packets; i++) {
        struct bn packet = packets[i];
        bignum_mod(&packet, &packet, &prime);
        for (size_t j = 0; j < n_threshold; j++) {
            bignum_add(&tmp, power_sums + j, &packet);
            bignum_mod(power_sums + j, &tmp, &prime);
            if ((j + 1) < n_threshold) {
                bignum_mul(&tmp, &packet, packets + i);
                bignum_mod(&packet, &tmp, &prime);
            }
        }
    }
    printf("Done!\n");
}

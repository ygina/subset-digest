#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct bloom_cell {
    size_t count;
    size_t key_sum;
};

#define VERBOSE                 0
#define DISJOINT_BUCKET_RANGES  0

#if DISJOINT_BUCKET_RANGES
#define HASH_TO_BUCKET(packet, hash_idx) \
    ((hash(packet, hash_idx) % n_buckets_per_hash) + (hash_idx * n_buckets_per_hash))
#else
#define HASH_TO_BUCKET(packet, hash_idx) \
    (hash(packet, hash_idx) % n_buckets)
#endif

size_t hash(size_t x, size_t which_hash) {
    return (x * 33) ^ which_hash; // djb2ish
}

int compare_size_ts(const void *_a, const void *_b) {
    size_t a = *(size_t *)_a, b = *(size_t *)_b;
    if (a < b) return -1;
    if (a > b) return +1;
    return 0;
}

int main() {
    srand(24);

    size_t n_packets = 1e5,
           n_dropped = 1e3,
           n_hashes = 5,
           n_buckets = 1e6,
           n_buckets_per_hash = n_buckets / n_hashes;
#if DISJOINT_BUCKET_RANGES
    assert(!(n_buckets % n_hashes));
#endif

    size_t *packets = malloc(n_packets * sizeof(packets[0]));
    for (size_t i = 0; i < n_packets; i++) packets[i] = rand();
    qsort(packets, n_packets, sizeof(packets[0]), compare_size_ts);

    size_t *dropped = malloc(n_dropped * sizeof(dropped[0]));
    for (size_t i = 0; i < n_dropped; i++) {
redrop: dropped[i] = rand() % n_packets;
        for (size_t j = 0; j < i; j++) {
            if (dropped[j] == dropped[i]) goto redrop;
        }
#if VERBOSE
        printf("Dropping %lu\n", dropped[i]);
#endif
    }
    qsort(dropped, n_dropped, sizeof(dropped[0]), compare_size_ts);

    struct bloom_cell *src_table = calloc(n_buckets, sizeof(src_table[0])),
                      *dst_table = calloc(n_buckets, sizeof(dst_table[0]));
    // Insert the packets.
    size_t drop_idx = 0;
    for (size_t i = 0; i < n_packets; i++) {
        int is_dropped = drop_idx < n_dropped && dropped[drop_idx] == i;
        if (is_dropped) drop_idx++;

        for (size_t h = 0; h < n_hashes; h++) {
            size_t bucket = HASH_TO_BUCKET(packets[i], h);
            src_table[bucket].count++;
            src_table[bucket].key_sum ^= packets[i];
            if (!is_dropped) {
                dst_table[bucket].count++;
                dst_table[bucket].key_sum ^= packets[i];
            }
        }
    }

    // Subtract the packets.
    struct bloom_cell *delta_table = calloc(n_buckets, sizeof(delta_table[0]));
    for (size_t i = 0; i < n_buckets; i++) {
        delta_table[i] = (struct bloom_cell){
            .count = src_table[i].count - dst_table[i].count,
            .key_sum = src_table[i].key_sum ^ dst_table[i].key_sum,
        };
    }

    // List out the contents until fixedpoint. Many ways to optimize this if
    // needed.
    size_t n_recovered = 0;
    for (int any_change = 1; any_change; ) {
        any_change = 0;
        for (size_t i = 0; i < n_buckets; i++) {
            if (delta_table[i].count != 1) continue;
            any_change = 1;
            size_t packet = delta_table[i].key_sum;
            if (!bsearch(&packet, packets, n_packets, sizeof(packets[0]), compare_size_ts)) {
                printf("[Error] Recovered packet was not sent --- malicious!\n");
                return 1;
            }
            n_recovered++;
#if VERBOSE
            printf("[Solver] Dropped packet: %4lu\n", packet);
#endif
            for (size_t h = 0; h < n_hashes; h++) {
                size_t bucket = HASH_TO_BUCKET(packet, h);
                delta_table[bucket].count--;
                delta_table[bucket].key_sum ^= packet;
            }
        }
    }

    for (size_t i = 0; i < n_buckets; i++) {
        if (delta_table[i].count == 0) continue;
        printf("[Error] Too many hash collisions after %4lu recovered.\n", n_recovered);
        return 1;
    }

    printf("Successfully solved for the dropped packets.\n");

    return 0;
}

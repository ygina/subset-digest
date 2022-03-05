#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glpk.h>
#include "options.h"

struct bloom_cell {
    size_t count;
    size_t key_sum;
};

enum ModifyType { IBLT_INSERT, IBLT_DELETE };

static inline size_t hash(size_t x, size_t which_hash) {
    return (x * 33) ^ which_hash; // djb2ish
}

static inline int compare_size_ts(const void *_a, const void *_b) {
    size_t a = *(size_t *)_a, b = *(size_t *)_b;
    if (a < b) return -1;
    if (a > b) return +1;
    return 0;
}

static inline void iblt_modify(struct bloom_cell *iblt, size_t key, enum ModifyType type) {
    for (size_t h = 0; h < n_hashes; h++) {
        size_t bucket = HASH_TO_BUCKET(key, h);
        if (type == IBLT_INSERT) iblt[bucket].count++;
        else                     iblt[bucket].count--;
        iblt[bucket].key_sum ^= key;
    }
}

static inline struct bloom_cell *iblt_subtract(struct bloom_cell *a, struct bloom_cell *b) {
    struct bloom_cell *delta_table = calloc(n_buckets, sizeof(delta_table[0]));
    for (size_t i = 0; i < n_buckets; i++) {
        delta_table[i] = (struct bloom_cell){
            .count = a[i].count - b[i].count,
            .key_sum = a[i].key_sum ^ b[i].key_sum,
        };
    }
    return delta_table;
}

// Many ways to optimize this if needed.
static inline int iblt_list(struct bloom_cell *iblt, size_t *keys, size_t *n_keys) {
    int any_left = 0;
    for (unsigned any_change = 1; any_change--; ) {
        any_left = 0;
        for (size_t i = 0; i < n_buckets; i++) {
            any_left |= (iblt[i].count > 0);
            if (iblt[i].count != 1) continue;

            size_t packet = iblt[i].key_sum;
            keys[(*n_keys)++] = packet;
            iblt_modify(iblt, packet, IBLT_DELETE);
            any_change = 1;
        }
    }
    return any_left;
}

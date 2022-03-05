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

static const size_t n_packets = 1e6,
                    n_dropped = 1e3,
                    n_hashes = 5,
                    n_buckets = 1e6,
                    n_buckets_per_hash = n_buckets / n_hashes;
static inline size_t hash(size_t x, size_t which_hash);
static inline int compare_size_ts(const void *_a, const void *_b);
enum ModifyType { IBLT_INSERT, IBLT_DELETE };
static inline void iblt_modify(struct bloom_cell *iblt, size_t key, enum ModifyType type);
static inline struct bloom_cell *iblt_subtract(struct bloom_cell *a, struct bloom_cell *b);
static inline int iblt_list(struct bloom_cell *iblt, size_t *keys, size_t *n_keys);
static inline int ilp_list(struct bloom_cell *iblt, size_t *options, size_t *keys, size_t *n_keys);

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

static inline int ilp_list(struct bloom_cell *iblt, size_t *packets, size_t *keys, size_t *n_keys) {
    glp_prob *prob = glp_create_prob();
    glp_add_rows(prob, n_buckets);
    glp_add_cols(prob, n_packets);
    for (size_t i = 0; i < n_buckets; i++) {
        // This row = the number of dropped packets which land in this bucket.
        VERBOSE_DO(printf("[GLPK] Setting row bound to %lu\n", iblt[i].count);)
        glp_set_row_bnds(prob, i + 1, GLP_FX, iblt[i].count, iblt[i].count);
    }
    for (size_t j = 0; j < n_packets; j++) glp_set_col_kind(prob, j + 1, GLP_BV);

    // The (i, j) entry is the number of times packet j falls into bucket i.
    // We do one column at a time.
    int *indices = malloc((n_hashes + 1) * sizeof(indices[0]));
    double *values = malloc((n_hashes + 1) * sizeof(values[0]));
    for (size_t j = 0; j < n_packets; j++) {
        memset(indices, 0, (n_hashes + 1) * sizeof(indices[0]));
        memset(values, 0, (n_hashes + 1) * sizeof(values[0]));
        size_t len = 0;

        for (size_t h = 0; h < n_hashes; h++) {
            size_t bucket = HASH_TO_BUCKET(packets[j], h) + 1;
            for (size_t i = 1; i <= len; i++) {
                if (indices[i] != bucket) continue;
                values[i]++;
                goto next_hash;
            }
            indices[++len] = bucket;
            values[len]++;
next_hash:  continue;
        }

        glp_set_mat_col(prob, j + 1, len, indices, values);
    }
    free(indices); free(values);

    VERBOSE_DO(glp_write_lp(prob, NULL, "problem.txt");)
    glp_iocp parm;
    glp_init_iocp(&parm);
    parm.presolve = GLP_ON;
    int result = glp_intopt(prob, &parm);
    assert(!result);

    for (size_t i = 0; i < n_packets; i++)
        if (glp_mip_col_val(prob, i + 1))
            keys[(*n_keys)++] = packets[i];
}

static inline size_t hash(size_t x, size_t which_hash) {
    return (x * 33) ^ which_hash; // djb2ish
}

static inline int compare_size_ts(const void *_a, const void *_b) {
    size_t a = *(size_t *)_a, b = *(size_t *)_b;
    if (a < b) return -1;
    if (a > b) return +1;
    return 0;
}

// ilp.c
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <glpk.h>

#define VERBOSE 0
#if VERBOSE
#define VERBOSE_DO(...) __VA_ARGS__
#else
#define VERBOSE_DO(...)
#endif
#define SAVE_PROBLEM_TXT 0

/**
 * Parameters:
 * - n_buckets: number of buckets in the counting Bloom filter
 * - cbf: vector of length `n_buckets`, the counters in the CBF
 * - sums: vector of length `n_buckets`, the sums in the CBF
 * - modulus: the modulus of the sums
 * - n_hashes: number of hash functions per packet
 * - n_packets: number of packets in the log
 * - pkt_hashes: vector of length `n_hashes*n_packets`, indicates which entries
 *   to set in the ILP matrix. for example, the first `n_hashes` entries
 *   indicates the indices to set in the first row of the matrix, based on
 *   which buckets the first packet hashes to (which can be repeated).
 * - pkt_data: vector of length `n_packets` of the hashed packets.
 * - n_dropped: expected number of dropped packets
 *
 * Returns:
 * - dropped: vector of length `n_dropped`, the indices of the packets that
 *   were dropped
 */
int32_t solve_ilp_glpk(size_t n_buckets,
                       size_t *cbf,
                       uint32_t *sums,
                       uint64_t modulus,
                       size_t n_hashes,
                       size_t n_packets,
                       uint32_t *pkt_hashes,
                       uint32_t *pkt_data,
                       size_t n_dropped,
                       size_t *dropped) {
    // TODO: delete zero counters.
    glp_prob *prob = glp_create_prob();
    // First n_buckets rows are for the counts, second are for the hashes.
    glp_add_rows(prob, 2 * n_buckets);
    // First n_packets cols are for the packets (IVs), second are for the
    // modulus slacks, bounded by the counts.
    glp_add_cols(prob, n_packets + n_buckets);
    for (size_t i = 0; i < n_buckets; i++) {
        // This row = the number of dropped packets which land in this bucket.
        VERBOSE_DO(printf("[GLPK] Setting row bound %zu to %zu\n", i + 1, cbf[i]);)
        glp_set_row_bnds(prob, i + 1, GLP_FX, cbf[i], cbf[i]);
    }
    // Packet variables are binary
    for (size_t j = 0; j < n_packets; j++) glp_set_col_kind(prob, j + 1, GLP_BV);
    // Set the hash rows/cols
    for (size_t i = 0; i < n_buckets; i++) {
        // This row = the sum from the bucket - k * modulus.
        size_t glpk_id = i + 1 + n_buckets;
        VERBOSE_DO(printf("[GLPK] Setting row bound %zu to %zu\n", i + 1, sums[i]);)
        glp_set_row_bnds(prob, glpk_id, GLP_FX, sums[i], sums[i]);
    }
    for (size_t j = 0; j < n_buckets; j++) {
        glp_set_col_kind(prob, n_packets + j + 1, GLP_IV);
        glp_set_col_bnds(prob, n_packets + j + 1, GLP_FR, 0, cbf[j]);
    }

    // The (i, j) entry is:
    // - in (<n_buckets, <n_packets): number of times packet j falls into
    //   bucket i.
    // - in (<n_buckets, >=n_packets): 0
    // - in (>=n_buckets, <n_packets): sum of hashes of packet j that land in bucket i
    // - in (>=n_buckets, >=n_packets): modulus if i == j, else 0
    // We do one column at a time. Note that a double should fit all int33s.
    // TODO(masot): may overflow if we have lots of things summing into the
    // same spot, but should be OK because mod 2**32 ? ...
    size_t size = 2 * n_hashes + 1;
    int *indices = malloc(size * sizeof(indices[0]));
    double *values = malloc(size * sizeof(values[0]));
    for (size_t j = 0; j < n_packets; j++) {
        memset(indices, 0, size * sizeof(indices[0]));
        memset(values, 0, size * sizeof(values[0]));
        size_t len = 0;

        // Set the counts.
        for (size_t h = 0; h < n_hashes; h++) {
            int bucket = pkt_hashes[j*n_hashes + h] + 1;
            // Handle hash functions hashing the packet to the same buckets
            for (size_t i = 1; i <= len; i++) {
                if (indices[i] != bucket) continue;
                values[i]++;
                goto next_hash;
            }
            indices[++len] = bucket;
            values[len]++;
next_hash:  continue;
        }

        // Set the data values.
        for (size_t h = 0; h < n_hashes; h++) {
            int bucket = pkt_hashes[j*n_hashes + h] + 1 + n_buckets;
            // Handle hash functions hashing the packet to the same buckets
            for (size_t i = 1; i <= len; i++) {
                if (indices[i] != bucket) continue;
                values[i] += pkt_data[j];
                goto next_hash2;
            }
            indices[++len] = bucket;
            values[len] += pkt_data[j];
next_hash2: continue;
        }

        glp_set_mat_col(prob, j + 1, len, indices, values);
    }

    // Set constraints on the modulus
    memset(indices, 0, size * sizeof(indices[0]));
    memset(values, 0, size * sizeof(values[0]));
    for (size_t j = 0; j < n_buckets; j++) {
        indices[1] = n_buckets + j + 1;
        values[1] = modulus;

        glp_set_mat_col(prob, n_packets + j + 1, 1, indices, values);
    }
    free(indices); free(values);

#if SAVE_PROBLEM_TXT
    glp_write_lp(prob, NULL, "problem.txt");
#endif
    glp_iocp parm;
    glp_init_iocp(&parm);
    parm.presolve = GLP_ON;
    int result = glp_intopt(prob, &parm);
    // no solution to the ILP
    if (result != 0) {
        return -1;
    }

    // TODO: what if there are multiple solutions?
    size_t len = 0;
    for (size_t i = 0; i < n_packets; i++) {
        if (!glp_mip_col_val(prob, i + 1)) continue;

        // dropped more packets than expected
        if (len >= n_dropped) return -2;

        dropped[len++] = i;
    }
    // dropped fewer packets than expected
    if (len < n_dropped) {
        return -3;
    } else {
        return 0;
    }
    return 0;
}

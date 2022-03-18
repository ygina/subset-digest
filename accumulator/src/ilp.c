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

static glp_prob *prob = 0;
static size_t *last_sln = 0, n_last_sln = 0;

/**
 * Parameters:
 * - n_buckets: number of buckets in the counting Bloom filter
 * - cbf: vector of length `n_buckets`, the counters in the CBF
 * - n_hashes: number of hash functions per packet
 * - n_packets: number of packets in the log
 * - pkt_hashes: vector of length `n_hashes*n_packets`, indicates which entries
 *   to set in the ILP matrix. for example, the first `n_hashes` entries
 *   indicates the indices to set in the first row of the matrix, based on
 *   which buckets the first packet hashes to (which can be repeated).
 * - n_dropped: expected number of dropped packets
 *
 * Returns:
 * - dropped: vector of length `n_dropped`, the indices of the packets that
 *   were dropped
 */
void setup_ilp_glpk(size_t n_buckets,
                    size_t *cbf,
                    size_t n_hashes,
                    size_t n_packets,
                    uint32_t *pkt_hashes) {
    if (prob) free(prob);
    prob = glp_create_prob();
    glp_add_rows(prob, n_buckets);
    glp_add_cols(prob, n_packets);
    for (size_t i = 0; i < n_buckets; i++) {
        // This row = the number of dropped packets which land in this bucket.
        VERBOSE_DO(printf("[GLPK] Setting row bound %zu to %zu\n", i + 1, cbf[i]);)
        glp_set_row_bnds(prob, i + 1, GLP_FX, cbf[i], cbf[i]);
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
            int bucket = pkt_hashes[j*n_hashes + h] + 1;
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
    free(indices);
    free(values);
}

int32_t solve_ilp_glpk(size_t n_packets,
                       size_t n_dropped,
                       size_t *dropped) {
    assert(prob);
    VERBOSE_DO(glp_write_lp(prob, NULL, "problem.txt");)
    glp_iocp parm;
    glp_init_iocp(&parm);
    parm.presolve = GLP_ON;
    int result = glp_intopt(prob, &parm);
    // no solution to the ILP
    if (result != 0) {
        return -1;
    }

    // TODO: If there are multiple solutions, we need to add a new row to the
    // problem \sum_i sln[i] < n_dropped.
    last_sln = realloc(last_sln, n_dropped * sizeof(last_sln[0]));
    n_last_sln = n_dropped;
    size_t len = 0;
    for (size_t i = 0; i < n_packets; i++) {
        if (!glp_mip_col_val(prob, i + 1)) continue;

        // dropped more packets than expected
        if (len >= n_dropped) return -2;

        last_sln[len] = i;
        dropped[len++] = i;
    }

    // dropped fewer packets than expected
    if (len < n_dropped) return -3;
    return 0;
}

// Add a new row to the problem, negating the last solution.
// n_dropped should be the exact size of the solution.
void negate_last_sln() {
    int *indices = malloc((n_last_sln + 1) * sizeof(indices[0]));
    double *values = malloc((n_last_sln + 1) * sizeof(values[0]));
    for (size_t j = 0; j < n_last_sln; j++) {
        indices[j + 1] = last_sln[j] + 1;
        values[j + 1] = 1.;
    }
    glp_add_rows(prob, 1);
    size_t row_id = glp_get_num_rows(prob);
    glp_set_mat_row(prob, row_id, n_last_sln, indices, values);
    // NOTE: This assumes all solutions are the same length!
    glp_set_row_bnds(prob, row_id, GLP_UP, 0.0, n_last_sln - 1);
    free(indices);
    free(values);
}

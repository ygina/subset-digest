#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glpk.h>
#include "options.h"
#include "iblt.h"

int ilp_list(struct bloom_cell *iblt, size_t *packets, size_t *keys, size_t *n_keys) {
    // Pre-filter to just the packets which could possibly hash to this IBLT.
    size_t *possible = calloc(n_packets, sizeof(possible[0])),
           n_possible = 0;
    for (size_t j = 0; j < n_packets; j++) {
        for (size_t h = 0; h < n_hashes; h++) {
            size_t bucket = HASH_TO_BUCKET(packets[j], h);
            if (!(iblt[bucket].count)) goto next_pkt;
        }
        possible[n_possible++] = j;
next_pkt: continue;
    }

    glp_prob *prob = glp_create_prob();
    glp_add_rows(prob, n_buckets);
    glp_add_cols(prob, n_possible);
    for (size_t i = 0; i < n_buckets; i++) {
        // This row = the number of dropped packets which land in this bucket.
        VERBOSE_DO(printf("[GLPK] Setting row bound to %lu\n", iblt[i].count);)
        glp_set_row_bnds(prob, i + 1, GLP_FX, iblt[i].count, iblt[i].count);
    }
    for (size_t j = 0; j < n_possible; j++) glp_set_col_kind(prob, j + 1, GLP_BV);

    // The (i, j) entry is the number of times packet j falls into bucket i.
    // We do one column at a time.
    int *indices = malloc((n_hashes + 1) * sizeof(indices[0]));
    double *values = malloc((n_hashes + 1) * sizeof(values[0]));
    for (size_t j = 0; j < n_possible; j++) {
        memset(indices, 0, (n_hashes + 1) * sizeof(indices[0]));
        memset(values, 0, (n_hashes + 1) * sizeof(values[0]));
        size_t len = 0;

        for (size_t h = 0; h < n_hashes; h++) {
            size_t bucket = HASH_TO_BUCKET(packets[possible[j]], h) + 1;
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

    for (size_t i = 0; i < n_possible; i++)
        if (glp_mip_col_val(prob, i + 1))
            keys[(*n_keys)++] = packets[possible[i]];
}

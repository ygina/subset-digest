#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glpk.h>

int main() {
    srand(24);

    size_t n_packets = 10,
           n_dropped = 1,
           n_buckets = 10,
           n_hashes = 1;

    size_t *buckets = malloc(n_packets * n_hashes * sizeof(buckets[0]));
#define BUCKET_OF(packet, hash) buckets[(packet * n_hashes) + hash]
    for (size_t packet = 0; packet < n_packets; packet++) {
        for (size_t hash = 0; hash < n_hashes; hash++) {
            BUCKET_OF(packet, hash) = rand() % n_buckets;
            printf("Bucket of packet %4lu with hash %4lu is %4lu\n",
                   packet, hash, BUCKET_OF(packet, hash));
        }
    }

    size_t *dropped = malloc(n_dropped * sizeof(dropped[0]));
    for (size_t i = 0; i < n_dropped; i++) {
redrop: dropped[i] = rand() % n_packets;
        for (size_t j = 0; j < i; j++) {
            if (dropped[j] == dropped[i]) goto redrop;
        }
        printf("Dropping %lu\n", dropped[i]);
    }

    // Setup the ILP.
    glp_prob *prob = glp_create_prob();

    glp_add_rows(prob, n_buckets);
    glp_add_cols(prob, n_packets);

    for (size_t i = 0; i < n_buckets; i++) {
        // This row = the number of dropped packets which land in this bucket.
        size_t row_eq = 0;
        for (size_t d = 0; d < n_dropped; d++) {
        for (size_t h = 0; h < n_hashes; h++)
            row_eq += (BUCKET_OF(dropped[d], h) == i);
        }
        printf("Setting row bound to %lu\n", row_eq);
        glp_set_row_bnds(prob, i + 1, GLP_UP, row_eq, row_eq);
    }
    glp_write_mps(prob, GLP_MPS_FILE, NULL, "problem0.txt");

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
            size_t bucket = BUCKET_OF(j, h) + 1;
            for (size_t i = 1; i <= len; i++) {
                if (indices[i] == bucket) {
                    values[i]++;
                    goto next_hash;
                }
            }
            indices[++len] = bucket;
            values[len]++;
next_hash:  continue;
        }

        glp_set_mat_col(prob, j + 1, len, indices, values);
    }

    glp_write_mps(prob, GLP_MPS_FILE, NULL, "problem.txt");

    glp_iocp parm;
    glp_init_iocp(&parm);
    parm.presolve = GLP_ON;
    int result = glp_intopt(prob, &parm);
    assert(!result);
    glp_print_sol(prob, "solution.txt");
}

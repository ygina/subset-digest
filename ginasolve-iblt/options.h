#ifndef OPTIONS_H_
#define OPTIONS_H_

#include <stdlib.h>

static const size_t n_packets = 1e6,
                    n_dropped = 1e3,
                    n_hashes = 5,
                    n_buckets = 1e6,
                    n_buckets_per_hash = n_buckets / n_hashes;

#define VERBOSE                 0
#define DISJOINT_BUCKET_RANGES  0

#if VERBOSE
#define VERBOSE_DO(...) __VA_ARGS__
#else
#define VERBOSE_DO(...)
#endif

#if DISJOINT_BUCKET_RANGES
#define HASH_TO_BUCKET(packet, hash_idx) \
    ((hash(packet, hash_idx) % n_buckets_per_hash) + (hash_idx * n_buckets_per_hash))
#else
#define HASH_TO_BUCKET(packet, hash_idx) \
    (hash(packet, hash_idx) % n_buckets)
#endif

#endif // OPTIONS_H_

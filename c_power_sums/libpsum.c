#include <stdint.h>
#include <stddef.h>

void c_power_sums(uint32_t *psums, size_t n_psums,
                  uint32_t elem, uint32_t prime) {
    uint32_t value = 1;
    for (size_t i = 0; i < n_psums; i++) {
        value = (((uint64_t)value) * ((uint64_t)elem)) % ((uint64_t)prime);
        psums[i] = (((uint64_t)psums[i]) + ((uint64_t)value)) % ((uint64_t)prime);
    }
}

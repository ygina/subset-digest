#ifndef POWER_SUM_ACCUMULATOR_HPP_INCLUDED
#define POWER_SUM_ACCUMULATOR_HPP_INCLUDED

#include <array>   // for std::array
#include <unordered_set>
#include <cstddef> // for std::size_t

#include "ModularInteger.hpp" // for ModularInteger


template <typename T_NARROW, typename T_WIDE,
          T_NARROW MODULUS, std::size_t SIZE>
consteval std::array<ModularInteger<T_NARROW, T_WIDE, MODULUS>, SIZE>
modular_inverse_table() noexcept {
    using ModInt = ModularInteger<T_NARROW, T_WIDE, MODULUS>;
    std::array<ModInt, SIZE> result;
    for (std::size_t i = 0; i < SIZE; ++i) {
        result[i] = ModInt(i + 1).inv();
    }
    return result;
}


template <typename T_NARROW, typename T_WIDE,
          T_NARROW MODULUS, std::size_t SIZE,
          std::size_t PACKET_BYTES>
class PowerSumAccumulator {

    static_assert(SIZE > 0);

    using ModInt = ModularInteger<T_NARROW, T_WIDE, MODULUS>;

    static constexpr std::array<ModInt, SIZE> inverse_table =
        modular_inverse_table<T_NARROW, T_WIDE, MODULUS, SIZE>();

    bool is_buffering = true;
    std::vector<std::array<uint8_t, PACKET_BYTES>> packets;
    std::array<ModInt, SIZE> power_sums;

public:

    std::vector<T_NARROW> pkt_hashes;
    size_t chosen_offset;

    constexpr PowerSumAccumulator() noexcept {
        for (std::size_t i = 0; i < SIZE; ++i) {
            power_sums[i] = ModInt();
        }
    }

    constexpr PowerSumAccumulator(const PowerSumAccumulator &other) noexcept {
        // TODO: masot update
        assert(false);
        for (std::size_t i = 0; i < SIZE; ++i) {
            power_sums[i] = other.power_sums[i];
        }
    }

    constexpr void insert(const std::array<uint8_t, PACKET_BYTES> &value) noexcept {
        assert(is_buffering);
        packets.emplace_back(value);
    }

    constexpr T_NARROW pkt_hash(size_t pkt_i, size_t offset) {
        std::array<uint8_t, PACKET_BYTES> &packet = packets.at(pkt_i);
        size_t len = 8 * sizeof(PACKET_BYTES), // in bits
               skip = offset % 8,
               idx = offset / 8,
               into = 0;
        T_NARROW hash = 0;
        // TODO duff or something smarter
        while (len) {
            hash = hash | (((T_NARROW)(packet[idx] >> skip)) << into);

            len -= std::min(len, 8 - skip);
            into += 8 - skip;
            skip = 0;
            idx++;
        }
        if (hash == 65521) hash = 65520;
        // std::cout << "Hash of packet " << pkt_i << " with offset " << offset << " is " << hash << std::endl;
        return hash;
    }

    constexpr size_t find_offset() noexcept {
        // return 0;
        std::unordered_set<T_NARROW> hashes;
        size_t max_offset = (8 * PACKET_BYTES) - (8 * sizeof(T_NARROW));
        size_t best_offset = 0, best_conflicts = -1;
        for (size_t offset = 0; offset < max_offset; offset++) {
            hashes.clear();
            size_t n_conflicts = 0;
            for (size_t i = 0; i < packets.size(); i++) {
                if (hashes.insert(pkt_hash(i, offset)).second) continue;
                n_conflicts++;
            }
            if (n_conflicts < best_conflicts) {
                best_offset = offset;
                best_conflicts = n_conflicts;
            }
            if (!n_conflicts) break;
        }
#if 1
        std::cout << "Offset " << best_offset << " leads to " << best_conflicts << " collisions." << std::endl;
#endif
        return best_offset;
    }

    constexpr void unbuffer(size_t offset = -1) noexcept {
        // std::cout << "Unbuffering with offset " << offset << std::endl;
        assert(is_buffering);
        is_buffering = false;
        if (offset == -1) {
            chosen_offset = find_offset();
        } else {
            chosen_offset = offset;
        }

        offset = chosen_offset;

        assert(offset != -1);

#if 0
        if (offset != 0) {
            std::cout << "Using interesting offset: " << offset << std::endl;
        }
#endif

        // std::cout << "Doing sums..." << std::endl;
        for (size_t p = 0; p < packets.size(); p++) {
            pkt_hashes.push_back(pkt_hash(p, chosen_offset));
            // std::cout << "Packet hash: " << pkt_hashes.back() << std::endl;
            const ModInt x{pkt_hash(p, chosen_offset)};
            // std::cout << "Summing up " << x.value << " should be " << pkt_hashes.back() << std::endl;
            ModInt y = x;
            for (std::size_t i = 0; i < SIZE - 1; ++i) {
                power_sums[i] += y;
                y *= x;
            }
            power_sums[SIZE - 1] += y;
        }
    }

    constexpr void clear() noexcept {
        is_buffering = true;
        chosen_offset = 0;
        packets.clear();
        pkt_hashes.clear();
        for (std::size_t i = 0; i < SIZE; ++i)
            power_sums[i] = ModInt();
    }

    constexpr PowerSumAccumulator &operator-=(
        const PowerSumAccumulator &other
    ) noexcept {
        assert(!is_buffering);
        assert(!other.is_buffering);

        for (std::size_t i = 0; i < SIZE; ++i) {
            power_sums[i] -= other.power_sums[i];
        }
        return *this;
    }

    constexpr std::array<ModInt, SIZE>
    to_polynomial_coefficients() const noexcept {
        assert(!is_buffering);
        std::array<ModInt, SIZE> coeffs;
        coeffs[0] = -power_sums[0];
        for (std::size_t i = 1; i < SIZE; ++i) {
            for (std::size_t j = 0; j < i; ++j) {
                coeffs[i] -= power_sums[j] * coeffs[i - j - 1];
            }
            coeffs[i] -= power_sums[i];
            coeffs[i] *= inverse_table[i];
        }
        return coeffs;
    }

}; // class PowerSumAccumulator


#endif // POWER_SUM_ACCUMULATOR_HPP_INCLUDED

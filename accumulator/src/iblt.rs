use std::time::Instant;
use std::collections::HashMap;
use num_bigint::BigUint;
use num_traits::Zero;
use bloom_sd::InvBloomLookupTable;
use crate::Accumulator;
use digest::Digest;

#[link(name = "glpk", kind = "dylib")]
extern "C" {
    fn solve_ilp_glpk(
        n_buckets: usize,
        iblt: *const usize,
        n_hashes: usize,
        n_packets: usize,
        pkt_hashes: *const u32,
        n_dropped: usize,
        dropped: *mut usize,
    ) -> i32;
}

/// The counting bloom filter (IBLT) accumulator stores a IBLT of all processed
/// packets in addition to the digest.
///
/// On validation, the accumulator calculates the IBLT of the given list of
/// elements and subtracts the processed IBLT. The resulting difference IBLT
/// represents all lost elements. If there is a subset of given elements that
/// produces the same IBLT, we can say with high probability the log is good.
/// The count may be stored modulo some number.
pub struct IBLTAccumulator {
    digest: Digest,
    num_elems: usize,
    iblt: InvBloomLookupTable,
}

// TODO: IBLT parameters
// TODO: may also want to map IBLT entries to u32 with DJB hash
const LOG_DATA_LENGTH: u32 = 128;
const BITS_PER_ENTRY: usize = 16;
const FALSE_POSITIVE_RATE: f32 = 0.0001;

impl IBLTAccumulator {
    pub fn new(threshold: usize) -> Self {
        let iblt = InvBloomLookupTable::with_rate(
            LOG_DATA_LENGTH,
            BITS_PER_ENTRY,
            FALSE_POSITIVE_RATE,
            threshold.try_into().unwrap(),
        );
        let data_size = std::mem::size_of_val(&iblt.data()[0]);
        debug!("{} entries and {} bits per entry",
            iblt.num_entries(), BITS_PER_ENTRY);
        info!("size of iblt = {} bytes",
            (iblt.num_entries() as usize) * (BITS_PER_ENTRY + data_size) / 8);
        Self {
            digest: Digest::new(),
            num_elems: 0,
            iblt,
        }
    }

    pub fn new_with_rate(threshold: usize, fp_rate: f32) -> Self {
        let iblt = InvBloomLookupTable::with_rate(
            LOG_DATA_LENGTH,
            BITS_PER_ENTRY,
            fp_rate,
            threshold.try_into().unwrap(),
        );
        let data_size = std::mem::size_of_val(&iblt.data()[0]);
        debug!("{} entries and {} bits per entry",
            iblt.num_entries(), BITS_PER_ENTRY);
        info!("size of iblt = {} bytes",
            (iblt.num_entries() as usize) * (BITS_PER_ENTRY + data_size) / 8);
        Self {
            digest: Digest::new(),
            num_elems: 0,
            iblt,
        }
    }

    /// Deserialize the accumulator into bytes.
    pub fn deserialize_bytes(bytes: &[u8]) -> Self {
        unimplemented!()
    }

    pub fn equals(&self, other: &Self) -> bool {
        unimplemented!()
    }
}

impl Accumulator for IBLTAccumulator {
    fn serialize_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }

    fn process(&mut self, elem: &BigUint) {
        self.digest.add(elem);
        self.num_elems += 1;
        self.iblt.insert(elem);
    }

    fn process_batch(&mut self, elems: &Vec<BigUint>) {
        for elem in elems {
            self.process(elem);
        }
    }

    fn total(&self) -> usize {
        self.num_elems
    }

    fn validate(&self, elems: &Vec<BigUint>) -> bool {
        let t1 = Instant::now();
        if elems.len() < self.total() {
            warn!("more elements received than logged");
            return false;
        }

        // If no elements are missing, just recalculate the digest.
        let n_dropped = elems.len() - self.total();
        if n_dropped == 0 {
            let mut digest = Digest::new();
            for elem in elems {
                digest.add(elem);
            }
            return digest.equals(&self.digest);
        }

        let mut iblt = self.iblt.empty_clone();
        for elem in elems {
            iblt.insert(elem);
        }
        for i in 0..(iblt.num_entries() as usize) {
            let processed_count = iblt.counters().get(i);
            let received_count = self.iblt.counters().get(i);
            // TODO: handle counter overflows i.e. if the Bloom filter
            // stores the count modulo some number instead of the exact count
            if processed_count < received_count {
                return false;
            }
            let difference_count = processed_count - received_count;
            iblt.counters_mut().set(i, difference_count);

            // Additionally set the data value
            let processed_data = &iblt.data()[i];
            let received_data = &self.iblt.data()[i];
            let difference_data = if processed_data >= received_data {
                processed_data - received_data
            } else {
                (u128::MAX - received_data) + processed_data
            };
            if difference_count == 0 && !difference_data.is_zero() {
                return false;
            }
            iblt.data_mut()[i] = difference_data;
        }
        let t2 = Instant::now();
        info!("calculated the difference iblt: {:?}", t2 - t1);

        // Remove any elements that are definitely dropped based on counters
        // in the IBLT that are set to 1. Then find the remaining list of
        // candidate dropped elements by based on any whose indexes are still
        // not 0. If elements are not unique, the ILP can find _a_ solution.
        let mut removed = iblt.eliminate_elems();
        let t3 = Instant::now();
        info!("eliminated {}/{} elements using the iblt: {:?}",
            removed.len(), n_dropped, t3 - t2);

        // The remaining maybe dropped elements should make up any non-zero
        // entries in the IBLT. Since we checked that the number of dropped
        // elements is at most the size of the original set, if we removed the
        // number of dropped elements, then the IBLT necessarily only has zero
        // entries. This means solving an ILP is unnecessary but we still
        // sanity check that the digest matches.
        if removed.len() == n_dropped {
            let mut digest = Digest::new();
            for elem in elems {
                if !removed.remove(elem) {
                    digest.add(elem);
                }
            }
            assert!(digest.equals(&self.digest));
            return true;
        }

        // Then there are still some remaining candidate dropped elements,
        // and the IBLT is not empty. n equations, the number of remaining
        // candidate elements, in k variables, the number of cells in the IBLT.
        let mut elems_i: Vec<usize> = vec![];
        let pkt_hashes: Vec<u32> = elems
            .iter()
            .enumerate()
            .filter(|(_, elem)| iblt.contains(&elem))
            .flat_map(|(i, elem)| {
                elems_i.push(i);
                iblt.indexes(&elem)
            })
            .map(|hash| hash as u32)
            .collect();
        let counters: Vec<usize> = (0..(iblt.num_entries() as usize))
            .map(|i| iblt.counters().get(i))
            .map(|count| count.try_into().unwrap())
            .collect();
        assert!(n_dropped > removed.len());
        let n_dropped_remaining = n_dropped - removed.len();
        assert!(n_dropped_remaining <= elems_i.len());
        let t4 = Instant::now();
        info!("setup system of {} eqs in {} vars (expect sols to sum to {}): {:?}",
            elems_i.len(),
            counters.len(),
            n_dropped_remaining,
            t4 - t3);

        // Solve the ILP with GLPK. The result is the indices of the dropped
        // packets in the `maybe_dropped` vector. The number of solutions
        // does not depend entirely on the number of equations and variables.
        // Instead, if there are fewer (linearly independent) equations than
        // the sum of the counters divided by the number of hashes, then there
        // is no solution. If there are more, there may be multiple solutions.
        let mut dropped: Vec<usize> = vec![0; n_dropped_remaining];
        let err = unsafe {
            solve_ilp_glpk(
                counters.len(),
                counters.as_ptr(),
                iblt.num_hashes() as usize,
                elems_i.len(),
                pkt_hashes.as_ptr(),
                n_dropped_remaining,
                dropped.as_mut_ptr(),
            )
        };
        let t5 = Instant::now();
        info!("solved ILP: {:?}", t5 - t4);
        if err == 0 {
            // TODO: verify the XORs check out when removing these elements
            // from the difference IBLT?
            let mut dropped_count: HashMap<BigUint, usize> = HashMap::new();
            for dropped_i in dropped {
                let elem = elems[elems_i[dropped_i]].clone();
                *(dropped_count.entry(elem).or_insert(0)) += 1;
            }
            for elem in removed {
                *(dropped_count.entry(elem).or_insert(0)) += 1;
            }
            crate::check_digest(elems, dropped_count, &self.digest)
        } else {
            warn!("ILP solving error: {}", err);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;
    use rand::Rng;
    use num_bigint::ToBigUint;

    fn gen_elems(n: usize) -> Vec<BigUint> {
        let mut rng = rand::thread_rng();
        (0..n).map(|_| rng.gen::<u128>().to_biguint().unwrap()).collect()
    }

    #[test]
    fn test_not_equals() {
        let acc1 = IBLTAccumulator::new(100);
        let acc2 = IBLTAccumulator::new(100);
        assert!(!acc1.equals(&acc2), "different digest nonce");
    }

    #[test]
    fn empty_serialization() {
        let acc1 = IBLTAccumulator::new(1000);
        let acc2 = IBLTAccumulator::deserialize_bytes(&acc1.serialize_bytes());
        assert!(acc1.equals(&acc2));
    }

    #[test]
    fn serialization_with_data() {
        let mut acc1 = IBLTAccumulator::new(1000);
        let acc2 = IBLTAccumulator::deserialize_bytes(&acc1.serialize_bytes());
        acc1.process_batch(&gen_elems(10));
        let acc3 = IBLTAccumulator::deserialize_bytes(&acc1.serialize_bytes());
        assert!(!acc1.equals(&acc2));
        assert!(acc1.equals(&acc3));
    }
}

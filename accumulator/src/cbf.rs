#[cfg(not(feature = "disable_validation"))]
use std::collections::HashMap;
#[cfg(not(feature = "disable_validation"))]
use std::time::Instant;

use bincode;
use serde::{Serialize, Deserialize};
use bloom_sd::CountingBloomFilter;
use crate::Accumulator;
use digest::Digest;

#[cfg(not(feature = "disable_validation"))]
#[link(name = "glpk", kind = "dylib")]
extern "C" {
    fn solve_ilp_glpk(
        n_buckets: usize,
        cbf: *const usize,
        n_hashes: usize,
        n_packets: usize,
        pkt_hashes: *const u32,
        n_dropped: usize,
        dropped: *mut usize,
    ) -> i32;
}

/// The counting bloom filter (CBF) accumulator stores a CBF of all processed
/// packets in addition to the digest.
///
/// On validation, the accumulator calculates the CBF of the given list of
/// elements and subtracts the processed CBF. The resulting difference CBF
/// represents all lost elements. If there is a subset of given elements that
/// produces the same CBF, we can say with high probability the log is good.
/// The count may be stored modulo some number.
#[derive(Serialize, Deserialize)]
pub struct CBFAccumulator {
    digest: Digest,
    cbf: CountingBloomFilter,
}

// TODO: CBF parameters
const BITS_PER_ENTRY: usize = 16;
const FALSE_POSITIVE_RATE: f32 = 0.0001;

impl CBFAccumulator {
    pub fn new(threshold: usize) -> Self {
        Self {
            digest: Digest::new(),
            cbf: CountingBloomFilter::with_rate(
                BITS_PER_ENTRY,
                FALSE_POSITIVE_RATE,
                threshold.try_into().unwrap(),
            ),
        }
    }

    pub fn equals(&self, other: &Self) -> bool {
        self.digest == other.digest
            && self.cbf.equals(&other.cbf)
    }
}

impl Accumulator for CBFAccumulator {
    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    fn reset(&mut self) {
        self.digest = Digest::new();
        self.cbf = self.cbf.empty_clone();
    }

    fn process(&mut self, elem: &[u8]) {
        self.digest.add(elem);
        self.cbf.insert(&elem);
    }

    fn process_batch(&mut self, elems: &Vec<Vec<u8>>) {
        for elem in elems {
            self.process(elem);
        }
    }

    fn total(&self) -> usize {
        self.digest.count as _
    }

    #[cfg(feature = "disable_validation")]
    fn validate(&self, _elems: &Vec<Vec<u8>>) -> bool {
        panic!("validation not enabled")
    }

    #[cfg(not(feature = "disable_validation"))]
    fn validate(&self, elems: &Vec<Vec<u8>>) -> bool {
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

        // Calculate the difference CBF.
        let mut cbf = self.cbf.empty_clone();
        for elem in elems {
            cbf.insert(elem);
        }
        for i in 0..(cbf.num_entries() as usize) {
            let processed_count = cbf.counters().get(i);
            let received_count = self.cbf.counters().get(i);
            // TODO: handle counter overflows i.e. if the Bloom filter
            // stores the count modulo some number instead of the exact count
            if processed_count < received_count {
                return false;
            }
            cbf.counters_mut().set(i, processed_count - received_count)
        }
        let t2 = Instant::now();
        debug!("calculated the difference cbf: {:?}", t2 - t1);

        // n equations, the total number of candidate elements,
        // in k variables, the number of cells in the CBF. Omit equations
        // where none of the indexes are set in the difference CBF.
        let mut elems_i: Vec<usize> = vec![];
        let pkt_hashes: Vec<u32> = elems
            .iter()
            .enumerate()
            .filter(|(_, elem)| cbf.contains(&elem))
            .flat_map(|(i, elem)| {
                elems_i.push(i);
                cbf.indexes(&elem)
            })
            .map(|hash| hash as u32)
            .collect();
        let counters: Vec<usize> = (0..(cbf.num_entries() as usize))
            .map(|i| cbf.counters().get(i))
            .map(|count| count.try_into().unwrap())
            .collect();
        let t3 = Instant::now();
        info!("setup system of {} eqs in {} vars (expect {} solutions, {}): {:?}",
            elems_i.len(),
            counters.len(),
            counters.iter().sum::<usize>() / cbf.num_hashes() as usize,
            n_dropped,
            t3 - t2);

        // Solve the ILP with GLPK. The result is the indices of the dropped
        // packets in the `elems_i` vector. This just shows that there is _a_
        // solution to the ILP, we don't know if it's the right one.
        // TODO: Ideally, we could check all solutions. This will require a
        // probabilistic analysis. It may falsely claim a router a malicious
        // with low probability. It will only state the router is correct if
        // it actually is.
        let mut dropped: Vec<usize> = vec![0; n_dropped];
        let err = unsafe {
            solve_ilp_glpk(
                counters.len(),
                counters.as_ptr(),
                cbf.num_hashes() as usize,
                elems_i.len(),
                pkt_hashes.as_ptr(),
                n_dropped,
                dropped.as_mut_ptr(),
            )
        };
        let t4 = Instant::now();
        debug!("solved ILP: {:?}", t4 - t3);
        if err == 0 {
            let mut dropped_count: HashMap<Vec<u8>, usize> = HashMap::new();
            for dropped_i in dropped {
                let elem = &elems[elems_i[dropped_i]];
                let count = dropped_count.entry(elem.clone()).or_insert(0);
                *count += 1;
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
    use bincode;
    use rand;
    use rand::Rng;

    const NBYTES: usize = 16;

    fn gen_elems(n: usize) -> Vec<Vec<u8>> {
        let mut rng = rand::thread_rng();
        (0..n).map(|_| (0..NBYTES).map(|_| rng.gen::<u8>()).collect()).collect()
    }

    #[test]
    fn test_not_equals() {
        let acc1 = CBFAccumulator::new(100);
        let acc2 = CBFAccumulator::new(100);
        assert!(!acc1.equals(&acc2), "different digest nonce");
    }

    #[test]
    fn empty_serialization() {
        let acc1 = CBFAccumulator::new(1000);
        let bytes = bincode::serialize(&acc1).unwrap();
        let acc2: CBFAccumulator = bincode::deserialize(&bytes).unwrap();
        assert!(acc1.equals(&acc2));
    }

    #[test]
    fn serialization_with_data() {
        let mut acc1 = CBFAccumulator::new(1000);
        let bytes = bincode::serialize(&acc1).unwrap();
        let acc2: CBFAccumulator = bincode::deserialize(&bytes).unwrap();
        acc1.process_batch(&gen_elems(10));
        let bytes = bincode::serialize(&acc1).unwrap();
        let acc3: CBFAccumulator = bincode::deserialize(&bytes).unwrap();
        assert!(!acc1.equals(&acc2));
        assert!(acc1.equals(&acc3));
    }
}

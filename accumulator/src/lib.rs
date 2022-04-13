#[macro_use]
extern crate log;

mod cbf;
mod iblt;
mod naive;
mod power_sum;

use num_bigint::BigUint;

pub use cbf::CBFAccumulator;
pub use iblt::IBLTAccumulator;
pub use naive::NaiveAccumulator;
pub use power_sum::PowerSumAccumulator;

pub trait Accumulator {
    /// Serialize the accumulator to bytes.
    fn to_bytes(&self) -> Vec<u8>;
    /// Process a single element.
    fn process(&mut self, elem: &BigUint);
    /// Process a batch of elements.
    fn process_batch(&mut self, elems: &Vec<BigUint>);
    /// The total number of processed elements.
    fn total(&self) -> usize;
    /// Validate the accumulator against a list of elements.
    ///
    /// The accumulator is valid if the elements that the accumulator has
    /// processed are a subset of the provided list of elements. If valid,
    /// the function also returns the indexes of the missing elements.
    fn validate(&self, elems: &Vec<BigUint>) -> Result<Vec<usize>, ()>;
}

#[cfg(test)]
mod tests {
    use rand;
    use rand::Rng;
    use num_bigint::{BigUint, ToBigUint};
    use std::collections::HashSet;
    use super::*;

    const MALICIOUS_ELEM: u128 = u128::max_value();

    fn base_accumulator_test(
        mut accumulator: Box<dyn Accumulator>,
        num_logged: usize,
        num_dropped: usize,
        malicious: bool,
    ) {
        let mut rng = rand::thread_rng();
        let elems: Vec<BigUint> = (0..num_logged).map(|_| loop {
            let elem = rng.gen::<u128>();
            if elem != MALICIOUS_ELEM {
                break elem.to_biguint().unwrap();
            }
        }).collect();
        // indexes may be repeated but it's close enough
        let dropped_is = {
            let mut set = HashSet::new();
            while set.len() < num_dropped {
                set.insert(rng.gen_range(0..num_logged));
            }
            set
        };
        let malicious_i: usize = rng.gen_range(0..num_logged);
        for i in 0..elems.len() {
            if malicious && malicious_i == i {
                accumulator.process(&MALICIOUS_ELEM.to_biguint().unwrap());
            } else if !dropped_is.contains(&i) {
                accumulator.process(&elems[i]);
            }
        }
        let result = accumulator.validate(&elems);
        assert_eq!(result.is_ok(), !malicious);
        if !malicious {
            assert_eq!(result.unwrap().len(), num_dropped);
        }
    }

    #[test]
    fn naive_none_dropped() {
        let accumulator = NaiveAccumulator::new();
        base_accumulator_test(Box::new(accumulator), 100, 0, false);
    }

    #[test]
    fn naive_all_dropped() {
        let accumulator = NaiveAccumulator::new();
        base_accumulator_test(Box::new(accumulator), 100, 0, false);
    }

    #[test]
    fn naive_one_dropped() {
        let accumulator = NaiveAccumulator::new();
        base_accumulator_test(Box::new(accumulator), 100, 1, false);
    }

    #[ignore]
    #[test]
    fn naive_two_dropped() {
        let accumulator = NaiveAccumulator::new();
        base_accumulator_test(Box::new(accumulator), 100, 2, false);
    }

    #[ignore]
    #[test]
    fn naive_three_dropped() {
        let accumulator = NaiveAccumulator::new();
        base_accumulator_test(Box::new(accumulator), 100, 3, false);
    }

    #[test]
    fn naive_one_malicious_and_none_dropped() {
        let accumulator = NaiveAccumulator::new();
        base_accumulator_test(Box::new(accumulator), 100, 0, true);
    }

    #[test]
    fn naive_one_malicious_and_one_dropped() {
        let accumulator = NaiveAccumulator::new();
        base_accumulator_test(Box::new(accumulator), 100, 1, true);
    }

    #[ignore]
    #[test]
    fn naive_one_malicious_and_many_dropped() {
        // validation takes much longer to fail because many
        // combinations must be tried and they all fail
        let accumulator = NaiveAccumulator::new();
        base_accumulator_test(Box::new(accumulator), 100, 3, true);
    }

    #[test]
    fn power_sum_none_dropped() {
        let accumulator = PowerSumAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 0, false);
    }

    #[test]
    fn power_sum_all_dropped() {
        let accumulator = PowerSumAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 0, false);
    }

    #[test]
    fn power_sum_one_dropped() {
        let accumulator = PowerSumAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 1, false);
    }

    #[test]
    fn power_sum_two_dropped() {
        let accumulator = PowerSumAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 2, false);
    }

    #[test]
    fn power_sum_many_dropped() {
        let accumulator = PowerSumAccumulator::new(1000);
        base_accumulator_test(Box::new(accumulator), 1000, 10, false);
    }

    #[test]
    fn power_sum_one_malicious_and_none_dropped() {
        let accumulator = PowerSumAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 0, true);
    }

    #[test]
    fn power_sum_one_malicious_and_one_dropped() {
        let accumulator = PowerSumAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 1, true);
    }

    #[test]
    fn power_sum_one_malicious_and_many_dropped() {
        // validation is much faster than the naive approach
        let accumulator = PowerSumAccumulator::new(1000);
        base_accumulator_test(Box::new(accumulator), 1000, 10, true);
    }

    #[test]
    fn cbf_none_dropped() {
        let accumulator = CBFAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 0, false);
    }

    #[test]
    fn cbf_all_dropped() {
        let accumulator = CBFAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 100, false);
    }

    #[test]
    fn cbf_one_dropped() {
        let accumulator = CBFAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 1, false);
    }

    #[test]
    fn cbf_two_dropped() {
        let accumulator = CBFAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 2, false);
    }

    #[test]
    fn cbf_many_dropped() {
        let accumulator = CBFAccumulator::new(1000);
        base_accumulator_test(Box::new(accumulator), 1000, 10, false);
    }

    #[test]
    fn cbf_one_malicious_and_none_dropped() {
        let accumulator = CBFAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 0, true);
    }

    #[test]
    fn cbf_one_malicious_and_one_dropped() {
        let accumulator = CBFAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 1, true);
    }

    #[test]
    fn cbf_one_malicious_and_many_dropped() {
        // validation is much faster compared to the naive approach,
        // so we increase the number of packets
        let accumulator = CBFAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 1000, 10, true);
    }

    #[test]
    fn iblt_none_dropped() {
        let accumulator = IBLTAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 0, false);
    }

    #[test]
    fn iblt_all_dropped() {
        let accumulator = IBLTAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 100, false);
    }

    #[test]
    fn iblt_one_dropped() {
        let accumulator = IBLTAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 1, false);
    }

    #[test]
    fn iblt_many_dropped_without_ilp_solver() {
        let accumulator = IBLTAccumulator::new(1000);
        base_accumulator_test(Box::new(accumulator), 1000, 10, false);
    }

    #[test]
    fn iblt_many_dropped_with_ilp_solver() {
        let accumulator = IBLTAccumulator::new_with_rate(1000, 0.1);
        base_accumulator_test(Box::new(accumulator), 1000, 100, false);
    }

    #[test]
    fn iblt_one_malicious_and_none_dropped() {
        let accumulator = IBLTAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 0, true);
    }

    #[test]
    fn iblt_one_malicious_and_one_dropped() {
        let accumulator = IBLTAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 100, 1, true);
    }

    #[test]
    fn iblt_one_malicious_and_many_dropped() {
        let accumulator = IBLTAccumulator::new(100);
        base_accumulator_test(Box::new(accumulator), 1000, 10, true);
    }
}

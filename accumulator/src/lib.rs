#[macro_use]
extern crate log;

mod iblt;
mod naive;
mod power_sum;

pub use iblt::*;
pub use naive::NaiveAccumulator;
pub use power_sum::PowerSumAccumulator;

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationResult {
    Valid,
    Invalid,
    PsumCollisionsValid,
    PsumCollisionsInvalid,
    PsumExceedsThreshold,
    PsumErrorFindingRoots,
    IbltBenignWraparound,
    IbltCollisionsValid,
    IbltCollisionsInvalid,
    IbltIlpValid,
    IbltIlpInvalid,
    IbltIlpCollisionsValid,
    IbltIlpCollisionsInvalid,
    IbltMaliciousWraparound,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        match self {
            ValidationResult::Valid => true,
            ValidationResult::PsumCollisionsValid => true,
            ValidationResult::IbltIlpValid => true,
            ValidationResult::IbltCollisionsValid => true,
            ValidationResult::IbltIlpCollisionsValid => true,
            _ => false,
        }
    }

    pub fn is_undetermined(&self) -> bool {
        match self {
            ValidationResult::PsumExceedsThreshold => true,
            ValidationResult::IbltBenignWraparound => true,
            _ => false,
        }
    }

    pub fn is_collisions(&self) -> bool {
        match self {
            ValidationResult::PsumCollisionsValid => true,
            ValidationResult::PsumCollisionsInvalid => true,
            ValidationResult::IbltCollisionsValid => true,
            ValidationResult::IbltCollisionsInvalid => true,
            ValidationResult::IbltIlpCollisionsValid => true,
            ValidationResult::IbltIlpCollisionsInvalid => true,
            _ => false,
        }
    }

    pub fn is_ilp(&self) -> bool {
        match self {
            ValidationResult::IbltCollisionsValid => true,
            ValidationResult::IbltCollisionsInvalid => true,
            ValidationResult::IbltIlpValid => true,
            ValidationResult::IbltIlpInvalid => true,
            ValidationResult::IbltIlpCollisionsValid => true,
            ValidationResult::IbltIlpCollisionsInvalid => true,
            _ => false,
        }
    }
}

pub trait Accumulator {
    /// Serialize the accumulator to bytes.
    fn to_bytes(&self) -> Vec<u8>;
    /// Resets the accumulator to its initial state.
    fn reset(&mut self);
    /// Process a single element.
    fn process(&mut self, elem: &[u8]);
    /// Process a batch of elements.
    fn process_batch(&mut self, elems: &Vec<Vec<u8>>);
    /// The total number of processed elements.
    fn total(&self) -> usize;
    /// Validate the accumulator against a list of elements.
    ///
    /// The accumulator is valid if the elements that the accumulator has
    /// processed are a subset of the provided list of elements.
    fn validate(&self, elems: &Vec<Vec<u8>>) -> ValidationResult;
}

#[cfg(test)]
mod tests {
    use rand;
    use rand::Rng;
    use super::*;

    const NBYTES: usize = 16;
    const MALICIOUS_ELEM: [u8; NBYTES] = [0; NBYTES];
    const SEED: Option<u64> = Some(1234);

    fn base_accumulator_test(
        mut accumulator: Box<dyn Accumulator>,
        num_logged: usize,
        num_dropped: usize,
        malicious: bool,
    ) {
        let mut rng = rand::thread_rng();
        let elems: Vec<Vec<u8>> = (0..num_logged).map(|_| loop {
            let elem = (0..NBYTES).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
            if elem != MALICIOUS_ELEM {
                break elem;
            }
        }).collect();
        // indexes may be repeated but it's close enough
        let dropped_is: Vec<usize> = (0..num_dropped)
            .map(|_| rng.gen_range(0..num_logged)).collect();
        let malicious_i: usize = rng.gen_range(0..num_logged);
        for i in 0..elems.len() {
            if malicious && malicious_i == i {
                accumulator.process(&MALICIOUS_ELEM);
            } else if !dropped_is.contains(&i) {
                accumulator.process(&elems[i]);
            }
        }
        let valid = accumulator.validate(&elems).is_valid();
        assert_eq!(valid, !malicious);
    }

    #[test]
    fn naive_none_dropped() {
        let accumulator = NaiveAccumulator::new(SEED);
        base_accumulator_test(Box::new(accumulator), 100, 0, false);
    }

    #[test]
    fn naive_all_dropped() {
        let accumulator = NaiveAccumulator::new(SEED);
        base_accumulator_test(Box::new(accumulator), 100, 0, false);
    }

    #[test]
    fn naive_one_dropped() {
        let accumulator = NaiveAccumulator::new(SEED);
        base_accumulator_test(Box::new(accumulator), 100, 1, false);
    }

    #[ignore]
    #[test]
    fn naive_two_dropped() {
        let accumulator = NaiveAccumulator::new(SEED);
        base_accumulator_test(Box::new(accumulator), 100, 2, false);
    }

    #[ignore]
    #[test]
    fn naive_three_dropped() {
        let accumulator = NaiveAccumulator::new(SEED);
        base_accumulator_test(Box::new(accumulator), 100, 3, false);
    }

    #[test]
    fn naive_one_malicious_and_none_dropped() {
        let accumulator = NaiveAccumulator::new(SEED);
        base_accumulator_test(Box::new(accumulator), 100, 0, true);
    }

    #[test]
    fn naive_one_malicious_and_one_dropped() {
        let accumulator = NaiveAccumulator::new(SEED);
        base_accumulator_test(Box::new(accumulator), 100, 1, true);
    }

    #[ignore]
    #[test]
    fn naive_one_malicious_and_many_dropped() {
        // validation takes much longer to fail because many
        // combinations must be tried and they all fail
        let accumulator = NaiveAccumulator::new(SEED);
        base_accumulator_test(Box::new(accumulator), 100, 3, true);
    }

    #[test]
    fn power_sum_none_dropped() {
        let accumulator = PowerSumAccumulator::new(100, SEED);
        base_accumulator_test(Box::new(accumulator), 100, 0, false);
    }

    #[test]
    fn power_sum_all_dropped() {
        let accumulator = PowerSumAccumulator::new(100, SEED);
        base_accumulator_test(Box::new(accumulator), 100, 0, false);
    }

    #[test]
    fn power_sum_one_dropped() {
        let accumulator = PowerSumAccumulator::new(100, SEED);
        base_accumulator_test(Box::new(accumulator), 100, 1, false);
    }

    #[test]
    fn power_sum_two_dropped() {
        let accumulator = PowerSumAccumulator::new(100, SEED);
        base_accumulator_test(Box::new(accumulator), 100, 2, false);
    }

    #[test]
    fn power_sum_many_dropped() {
        let accumulator = PowerSumAccumulator::new(1000, SEED);
        base_accumulator_test(Box::new(accumulator), 1000, 10, false);
    }

    #[test]
    fn power_sum_one_malicious_and_none_dropped() {
        let accumulator = PowerSumAccumulator::new(100, SEED);
        base_accumulator_test(Box::new(accumulator), 100, 0, true);
    }

    #[test]
    fn power_sum_one_malicious_and_one_dropped() {
        let accumulator = PowerSumAccumulator::new(100, SEED);
        base_accumulator_test(Box::new(accumulator), 100, 1, true);
    }

    #[test]
    fn power_sum_one_malicious_and_many_dropped() {
        // validation is much faster than the naive approach
        let accumulator = PowerSumAccumulator::new(1000, SEED);
        base_accumulator_test(Box::new(accumulator), 1000, 10, true);
    }

    #[test]
    fn iblt_none_dropped() {
        let accumulator = IBLTAccumulator::new(100, SEED);
        base_accumulator_test(Box::new(accumulator), 100, 0, false);
    }

    #[test]
    fn iblt_all_dropped() {
        let accumulator = IBLTAccumulator::new(100, SEED);
        base_accumulator_test(Box::new(accumulator), 100, 100, false);
    }

    #[test]
    fn iblt_one_dropped() {
        let accumulator = IBLTAccumulator::new(100, SEED);
        base_accumulator_test(Box::new(accumulator), 100, 1, false);
    }

    #[test]
    fn iblt_many_dropped_without_ilp_solver() {
        let accumulator = IBLTAccumulator::new(1000, SEED);
        base_accumulator_test(Box::new(accumulator), 1000, 10, false);
    }

    #[test]
    fn iblt_many_dropped_with_ilp_solver() {
        let accumulator = IBLTAccumulator::new_with_params(1000, 8, 2, 2, SEED);
        base_accumulator_test(Box::new(accumulator), 1000, 100, false);
    }

    #[test]
    fn iblt_one_malicious_and_none_dropped() {
        let accumulator = IBLTAccumulator::new(100, SEED);
        base_accumulator_test(Box::new(accumulator), 100, 0, true);
    }

    #[test]
    fn iblt_one_malicious_and_one_dropped() {
        let accumulator = IBLTAccumulator::new(100, SEED);
        base_accumulator_test(Box::new(accumulator), 100, 1, true);
    }

    #[test]
    fn iblt_one_malicious_and_many_dropped() {
        let accumulator = IBLTAccumulator::new(100, SEED);
        base_accumulator_test(Box::new(accumulator), 1000, 10, true);
    }
}

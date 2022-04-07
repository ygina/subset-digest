use std::hash::BuildHasher;
use std::collections::HashSet;
use std::collections::hash_map::RandomState;
use bloom::valuevec::ValueVec;
use num_bigint::{BigUint, ToBigUint};
use num_traits::{One, Zero};
use crate::hashing::HashIter;

/// TODO: Fatally, assumes inserted elements are unique.
/// Elements are u32s.
pub struct InvBloomLookupTable<R = RandomState, S = RandomState> {
    counters: ValueVec,
    max_data_value: BigUint,
    data: Vec<BigUint>,
    num_entries: u64,
    num_hashes: u32,
    hash_builder_one: R,
    hash_builder_two: S,
}

impl InvBloomLookupTable<RandomState, RandomState> {
    /// Creates a InvBloomLookupTable that uses `bits_per_entry` bits for
    /// each entry and expects to hold `expected_num_items`. The filter
    /// will be sized to have a false positive rate of the value specified
    /// in `rate`.
    pub fn with_rate(
        log2_data_length: u32,
        bits_per_entry: usize,
        rate: f32,
        expected_num_items: u32,
    ) -> Self {
        // TODO: determine number of entries and hashes from IBLT paper
        let num_entries = bloom::bloom::needed_bits(rate, expected_num_items);
        let num_hashes = bloom::bloom::optimal_num_hashes(
            bits_per_entry,
            expected_num_items,
        );
        InvBloomLookupTable {
            max_data_value: 2_u8.to_biguint().unwrap().pow(log2_data_length)
                - BigUint::one(),
            data: vec![BigUint::zero(); num_entries],
            counters: ValueVec::new(bits_per_entry, num_entries),
            num_entries: num_entries as u64,
            num_hashes,
            hash_builder_one: RandomState::new(),
            hash_builder_two: RandomState::new(),
        }
    }

    /// Clones the InvBloomLookupTable where all counters are 0.
    pub fn empty_clone(&self) -> Self {
        let bits_per_entry = self.counters.bits_per_val();
        Self {
            max_data_value: self.max_data_value.clone(),
            data: vec![0.to_biguint().unwrap(); self.num_entries as usize],
            counters: ValueVec::new(bits_per_entry, self.num_entries as usize),
            num_entries: self.num_entries,
            num_hashes: self.num_hashes,
            hash_builder_one: self.hash_builder_one.clone(),
            hash_builder_two: self.hash_builder_two.clone(),
        }
    }

    pub fn data(&self) -> &Vec<BigUint> {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut Vec<BigUint> {
        &mut self.data
    }

    pub fn counters(&self) -> &ValueVec {
        &self.counters
    }

    pub fn counters_mut(&mut self) -> &mut ValueVec {
        &mut self.counters
    }

    pub fn num_entries(&self) -> u64 {
        self.num_entries
    }

    pub fn num_hashes(&self) -> u32 {
        self.num_hashes
    }

    pub fn equals(&self, other: &Self) -> bool {
        unimplemented!()
    }
}

impl<R,S> InvBloomLookupTable<R,S> where R: BuildHasher, S: BuildHasher {
    /// Inserts an item, returns true if the item was already in the filter
    /// any number of times.
    pub fn insert(&mut self, item: &BigUint) -> bool {
        let mut min = u32::max_value();
        for h in HashIter::from(item,
                                self.num_hashes,
                                &self.hash_builder_one,
                                &self.hash_builder_two) {
            let idx = (h % self.num_entries) as usize;
            let cur = self.counters.get(idx);
            if cur < min {
                min = cur;
            }
            if cur < self.counters.max_value() {
                self.counters.set(idx, cur + 1);
                let difference = &self.max_data_value - &self.data[idx];
                if difference > *item {
                    self.data[idx] += item;
                } else {
                    self.data[idx] = item - difference;
                }
            } else {
                panic!("counting bloom filter counter overflow");
            }
        }
        min > 0
    }

    /// Removes an item, panics if the item does not exist.
    pub fn remove(&mut self, item: &BigUint) {
        for h in HashIter::from(item,
                                self.num_hashes,
                                &self.hash_builder_one,
                                &self.hash_builder_two) {
            let idx = (h % self.num_entries) as usize;
            let cur = self.counters.get(idx);
            if cur == 0 {
                panic!("item is not in the iblt");
            }
            self.counters.set(idx, cur - 1);
            if self.data[idx] >= *item {
                self.data[idx] -= item;
            } else {
                self.data[idx] = &self.max_data_value - (item - &self.data[idx]);
            }
        }
    }

    /// Checks if the item has been inserted into this InvBloomLookupTable.
    /// This function can return false positives, but not false negatives.
    pub fn contains(&self, item: &BigUint) -> bool {
        for h in HashIter::from(item,
                                self.num_hashes,
                                &self.hash_builder_one,
                                &self.hash_builder_two) {
            let idx = (h % self.num_entries) as usize;
            let cur = self.counters.get(idx);
            if cur == 0 {
                return false;
            }
        }
        true
    }

    /// Gets the indexes of the item in the vector.
    pub fn indexes(&self, item: &BigUint) -> Vec<usize> {
        HashIter::from(item,
                       self.num_hashes,
                       &self.hash_builder_one,
                       &self.hash_builder_two)
            .into_iter()
            .map(|h| (h % self.num_entries) as usize)
            .collect()
    }

    /// Enumerates as many items as possible in the IBLT and removes them.
    /// Returns the removed items. Note removed elements must be unique
    /// unless the IBLT uses an accumulator function that is not an XOR.
    pub fn eliminate_elems(&mut self) -> HashSet<BigUint> {
        // Loop through all the counters of the IBLT until there are no
        // remaining cells with count 1. This is O(num_counters*max_count).
        let mut removed_set: HashSet<BigUint> = HashSet::new();
        loop {
            let mut removed = false;
            for i in 0..(self.num_entries as usize) {
                if self.counters.get(i) != 1 {
                    continue;
                }
                let item = self.data[i].clone();
                self.remove(&item);
                assert!(removed_set.insert(item));
                removed = true;
            }
            if !removed {
                return removed_set;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;

    fn init_iblt() -> InvBloomLookupTable {
        InvBloomLookupTable::with_rate(128, 8, 0.01, 10)
    }

    fn vvsum(vec: &ValueVec) -> usize {
        let num_entries = vec.len() / vec.bits_per_val();
        (0..num_entries).map(|i| vec.get(i)).sum::<u32>() as usize
    }

    #[test]
    fn init_iblt_with_rate() {
        let iblt = init_iblt();
        assert_eq!(iblt.num_entries(), 96);
        assert_eq!(iblt.num_hashes(), 2);
        assert_eq!(vvsum(iblt.counters()), 0);
        assert_eq!(iblt.data().iter().sum::<BigUint>(), BigUint::zero());
        assert_eq!(iblt.data().len(), iblt.num_entries() as usize);
    }

    #[test]
    fn test_equals() {
        let mut iblt1 = init_iblt();
        let iblt2 = init_iblt();
        assert!(!iblt1.equals(&iblt2), "different random state");
        let iblt3 = iblt1.empty_clone();
        assert!(iblt1.equals(&iblt3), "empty clone duplicates random state");
        iblt1.insert(&1234_u32.to_biguint().unwrap());
        let iblt4 = iblt1.empty_clone();
        assert!(!iblt1.equals(&iblt4), "empty clone removes data");
        assert!(iblt1.equals(&iblt1), "reflexive equality");
        assert!(iblt2.equals(&iblt2), "reflexive equality");
    }

    #[test]
    fn test_insert() {
        let mut iblt = init_iblt();
        let elem = 1234_u32.to_biguint().unwrap();
        let indexes = iblt.indexes(&elem);
        for &idx in &indexes {
            assert_eq!(iblt.counters().get(idx), 0);
            assert_eq!(iblt.data()[idx], BigUint::zero());
        }
        assert!(!iblt.insert(&elem), "element did not exist already");
        assert_eq!(vvsum(iblt.counters()), 1 * iblt.num_hashes() as usize);
        for &idx in &indexes {
            assert_ne!(iblt.counters().get(idx), 0);
            assert_ne!(iblt.data()[idx], BigUint::zero());
        }
        assert!(iblt.insert(&elem), "added element twice");
        assert_eq!(vvsum(iblt.counters()), 2 * iblt.num_hashes() as usize);
        for &idx in &indexes {
            assert_ne!(iblt.counters().get(idx), 0);
            assert_ne!(iblt.data()[idx], BigUint::zero());
        }
    }

    #[test]
    fn test_empty_clone() {
        let mut iblt1 = init_iblt();
        iblt1.insert(&1234_u32.to_biguint().unwrap());
        iblt1.insert(&5678_u32.to_biguint().unwrap());
        let iblt2 = iblt1.empty_clone();
        assert!(vvsum(iblt1.counters()) > 0);
        assert_eq!(vvsum(iblt2.counters()), 0);
        assert!(iblt1.data().iter().sum::<BigUint>() > BigUint::zero());
        assert_eq!(iblt2.data().iter().sum::<BigUint>(), BigUint::zero());
        assert_eq!(
            iblt1.indexes(&1234_u32.to_biguint().unwrap()),
            iblt2.indexes(&1234_u32.to_biguint().unwrap()));
    }

    #[test]
    #[should_panic]
    fn counter_overflow() {
        let mut iblt = InvBloomLookupTable::with_rate(128, 1, 0.01, 10);
        iblt.insert(&1234_u32.to_biguint().unwrap());
        iblt.insert(&1234_u32.to_biguint().unwrap());
    }
}

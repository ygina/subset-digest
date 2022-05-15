use std::collections::HashSet;
use std::num::Wrapping;
use std::marker::PhantomData;

use rand;
use serde::{Serialize, Deserialize};
use siphasher::sip128::SipHasher13;

use crate::valuevec::ValueVec;
use crate::hashing::*;

#[derive(Serialize, Deserialize)]
#[serde(remote = "SipHasher13")]
struct SipHasher13Def {
    #[serde(getter = "SipHasher13::keys")]
    keys: (u64, u64),
}

// Provide a conversion to construct the remote type.
impl From<SipHasher13Def> for SipHasher13 {
    fn from(def: SipHasher13Def) -> SipHasher13 {
        SipHasher13::new_with_keys(def.keys.0, def.keys.1)
    }
}

#[derive(Serialize, Deserialize)]
pub struct InvBloomLookupTable<T> {
    counters: ValueVec,
    // sum of djb_hashed data with wraparound overflow
    data: Vec<u32>,
    num_entries: u64,
    num_hashes: u32,
    seed: u64,
    #[serde(with = "SipHasher13Def")]
    hash_builder_one: SipHasher13,
    #[serde(with = "SipHasher13Def")]
    hash_builder_two: SipHasher13,
    phantom: PhantomData<T>,
}

impl<T> InvBloomLookupTable<T> {
    /// Creates a InvBloomLookupTable that uses `bits_per_entry` bits for each
    /// entry, `num_entries` number of entries, and `num_hashes` number of hash
    /// functions. The data_size is the number of bits in the data field,
    /// where the value can be 8, 16, or 32.
    ///
    /// The recommended parameters are 10x entries the number of expected items,
    /// and 2 hash functions. These were experimentally found to provide the
    /// best tradeoff between space and false positive rates (stating the
    /// router is malicious when it is not).
    pub fn new(
        data_size: u32,
        bits_per_entry: usize,
        num_entries: usize,
        num_hashes: u32,
    ) -> InvBloomLookupTable<T> {
        use rand::RngCore;
        let seed = rand::rngs::OsRng.next_u64();
        Self::new_with_seed(
            seed,
            data_size,
            bits_per_entry,
            num_entries,
            num_hashes,
        )
    }

    /// Like `new()`, but seeds the hash builders.
    pub fn new_with_seed(
        seed: u64,
        data_size: u32,
        bits_per_entry: usize,
        num_entries: usize,
        num_hashes: u32,
    ) -> InvBloomLookupTable<T> {
        assert!(data_size == 32);
        use rand::{SeedableRng, rngs::SmallRng, Rng};
        let mut rng = SmallRng::seed_from_u64(seed);
        InvBloomLookupTable {
            data: vec![0; num_entries],
            counters: ValueVec::new(bits_per_entry, num_entries),
            num_entries: num_entries as u64,
            num_hashes,
            seed,
            hash_builder_one: SipHasher13::new_with_keys(rng.gen(), rng.gen()),
            hash_builder_two: SipHasher13::new_with_keys(rng.gen(), rng.gen()),
            phantom: PhantomData,
        }
    }

    /// Clones the InvBloomLookupTable where all counters are 0.
    pub fn empty_clone(&self) -> Self {
        let bits_per_entry = self.counters.bits_per_val();
        Self {
            data: vec![0; self.num_entries as usize],
            counters: ValueVec::new(bits_per_entry, self.num_entries as usize),
            num_entries: self.num_entries,
            num_hashes: self.num_hashes,
            seed: self.seed,
            hash_builder_one: self.hash_builder_one.clone(),
            hash_builder_two: self.hash_builder_two.clone(),
            phantom: PhantomData,
        }
    }

    pub fn data(&self) -> &Vec<u32> {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut Vec<u32> {
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

    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn equals(&self, other: &Self) -> bool {
        self.num_entries == other.num_entries
            && self.num_hashes == other.num_hashes
            && self.hash_builder_one.keys() == other.hash_builder_one.keys()
            && self.hash_builder_two.keys() == other.hash_builder_two.keys()
            && self.data == other.data
            && self.counters == other.counters
    }
}

pub trait IBLTOperations<T> {
    /// Inserts an item, returns true if the item was already in the filter
    /// any number of times.
    fn insert(&mut self, item: T) -> bool;

    /// Removes an item, panics if the item does not exist.
    fn remove(&mut self, item: T);

    /// Checks if the item has been inserted into this InvBloomLookupTable.
    /// This function can return false positives, but not false negatives.
    fn contains(&self, item: T) -> bool;

    /// Gets the indexes of the item in the vector.
    fn indexes(&self, item: T) -> Vec<usize>;

    /// Enumerates as many items as possible in the IBLT and removes them.
    /// Returns the removed items. Note removed elements must be unique
    /// because the corresponding counters would be at least 2.
    /// The caller will need to map elements to the inserted data type.
    fn eliminate_elems(&mut self) -> HashSet<T>;
}

impl<T> InvBloomLookupTable<T> {
    pub fn insert(&mut self, item: u32) -> bool {
        let mut min = self.counters.max_value();
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
            } else {
                self.counters.set(idx, 0);
            }
            self.data[idx] = (Wrapping(self.data[idx]) + Wrapping(item)).0;
        }
        min > 0
    }

    pub fn remove(&mut self, item: u32) {
        for h in HashIter::from(item,
                            self.num_hashes,
                            &self.hash_builder_one,
                            &self.hash_builder_two) {
            let idx = (h % self.num_entries) as usize;
            let cur = self.counters.get(idx);
            if cur == 0 {
                // wraparound
                self.counters.set(idx, self.counters.max_value());
            } else {
                self.counters.set(idx, cur - 1);
            }
            self.data[idx] = (Wrapping(self.data[idx]) - Wrapping(item)).0;
        }
    }

    pub fn contains(&self, item: u32) -> bool {
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

    pub fn indexes(&self, item: u32) -> Vec<usize> {
        HashIter::from(item,
                       self.num_hashes,
                       &self.hash_builder_one,
                       &self.hash_builder_two)
            .into_iter()
            .map(|h| (h % self.num_entries) as usize)
            .collect()
    }

    pub fn eliminate_elems(&mut self) -> HashSet<u32> {
        // Loop through all the counters of the IBLT until there are no
        // remaining cells with count 1. This is O(num_counters*max_count).
        let mut removed_set: HashSet<u32> = HashSet::new();
        loop {
            let mut removed = false;
            for i in 0..(self.num_entries as usize) {
                if self.counters.get(i) != 1 {
                    continue;
                }
                let item = self.data[i];
                self.remove(item);
                assert!(removed_set.insert(item));
                removed = true;
            }
            if !removed {
                return removed_set;
            }
        }
    }
}

// impl IBLTOperations<u16> for InvBloomLookupTable {
//     fn insert(&mut self, item: u16) -> bool {
//         assert_eq!(self.data_size, 16);
//         let mut min = self.counters.max_value();
//         for h in HashIter::from(item,
//                                 self.num_hashes,
//                                 &self.hash_builder_one,
//                                 &self.hash_builder_two) {
//             let idx = (h % self.num_entries) as usize;
//             let cur = self.counters.get(idx);
//             if cur < min {
//                 min = cur;
//             }
//             if cur < self.counters.max_value() {
//                 self.counters.set(idx, cur + 1);
//             } else {
//                 self.counters.set(idx, 0);
//             }
//             self.data.set(idx, (Wrapping(self.data.get(idx) as u16)
//                 + Wrapping(item as u16)).0 as u32);
//         }
//         min > 0
//     }

//     fn remove(&mut self, item: u16) {
//         for h in HashIter::from(item,
//                             self.num_hashes,
//                             &self.hash_builder_one,
//                             &self.hash_builder_two) {
//             let idx = (h % self.num_entries) as usize;
//             let cur = self.counters.get(idx);
//             if cur == 0 {
//                 // wraparound
//                 self.counters.set(idx, self.counters.max_value());
//             } else {
//                 self.counters.set(idx, cur - 1);
//             }
//             self.data.set(
//                 idx, (Wrapping(self.data.get(idx) as u16) - Wrapping(item
//                     as u16)).0 as u32);
//         }
//     }

//     fn contains(&self, item: u16) -> bool {
//         for h in HashIter::from(item,
//                                 self.num_hashes,
//                                 &self.hash_builder_one,
//                                 &self.hash_builder_two) {
//             let idx = (h % self.num_entries) as usize;
//             let cur = self.counters.get(idx);
//             if cur == 0 {
//                 return false;
//             }
//         }
//         true
//     }

//     fn indexes(&self, item: u16) -> Vec<usize> {
//         HashIter::from(item,
//                        self.num_hashes,
//                        &self.hash_builder_one,
//                        &self.hash_builder_two)
//             .into_iter()
//             .map(|h| (h % self.num_entries) as usize)
//             .collect()
//     }

//     fn eliminate_elems(&mut self) -> HashSet<u16> {
//         // Loop through all the counters of the IBLT until there are no
//         // remaining cells with count 1. This is O(num_counters*max_count).
//         let mut removed_set: HashSet<u16> = HashSet::new();
//         loop {
//             let mut removed = false;
//             for i in 0..(self.num_entries as usize) {
//                 if self.counters.get(i) != 1 {
//                     continue;
//                 }
//                 let item = self.data.get(i).clone() as u16;
//                 self.remove(item);
//                 assert!(removed_set.insert(item));
//                 removed = true;
//             }
//             if !removed {
//                 return removed_set;
//             }
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use bincode;

    const DATA_SIZE: u32 = 32;

    fn init_iblt() -> InvBloomLookupTable<u32> {
        InvBloomLookupTable::new(DATA_SIZE, 8, 100, 2)
    }

    fn vvsum(vec: &ValueVec) -> usize {
        let num_entries = vec.len() / vec.bits_per_val();
        (0..num_entries).map(|i| vec.get(i)).sum::<u32>() as usize
    }

    fn data_is_nonzero(vec: &Vec<u32>) -> bool {
        for i in 0..vec.len() {
            if vec[i] != 0 {
                return true;
            }
        }
        false
    }

    #[test]
    fn test_serialization_empty() {
        let iblt1 = init_iblt();
        let bytes = bincode::serialize(&iblt1).unwrap();
        let iblt2 = bincode::deserialize(&bytes).unwrap();
        assert!(iblt1.equals(&iblt2));
    }

    #[test]
    fn test_serialization_with_data() {
        let mut iblt1 = init_iblt();
        iblt1.insert(1234);
        let bytes = bincode::serialize(&iblt1).unwrap();
        let iblt2 = bincode::deserialize(&bytes).unwrap();
        assert!(iblt1.equals(&iblt2));
    }

    #[test]
    fn test_new_iblt() {
        let iblt = init_iblt();
        assert_eq!(iblt.num_entries(), 100);
        assert_eq!(iblt.num_hashes(), 2);
        assert_eq!(vvsum(iblt.counters()), 0);
        assert_eq!(iblt.data().iter().sum::<u32>(), 0);
    }

    #[test]
    fn test_new_iblt_with_seed() {
        let iblt1: InvBloomLookupTable<u32> =
            InvBloomLookupTable::new_with_seed(111, DATA_SIZE, 8, 100, 2);
        let iblt2 = InvBloomLookupTable::new_with_seed(222, DATA_SIZE, 8, 100, 2);
        let iblt3 = InvBloomLookupTable::new_with_seed(111, DATA_SIZE, 8, 100, 2);
        assert!(!iblt1.equals(&iblt2));
        assert!(iblt1.equals(&iblt3));
    }

    #[test]
    fn test_equals() {
        let mut iblt1 = init_iblt();
        let iblt2 = init_iblt();
        assert!(!iblt1.equals(&iblt2), "different random state");
        let iblt3 = iblt1.empty_clone();
        assert!(iblt1.equals(&iblt3), "empty clone duplicates random state");
        iblt1.insert(1234);
        let iblt4 = iblt1.empty_clone();
        assert!(!iblt1.equals(&iblt4), "empty clone removes data");
        assert!(iblt1.equals(&iblt1), "reflexive equality");
        assert!(iblt2.equals(&iblt2), "reflexive equality");
    }

    #[test]
    fn test_insert_without_overflow() {
        let mut iblt = init_iblt();
        let elem = 1234;
        let indexes = iblt.indexes(elem);
        for &idx in &indexes {
            assert_eq!(iblt.counters().get(idx), 0);
            assert_eq!(iblt.data()[idx], 0);
        }
        assert!(!iblt.insert(elem), "element did not exist already");
        assert_eq!(vvsum(iblt.counters()), 1 * iblt.num_hashes() as usize);
        for &idx in &indexes {
            assert_ne!(iblt.counters().get(idx), 0);
            assert_ne!(iblt.data()[idx], 0);
        }
        assert!(iblt.insert(elem), "added element twice");
        assert_eq!(vvsum(iblt.counters()), 2 * iblt.num_hashes() as usize);
        for &idx in &indexes {
            assert_ne!(iblt.counters().get(idx), 0);
            assert_ne!(iblt.data()[idx], 0);
        }
    }

    #[test]
    fn test_empty_clone() {
        let mut iblt1 = init_iblt();
        iblt1.insert(1234);
        iblt1.insert(5678);
        let iblt2 = iblt1.empty_clone();
        assert!(vvsum(iblt1.counters()) > 0);
        assert_eq!(vvsum(iblt2.counters()), 0);
        assert!(data_is_nonzero(iblt1.data()));
        assert_eq!(iblt2.data().iter().sum::<u32>(), 0);
        assert_eq!(
            iblt1.indexes(1234),
            iblt2.indexes(1234));
    }

    #[test]
    fn test_insert_with_counter_overflow() {
        // 1 bit per entry
        let mut iblt: InvBloomLookupTable<u32> =
            InvBloomLookupTable::new(DATA_SIZE, 1, 10, 1);
        let elem = 1234;
        let i = iblt.indexes(elem)[0];

        // counters and data are updated
        iblt.insert(elem);
        assert_eq!(iblt.counters().get(i), 1);
        assert_eq!(iblt.data()[i], elem);

        // on overflow, counter is zero but data is nonzero
        iblt.insert(elem);
        assert_eq!(iblt.counters().get(i), 0);
        assert_eq!(iblt.data()[i], elem * 2);
    }

    #[test]
    fn test_insert_with_data_wraparound() {
        let mut iblt: InvBloomLookupTable<u32> =
            InvBloomLookupTable::new(DATA_SIZE, 2, 10, 1);
        let elem = 2086475114;  // very big element
        let i = iblt.indexes(elem)[0];

        // counters and data are updated
        iblt.insert(elem);
        assert_eq!(iblt.counters().get(i), 1);
        assert_eq!(iblt.data()[i], elem);

        // on overflow, counter is zero but data is nonzero
        iblt.insert(elem);
        iblt.insert(elem);
        assert_eq!(iblt.counters().get(i), 3);
        assert!(iblt.data()[i] < elem);
    }

    #[test]
    fn test_eliminate_all_elems_without_duplicates() {
        let mut iblt: InvBloomLookupTable<u32> =
            InvBloomLookupTable::new_with_seed(111, DATA_SIZE, 8, 10, 2);
        let n: usize = 6;
        for elem in 0..(n as u32) {
            iblt.insert(elem);
        }
        assert_eq!(vvsum(iblt.counters()), n * (iblt.num_hashes() as usize));

        // Return the original elements
        let mut elems = iblt.eliminate_elems();
        assert_eq!(elems.len(), n);
        assert_eq!(vvsum(iblt.counters()), 0);
        assert_eq!(iblt.data().iter().sum::<u32>(), 0);
        for elem in 0..(n as u32) {
            assert!(elems.remove(&elem));
        }
    }

    #[test]
    fn test_eliminate_all_elems_with_duplicates() {
        let mut iblt: InvBloomLookupTable<u32> =
            InvBloomLookupTable::new_with_seed(111, DATA_SIZE, 8, 10, 2);
        let n: usize = 7;
        for elem in 1..(n as u32) {
            iblt.insert(elem);
        }
        iblt.insert(1_u32);  // duplicate element
        assert_eq!(vvsum(iblt.counters()), n * (iblt.num_hashes() as usize));

        // Not all elements were eliminated
        let elems = iblt.eliminate_elems();
        assert!(elems.len() < n);
        assert_eq!(vvsum(iblt.counters()),
            (n - elems.len()) * (iblt.num_hashes() as usize));

        // Test that the sums were updated correctly?
        assert!(data_is_nonzero(iblt.data()));
    }
}


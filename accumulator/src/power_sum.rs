use std::collections::HashMap;
use std::time::Instant;
use crate::Accumulator;
use digest::XorDigest;

/// I picked some random prime number in the range [2^32, 2^64] from
/// https://en.wikipedia.org/wiki/List_of_prime_numbers.
/// This one is a Thabit prime, which is not of significance.
const LARGE_PRIME: i64 = 51539607551;

/// The power sum accumulator stores the power sums of all processed elements
/// up to the threshold number of lost elements.
///
/// On validation, the accumulator computes the power sums for the given
/// list of elements, and subtracts the corresponding power sums of the
/// processed elements. The result is a system of polynomial equations for
/// the power sums of the lost elements. We solve this system to find the
/// values of the lost elements, and determine if these are a subset of the
/// given list. If it is, the log is valid. If it is not, or there is no
/// solution, then the log is invalid.
///
/// Note that validation cannot be  performed if the number of lost elements
/// exceeds the threshold. All calculations are done in a finite field, modulo
/// some 2^32 < large prime < 2^64 (the range of possible elements).
pub struct PowerSumAccumulator {
    digest: XorDigest,
    num_elems: usize,
    power_sums: Vec<i64>,
}

#[link(name = "pari", kind = "dylib")]
extern "C" {
    fn find_integer_monic_polynomial_roots_libpari(
        roots: *mut i64,
        coeffs: *const i64,
        field: i64,
        degree: usize,
    ) -> i32;
}

/// https://www.geeksforgeeks.org/multiply-large-integers-under-large-modulo/
fn mul_and_mod(mut a: i64, mut b: i64, modulo: i64) -> i64 {
    let mut res = 0;
    while b > 0 {
        if (b & 1) == 1 {
            res = (res + a) % modulo;
        }
        a = (2 * a) % modulo;
        b >>= 1; // b = b / 2
    }
    res
}

// modular division
fn div_and_mod(mut a: i64, mut b: i64, modulo: i64) -> i64 {
    // divide `a` and `b` by the GCD of `a` and `modulo`
    let gcd = {
        let (mut x, mut y) = if a < b {
            (a, b)
        } else {
            (b, a)
        };
        loop {
            let remainder = y - x * (y / x);
            if remainder == 0 {
                break x;
            }
            y = x;
            x = remainder;
        }
    };
    a /= gcd;
    b /= gcd;
    if b == 1 {
        return a;
    }

    // find the modular multiplicative inverse of b mod modulo
    // ax + by = gcd(a, b)
    let mmi = {
        let (mut old_r, mut r) = (b, modulo);
        let (mut old_x, mut x) = (1, 0);
        let (mut old_y, mut y) = (0, 1);
        while r != 0 {
            let quotient = old_r / r;
            (old_r, r) = (r, old_r - quotient * r);
            (old_x, x) = (x, old_x - quotient * x);
            (old_y, y) = (y, old_y - quotient * y);
        }
        let mut mmi = old_x;
        while mmi < 0 {
            mmi += modulo;
        }
        mmi
    };

    // return the divided `a` value multiplied by the MMI in the field
    mul_and_mod(a, mmi, modulo)
}

fn calculate_power_sums(elems: &Vec<u32>, threshold: usize) -> Vec<i64> {
    let mut power_sums: Vec<i64> = vec![0; threshold];
    for &elem in elems {
        let mut value = 1;
        for i in 0..power_sums.len() {
            value = mul_and_mod(value, elem as i64, LARGE_PRIME);
            power_sums[i] = (power_sums[i] + value) % LARGE_PRIME;
        }
    }
    power_sums
}

fn calculate_difference(lhs: Vec<i64>, rhs: &Vec<i64>) -> Vec<i64> {
    (0..lhs.len())
        .map(|i| lhs[i] + LARGE_PRIME - rhs[i])
        .map(|power_sum| power_sum % LARGE_PRIME)
        .collect()
}

// https://en.wikipedia.org/wiki/Newton%27s_identities
//   e0 = 1
//   e1 = e0*p0
// 2*e2 = e1*p0 - e0*p1
// 3*e3 = e2*p0 - e1*p1 + e0*p2
// 4*e4 = e3*p0 - e2*p1 + e1*p2 - e0*p3
// ...
// Returns the coefficients as positive numbers in the field GF(LARGE_PRIME).
fn compute_polynomial_coefficients(p: Vec<i64>) -> Vec<i64> {
    let n = p.len();
    if n == 0 {
        return vec![];
    }
    let mut e: Vec<i64> = vec![1];
    for i in 0..n {
        let mut sum = 0;
        for j in 0..(i+1) {
            if j & 1 == 0 {
                sum += mul_and_mod(e[i-j], p[j], LARGE_PRIME);
            } else {
                sum -= mul_and_mod(e[i-j], p[j], LARGE_PRIME);
            }
        }
        while sum < 0 {
            sum += LARGE_PRIME;
        }
        e.push(div_and_mod(sum, i as i64 + 1, LARGE_PRIME));
    }
    for i in 0..(n+1) {
        if i & 1 != 0 {
            e[i] *= -1;
            e[i] += LARGE_PRIME;
        }
    }
    // includes the leading coefficient
    e

    /*
    let n = p.len();
    let mut coeffs: Vec<i64> = vec![0; n];
    unsafe {
        compute_polynomial_coefficients_wrapper(
            coeffs.as_mut_ptr(),
            p.as_ptr(),
            n,
        );
    }
    */
}

fn find_integer_monic_polynomial_roots(
    coeffs: Vec<i64>,
) -> Result<Vec<i64>, String> {
    let mut roots: Vec<i64> = vec![0; coeffs.len() - 1];
    if unsafe {
        find_integer_monic_polynomial_roots_libpari(
            roots.as_mut_ptr(),
            coeffs.as_ptr(),
            LARGE_PRIME,
            roots.len(),
        )
    } == 0 {
        Ok(roots)
    } else {
        Err("could not factor polynomial".to_string())
    }
}

impl PowerSumAccumulator {
    pub fn new(threshold: usize) -> Self {
        Self {
            digest: XorDigest::new(),
            num_elems: 0,
            power_sums: (0..threshold).map(|_| 0).collect(),
        }
    }
}

impl Accumulator for PowerSumAccumulator {
    fn process(&mut self, elem: u32) {
        self.digest.add(elem);
        self.num_elems += 1;
        let mut value: i64 = 1;
        for i in 0..self.power_sums.len() {
            value = mul_and_mod(value, elem as i64, LARGE_PRIME);
            self.power_sums[i] = (self.power_sums[i] + value) % LARGE_PRIME;
        }
    }

    fn process_batch(&mut self, elems: &Vec<u32>) {
        for &elem in elems {
            self.process(elem);
        }
    }

    fn total(&self) -> usize {
        self.num_elems
    }

    fn validate(&self, elems: &Vec<u32>) -> bool {
        // The number of power sum equations we need is equal to
        // the number of lost elements. Validation cannot be performed
        // if this number exceeds the threshold.
        if elems.len() < self.total() {
            warn!("more elements received than logged");
            return false;
        }
        let n_values = elems.len() - self.total();
        let threshold = self.power_sums.len();
        if n_values > threshold {
            panic!("number of lost elements exceeds threshold");
        }

        // Calculate the power sums of the given list of elements.
        // Find the difference with the power sums of the processed elements.
        // If no elements are missing, then all the power sums should be zero.
        let t1 = Instant::now();
        let power_sums = calculate_power_sums(elems, threshold);
        let t2 = Instant::now();
        debug!("calculated power sums: {:?}", t2 - t1);
        let power_sums_diff = calculate_difference(power_sums, &self.power_sums);
        let t3 = Instant::now();
        debug!("calculated power sum difference: {:?}", t3 - t2);
        if n_values == 0 {
            for diff in power_sums_diff {
                if diff != 0 {
                    return false;
                }
            }
            return true;
        }

        // Solve the system of equations.
        let coeffs = compute_polynomial_coefficients(
            power_sums_diff[..n_values].to_vec());
        let t4 = Instant::now();
        debug!("computed polynomial coefficients: {:?}", t4 - t3);
        let roots = {
            let roots = find_integer_monic_polynomial_roots(coeffs);
            let t5 = Instant::now();
            debug!("found integer monic polynomial roots: {:?}", t5 - t4);
            match roots {
                Ok(roots) => roots,
                Err(_) => {
                    return false;
                }
            }
        };

        // Check that a solution exists and that the solution is a subset of
        // the element list.
        // TODO: we might also want to recompute the power sum equations beyond
        // n_values in case the router fudged just one equation or something.
        // TODO: is it easy for the router to fudge the equations?
        let t5 = Instant::now();
        let mut elem_count: HashMap<u32, usize> = HashMap::new();
        for &elem in elems {
            let count = elem_count.entry(elem).or_insert(0);
            *count += 1;
        }
        for root in roots {
            let root = u32::try_from(root);
            if root.is_err() {
                return false;
            }
            let count = elem_count.entry(root.unwrap()).or_insert(0);
            if *count == 0 {
                return false;
            }
            *count -= 1;
        }
        let t6 = Instant::now();
        debug!("checked roots against element list: {:?}", t6 - t5);
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mul_and_mod() {
        assert_eq!(mul_and_mod(2, 3, 10), 6);
        assert_eq!(mul_and_mod(2, 4, 10), 8);
        assert_eq!(mul_and_mod(2, 3, 5), 1);
        assert_eq!(mul_and_mod(2, 4, 5), 3);
    }

    #[test]
    fn test_div_and_mod() {
        assert_eq!(div_and_mod(8, 2, 10), 4);
        assert_eq!(div_and_mod(8, 3, 10), 6); // MMI of 3 mod 10 = 7
        assert_eq!(div_and_mod(8, 6, 10), 8);
    }

    #[test]
    fn test_calculate_power_sums() {
        assert_eq!(calculate_power_sums(&vec![2, 3, 5], 2), vec![10, 38]);
        assert_eq!(calculate_power_sums(&vec![2, 3, 5], 3), vec![10, 38, 160]);
        let one_large_num = calculate_power_sums(&vec![4294967295], 3);
        assert_eq!(one_large_num, vec![4294967295, 8947848534, 17567609286]);
        let two_large_nums = calculate_power_sums(&vec![4294967295, 2294967295], 3);
        assert_eq!(two_large_nums, vec![6589934590, 32873368637, 30483778854]);
    }

    #[test]
    fn test_calculate_difference() {
        let diff = calculate_difference(vec![2, 3, 4], &vec![1, 2, 3]);
        assert_eq!(diff, vec![1, 1, 1]);
        let diff = calculate_difference(vec![2, 3, 4], &vec![1, 2, 3, 4]);
        assert_eq!(diff, vec![1, 1, 1]);
        let overflow_diff = calculate_difference(vec![1], &vec![2]);
        assert_eq!(overflow_diff, vec![51539607550]);
    }

    #[test]
    fn test_compute_polynomial_coefficients_small_numbers() {
        let x = vec![2, 3, 5];
        let power_sums_diff = calculate_power_sums(&x, 3);
        assert_eq!(power_sums_diff, vec![10, 38, 160]);
        let coeffs = compute_polynomial_coefficients(power_sums_diff);
        assert_eq!(coeffs, vec![1, -10+LARGE_PRIME, 31, -30+LARGE_PRIME]);
    }

    #[test]
    fn test_compute_polynomial_coefficients_large_numbers() {
        let x = vec![4294966796, 3987231002];
        let power_sums_diff = calculate_power_sums(&x, 2);
        assert_eq!(power_sums_diff, vec![8282197798, 20796235250]);
        let coeffs = compute_polynomial_coefficients(power_sums_diff);
        let e1 = (x[0] as i64) + (x[1] as i64) % LARGE_PRIME;
        let e2 = mul_and_mod(x[0] as i64, x[1] as i64, LARGE_PRIME);
        assert_eq!(coeffs, vec![1, -e1+LARGE_PRIME, e2]);
    }

    #[test]
    fn test_find_integer_monic_polynomial_roots_small_numbers() {
        let x = vec![2, 3, 5];
        let power_sums_diff = calculate_power_sums(&x, x.len());
        let coeffs = compute_polynomial_coefficients(power_sums_diff);
        let mut roots = {
            let roots = find_integer_monic_polynomial_roots(coeffs);
            assert!(roots.is_ok());
            roots.unwrap()
        };
        roots.sort();
        assert_eq!(roots, x.into_iter().map(|x| x as i64).collect::<Vec<_>>());
    }

    #[test]
    fn test_find_integer_monic_polynomial_roots_large_numbers() {
        let x = vec![3987231002, 4294966796];
        let power_sums_diff = calculate_power_sums(&x, x.len());
        let coeffs = compute_polynomial_coefficients(power_sums_diff);
        let mut roots = {
            let roots = find_integer_monic_polynomial_roots(coeffs);
            assert!(roots.is_ok());
            roots.unwrap()
        };
        roots.sort();
        assert_eq!(roots, x.into_iter().map(|x| x as i64).collect::<Vec<_>>());
    }

    #[test]
    fn test_find_integer_monic_polynomial_roots_no_solution() {
        let coeffs = vec![1, 47920287469, 12243762544, 39307197049];
        let roots = find_integer_monic_polynomial_roots(coeffs);
        assert!(roots.is_err());
    }
}

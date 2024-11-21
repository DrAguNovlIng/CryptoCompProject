use rand::prelude::Distribution;
use num_bigint::{BigInt, BigUint, RandomBits, ToBigInt};
use miller_rabin::is_prime;


// Method to generate a prime, this is done by picking a random number of the desired size and using the Miller-Rabin primality test
pub fn generate_prime(size: u64) -> BigInt {
    for _ in 0..10000 {
        let rng = &mut rand::thread_rng();
        let maybe_prime: BigUint = RandomBits::new(size).sample(rng);
        if is_prime(&maybe_prime, 12) {
            return maybe_prime.to_bigint().unwrap();
        }
    }
    panic!("Could not generate prime number");
}
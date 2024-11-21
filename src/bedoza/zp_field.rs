use serde::{Deserialize, Serialize};
use std::{fs::File, io::Write};
use rand::prelude::Distribution;
use num_bigint::{BigInt, BigUint, RandomBits, ToBigInt};
use crate::prime_functions::generate_prime;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZpField {
    pub size_in_bits: u64, //size of the prime in bits
    pub p: BigInt, //prime number
}

impl ZpField {
    pub fn new(group_size: u64) -> Self {
        Self {
            size_in_bits: group_size,
            p: generate_prime(group_size),
        }
    }

    pub fn struct_from_file(path: &str) -> Self {
        let file = File::open(path).unwrap();
        serde_json::from_reader(file).unwrap()
    }

    pub fn struct_to_file(&self, path: &str) {
        let json = serde_json::to_string(&self).unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }
    
    pub fn generate_random_element(&mut self) -> BigInt {
        for _ in 0..10000 {
            let rng = &mut rand::thread_rng();
            let random_bits: BigUint = RandomBits::new(self.size_in_bits).sample(rng);
            let maybe_field: BigInt = random_bits.to_bigint().unwrap();
            if (maybe_field < self.p) && (maybe_field != 0.to_bigint().unwrap()) {
                return maybe_field;
            }
        }
        panic!("Could not generate prime number");
    }
}

use serde::{Deserialize, Serialize};
use std::{fs::File, io::Write};
use rand::prelude::Distribution;
use num_bigint::{BigInt, BigUint, RandomBits, ToBigInt};
use crate::prime_functions::generate_prime;

pub type ZpFieldElement = BigInt;

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

    pub fn new_from_prime(prime: BigInt, group_size: u64) -> Self {
        Self {
            size_in_bits: group_size,
            p: prime
        }
    }

    //Creates a struct from a file to avoid prime re-generation
    pub fn struct_from_file(path: &str) -> Self {
        let file = File::open(path).unwrap();
        serde_json::from_reader(file).unwrap()
    }

    //Writes the struct to a file to avoid future prime re-generation
    pub fn struct_to_file(&self, path: &str) {
        let json = serde_json::to_string(&self).unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }
    
    //Creates a field element from a BigInt value, i.e. takes the value mod p
    pub fn create_field_element(&self, value: BigInt) -> ZpFieldElement {
        value.modpow(&BigInt::from(1u8), &self.p)
    }

    //Generates a random element in the field, this is done by repeatedly trials such that the output is uniformly random
    pub fn generate_random_element(&self) -> ZpFieldElement {
        for _ in 0..10000 {
            let rng = &mut rand::thread_rng();
            let random_bits: BigUint = RandomBits::new(self.size_in_bits).sample(rng);
            let maybe_field: ZpFieldElement = random_bits.to_bigint().unwrap();
            if maybe_field < self.p {
                return maybe_field;
            }
        }
        panic!("Could not generate prime number");
    }

    //Addition in the field
    pub fn add(&self, a: ZpFieldElement, b: ZpFieldElement) -> ZpFieldElement {
        //modpow is used for the modulo operation, since % is the remainder function and can be negative
        (a + b).modpow(&BigInt::from(1u8), &self.p)
    }

    //Multiplication in the field
    pub fn mul(&self, a: ZpFieldElement, b: ZpFieldElement) -> ZpFieldElement {
        //modpow is used for the modulo operation, since % is the remainder function and can be negative
        (a * b).modpow(&BigInt::from(1u8), &self.p)
    }
    
}

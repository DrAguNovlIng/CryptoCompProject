use std::{fs::File, io::Write};
use rand::prelude::Distribution;
use num_bigint::{BigInt, BigUint, RandomBits, ToBigInt};
use miller_rabin::is_prime;
use serde::{Deserialize, Serialize};
use crate::threshold_ecdsa::prime_functions::generate_prime;


/*

    Implementation of everything Group related
    This includes saving and reading groups to and from files
    since generating a group is time consuming

*/
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Group {
    pub g: BigInt, //generator
    pub q: BigInt, //order of the group
    pub p: BigInt, //prime number
}

impl Group {
    pub fn new(group_size: u64) -> Self {
        generate_safe_prime_group(group_size)
    }

    // Methods to write and read groups to and from files, saving time when testing, instead of generating a new group every time
    pub fn struct_from_file(path: &str) -> Self {
        let file = File::open(path).unwrap();
        serde_json::from_reader(file).unwrap()
    }

    pub fn struct_to_file(&self, path: &str) {
        let json = serde_json::to_string(&self).unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }

    pub fn gen_random_exponent(&self) -> BigInt {
        let rng = &mut rand::thread_rng();
        loop {
            let random: BigUint = RandomBits::new(self.q.bits()).sample(rng);
            let r = random.to_bigint().unwrap();
            if r < self.q {
                return r;
            }
        }
    }
}

/*
    Methods for generate primes and safe prime groups
*/

// Method to generate a safe prime group, this is done by generating a prime q and then checking if 2q+1 is also a prime
pub fn generate_safe_prime_group(size: u64) -> Group {
    for _ in 0..10000 {
        let q = generate_prime(size);
        let p = 2u8 * q.clone() + 1u8;
        if is_prime(&p, 10) {
            let g = generate_random_safe_prime_group_element(p.clone());
            return Group { g, q, p };
        }
    }
    panic!("Could not generate a safe prime group");
}

pub fn generate_random_safe_prime_group_element(p: BigInt) -> BigInt {
    //We do not imput r, but rely on the rand crate to sample for us.
    let rng = &mut rand::thread_rng();
    loop {
        let random: BigUint = RandomBits::new(p.bits()).sample(rng);
        let s = random.to_bigint().unwrap();
        if s < p {
            let h = s.modpow(&BigInt::from(2u8), &p);
            return h;
        }
    }
}

/*
    Implementation of ElGamal
*/

pub type Ciphertext = (BigInt, BigInt);
pub type Plaintext = BigInt;
pub type SecretKey = BigInt;
pub type PublicKey = BigInt; //We simply omit sending the group along for simplicity (we assume they agree on the group)

pub struct ElGamal {
    pub group: Group,
}

impl ElGamal {
    //The constructure creates a group of prime order q and a generator g
    pub fn new(group: Group) -> Self {
        Self { group: group }
    }

    pub fn gen_sk(&self) -> SecretKey {
        self.group.gen_random_exponent()
    }

    //Takes a secret key and outputs a corresponding public key
    pub fn gen_pk(&self, sk: SecretKey) -> PublicKey {
        let h = self.group.g.modpow(&sk, &self.group.p);
        h
    }

    //Takes some randomness and outputs a random looking public key
    pub fn o_gen_pk(&self) -> PublicKey {
        generate_random_safe_prime_group_element(self.group.p.clone())
    }

    fn encode_message(&self, m: Plaintext) -> BigInt {
        //Encode the message to a field element
        if (&m + BigInt::from(1u8)).modpow(&self.group.q, &self.group.p) == BigInt::from(1u8) {
            return (m + BigInt::from(1u8)).modpow(&BigInt::from(1u8), &self.group.p);
        }
        else {
            return (-m - BigInt::from(1u8)).modpow(&BigInt::from(1u8), &self.group.p);
        }
    }

    fn decode_message(&self, encoded_m: BigInt) -> Plaintext {
        //Decode the field element to a message
        if encoded_m <= self.group.q {
            return (encoded_m - BigInt::from(1u8)).modpow(&BigInt::from(1u8), &self.group.p);
        } 
        else {
            return (-encoded_m - BigInt::from(1u8)).modpow(&BigInt::from(1u8), &self.group.p);
        }
    }

    //Encrypts a message using a public key
    pub fn enc(&self, pk: PublicKey, m: Plaintext) -> Ciphertext {
        let encoded_m = self.encode_message(m);
        let p = &self.group.p;
        let r = self.group.gen_random_exponent();
        let c1 = self.group.g.modpow(&r, p);
        let hr = pk.modpow(&r, p);
        let c2 = ((encoded_m % p) * (hr % p)) % p; //Might be too slow for large m, but should be fine for us
        (c1, c2)
    }

    //Decrypts a message using a secret key
    pub fn dec(&self, sk: SecretKey, c: Ciphertext) -> Plaintext {
        let p = &self.group.p;
        let c1 = c.0;
        let c2 = c.1;
        let hr = c1.modpow(&sk, p);
        let hr_inv = hr.modinv(p).unwrap();

        let encoded_m = ((c2 % p) * (hr_inv % p)) % p; //Might be too slow for large m, but should be fine for us
        self.decode_message(encoded_m)
    }
}
pub mod elgamal;

use elgamal::{ElGamal, PublicKey, Plaintext, SecretKey, Ciphertext, Group};
use num_bigint::BigInt;

pub struct Chooser {
    el_gamal: ElGamal,
    input: u8,
    option_count: u8,
    sk: SecretKey
}

impl Chooser {
    pub fn new(common_group: Group, option_count: u8) -> Self {
        Self { el_gamal: ElGamal::new(common_group), input: 0, option_count, sk: BigInt::from(0u8) }
    }

    pub fn choose(&mut self, input: u8) -> Vec<PublicKey> {
            self.input = input;
            self.sk = self.el_gamal.gen_sk();

            let mut res: Vec<PublicKey> = vec![BigInt::from(0u8); self.option_count as usize];
            for i in 0..self.option_count {
                if i != input {
                    res[i as usize] = self.el_gamal.o_gen_pk()
                }
            }
            res[input as usize] = self.el_gamal.gen_pk(self.sk.clone());
            res
        }

    pub fn retrieve(&mut self, m2: Vec<Ciphertext>) -> Plaintext {
        let ciphertext = m2[self.input as usize].clone();
        let decryption = self.el_gamal.dec(self.sk.clone(), ciphertext);
        decryption
    }
}

pub struct Producer {
    el_gamal: ElGamal,
    option_count: u8,
    producer_function: fn(u8, u8) -> BigInt
}

impl Producer {
    pub fn new(common_group: Group, set_size: u8, ot_func: fn(u8, u8) -> BigInt) -> Self {
        Self { el_gamal: ElGamal::new(common_group), option_count: set_size, producer_function: ot_func }
    }

    pub fn transfer(&mut self, input: u8, m1_from_alice: Vec<PublicKey>) -> Vec<Ciphertext> {
        let func = self.producer_function;
        let mut res: Vec<Ciphertext> = vec![(BigInt::from(0u8),BigInt::from(0u8)); self.option_count as usize];
        for i in 0..self.option_count {
            let func_out = func(i, input);
            if func_out > self.el_gamal.group.p {
                panic!("Function output is larger than prime p");
            }
            res[i as usize] = self.el_gamal.enc(m1_from_alice[i as usize].clone(), func_out);
        }
        res
    }
}
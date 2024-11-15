use std::array::from_fn;
use num_bigint::BigInt;

pub mod ot;
use crate::ot::elgamal::{ElGamal, PublicKey, SecretKey, Ciphertext, Group};

/*

    Imeplementation of Alice

*/
pub struct Alice {
    el_gamal: ElGamal,
    input_a: bool,
    input_b: bool,
    input_r: bool,
    sk: SecretKey
}

fn translate_input(input: u8) -> (bool, bool, bool) {
    let a = (input & 4) > 0;
    let b = (input & 2) > 0;
    let r = (input & 1) > 0;
    (a, b, r)
}

fn translate_input_back(a: bool, b: bool, r: bool) -> u8 {
    let mut res = 0;
    if a { res += 4}
    if b { res += 2}
    if r { res += 1}
    res
}

impl Alice {
    pub fn new(common_group: Group) -> Self {
        Self { el_gamal: ElGamal::new(common_group), input_a: false, input_b: false, input_r: false, sk: BigInt::from(0u8) }
    }

    pub fn choose(&mut self, input: u8) -> [PublicKey; 8] {
            let (a, b, r) = translate_input(input);
            self.input_a = a;
            self.input_b = b;
            self.input_r = r;
            self.sk = self.el_gamal.gen_sk();
            let mut res: [PublicKey; 8] = from_fn(|_| {BigInt::from(0u8)});
            for i in 0..8 {
                if i != input {
                    res[i as usize] = self.el_gamal.o_gen_pk()
                }
            }
            res[input as usize] = self.el_gamal.gen_pk(self.sk.clone());
            res
        }

    pub fn retrieve(&mut self, m2: [Ciphertext; 8]) -> u8 {
        let input_index = translate_input_back(self.input_a, self.input_b, self.input_r);
        let ciphertext = m2[input_index as usize].clone();
        let decryption = self.el_gamal.dec(self.sk.clone(), ciphertext);
        decryption.to_bytes_be().1[0] //We know it is 0 or 1 at this point, so this is safe
    }
}


/*

    Implementation of Bob

*/
pub struct Bob {
    el_gamal: ElGamal,
    input_a: bool,
    input_b: bool,
    input_r: bool,
}

fn blood_function(alice: (bool, bool, bool), bob: (bool, bool, bool)) -> bool {
    if alice.0 < bob.0 {return false}
    if alice.1 < bob.1 {return false}
    if alice.2 < bob.2 {return false}
    true
}

impl Bob {
    pub fn new(common_group: Group) -> Self {
        Self { el_gamal: ElGamal::new(common_group),  input_a: false, input_b: false, input_r: false }
    }

    pub fn transfer(&mut self, input: u8, m1_from_alice: [PublicKey; 8]) -> [Ciphertext; 8] {
        let (a, b, r) = translate_input(input);
        self.input_a = a;
        self.input_b = b;
        self.input_r = r;
        let mut res: [Ciphertext; 8] = from_fn(|_| {(BigInt::from(0u8),BigInt::from(0u8))});
        for i in 0..8 {
            res[i as usize] = self.el_gamal.enc(m1_from_alice[i as usize].clone(), BigInt::from(blood_function(translate_input(i), (a,b,r))))
        }
        res
    }
}

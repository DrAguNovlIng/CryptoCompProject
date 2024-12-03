pub mod ot;
pub mod bedoza;
pub mod prime_functions;

use bedoza::{zp_field::ZpField, Bedoza, party::ShareName};
use ot::elgamal::Group;

pub struct ThresholdECDSA {
    bedoza: Bedoza,
}

impl ThresholdECDSA {
    pub fn new(ot_group: Group, zp_group: ZpField) -> Self {
        Self {
            bedoza: Bedoza::new(ot_group, zp_group),
        }
    }


    //Generate a keypair for a specific user
    pub fn gen_keypair(&mut self) {
        todo!()
    }

    //The user independent preprocessing step, the output is a tuple with a secret shared point k, and a secret shared Zp field element k^-1
    pub fn user_independent_preprocessing(&mut self) -> (ShareName, ShareName) {
        todo!()
    }

    //The user dependent preprocessing step, the output is a tuple (k, k^-1, sk_j')
    pub fn user_dependent_preprocessing(&mut self, sk_j: ShareName) -> (ShareName, ShareName, ShareName) {
        todo!()
    }

    //Signing a message M using a preproccesed tuple (k, k^-1, sk_j')
}

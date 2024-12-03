pub mod ot;
pub mod bedoza;
pub mod prime_functions;

use bedoza::{party::ShareName, zp_field::{ZpField, ZpFieldElement}, Bedoza};
use ot::elgamal::Group;
use p256::ProjectivePoint;

type PublicKey = ProjectivePoint;
type Signature = (ZpFieldElement, ProjectivePoint);

pub struct ThresholdECDSA {
    bedoza: Bedoza,
}

impl ThresholdECDSA {
    pub fn new(ot_group: Group, zp_group: ZpField) -> Self {
        Self {
            bedoza: Bedoza::new(ot_group, zp_group),
        }
    }

    //Generate a keypair for a specific user, i.e. ([sk_j], pk_j)
    pub fn gen_keypair(&mut self) -> (ShareName, PublicKey) {
        todo!()
    }

    //The user independent preprocessing step, the output is a tuple (<k>, [k^-1])
    pub fn user_independent_preprocessing(&mut self) -> (ShareName, ShareName) {
        todo!()
    }

    //The user dependent preprocessing step, the output is a tuple (<k>, [k^-1], [sk_j'])
    pub fn user_dependent_preprocessing(&mut self, sk_j: ShareName, k: ShareName, k_inv: ShareName) -> (ShareName, ShareName, ShareName) {
        todo!()
    }

    //Signing a message M using a preproccesed tuple (k, k^-1, sk_j'), the output is a signature (r,s)
    pub fn sign(&mut self, k: ShareName, k_inv: ShareName, sk_j: ShareName, message: &str) -> Signature {
        todo!()
    }
}

//Verifying a signature (r,s) on a message M using a public key pk_j
pub fn verify_signature(pk: PublicKey, message: &str, signature: Signature) -> bool {
    todo!()
}
pub mod ot;
pub mod bedoza;
pub mod prime_functions;
pub mod hashing;

use num_bigint::{BigInt, Sign};
use p256::elliptic_curve::point::AffineCoordinates;
use bedoza::{party::ShareName, zp_field::{ZpField, ZpFieldElement}, Bedoza};
use ot::elgamal::Group;
use p256::ProjectivePoint;
use crate::threshold_ecdsa::bedoza::ec_helpers::bigint_to_scalar;
use crate::threshold_ecdsa::hashing::hash_string;

type PublicKey = ProjectivePoint;
type Signature = (ZpFieldElement, ZpFieldElement);

pub struct ThresholdECDSA {
    bedoza: Bedoza,
    zp_field: ZpField,
}
/*
    Implementation of Threashold ECDSA according to the paper
    Note that some compuation that depends only on public information 
    (such as opened variables) is done here in this file for simplicity.
    In a real world scenario, both parties would compute the information themselves.
*/
impl ThresholdECDSA {
    pub fn new(ot_group: Group, zp_field: ZpField) -> Self {
        Self {
            bedoza: Bedoza::new(ot_group, zp_field.clone()),
            zp_field,
        }
    }

    //Generate a keypair for a specific user, i.e. ([sk_j], pk_j)
    pub fn gen_keypair(&mut self) -> (ShareName, PublicKey) {
        let sk = self.bedoza.rand();
        self.bedoza.convert_ec(sk.clone());
        let pk = self.bedoza.open_ec(sk.clone());

        (sk, pk)
    }

    //The user independent preprocessing step, the output is a tuple (<k>, [k^-1])
    pub fn user_independent_preprocessing(&mut self) -> (ShareName, ShareName) {
        let (k_inverse, b, c) = self.bedoza.rand_mul();
        let c_open = self.bedoza.open(c);
        let c_inverse = self.zp_field.find_inverse(c_open);
        self.bedoza.convert_ec(b.clone());
        let k = self.bedoza.mul_const_ec(b, c_inverse);
        (k, k_inverse)
    }

    //The user dependent preprocessing step, the output is a tuple (<k>, [k^-1], [sk_j'])
    pub fn user_dependent_preprocessing(&mut self, sk_j: ShareName, k: ShareName, k_inv: ShareName) -> (ShareName, ShareName, ShareName) {
        let sk_j_prime= self.bedoza.mul(k_inv.clone(), sk_j);
        (k, k_inv, sk_j_prime)
    }

    //Signing a message M using a preproccesed tuple (k, k^-1, sk_j'), the output is a signature (r,s)
    pub fn sign(&mut self, k: ShareName, k_inv: ShareName, sk_j_prime: ShareName, message: &str) -> Signature {
        let r = self.bedoza.open_ec(k);
        let x = r.to_affine().x();
        let x_as_field_elem = self.zp_field.create_field_element(BigInt::from_bytes_be(Sign::Plus, x.as_slice()));
        let h_m = hash_string(message, self.zp_field.clone());
        let s_left = self.bedoza.mul_const(k_inv, h_m.clone());
        let s_right = self.bedoza.mul_const(sk_j_prime, x_as_field_elem.clone());
        let s = self.bedoza.add(s_left, s_right);
        let s_open = self.bedoza.open(s);

        (x_as_field_elem, s_open)
    }

    //Verifying a signature (r,s) on a message M using a public key pk_j
    //Note this can be done locally
    pub fn verify_signature(&self, pk: PublicKey, message: &str, signature: Signature) -> bool {
        let h_m = hash_string(message, self.zp_field.clone());
        let s_inv = self.zp_field.find_inverse(signature.1.clone());
        let left = ProjectivePoint::GENERATOR * bigint_to_scalar(self.zp_field.mul(h_m, s_inv.clone()));
        let right = pk * bigint_to_scalar(self.zp_field.mul(s_inv.clone(), signature.0.clone()));
        let calculated_r_x = (left + right).to_affine().x();
        let calculated_r_x_field_elem = self.zp_field.create_field_element(BigInt::from_bytes_be(Sign::Plus, calculated_r_x.as_slice()));

        calculated_r_x_field_elem == signature.0
    }
}


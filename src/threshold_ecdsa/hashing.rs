use num_bigint::{BigUint, ToBigInt};
use sha2::{Sha512, Digest};
use crate::threshold_ecdsa::bedoza::zp_field::{ZpField, ZpFieldElement};

pub fn hash_string(message: &str, zp_field: ZpField) -> ZpFieldElement {
    let mut hasher = Sha512::new();
    hasher.update(message);
    let result = hasher.finalize();

    let hash_as_biguint = BigUint::from_bytes_be(&result.to_vec());
    let hash_as_bigint = hash_as_biguint.to_bigint().unwrap();
    zp_field.create_field_element(hash_as_bigint)
}
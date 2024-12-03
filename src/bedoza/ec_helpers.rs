use num_bigint::BigInt;
use p256::elliptic_curve::scalar::FromUintUnchecked;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ProjectivePoint, U256, Scalar};

pub fn print_elliptic_curve_point(point: &ProjectivePoint) {
    let encoded_point = point.to_affine().to_encoded_point(false);
    println!("Encoded point x: {:?}",encoded_point.x());
    println!("Encoded point y: {:?}",encoded_point.y());
}

fn pad_to_32_bytes_big_endian(value: &BigInt) -> Vec<u8> {
    let mut bytes = value.to_bytes_be().1;
    while bytes.len() < 32 {
        bytes.insert(0, 0); //Prepend zeroes to reach 32 bytes
    }
    bytes
}

pub fn bigint_to_scalar(value: BigInt) -> Scalar {
    let u256_int = U256::from_be_slice(&pad_to_32_bytes_big_endian(&value));
    let result = Scalar::from_uint_unchecked(u256_int);
    result
}

extern crate cc;

use std::ops::Mul;
use cc::bedoza;
use cc::{ot::elgamal::Group, ot::elgamal::ElGamal};
use cc::bedoza::zp_field::ZpField;
use num_bigint::BigInt;
use alphabet::*;

use p256::elliptic_curve::group::Group as P256Group;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::scalar::FromUintUnchecked;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{Scalar, U256};
use p256::elliptic_curve::bigint::Encoding;
use num_traits::One;

fn load_groups() -> (Group, ZpField) {
    let common_group = Group::struct_from_file("group512.txt");
    let zp_field = ZpField::struct_from_file("zp_field_p256.txt");

    // let zp_field = ZpField::struct_from_file("zp_field2048.txt");
    // let zp_field = ZpField::struct_from_file("zp_binary.txt");
    (common_group, zp_field)
}
#[test]
fn test_curve() {
    let generator = p256::ProjectivePoint::generator();

    let affine_point = generator.to_affine();
    println!("Normal x: {:?}",affine_point.x());

    let affine_point_encoded = affine_point.to_encoded_point(false);
    println!("Encoded point x: {:?}",affine_point_encoded.x());
    println!("Encoded point y: {:?}",affine_point_encoded.y());

    let some_element = generator.mul(Scalar::from(2u32));
    let affine_point2 = some_element.to_affine();
    println!("Normal x times 2: {:?}",affine_point2.x());

}

#[test]
fn test_ecg_share() {
    let generator = p256::ProjectivePoint::generator();
    let (_common_group, mut zp_field) = load_groups();

    let a = zp_field.create_field_element(BigInt::from(73));

    let mut a_bytes_be = a.to_bytes_be().1;

    while a_bytes_be.len() < 32 {
        a_bytes_be.insert(0, 0); // Prepend zeroes to reach 32 bytes
    }

    let some_element = generator.mul(Scalar::from_uint_unchecked(U256::from_be_slice(&a_bytes_be)));

    let affine_point = some_element.to_affine();
    let affine_point_encoded = affine_point.to_encoded_point(false);
    println!("pub Encoded point x: {:?}",affine_point_encoded.x());
    println!("pub Encoded point y: {:?}",affine_point_encoded.y());


    let a_alice_value = zp_field.generate_random_element();
    let mut a_alice_be = a_alice_value.to_bytes_be().1;

    while a_alice_be.len() < 32 {
        a_alice_be.insert(0, 0); // Prepend zeroes to reach 32 bytes
    }

    let a_bob_value = zp_field.add(a.clone(), -a_alice_value.clone());
    let mut a_bob_be = a_bob_value.to_bytes_be().1;

    while a_bob_be.len() < 32 {
        a_bob_be.insert(0, 0); // Prepend zeroes to reach 32 bytes
    }

    let alice_mul_gen = generator.mul(Scalar::from_uint_unchecked(U256::from_be_slice(&a_alice_be)));
    let bob_mul_gen = generator.mul(Scalar::from_uint_unchecked(U256::from_be_slice(&a_bob_be)));

    let alice_affine = alice_mul_gen.to_affine();
    let alice_encoded_point = alice_affine.to_encoded_point(false);

    let bob_affine = bob_mul_gen.to_affine();
    let bob_encoded_point = bob_affine.to_encoded_point(false);

    println!("Alice encoded point x: {:?}",alice_encoded_point.x());
    println!("Bob encoded point x: {:?}",bob_encoded_point.x());

    let added_point = alice_mul_gen.add(&bob_mul_gen);
    let added_affine = added_point.to_affine();
    let added_encoded_point = added_affine.to_encoded_point(false);
    
    println!("added Encoded point x: {:?}",added_encoded_point.x());
    println!("added Encoded point y: {:?}",added_encoded_point.y());

    /*
    match alice_encoded_point.x() {
        Some(x_a) => match bob_encoded_point.x() {
            Some(x_b) => {
                let x1: U256 = U256::from_be_slice(&x_a);
                let x2: U256 = U256::from_be_slice(&x_b);
                let mut p_bytes = zp_field.p.to_bytes_be().1;
                while p_bytes.len() < 32 {
                    p_bytes.insert(0, 0); // Prepend zeroes to reach 32 bytes
                }
                // let sum = (x1 + x2) % U256::from_be_slice(&p_bytes);
                let sum: U256 = x1.add_mod(&x2, &U256::from_be_slice(&p_bytes));
                println!("sum x: {:?}",sum.to_be_bytes());
            }
            _ => {}
        },
        _ => {}
    }
    */

}


fn _gen_fixed_elliptical_curve_prime_to_file() {
    let two = BigInt::from(2);
    let one = BigInt::one();

    // Compute 2^32 - 1
    let two_32_minus_1 = (&two.pow(32)) - &one;

    // Compute 2^224 * (2^32 - 1)
    let term1 = (&two.pow(224)) * &two_32_minus_1;

    // Compute 2^192
    let term2 = two.pow(192);

    // Compute 2^96
    let term3 = two.pow(96);

    // Compute p = 2^224 * (2^32 - 1) + 2^192 + 2^96 - 1
    let prime = term1 + term2 + term3 - &one;
    let prime_field = ZpField::new_from_prime(prime, 256);
    prime_field.struct_to_file("zp_field_p256.txt");

}

fn _gen_zp_field_to_file() {
    let prime_field = ZpField::new(2048);
    prime_field.struct_to_file("zp_field2048.txt");
}

fn _manual_test_name_generator() {
    alphabet!(LATIN = "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    let mut name_generator = LATIN.iter_words();

    for _ in 0..1000 {
        let name = name_generator.next().unwrap();
        println!("{}", name);
    }
}

#[test]
fn el_gamal_correctness_test() {
    let common_group = load_groups().0;
    let elgamal = ElGamal::new(common_group.clone());
    let message = "random message"; //Note message must be smaller than q
    let m = BigInt::from_bytes_be(num_bigint::Sign::Plus,message.as_bytes()) % common_group.p;

    let sk = elgamal.gen_sk();
    let pk = elgamal.gen_pk(sk.clone());

    let c = elgamal.enc(pk, m.clone());
    let decrypted_message = elgamal.dec(sk.clone(), c);

    assert_eq!(decrypted_message,m);
}

#[test]
fn ot_correctness_test_1() {
    let common_group = load_groups().0;
    let mut chooser = cc::ot::Chooser::new(common_group.clone(), 2);
    let mut producer = cc::ot::Producer::new(common_group.clone(), 2, |i, j| {
        BigInt::from(i*j) //I.e. the AND function
    });

    let m1 = chooser.choose(1);
    let m2 = producer.transfer(1, m1.clone());
    let result = chooser.retrieve(m2);

    assert_eq!(result, BigInt::from(1u8));
}

#[test]
fn ot_correctness_test_2() {
    let common_group = load_groups().0;
    let mut chooser = cc::ot::Chooser::new(common_group.clone(), 2);
    let mut producer = cc::ot::Producer::new(common_group.clone(), 2, |i, j| {
        BigInt::from(i*j) //I.e. the AND function
    });

    let m1 = chooser.choose(0);
    let m2 = producer.transfer(1, m1.clone());
    let result = chooser.retrieve(m2);

    assert_eq!(result, BigInt::from(0u8));
}

#[test]
fn test_zp_field() {
    let mut zp_field = load_groups().1;
    for _ in 0..1000 {
        let random_element = zp_field.generate_random_element();
        assert!(random_element < zp_field.p);
    }
    zp_field.struct_to_file("zp_field2048.txt");
}

#[test]
fn test_bedoza_random_generator() {
    let (common_group, zp_field) = load_groups();
    let mut bedoza = bedoza::Bedoza::new(common_group.clone(), zp_field.clone());

    for _ in 0..100 {
        let name = bedoza.rand();
        let share = bedoza.open(name.clone());
        assert!(share < zp_field.p);
        //println!("{}: {}", name, share);
    }
}

#[test]
fn test_bedoza_alice_identity() {
    let (common_group, zp_field) = load_groups();
    let mut bedoza = bedoza::Bedoza::new(common_group.clone(), zp_field.clone());

    for i in 0..10 {
        let elem = zp_field.create_field_element(BigInt::from(i));      
        let name = bedoza.create_secret_sharing_by_alice(zp_field.create_field_element(elem.clone()));
        let opened_share_value = bedoza.open(name.clone());
        assert_eq!(elem, opened_share_value);
    }
}

#[test]
fn test_bedoza_add_const() {
    let (common_group, zp_field) = load_groups();
    let mut bedoza = bedoza::Bedoza::new(common_group.clone(), zp_field.clone());

    for i in 0..10 {
        let elem = zp_field.create_field_element(BigInt::from(i));      
        let name = bedoza.create_secret_sharing_by_alice(elem.clone());
        let name2 = bedoza.add_const(name.clone(), zp_field.create_field_element(BigInt::from(2*i)));
        let opened_share_value = bedoza.open(name2.clone());
        assert_eq!(zp_field.create_field_element(BigInt::from(3*i)), opened_share_value);
    }
}


#[test]
fn test_bedoza_local_multiplication() {
    let (common_group, zp_field) = load_groups();
    let mut bedoza = bedoza::Bedoza::new(common_group.clone(), zp_field.clone());

    for i in 0..10 {
        let elem = zp_field.create_field_element(BigInt::from(i));      
        let name = bedoza.create_secret_sharing_by_alice(elem.clone());
        let name2 = bedoza.mul_const(name.clone(), zp_field.create_field_element(BigInt::from(2*i)));
        let opened_share_value = bedoza.open(name2.clone());
        assert_eq!(zp_field.create_field_element(BigInt::from(i*(2*i))), opened_share_value);
    }
}

#[test]
fn test_bedoza_adding_shares() {
    let (common_group, zp_field) = load_groups();
    let mut bedoza = bedoza::Bedoza::new(common_group.clone(), zp_field.clone());

    for i in 0..10 {
        let a = zp_field.create_field_element(BigInt::from(i));
        let b = zp_field.create_field_element(BigInt::from(3*i));

        let name_a = bedoza.create_secret_sharing_by_alice(a.clone());
        let name_b = bedoza.create_secret_sharing_by_bob(b.clone());

        let name_c = bedoza.add(name_a.clone(), name_b.clone());
        let opened_share_value = bedoza.open(name_c.clone());
        assert_eq!(zp_field.create_field_element(BigInt::from(4*i)), opened_share_value);
    }
}

#[test]
fn test_rand_mul() {
    let (common_group, zp_field) = load_groups();
    let mut bedoza = bedoza::Bedoza::new(common_group.clone(), zp_field.clone());

    let (u,v,w) = bedoza.rand_mul();
    let u_value = bedoza.open(u.clone());
    let v_value = bedoza.open(v.clone());
    let w_value = bedoza.open(w.clone());
    assert_eq!(zp_field.mul(u_value, v_value), w_value);
}

#[test]
fn test_local_const_mul() {
    let (common_group, zp_field) = load_groups();
    let mut bedoza = bedoza::Bedoza::new(common_group.clone(), zp_field.clone());

    for i in 0..10 {
        let a = zp_field.create_field_element(BigInt::from(i));
        let b = zp_field.create_field_element(BigInt::from(3*i));
        let x = zp_field.create_field_element(BigInt::from(9));
        let y = zp_field.create_field_element(BigInt::from(7));
        //I.e we have c = x * a + y * b
        //Thus c = 9*i + 7*3*i = 30*i

        let name_a = bedoza.create_secret_sharing_by_alice(a.clone());
        let name_b = bedoza.create_secret_sharing_by_bob(b.clone());

        let name_c = bedoza.local_const_mul(name_a.clone(), name_b.clone(), x.clone(), y.clone());
        let opened_share_value = bedoza.open(name_c.clone());
        assert_eq!(zp_field.create_field_element(BigInt::from(30*i)), opened_share_value);
    }
}

#[test]
fn test_multiplication() {
    let (common_group, zp_field) = load_groups();
    let mut bedoza = bedoza::Bedoza::new(common_group.clone(), zp_field.clone());

    for i in 0..10 {
        let a_value = zp_field.create_field_element(BigInt::from(i));
        let b_value = zp_field.create_field_element(BigInt::from(3*i));

        let name_a = bedoza.create_secret_sharing_by_alice(a_value.clone());
        let name_b = bedoza.create_secret_sharing_by_bob(b_value.clone());

        let name_c = bedoza.mul(name_a.clone(), name_b.clone());
        let opened_share_value = bedoza.open(name_c.clone());
        assert_eq!(zp_field.create_field_element(BigInt::from(3*i*i)), opened_share_value);
    }
}
extern crate cc;

use cc::bedoza;
use cc::{ot::elgamal::Group, ot::elgamal::ElGamal};
use cc::bedoza::zp_field::ZpField;
use num_bigint::BigInt;
use alphabet::*;

use p256::elliptic_curve::scalar::FromUintUnchecked;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::{NonZeroScalar, PublicKey, Scalar, ScalarPrimitive};
use p256::{NistP256, ProjectivePoint, U256};
use num_traits::One;

fn load_groups() -> (Group, ZpField) {
    let common_group = Group::struct_from_file("group512.txt");
    let zp_field = ZpField::struct_from_file("zp_field_p256_n.txt");

    // let zp_field = ZpField::struct_from_file("zp_field2048.txt");
    // let zp_field = ZpField::struct_from_file("zp_binary.txt");
    (common_group, zp_field)
}

fn print_elliptic_curve_point(point: &p256::ProjectivePoint) {
    let encoded_point = point.to_affine().to_encoded_point(false);
    println!("Encoded point x: {:?}",encoded_point.x());
    println!("Encoded point y: {:?}",encoded_point.y());
}

fn pad_to_32_bytes_big_endian(value: BigInt) -> Vec<u8> {
    let mut bytes = value.to_bytes_be().1;
    while bytes.len() < 32 {
        bytes.insert(0, 0); // Prepend zeroes to reach 32 bytes
    }
    bytes
}

fn bigint_to_scalar(value: BigInt) -> Scalar<NistP256> {
    let u256_int = U256::from_be_slice(&pad_to_32_bytes_big_endian(value.clone()));
    let primitive = ScalarPrimitive::<NistP256>::from_uint_unchecked(u256_int);
    let nist_scalar= Scalar::<NistP256>::from(primitive);
    nist_scalar    
}


#[test]
fn test_curve_homomorphism() {
    let (_common_group, zp_field) = load_groups();

    //a+b = c
    let zp_elem_a = zp_field.create_field_element(BigInt::from(3));
    let zp_elem_b = zp_field.create_field_element(BigInt::from(-2));
    let zp_elem_c = zp_field.add(zp_elem_a.clone(), zp_elem_b.clone());
    let not_zp_elem_d = zp_elem_a.clone() + zp_elem_b.clone(); //I.e not mod p

    println!("a+b = c in z_p");
    println!("a: {}", zp_elem_a);
    println!("b: {}", zp_elem_b);
    println!("c: {}", zp_elem_c);
    let scalar_of_a = bigint_to_scalar(zp_elem_a.clone());
    print!("a:");
    for e in scalar_of_a.to_bytes() {
        print!("[{}]", e)
    }
    println!();
    let scalar_of_b = bigint_to_scalar(zp_elem_b.clone());
    print!("b:");
    for e in scalar_of_b.to_bytes() {
        print!("[{}]", e)
    }
    println!();
    let scalar_of_c = bigint_to_scalar(zp_elem_c.clone());
    print!("c:");
    for e in scalar_of_c.to_bytes() {
        print!("[{}]", e)
    }
    println!();
    let scalar_of_d = bigint_to_scalar(not_zp_elem_d.clone());
    print!("d:");
    for e in scalar_of_d.to_bytes() {
        print!("[{}]", e)
    }
    println!();
    let a_pk = PublicKey::<NistP256>::from_secret_scalar(&NonZeroScalar::new(scalar_of_a).unwrap());
    let b_pk = PublicKey::<NistP256>::from_secret_scalar(&NonZeroScalar::new(scalar_of_b).unwrap());
    let c_pk = PublicKey::<NistP256>::from_secret_scalar(&NonZeroScalar::new(scalar_of_c).unwrap());
    let d_pk = PublicKey::<NistP256>::from_secret_scalar(&NonZeroScalar::new(scalar_of_d).unwrap());
    let c_direct_point = c_pk.to_projective();
    let d_direct_point = d_pk.to_projective();

    // println!("Printing point directly created from c");
    // print_elliptic_curve_point(&c_direct_point);
    // println!();

    let c_added_point = a_pk.to_projective().add(&b_pk.to_projective());

    // println!("Printing point made by adding points created from a and b");
    // print_elliptic_curve_point(&c_added_point);
    // println!();

    let is_equal = c_added_point.eq(&c_direct_point);
    let is_equal_d = c_added_point.eq(&d_direct_point);
    println!("c: {}", is_equal);
    println!("d: {}", is_equal_d);
    assert!(is_equal);
}

fn _gen_fixed_elliptical_curve_prime_to_file() {
    //THIS IS WRONG! The prime is not the order of the curve, (even though it is used in the elliptical curve)
    let two = BigInt::from(2);
    let one = BigInt::one();

    let term0 = two.pow(256);

    let term1 = two.pow(224);

    let term2 = two.pow(192);

    let term3 = two.pow(96);

    let prime = term0 - term1 + term2 + term3 - one;
    let prime_field = ZpField::new_from_prime(prime, 256);
    prime_field.struct_to_file("zp_field_p256.txt");
}

#[test]
fn _gen_fixed_elliptical_curve_order_to_file() {
    //Order of the curve in the p256 elliptical curve in hex is 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    let order = BigInt::parse_bytes(b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16).unwrap();
    let prime_field = ZpField::new_from_prime(order, 256);
    prime_field.struct_to_file("zp_field_p256_n.txt");
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
    let zp_field = load_groups().1;
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
extern crate cc;

use cc::bedoza;
use cc::{ot::elgamal::Group, ot::elgamal::ElGamal};
use cc::bedoza::zp_field::ZpField;
use num_bigint::BigInt;
use alphabet::*;

#[test]
fn el_gamal_correctness_test() {

    let common_group = Group::struct_from_file("group512.txt");
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
    let common_group = Group::struct_from_file("group512.txt");
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
    let common_group = Group::struct_from_file("group512.txt");
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
    let mut zp_field = ZpField::struct_from_file("zp_field2048.txt");
    for _ in 0..1000 {
        let random_element = zp_field.generate_random_element();
        assert!(random_element < zp_field.p);
    }
    zp_field.struct_to_file("zp_field2048.txt");
}

#[test]
fn test_name_generator() {
    alphabet!(LATIN = "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    let mut name_generator = LATIN.iter_words();

    for _ in 0..1000 {
        let name = name_generator.next().unwrap();
        println!("{}", name);
    }
}

#[test]
fn test_bedoza_random_generator() {
    let common_group = Group::struct_from_file("group512.txt");
    let zp_field = ZpField::struct_from_file("zp_field2048.txt");
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
    let common_group = Group::struct_from_file("group512.txt");
    let zp_field = ZpField::struct_from_file("zp_field2048.txt");
    let mut bedoza = bedoza::Bedoza::new(common_group.clone(), zp_field.clone());

    for i in 0..100 {
        let elem = zp_field.create_field_element(BigInt::from(i));      
        let name = bedoza.create_secret_sharing_by_alice(zp_field.create_field_element(elem.clone()));
        let opened_share_value = bedoza.open(name.clone());
        assert_eq!(elem, opened_share_value);
    }
}
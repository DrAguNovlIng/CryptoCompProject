extern crate cc;

use cc::treshold_ecdsa::bedoza::{self, ec_helpers};
use cc::treshold_ecdsa::ThresholdECDSA;
use cc::treshold_ecdsa::{ot::elgamal::Group, ot::elgamal::ElGamal};
use cc::treshold_ecdsa::bedoza::zp_field::ZpField;
use num_bigint::BigInt;
use alphabet::*;

use p256::ProjectivePoint;

fn load_groups() -> (Group, ZpField) {
    let common_group = Group::struct_from_file("group512.txt");
    let zp_field = ZpField::struct_from_file("zp_field_p256_n.txt");
    (common_group, zp_field)
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
    let mut chooser = cc::treshold_ecdsa::ot::Chooser::new(common_group.clone(), 2);
    let mut producer = cc::treshold_ecdsa::ot::Producer::new(common_group.clone(), 2, |i, j| {
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
    let mut chooser = cc::treshold_ecdsa::ot::Chooser::new(common_group.clone(), 2);
    let mut producer = cc::treshold_ecdsa::ot::Producer::new(common_group.clone(), 2, |i, j| {
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


#[test]
fn test_ec_share_homomorphism() {
    let (common_group, zp_field) = load_groups();
    let mut bedoza = bedoza::Bedoza::new(common_group.clone(), zp_field.clone());

    for _ in 0..20 {
        let zp_elem = zp_field.generate_random_element();
        
        //Creating point diretly from scalar
        let scalar = ec_helpers::bigint_to_scalar(zp_elem.clone());
        let directly_created_point = ProjectivePoint::GENERATOR * scalar;

        //Creating point by using shares
        let share_name = bedoza.create_secret_sharing_by_alice(zp_elem.clone());
        bedoza.convert_ec(share_name.clone());
        let opened_share_point = bedoza.open_ec(share_name.clone());

        //check if the points are equal
        assert_eq!(directly_created_point, opened_share_point);
    }
}

#[test]
fn test_threshold_ecdsa() {
    let (common_group, zp_field) = load_groups();
    let ecdsa = ThresholdECDSA::new(common_group.clone(), zp_field.clone());
    //todo
}
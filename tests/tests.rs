extern crate cc;

pub use cc::{ot::elgamal::Group, ot::elgamal::ElGamal};
use num_bigint::BigInt;


#[test]
fn el_gamal_correctness_test() {

    let common_group = Group::new_from_file("group512.txt");
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
    let common_group = Group::new_from_file("group512.txt");
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
    let common_group = Group::new_from_file("group512.txt");
    let mut chooser = cc::ot::Chooser::new(common_group.clone(), 2);
    let mut producer = cc::ot::Producer::new(common_group.clone(), 2, |i, j| {
        BigInt::from(i*j) //I.e. the AND function
    });

    let m1 = chooser.choose(0);
    let m2 = producer.transfer(1, m1.clone());
    let result = chooser.retrieve(m2);

    assert_eq!(result, BigInt::from(0u8));
}
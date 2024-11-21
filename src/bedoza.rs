pub mod zp_field;

use num_bigint::BigInt;
use crate::ot::{elgamal::Group, Chooser, Producer};
use crate::bedoza::zp_field::{ZpField, ZpFieldElement};
use std::collections::HashMap;
use alphabet::*;

type ShareName = String;


/*
    The Bedoza Protocol Arithmetic Black-box with 2 parties using OT for RandMul. The implementation is computationally passive secure.
*/
pub struct Bedoza {
    alice: Alice,
    bob: Bob,
    share_name_generator: Box<dyn Iterator<Item = String>>,
}

impl Bedoza {
    pub fn new() -> Self {
        let common_group = Group::struct_from_file("group512.txt");
        let zp_field = ZpField::struct_from_file("zp_field2048.txt");
        alphabet!(LATIN = "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        Self {
            alice: Alice::new(common_group.clone(), zp_field.clone()),
            bob: Bob::new(common_group.clone(), zp_field.clone()),
            share_name_generator: Box::new(LATIN.iter_words()),
        }
    }

    /*
        RandMul()
        Generates random tuple of secrets shared values such that the first to values (a,b) multiplied together equals the third value (c)
     */
    pub fn rand_mul(&mut self) -> (ShareName, ShareName, ShareName) {
        todo!()
    }

    /*
        Mul()
        Generates a new secret shared value which is the product of two previously shared values
     */
    pub fn mul(&mut self, a: ShareName, b: ShareName) -> ShareName {
        todo!()
    }

    /*
        Rand()
        Generates a random shared value
     */
    pub fn rand(&mut self) -> ShareName {
        //Generating a random field element by both parties generating a random share should be fine
        let name = self.share_name_generator.next().unwrap();
        self.alice.rand(name.clone());
        self.bob.rand(name.clone());
        name
    }

    /*
        Open()
        Opens a shared value
     */
    pub fn open(&mut self, secret_to_open: ShareName) -> ZpFieldElement {
        todo!()
    }

    /*
        LocalConstMul()
        Multiplies shared values with a constants s.t. the result c is c = x * a + y * b
     */
    pub fn local_const_mul(&mut self, a: ShareName, b: ShareName, x: ZpFieldElement, y: ZpFieldElement) -> ShareName {
        todo!()
    }
}


/*
    Implementation of the parties in the Bedoza protocol
*/
pub struct Alice {
    ot_chooser: Chooser,
    shares: HashMap<String, BigInt>,
    zp_field: ZpField,
}

impl Alice {
    pub fn new(common_group: Group, zp_field: ZpField) -> Self {
        Self {
            ot_chooser: Chooser::new(common_group, 2),
            shares: HashMap::new(),
            zp_field: zp_field,
        }
    }

    pub fn rand(&mut self, name_of_new_share: ShareName) {
        let random_element: ZpFieldElement = self.zp_field.generate_random_element();
        self.shares.insert(name_of_new_share, random_element);
    }
}

pub struct Bob {
    ot_producer: Producer,
    shares: HashMap<String, ZpFieldElement>,
    zp_field: ZpField,
}

impl Bob {
    pub fn new(common_group: Group, zp_field: ZpField) -> Self {
        Self {
            ot_producer: Producer::new(common_group, 2,
                |i, j| {
                BigInt::from(i * j) //Should be the function needed for RandMul() i.e. the only place we use OT
            }),
            zp_field: zp_field,
            shares: HashMap::new(),
        }
    }
    
    pub fn rand(&mut self, name_of_new_share: ShareName) {
        let random_element: ZpFieldElement = self.zp_field.generate_random_element();
        self.shares.insert(name_of_new_share, random_element);
    }
}
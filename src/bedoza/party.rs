use crate::ot::{elgamal::Group, Chooser, Producer};
use crate::bedoza::zp_field::{ZpField, ZpFieldElement};
use num_bigint::BigInt;
use std::collections::HashMap;

pub type ShareName = String;

pub struct Party {
    _ot_producer: Producer,
    _ot_chooser: Chooser,
    shares: HashMap<String, BigInt>,
    zp_field: ZpField,
}

impl Party {
    pub fn new(common_group: Group, zp_field: ZpField) -> Self {
        Self {
            _ot_producer: Producer::new(common_group.clone(), 2,
                |i, j| {
                BigInt::from(i * j) //Should be the function needed for RandMul() i.e. the only place we use OT
            }),
            _ot_chooser: Chooser::new(common_group, 2),
            shares: HashMap::new(),
            zp_field: zp_field,
        }
    }

    //Generates a random share, thus two of these shares can be used to create a secret sharing of a random value
    pub fn rand(&mut self, name_of_new_share: ShareName) {
        let random_element: ZpFieldElement = self.zp_field.generate_random_element();
        self.shares.insert(name_of_new_share, random_element);
    }

    //Creates a new secret sharing of a value, keeps one of the shares and returns the other
    pub fn create_secret_share(&mut self, name_of_new_share: ShareName, value: ZpFieldElement) -> ZpFieldElement {
        let random_element: ZpFieldElement = self.zp_field.generate_random_element();
        let own_share = self.zp_field.add(value, -random_element.clone()); //Thus own_share + random_element = value
        self.shares.insert(name_of_new_share, own_share);
        random_element
    }

    //Receives and saves a secret share from the other party
    pub fn receive_secret_share(&mut self, name_of_new_share: ShareName, value: ZpFieldElement) {
        self.shares.insert(name_of_new_share, value);
    }

    //Opens a share, returns the value of the share
    pub fn open_share(&mut self, share_to_open: ShareName) -> ZpFieldElement {
        let value = self.shares.get(&share_to_open);
        match value {
            Some(v) => {
                return v.clone()
            }
            None => {
                panic!("Share not found")
            }   
        }
    }

}
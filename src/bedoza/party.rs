use crate::ot::{elgamal::Group, Chooser, Producer};
use crate::bedoza::zp_field::{ZpField, ZpFieldElement};
use num_bigint::BigInt;
use p256::ProjectivePoint;
use std::collections::HashMap;

use super::ec_helpers;

pub type ShareName = String;

pub struct Party {
    _ot_producer: Producer,
    _ot_chooser: Chooser,
    zp_shares: HashMap<String, BigInt>,
    ec_shares: HashMap<String, ProjectivePoint>,
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
            zp_shares: HashMap::new(),
            ec_shares: HashMap::new(),
            zp_field: zp_field,
        }
    }

    //Generates a random share, thus two of these shares can be used to create a secret sharing of a random value
    pub fn rand(&mut self, name_of_new_share: ShareName) {
        let random_element: ZpFieldElement = self.zp_field.generate_random_element();
        self.zp_shares.insert(name_of_new_share, random_element);
    }

    //Creates a new secret sharing of a value, keeps one of the shares and returns the other
    pub fn create_secret_share(&mut self, name_of_new_share: ShareName, value: ZpFieldElement) -> ZpFieldElement {
        let random_element: ZpFieldElement = self.zp_field.generate_random_element();
        let own_share = self.zp_field.add(value, -random_element.clone()); //Thus own_share + random_element = value
        self.zp_shares.insert(name_of_new_share, own_share);
        random_element
    }

    //Receives and saves a secret share from the other party
    pub fn receive_secret_share(&mut self, name_of_new_share: ShareName, value: ZpFieldElement) {
        self.zp_shares.insert(name_of_new_share, value);
    }

    //Opens a share, returns the value of the share
    pub fn open_share(&self, share_to_open: ShareName) -> ZpFieldElement {
        let value = self.zp_shares.get(&share_to_open);
        match value {
            Some(v) => {
                return v.clone()
            }
            None => {
                panic!("Share not found")
            }   
        }
    }

    //Adds a constant value to an already known share
    pub fn add_const(&mut self, input_share: ShareName, output_share: ShareName, constant: ZpFieldElement) {
        let maybe_share = self.zp_shares.get_key_value(&input_share);
        match maybe_share {
            Some((_, v)) => {
                let new_value = self.zp_field.add(v.clone(), constant);
                self.zp_shares.insert(output_share, new_value.clone());
            }
            None => {
                panic!("Input Share not found")
            }
            
        }
    }

    //Multiplies a share with a constant value
    pub fn mul_const(&mut self, input_share: ShareName, output_share: ShareName, constant: ZpFieldElement) {
        let maybe_share = self.zp_shares.get_key_value(&input_share);
        match maybe_share {
            Some((_, v)) => {
                let new_value = self.zp_field.mul(v.clone(), constant);
                self.zp_shares.insert(output_share, new_value.clone());
            }
            None => {
                panic!("Input Share not found")
            }
        }
    }

    //Adds two shares together
    pub fn add(&mut self, input_share1: ShareName, input_share2: ShareName, output_share: ShareName) {
        let maybe_share1 = self.zp_shares.get_key_value(&input_share1);
        let maybe_share2 = self.zp_shares.get_key_value(&input_share2);
        match (maybe_share1, maybe_share2) {
            (Some((_, v1)), Some((_, v2))) => {
                let new_value = self.zp_field.add(v1.clone(), v2.clone());
                self.zp_shares.insert(output_share, new_value.clone());
            }
            _ => {
                panic!("Input Shares not found")
            }
        }
    }

    //Converts an already shared value in Zp to an EC share
    pub fn convert_to_ec_shares(&mut self, share: ShareName) {
        let maybe_value = self.zp_shares.get_key_value(&share); //TODO Check exsistence in map properly
        match maybe_value {
            Some((_, value)) => {
                let scalar = ec_helpers::bigint_to_scalar(value.clone());
                let point = ProjectivePoint::GENERATOR * scalar;
                self.ec_shares.insert(share, point);
            }
            None => {
                panic!("Share of type Zp field element not found, make sure to create the share first, before converting it to an EC share")
            }
            
        }
    }

    //Opens an EC share, returns the value of the share
    pub fn open_ec_share(&self, share: ShareName) -> ProjectivePoint {
        let maybe_point = self.ec_shares.get_key_value(&share);
        match maybe_point {
            Some((_, point)) => {
                return point.clone()
            }
            None => {
                panic!("Share of type EC point not found, make sure to create the share first, before opening it, i.e. using convert_to_ec_shares()")
            }
        }
    }
}
pub mod zp_field;
mod party;

use crate::ot::elgamal::Group;
use crate::bedoza::zp_field::{ZpField, ZpFieldElement};
use crate::bedoza::party::{Party, ShareName};
use alphabet::*;
use num_bigint::BigInt;


/*
    The Bedoza Protocol Arithmetic Black-box with 2 parties using OT for RandMul. The implementation is computationally passive secure.
*/
pub struct Bedoza {
    alice: Party,
    bob: Party,
    share_name_generator: Box<dyn Iterator<Item = String>>,
    zp_field: ZpField,
}

impl Bedoza {
    pub fn new(ot_group: Group, zp_group: ZpField) -> Self {
        let common_group = ot_group;
        let zp_field = zp_group;
        alphabet!(LATIN = "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        let mut latin_alphabet_iterator = LATIN.iter_words();
        latin_alphabet_iterator.next(); //Skip the first element which is an empty string
        Self {
            alice: Party::new(common_group.clone(), zp_field.clone()),
            bob: Party::new(common_group.clone(), zp_field.clone()),
            share_name_generator: Box::new(latin_alphabet_iterator),
            zp_field: zp_field,
        }
    }

    //Creates a secret sharing of a specific value between the two parties, in this case the randomness is picked by Alice
    pub fn create_secret_sharing_by_alice(&mut self, value: ZpFieldElement) -> ShareName {
        let name = self.share_name_generator.next().unwrap();
        let bob_share = self.alice.create_secret_share(name.clone(), value);
        self.bob.receive_secret_share(name.clone(), bob_share);
        name
    }

    //Creates a secret sharing of a specific value between the two parties, in this case the randomness is picked by Bob
    pub fn create_secret_sharing_by_bob(&mut self, value: ZpFieldElement) -> ShareName {
        let name = self.share_name_generator.next().unwrap();
        let alice_share = self.bob.create_secret_share(name.clone(), value);
        self.alice.receive_secret_share(name.clone(), alice_share);
        name
    }

    //Generates a random shared value
    pub fn rand(&mut self) -> ShareName {
        //Generating a random field element by both parties generating a random share should be fine
        let name = self.share_name_generator.next().unwrap();
        self.alice.rand(name.clone());
        self.bob.rand(name.clone());
        name
    }

    //Opens a shared value
    pub fn open(&mut self, secret_to_open: ShareName) -> ZpFieldElement {
        let alice_share = self.alice.open_share(secret_to_open.clone());
        let bob_share = self.bob.open_share(secret_to_open.clone());
        self.zp_field.add(alice_share, bob_share)
    }

    //Adds a constant to a shared value (local computation)
    pub fn add_const(&mut self, a: ShareName, constant: ZpFieldElement) -> ShareName {
        //one party adds the constant to their share and the other party does nothing (i.e adds 0)
        let output_share = self.share_name_generator.next().unwrap();
        self.alice.add_const(a.clone(), output_share.clone(), constant);
        self.bob.add_const(a, output_share.clone(), self.zp_field.create_field_element(BigInt::from(0)));
        output_share
    }

    //Multiplies a shared value with a constant (local computation)
    pub fn mul_const(&mut self, a: ShareName, constant: ZpFieldElement) -> ShareName {
        //both parties multiplies their share with the constant
        let output_share = self.share_name_generator.next().unwrap();
        self.alice.mul_const(a.clone(), output_share.clone(), constant.clone());
        self.bob.mul_const(a, output_share.clone(), constant);
        output_share
    }

    //Multiplies shared values with a constants s.t. the result c is c = x * a + y * b (local computation)
    pub fn local_const_mul(&mut self, _a: ShareName, _b: ShareName, _x: ZpFieldElement, _y: ZpFieldElement) -> ShareName {
        todo!()
    }

    //Adds two shared values together
    pub fn add(&mut self, a: ShareName, b: ShareName) -> ShareName {
        //both parties add their shares
        let output_share = self.share_name_generator.next().unwrap();
        self.alice.add(a.clone(), b.clone(), output_share.clone());
        self.bob.add(a, b, output_share.clone());
        output_share
    }

    //Generates random tuple of secrets shared values such that the first to values (a,b) multiplied together equals the third value (c)
    pub fn rand_mul(&mut self) -> (ShareName, ShareName, ShareName) {
        let u = self.share_name_generator.next().unwrap();
        let v = self.share_name_generator.next().unwrap();
        let w = self.share_name_generator.next().unwrap();

        //This is implemented like we are the trusted dealer
        let u_value = self.zp_field.generate_random_element();
        let v_value = self.zp_field.generate_random_element();
        let w_value = self.zp_field.mul(u_value.clone(), v_value.clone());
        
        //Creating the shares
        let u_alice_value = self.zp_field.generate_random_element();
        let u_bob_value = self.zp_field.add(u_value.clone(), -u_alice_value.clone());

        let v_alice_value = self.zp_field.generate_random_element();
        let v_bob_value = self.zp_field.add(v_value.clone(), -v_alice_value.clone());

        let w_alice_value = self.zp_field.generate_random_element();
        let w_bob_value = self.zp_field.add(w_value.clone(), -w_alice_value.clone());
        
        //Distribution of the shares
        self.alice.receive_secret_share(u.clone(), u_alice_value);
        self.bob.receive_secret_share(u.clone(), u_bob_value);
        
        self.alice.receive_secret_share(v.clone(), v_alice_value);
        self.bob.receive_secret_share(v.clone(), v_bob_value);

        self.alice.receive_secret_share(w.clone(), w_alice_value);
        self.bob.receive_secret_share(w.clone(), w_bob_value);

        (u, v, w)
    }

    //Generates a new secret shared value which is the product of two previously shared values

    pub fn mul(&mut self, _a: ShareName, _b: ShareName) -> ShareName {
        todo!()
    }
}

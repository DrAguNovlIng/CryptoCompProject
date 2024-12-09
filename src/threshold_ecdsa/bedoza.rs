pub mod zp_field;
pub mod ec_helpers;
pub mod party;
mod trusted_dealer;

use crate::threshold_ecdsa::ot::elgamal::Group;
use crate::threshold_ecdsa::bedoza::zp_field::{ZpField, ZpFieldElement};
use crate::threshold_ecdsa::bedoza::party::{Party, ShareName};
use alphabet::*;
use num_bigint::BigInt;
use p256::ProjectivePoint;
use trusted_dealer::TrustedDealer;


/*
    The Bedoza Protocol Arithmetic Black-box with 2 parties using OT for RandMul. The implementation is computationally passive secure.
*/
pub struct Bedoza {
    alice: Party,
    bob: Party,
    share_name_generator: Box<dyn Iterator<Item = String>>,
    zp_field: ZpField,
    trusted_dealer: TrustedDealer
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
            zp_field: zp_field.clone(),
            trusted_dealer: TrustedDealer::new(zp_field)
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
    pub fn open(&self, secret_to_open: ShareName) -> ZpFieldElement {
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
    //Note this is basically a macro for previous local functions
    pub fn local_const_mul(&mut self, a: ShareName, b: ShareName, x: ZpFieldElement, y: ZpFieldElement) -> ShareName {
        let left_term = self.mul_const(a.clone(), x);
        let right_term = self.mul_const(b.clone(), y);
        let res = self.add(left_term, right_term);
        res
    }

    //Adds two shared values together (local computation)
    pub fn add(&mut self, a: ShareName, b: ShareName) -> ShareName {
        //both parties add their shares
        let output_share = self.share_name_generator.next().unwrap();
        self.alice.add(a.clone(), b.clone(), output_share.clone());
        self.bob.add(a, b, output_share.clone());
        output_share
    }

    //Generates random tuple of secrets shared values such that the first to values (u,v) multiplied together equals the third value (w)
    pub fn rand_mul(&mut self) -> (ShareName, ShareName, ShareName) {
        let u = self.share_name_generator.next().unwrap();
        let v = self.share_name_generator.next().unwrap();
        let w = self.share_name_generator.next().unwrap();

        let uvw = self.trusted_dealer.generate_uvw();
        
        //Distribution of the shares
        self.alice.receive_secret_share(u.clone(), uvw.u.0);
        self.bob.receive_secret_share(u.clone(), uvw.u.1);
        
        self.alice.receive_secret_share(v.clone(), uvw.v.0);
        self.bob.receive_secret_share(v.clone(), uvw.v.1);

        self.alice.receive_secret_share(w.clone(), uvw.w.0);
        self.bob.receive_secret_share(w.clone(), uvw.w.1);

        (u, v, w)
    }

    //Generates a new secret shared value which is the product of two previously shared values
    pub fn mul(&mut self, x: ShareName, y: ShareName) -> ShareName {
        //variables renamed to match lecture notes
        let (u, v, w) = self.rand_mul();
        let d: ShareName = self.add(x.clone(), u);
        let e: ShareName = self.add(y.clone(), v);
        let d_value: ZpFieldElement = self.open(d.clone());
        let e_value: ZpFieldElement = self.open(e.clone());

        //Terms in step 6
        let ex: ShareName = self.mul_const(x.clone(), e_value.clone());
        let dy: ShareName = self.mul_const(y.clone(), d_value.clone());
        let ed: ZpFieldElement = self.zp_field.mul(e_value.clone(), d_value.clone());

        //Adding the terms
        let wex: ShareName = self.add(w.clone(), ex);
        let wexdy: ShareName = self.add(wex, dy);
        let z: ShareName = self.add_const(wexdy, -ed);
        z
    }

    //Converts a shared value from zp to elliptic curve, under the same name
    pub fn convert_ec(&mut self, a: ShareName) {
        //We convert by simply calling convert on both parties, since we have homomorphic properties between the groups
        self.alice.convert_to_ec_shares(a.clone());
        self.bob.convert_to_ec_shares(a);
    }

    //Opens a shared elliptic curve point
    pub fn open_ec(&self, a: ShareName) -> ProjectivePoint {
        let alice_share = self.alice.open_ec_share(a.clone());
        let bob_share = self.bob.open_ec_share(a);
        alice_share + bob_share //note this is addition in the elliptic curve group
    }

    pub fn mul_const_ec(&mut self, a: ShareName, constant: ZpFieldElement) -> ShareName {
        //both parties multiplies their share with the constant (ec)
        let output_share = self.share_name_generator.next().unwrap();
        self.alice.mul_const_ec(a.clone(), output_share.clone(), constant.clone());
        self.bob.mul_const_ec(a, output_share.clone(), constant);
        output_share
    }
}

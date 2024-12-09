use super::zp_field::{ZpField, ZpFieldElement};

//A triple of pairs containing secret sharings of u,v,w such that u*v = w
pub struct UvwTriple {
    pub u: (ZpFieldElement, ZpFieldElement),
    pub v: (ZpFieldElement, ZpFieldElement),
    pub w: (ZpFieldElement, ZpFieldElement)
}

pub struct TrustedDealer {
    zp_field: ZpField
}

impl TrustedDealer {
    pub fn new(zp_field: ZpField) -> Self {
        Self { zp_field }
    }

    //returns 3 tuples containing secret sharings of u,v,w such that u*v = w
    pub fn generate_uvw(&self) -> UvwTriple {
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

        UvwTriple{
            u: (u_alice_value, u_bob_value),
            v: (v_alice_value, v_bob_value),
            w :(w_alice_value, w_bob_value)
        }
    }
}
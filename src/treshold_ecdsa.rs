use crate::{bedoza::{zp_field::ZpField, Bedoza}, ot::elgamal::Group};

pub struct ThresholdECDSA {
    bedoza: Bedoza,
}

impl ThresholdECDSA {
    pub fn new(ot_group: Group, zp_group: ZpField) -> Self {
        Self {
            bedoza: Bedoza::new(ot_group, zp_group),
        }
    }
}

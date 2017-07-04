use std::ops::{Shr,Shl,AddAssign};
use std::convert::From;

use nom::IResult;

use num_bigint::{BigUint,BigInt,Sign};
use num_traits::identities::Zero;

struct MpUint(BigUint);

impl AddAssign for MpUint {

    fn add_assign(&mut self, other: MpUint) {
        *self = MpUint(&self.0 + other.0);
    }

}

impl Shr<usize> for MpUint {
    type Output = MpUint;

    fn shr(self, shift: usize) -> MpUint {
        MpUint(&self.0 >> shift)
    }

}

impl Shl<usize> for MpUint {
    type Output = MpUint;

    fn shl(self, shift: usize) -> MpUint {
        MpUint(&self.0 << shift)
    }

}

impl From<u8> for MpUint {

    fn from(i: u8) -> MpUint {
        MpUint(BigUint::from(i))
    }

}

pub fn parse_ssh_mpint(i: &[u8]) -> IResult<&[u8], BigInt> {
    if i.len() == 0 {
        IResult::Done(i, BigInt::zero())
    } else {
        bits!(i, do_parse!(
            sign: take_bits!(u8, 1) >>
            number: take_bits!(MpUint, i.len() * 8 - 1) >>
            ( BigInt::from_biguint(if sign == 0 { Sign::Plus } else { Sign::Minus }, number.0) )
        ))
    }
}


#[test]
fn test_positive_mpint() {
    let e = [
        0x04, 0xe7, 0x59, 0x2a, 0xe1, 0xb9, 0xb6, 0xbe, 0x7c, 0x81, 0x5f, 0xc8,
        0x3d, 0x55, 0x7b, 0x8f, 0xc7, 0x09, 0x1d, 0x71, 0x6c, 0xed, 0x68, 0x45,
        0x6c, 0x31, 0xc7, 0xf3, 0x65, 0x98, 0xa5, 0x44, 0x7d, 0xa4, 0x28, 0xdd,
        0xe7, 0x3a, 0xd9, 0xa1, 0x0e, 0x4b, 0x75, 0x3a, 0xde, 0x33, 0x99, 0x6e,
        0x41, 0x7d, 0xea, 0x88, 0xe9, 0x90, 0xe3, 0x5a, 0x27, 0xf8, 0x38, 0x09,
        0x01, 0x66, 0x46, 0xd4, 0xdc
    ];
    let expected = IResult::Done(b"" as &[u8], BigInt::new(Sign::Plus, vec![
        1715918044, 4164421889, 2430818855, 2112522473, 865693249, 1265973982,
        987341070, 2754141671, 2560967805, 835187557, 3983033708, 152924524,
        1434161095, 2170538045, 3115761276, 3881380577, 4
    ]));
    let num = parse_ssh_mpint(&e);
    assert_eq!(num, expected);
}

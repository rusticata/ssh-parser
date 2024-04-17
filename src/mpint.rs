use nom::bits::{bits, streaming::take as btake};
use nom::error::Error;
use nom::sequence::pair;
use nom::IResult;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::identities::Zero;
use std::ops::{AddAssign, Shl, Shr};

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
    if i.is_empty() {
        Ok((i, BigInt::zero()))
    } else {
        let (i, b) = bits(pair(
            btake::<_, _, _, Error<_>>(1usize),
            btake(i.len() * 8usize - 1),
        ))(i)?;
        let sign: u8 = b.0;
        let number = MpUint(b.1);
        let bi = BigInt::from_biguint(if sign == 0 { Sign::Plus } else { Sign::Minus }, number.0);
        Ok((i, bi))
    }
}

#[test]
fn test_positive_mpint() {
    let e = [
        0x04, 0xe7, 0x59, 0x2a, 0xe1, 0xb9, 0xb6, 0xbe, 0x7c, 0x81, 0x5f, 0xc8, 0x3d, 0x55, 0x7b,
        0x8f, 0xc7, 0x09, 0x1d, 0x71, 0x6c, 0xed, 0x68, 0x45, 0x6c, 0x31, 0xc7, 0xf3, 0x65, 0x98,
        0xa5, 0x44, 0x7d, 0xa4, 0x28, 0xdd, 0xe7, 0x3a, 0xd9, 0xa1, 0x0e, 0x4b, 0x75, 0x3a, 0xde,
        0x33, 0x99, 0x6e, 0x41, 0x7d, 0xea, 0x88, 0xe9, 0x90, 0xe3, 0x5a, 0x27, 0xf8, 0x38, 0x09,
        0x01, 0x66, 0x46, 0xd4, 0xdc,
    ];
    let expected = Ok((
        b"" as &[u8],
        BigInt::new(
            Sign::Plus,
            vec![
                1715918044, 4164421889, 2430818855, 2112522473, 865693249, 1265973982, 987341070,
                2754141671, 2560967805, 835187557, 3983033708, 152924524, 1434161095, 2170538045,
                3115761276, 3881380577, 4,
            ],
        ),
    ));
    let num = parse_ssh_mpint(&e);
    assert_eq!(num, expected);
}

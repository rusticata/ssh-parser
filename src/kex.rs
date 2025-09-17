//! # KEX parser
//!
//! This module contains parsing functions for the Key Exchange part of the
//! SSH 2.0 protocol.
//!
//! The supported Key Exchange protocols are the following:
//!
//!  - Diffie Hellman Key Exchange, `SSH_MSG_KEXDH_`, defined in RFC4253 section 8.
//!  - Elliptic Curve Diffie Hellman Key Exchange, `SSH_MSG_KEXECDH_INIT`, defined
//!    in RFC6239 sections 4.1 and 4.2.
//!  - Diffie Hellman Group and Key Exchange, `SSH_MSG_KEY_DH_GEX_`, defined in
//!    RFC4419 section 5.

#[cfg(feature = "integers")]
use std::marker::PhantomData;

use nom::bytes::complete::take;
use nom::combinator::{all_consuming, map, map_parser, rest};
use nom::error::Error;
use nom::number::streaming::be_u32;
use nom::sequence::{pair, tuple};
use nom::IResult;
#[cfg(feature = "integers")]
use num_bigint::BigInt;

use super::ssh::parse_string;

use super::{SshPacketKeyExchange, SshPacketUnparsed};

/// Diffie-Hellman Key Exchange Init message code.
/// Defined in [RFC4253 errata 1486](https://www.rfc-editor.org/errata/eid1486).
pub const SSH_MSG_KEXDH_INIT: u8 = 30;

/// Diffie-Hellman Key Exchange Reply message code.
/// Defined in [RFC4253 errata 1486](https://www.rfc-editor.org/errata/eid1486).
pub const SSH_MSG_KEXDH_REPLY: u8 = 31;

/// Elliptic Curve Diffie-Hellman Key Exchange Init message code.
/// Defined in [RFC6239 section 4.1](https://datatracker.ietf.org/doc/html/rfc6239#section-4.1).
pub const SSH_MSG_KEXECDH_INIT: u8 = SSH_MSG_KEXDH_INIT;

/// Elliptic Curve Diffie-Hellman Key Exchange Reply message code.
/// Defined in [RFC6239 section 4.2](https://datatracker.ietf.org/doc/html/rfc6239#section-4.2).
pub const SSH_MSG_KEXECDH_REPLY: u8 = SSH_MSG_KEXDH_REPLY;

/// Diffie-Hellman Group and Key Exchange Request message code.
/// Defined in [RFC4419 section 5](https://datatracker.ietf.org/doc/html/rfc4419#section-5).
pub const SSH_MSG_KEX_DH_GEX_REQUEST: u8 = 34;

/// Diffie-Hellman Group and Key Exchange Request Old message code.
/// Defined in [RFC4419 section 5](https://datatracker.ietf.org/doc/html/rfc4419#section-5).
pub const SSH_MSG_KEX_DH_GEX_REQUEST_OLD: u8 = 30;

/// Diffie-Hellman Group and Key Exchange Group message code.
/// Defined in [RFC4419 section 5](https://datatracker.ietf.org/doc/html/rfc4419#section-5).
pub const SSH_MSG_KEX_DH_GEX_GROUP: u8 = 31;

/// Diffie-Hellman Group and Key Exchange Init message code.
/// Defined in [RFC4419 section 5](https://datatracker.ietf.org/doc/html/rfc4419#section-5).
pub const SSH_MSG_KEX_DH_GEX_INIT: u8 = 32;

/// Diffie-Hellman Group and Key Exchange Reply message code.
/// Defined in [RFC4419 section 5](https://datatracker.ietf.org/doc/html/rfc4419#section-5).
pub const SSH_MSG_KEX_DH_GEX_REPLY: u8 = 33;

/// PQ/T Hybrid Key Exchange Init message code.
/// Defined in [draft RFC `draft-kampanakis-curdle-ssh-pq-ke-02` section 2.2](https://www.ietf.org/archive/id/draft-kampanakis-curdle-ssh-pq-ke-02.html#section-2.2)
pub const SSH_MSG_KEX_HYBRID_INIT: u8 = 30;

/// PQ/T Hybrid Key Exchange Reply message code.
/// Defined in [draft RFC `draft-kampanakis-curdle-ssh-pq-ke-02` section 2.2](https://www.ietf.org/archive/id/draft-kampanakis-curdle-ssh-pq-ke-02.html#section-2.2)
pub const SSH_MSG_KEX_HYBRID_REPLY: u8 = 31;

/// Supported PQ/T Hybrid Key Exchange algorithm.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SupportedHybridKEXAlgorithm {
    /// ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org
    ECDHNistP256Kyber512r3Sha256D00OQS,

    /// ecdh-nistp384-kyber-768r3-sha384-d00@openquantumsafe.org
    ECDHNistP384Kyber768r3Sha384D00OQS,

    /// ecdh-nistp521-kyber-1024r3-sha512-d00@openquantumsafe.org
    ECDHNistP521Kyber1024r3Sha512D00OQS,
}

impl SupportedHybridKEXAlgorithm {
    /// Returns the length in bytes of the post-quantum KEM public key.
    pub fn pq_pub_key_len(self) -> usize {
        match self {
            Self::ECDHNistP256Kyber512r3Sha256D00OQS => 800,
            Self::ECDHNistP384Kyber768r3Sha384D00OQS => 1184,
            Self::ECDHNistP521Kyber1024r3Sha512D00OQS => 1568,
        }
    }

    /// Returns the length in bytes of the ciphertext produced by the KEM algorithm.
    pub fn pq_ciphertext_len(self) -> usize {
        match self {
            Self::ECDHNistP256Kyber512r3Sha256D00OQS => 768,
            Self::ECDHNistP384Kyber768r3Sha384D00OQS => 1088,
            Self::ECDHNistP521Kyber1024r3Sha512D00OQS => 1568,
        }
    }
}

#[cfg(feature = "integers")]
fn parse_mpint(i: &[u8]) -> IResult<&[u8], BigInt> {
    map_parser(parse_string, crate::mpint::parse_ssh_mpint)(i)
}

#[cfg(not(feature = "integers"))]
fn parse_mpint(i: &[u8]) -> IResult<&[u8], &[u8]> {
    parse_string(i)
}

/// SSH Diffie-Hellman Key Exchange Init.
///
/// The message code is `SSH_MSG_KEXDH_INIT`, defined in [RFC4253 section 8](https://datatracker.ietf.org/doc/html/rfc4253#section-8).
#[derive(Debug, PartialEq)]
pub struct SshPacketDHKEXInit<'a> {
    /// The public key.
    #[cfg(feature = "integers")]
    pub e: BigInt,

    /// The public key.
    #[cfg(not(feature = "integers"))]
    pub e: &'a [u8],

    #[cfg(feature = "integers")]
    phantom: std::marker::PhantomData<&'a [u8]>,
}

#[cfg(feature = "integers")]
impl From<BigInt> for SshPacketDHKEXInit<'_> {
    fn from(e: BigInt) -> Self {
        Self {
            e,
            phantom: PhantomData,
        }
    }
}

#[cfg(not(feature = "integers"))]
impl<'a> From<&'a [u8]> for SshPacketDHKEXInit<'a> {
    fn from(e: &'a [u8]) -> Self {
        Self { e }
    }
}

impl<'a> SshPacketDHKEXInit<'a> {
    /// Parses a SSH Diffie-Hellman Key Exchange Init.
    pub fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        map(parse_mpint, Self::from)(i)
    }
}

/// SSH Diffie-Hellman Key Exchange Reply.
///
/// The message code is `SSH_MSG_KEXDH_REPLY`, defined in [RFC4253 section 8](https://datatracker.ietf.org/doc/html/rfc4253#section-8).
#[derive(Debug, PartialEq)]
pub struct SshPacketDHKEXReply<'a> {
    /// The server public host key and certificate.
    pub pubkey_and_cert: &'a [u8],

    /// The `f` value corresponding to `g^y mod p` where `g` is the group and `y` a random number.
    #[cfg(feature = "integers")]
    pub f: BigInt,

    /// The `f` value corresponding to `g^y mod p` where `g` is the group and `y` a random number.
    #[cfg(not(feature = "integers"))]
    pub f: &'a [u8],

    /// The signature.
    pub signature: &'a [u8],
}

#[cfg(feature = "integers")]
impl<'a, 'b, 'c> From<(&'b [u8], BigInt, &'c [u8])> for SshPacketDHKEXReply<'a>
where
    'b: 'a,
    'c: 'a,
{
    fn from((pubkey_and_cert, f, signature): (&'b [u8], BigInt, &'c [u8])) -> Self {
        Self {
            pubkey_and_cert,
            f,
            signature,
        }
    }
}

#[cfg(not(feature = "integers"))]
impl<'a, 'b, 'c, 'd> From<(&'b [u8], &'c [u8], &'d [u8])> for SshPacketDHKEXReply<'a>
where
    'b: 'a,
    'c: 'a,
    'd: 'a,
{
    fn from((pubkey_and_cert, f, signature): (&'b [u8], &'c [u8], &'d [u8])) -> Self {
        Self {
            pubkey_and_cert,
            f,
            signature,
        }
    }
}

/// An ECDSA signature.
///
/// ECDSA signatures are defined in [RFC5656 Section 3.1.2](https://tools.ietf.org/html/rfc5656#section-3.1.2).
#[derive(Debug, PartialEq)]
pub struct ECDSASignature<'a> {
    /// Identifier.
    pub identifier: &'a str,

    /// Blob.
    pub blob: &'a [u8],
}

impl<'a> SshPacketDHKEXReply<'a> {
    pub fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        map(tuple((parse_string, parse_mpint, parse_string)), Self::from)(i)
    }

    /// Parses the ECDSA signature.
    ///
    /// ECDSA signatures are Defined in [RFC5656 Section 3.1.2](https://tools.ietf.org/html/rfc5656#section-3.1.2).
    pub fn get_ecdsa_signature(&self) -> Result<ECDSASignature<'a>, SshKEXError<'a>> {
        let (_, (identifier, blob)) = pair(parse_string, parse_string)(self.signature)?;

        let identifier = std::str::from_utf8(identifier)?;
        Ok(ECDSASignature { identifier, blob })
    }
}

/// The key exchange protocol using Diffie Hellman Key Exchange, defined in RFC4253.
#[derive(Debug, Default, PartialEq)]
pub struct SshKEXDiffieHellman<'a> {
    /// The init message, i.e. `SSH_MSG_KEXDH_INIT`.
    pub init: Option<SshPacketDHKEXInit<'a>>,

    /// The reply message, i.e. `SSH_MSG_KEXDH_REPLY`.
    pub reply: Option<SshPacketDHKEXReply<'a>>,
}

/// SSH Elliptic Curve Diffie-Hellman Key Exchange Init.
///
/// The message is `SSH_MSG_KEXECDH_INIT`, defined in [RFC6239 section 4.1](https://datatracker.ietf.org/doc/html/rfc6239#section-4.1).
#[derive(Debug, PartialEq)]
pub struct SshPacketECDHKEXInit<'a> {
    /// The client's ephemeral contribution to theECDH exchange, encoded as an octet string.
    pub q_c: &'a [u8],
}

impl<'a, 'b> From<&'b [u8]> for SshPacketECDHKEXInit<'a>
where
    'b: 'a,
{
    fn from(q_c: &'b [u8]) -> Self {
        Self { q_c }
    }
}

impl<'a> SshPacketECDHKEXInit<'a> {
    pub fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        map(parse_string, Self::from)(i)
    }
}

/// SSH Elliptic Curve Diffie-Hellman Key Exchange Reply.
///
/// The message is `SSH_MSG_KEXECDH_REPLY`, defined in [RFC6239 section 4.2](https://datatracker.ietf.org/doc/html/rfc6239#section-4.2).
#[derive(Debug, PartialEq)]
pub struct SshPacketECDHKEXReply<'a> {
    /// A string encoding an X.509v3 certificate containing the server's ECDSA public host key.
    pub pubkey_and_cert: &'a [u8],

    /// The server's ephemeral contribution to the ECDH exchange, encoded as an octet string.
    pub q_s: &'a [u8],

    /// The server's signature of the newly established exchange hash value.
    pub signature: &'a [u8],
}

impl<'a, 'b, 'c, 'd> From<(&'b [u8], &'c [u8], &'d [u8])> for SshPacketECDHKEXReply<'a>
where
    'b: 'a,
    'c: 'a,
    'd: 'a,
{
    fn from((pubkey_and_cert, q_s, signature): (&'b [u8], &'c [u8], &'d [u8])) -> Self {
        Self {
            pubkey_and_cert,
            q_s,
            signature,
        }
    }
}

impl<'a> SshPacketECDHKEXReply<'a> {
    pub fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        map(
            tuple((parse_string, parse_string, parse_string)),
            Self::from,
        )(i)
    }
}

/// The key exchange protocol using Elliptic Curve Diffie Hellman Key Exchange, defined in RFC6239.
#[derive(Debug, Default, PartialEq)]
pub struct SshKEXECDiffieHellman<'a> {
    /// The init message, i.e. `SSH_MSG_KEXECDH_INIT`.
    pub init: Option<SshPacketECDHKEXInit<'a>>,

    /// The reply message, i.e. `SSH_MSG_KEXECDH_REPLY`.
    pub reply: Option<SshPacketECDHKEXReply<'a>>,
}

/// SSH Diffie-Hellman Group and Key Exchange Request.
///
/// The message code is `SSH_MSG_KEY_DH_GEX_REQUEST`, defined in [RFC4419 section 5](https://datatracker.ietf.org/doc/html/rfc4419#section-5).
///
/// The message is defined in [RFC4419 section 3](https://datatracker.ietf.org/doc/html/rfc4419#section-3).
#[derive(Debug, PartialEq)]
pub struct SshPacketDhKEXGEXRequest {
    /// Minimal size in bits of an acceptable group.
    pub min: u32,

    /// Preferred size in bits of the group the server will send.
    pub n: u32,

    /// Maximal size in bits of an acceptable group.
    pub max: u32,
}

impl From<(u32, u32, u32)> for SshPacketDhKEXGEXRequest {
    fn from((min, n, max): (u32, u32, u32)) -> Self {
        Self { min, n, max }
    }
}

impl SshPacketDhKEXGEXRequest {
    pub fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        map(tuple((be_u32, be_u32, be_u32)), Self::from)(i)
    }
}

/// SSH Diffie-Hellman Group and Key Exchange Request (old).
///
/// The message code is `SSH_MSG_KEY_DH_GEX_REQUEST_OLD`, defined in [RFC4419 section 5](https://datatracker.ietf.org/doc/html/rfc4419#section-5).
///
/// The message is defined in [RFC4419 section 3](https://datatracker.ietf.org/doc/html/rfc4419#section-3).
#[derive(Debug, PartialEq)]
pub struct SshPacketDhKEXGEXRequestOld {
    /// Preferred size in bits of the group the server will send.
    pub n: u32,
}

impl From<u32> for SshPacketDhKEXGEXRequestOld {
    fn from(n: u32) -> Self {
        Self { n }
    }
}

impl SshPacketDhKEXGEXRequestOld {
    pub fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        map(be_u32, Self::from)(i)
    }
}

/// SSH Diffie-Hellman Group and Key Exchange Group.
///
/// The message code is `SSH_MSG_KEX_DH_GEX_GROUP`, defined in [RFC4419 section 5](https://datatracker.ietf.org/doc/html/rfc4419#section-5).
///
///
/// The message is defined in [RFC4419 section 3](https://datatracker.ietf.org/doc/html/rfc4419#section-3).
#[derive(Debug, PartialEq)]
pub struct SshPacketDhKEXGEXGroup<'a> {
    /// The safe prime.
    #[cfg(feature = "integers")]
    pub p: BigInt,

    /// The safe prime.
    #[cfg(not(feature = "integers"))]
    pub p: &'a [u8],

    /// The generator for the subgroup in the Galois Field GF(p).
    #[cfg(feature = "integers")]
    pub g: BigInt,

    /// The generator for the subgroup in the Galois Field GF(p).
    #[cfg(not(feature = "integers"))]
    pub g: &'a [u8],

    #[cfg(feature = "integers")]
    phantom: PhantomData<&'a [u8]>,
}

#[cfg(feature = "integers")]
impl From<(BigInt, BigInt)> for SshPacketDhKEXGEXGroup<'_> {
    fn from((p, g): (BigInt, BigInt)) -> Self {
        Self {
            p,
            g,
            phantom: PhantomData,
        }
    }
}

#[cfg(not(feature = "integers"))]
impl<'a, 'b, 'c> From<(&'b [u8], &'c [u8])> for SshPacketDhKEXGEXGroup<'a>
where
    'b: 'a,
    'c: 'a,
{
    fn from((p, g): (&'b [u8], &'c [u8])) -> Self {
        Self { p, g }
    }
}

impl<'a> SshPacketDhKEXGEXGroup<'a> {
    pub fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        map(pair(parse_mpint, parse_mpint), Self::from)(i)
    }
}

/// SSH Diffie-Hellman Group and Key Exchange Init.
///
/// The message code is `SSH_MSG_KEX_DH_GEX_INIT`, defined in [RFC4419 section 5](https://datatracker.ietf.org/doc/html/rfc4419#section-5).
///
/// The message is defined in [RFC4419 section 3](https://datatracker.ietf.org/doc/html/rfc4419#section-3).
#[derive(Debug, PartialEq)]
pub struct SshPacketDhKEXGEXInit<'a> {
    /// The public key.
    #[cfg(feature = "integers")]
    pub e: BigInt,

    /// The public key.
    #[cfg(not(feature = "integers"))]
    pub e: &'a [u8],

    #[cfg(feature = "integers")]
    phantom: PhantomData<&'a [u8]>,
}

#[cfg(feature = "integers")]
impl From<BigInt> for SshPacketDhKEXGEXInit<'_> {
    fn from(e: BigInt) -> Self {
        Self {
            e,
            phantom: PhantomData,
        }
    }
}

#[cfg(not(feature = "integers"))]
impl<'a, 'b> From<&'b [u8]> for SshPacketDhKEXGEXInit<'a>
where
    'b: 'a,
{
    fn from(e: &'b [u8]) -> Self {
        Self { e }
    }
}

/// Parses a SSH Diffie-Hellman Group and Key Exchange init.
impl<'a> SshPacketDhKEXGEXInit<'a> {
    pub fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        map(parse_mpint, Self::from)(i)
    }
}

/// SSH Diffie-Hellman Group and Key Exchange Reply.
///
/// The message code is `SSH_MSG_KEX_DH_GEX_REPLY`, defined in [RFC4419 section 5](https://datatracker.ietf.org/doc/html/rfc4419#section-5).
///
/// The message is defined in [RFC4419 section 3](https://datatracker.ietf.org/doc/html/rfc4419#section-3).
#[derive(Debug, PartialEq)]
pub struct SshPacketDhKEXGEXReply<'a> {
    /// Server public host key and certificate.
    pub pubkey_and_cert: &'a [u8],

    /// f.
    #[cfg(feature = "integers")]
    pub f: BigInt,

    /// f.
    #[cfg(not(feature = "integers"))]
    pub f: &'a [u8],

    /// Signature.
    pub signature: &'a [u8],
}

#[cfg(feature = "integers")]
impl<'a, 'b, 'c> From<(&'b [u8], BigInt, &'c [u8])> for SshPacketDhKEXGEXReply<'a>
where
    'b: 'a,
    'c: 'a,
{
    fn from((pubkey_and_cert, f, signature): (&'b [u8], BigInt, &'c [u8])) -> Self {
        Self {
            pubkey_and_cert,
            f,
            signature,
        }
    }
}

#[cfg(not(feature = "integers"))]
impl<'a, 'b, 'c, 'd> From<(&'b [u8], &'c [u8], &'d [u8])> for SshPacketDhKEXGEXReply<'a>
where
    'b: 'a,
    'c: 'a,
    'd: 'a,
{
    fn from((pubkey_and_cert, f, signature): (&'b [u8], &'c [u8], &'d [u8])) -> Self {
        Self {
            pubkey_and_cert,
            f,
            signature,
        }
    }
}

impl<'a> SshPacketDhKEXGEXReply<'a> {
    pub fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        map(tuple((parse_string, parse_mpint, parse_string)), Self::from)(i)
    }
}

/// The key exchange protocol using Diffie Hellman Group and Key, defined in RFC4419.
#[derive(Debug, Default, PartialEq)]
pub struct SshKEXDiffieHellmanKEXGEX<'a> {
    /// The request message, i.e. `SSH_MSG_KEY_DH_GEX_REQUEST`.
    pub request: Option<SshPacketDhKEXGEXRequest>,

    /// The request message (old variant), i.e. `SSH_MSG_KEY_DH_GEX_REQUEST_OLD`.
    pub request_old: Option<SshPacketDhKEXGEXRequestOld>,

    /// The group message, i.e. `SSH_MSG_KEX_DH_GEX_GROUP`.
    pub group: Option<SshPacketDhKEXGEXGroup<'a>>,

    /// The init message, i.e. `SSH_MSG_KEX_DH_GEX_INIT`.
    pub init: Option<SshPacketDhKEXGEXInit<'a>>,

    /// The init message, i.e. `SSH_MSG_KEX_DH_GEX_REPLY`.
    pub reply: Option<SshPacketDhKEXGEXReply<'a>>,
}

/// SSH Hybrid Key Exchange init.
///
/// The message code is `SSH_MSG_KEX_HYBRID_INIT`, defined in
/// [draft RFC `draft-kampanakis-curdle-ssh-pq-ke-02` section 2.2](https://www.ietf.org/archive/id/draft-kampanakis-curdle-ssh-pq-ke-02.html#section-2.2)
#[derive(Debug, PartialEq)]
pub struct SshPacketHybridKEXInit<'a> {
    /// The post-quantum KEM's public key (`C_PK2`).
    pub pq_pub_key: &'a [u8],

    /// The traditional / classical KEX public key.
    pub classical_pub_key: &'a [u8],
}

impl<'a> SshPacketHybridKEXInit<'a> {
    /// Parses a SSH PQ/T Hybrid Key Exchange Init.
    pub fn parse(i: &'a [u8], alg: SupportedHybridKEXAlgorithm) -> IResult<&'a [u8], Self> {
        let pq_len = alg.pq_pub_key_len();
        let (i, (pq_pub_key, classical_pub_key)) =
            map_parser(parse_string, tuple((take(pq_len), rest)))(i)?;
        Ok((
            i,
            Self {
                pq_pub_key,
                classical_pub_key,
            },
        ))
    }
}

/// SSH Hybrid Key Exchange reply.
///
/// The message code is `SSH_MSG_KEX_HYBRID_REPLY`, defined in
/// [draft RFC `draft-kampanakis-curdle-ssh-pq-ke-02` section 2.2](https://www.ietf.org/archive/id/draft-kampanakis-curdle-ssh-pq-ke-02.html#section-2.2)
#[derive(Debug, PartialEq)]
pub struct SshPacketHybridKEXReply<'a> {
    /// K_S, server's public host key.
    pub pubkey_and_cert: &'a [u8],

    /// S_CT2, the ciphertext 'ct' output of the corresponding KEM's 'Encaps' algorithm.
    pub pq_ciphertext: &'a [u8],

    /// S_PK1, ephemeral (EC)DH server public key.
    pub classical_pub_key: &'a [u8],

    /// Signature.
    pub signature: &'a [u8],
}

impl<'a> SshPacketHybridKEXReply<'a> {
    /// Parses a SSH PQ/T Hybrid Key Exchange reply.
    pub fn parse(i: &'a [u8], alg: SupportedHybridKEXAlgorithm) -> IResult<&'a [u8], Self> {
        let ct_len = alg.pq_ciphertext_len();
        let (i, (pubkey_and_cert, (pq_ciphertext, classical_pub_key), signature)) = tuple((
            parse_string,
            map_parser(parse_string, tuple((take(ct_len), rest))),
            parse_string,
        ))(i)?;
        Ok((
            i,
            Self {
                pubkey_and_cert,
                pq_ciphertext,
                classical_pub_key,
                signature,
            },
        ))
    }
}

/// The key exchange protocol using PQ/T Key Exchange, defined in
/// [draft RFC `draft-kampanakis-curdle-ssh-pq-ke-02`](https://www.ietf.org/archive/id/draft-kampanakis-curdle-ssh-pq-ke-02.html).
#[derive(Debug, PartialEq)]
pub struct SshHybridKEX<'a> {
    /// The init message, i.e. `SSH_MSG_KEX_HYBRID_INIT`.
    pub init: Option<SshPacketHybridKEXInit<'a>>,

    /// The reply message, i.e. `SSH_MSG_KEX_HYBRID_REPLY`.
    pub reply: Option<SshPacketHybridKEXReply<'a>>,

    /// The algorithm.
    pub alg: SupportedHybridKEXAlgorithm,
}

impl SshHybridKEX<'_> {
    /// Initializes a new [`SshHybridKEX`] using the given algorithm.
    pub fn new(alg: SupportedHybridKEXAlgorithm) -> Self {
        Self {
            init: None,
            reply: None,
            alg,
        }
    }
}

/// An error occurring in the KEX parser.
#[derive(Debug)]
pub enum SshKEXError<'a> {
    /// nom error.
    Nom(nom::Err<Error<&'a [u8]>>),

    /// Could not negociate a KEX algorithm.
    NegociationFailed,

    /// Unknown KEX protocol.
    UnknownProtocol,

    /// Duplicated message.
    DuplicatedMessage,

    /// Unexpected message.
    UnexpectedMessage,

    /// Invalid UTF-8 string.
    InvalidUtf8(std::str::Utf8Error),

    /// Other error.
    Other(String),
}

impl std::fmt::Display for SshKEXError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<'a> From<nom::Err<Error<&'a [u8]>>> for SshKEXError<'a> {
    fn from(e: nom::Err<Error<&'a [u8]>>) -> Self {
        Self::Nom(e)
    }
}

impl From<String> for SshKEXError<'_> {
    fn from(e: String) -> Self {
        Self::Other(e)
    }
}

impl From<&str> for SshKEXError<'_> {
    fn from(e: &str) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<std::str::Utf8Error> for SshKEXError<'_> {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::InvalidUtf8(e)
    }
}

impl std::error::Error for SshKEXError<'_> {}

macro_rules! parse_match_and_assign {
    ($variant:ident, $field:ident, $struct:ident, $payload:ident) => {
        if $variant.$field.is_some() {
            Err(SshKEXError::DuplicatedMessage)
        } else {
            $variant.$field = Some(all_consuming($struct::parse)($payload)?.1);
            Ok(())
        }
    };
}

/// Parses a hybrid KEX message, matches its owner and assign the parsed
/// object to it.
///
/// We use a macro here because we take a field of `SshHybridKEX` as a parameter
/// (the receiver).
macro_rules! parse_match_and_assign_hybrid {
    ($variant:ident, $field:ident, $struct:ident, $payload:ident) => {
        if $variant.$field.is_some() {
            Err(SshKEXError::DuplicatedMessage)
        } else {
            let alg = $variant.alg;
            $variant.$field = Some(all_consuming(|i| $struct::parse(i, alg))($payload)?.1);
            Ok(())
        }
    };
}

/// Negociates the KEX algorithm.
pub fn ssh_kex_negociate_algorithm<'a, 'b, 'c, S1, S2>(
    client_kex_algs: impl IntoIterator<Item = &'b S1>,
    server_kex_algs: impl IntoIterator<Item = &'c S2>,
) -> Option<&'a str>
where
    'b: 'a,
    'c: 'a,
    S1: AsRef<str> + 'b + ?Sized,
    S2: AsRef<str> + 'c + ?Sized,
{
    let server_algs = server_kex_algs
        .into_iter()
        .map(|s| s.as_ref())
        .collect::<Vec<_>>();
    client_kex_algs
        .into_iter()
        .find(|&item| server_algs.contains(&item.as_ref()))
        .map(|s| s.as_ref())
}

/// The key exchange protocol.
#[derive(Debug, PartialEq)]
pub enum SshKEX<'a> {
    /// Diffie Hellman Key Exchange, defined in RFC4253.
    DiffieHellman(SshKEXDiffieHellman<'a>),

    /// Elliptic Curve Diffie Hellman, defined in RFC6239.
    ECDiffieHellman(SshKEXECDiffieHellman<'a>),

    /// Diffie Hellman Group and Key, defined in RFC4419.
    DiffieHellmanKEXGEX(SshKEXDiffieHellmanKEXGEX<'a>),

    /// PQ/T Hybrid Key Exchange, defined in
    /// [draft RFC `draft-kampanakis-curdle-ssh-pq-ke-02`](https://www.ietf.org/archive/id/draft-kampanakis-curdle-ssh-pq-ke-02.html).
    HybridKEX(SshHybridKEX<'a>),
}

impl<'a> SshKEX<'a> {
    /// Initializes a [`SshKEX`] using the kex algorithms sent during the kex exchange
    /// init stage.
    /// The returned string is the negociated KEX algorithm.
    pub fn init<'b, 'c>(
        client_kex_init: &'b SshPacketKeyExchange<'b>,
        server_kex_init: &'c SshPacketKeyExchange<'c>,
    ) -> Result<(Self, &'a str), SshKEXError<'a>>
    where
        'b: 'a,
        'c: 'a,
    {
        let client_kex_list = client_kex_init.get_kex_algs()?;
        let server_kex_list = server_kex_init.get_kex_algs()?;
        let negociated_alg = ssh_kex_negociate_algorithm(client_kex_list, server_kex_list)
            .ok_or(SshKEXError::NegociationFailed)?;
        match negociated_alg {
            "diffie-hellman-group1-sha1"
            | "diffie-hellman-group14-sha1"
            | "diffie-hellman-group14-sha256"
            | "diffie-hellman-group16-sha512"
            | "diffie-hellman-group18-sha512" => {
                Ok(Self::DiffieHellman(SshKEXDiffieHellman::default()))
            }
            "curve25519-sha256"
            | "curve25519-sha256@libssh.org"
            | "curve448-sha512"
            | "ecdh-sha2-nistp256"
            | "ecdh-sha2-nistp384"
            | "ecdh-sha2-nistp521" => Ok(Self::ECDiffieHellman(SshKEXECDiffieHellman::default())),
            "diffie-hellman-group-exchange-sha1" | "diffie-hellman-group-exchange-sha256" => Ok(
                Self::DiffieHellmanKEXGEX(SshKEXDiffieHellmanKEXGEX::default()),
            ),
            "ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org" => Ok(Self::HybridKEX(
                SshHybridKEX::new(SupportedHybridKEXAlgorithm::ECDHNistP256Kyber512r3Sha256D00OQS),
            )),
            "ecdh-nistp384-kyber-768r3-sha384-d00@openquantumsafe.org" => Ok(Self::HybridKEX(
                SshHybridKEX::new(SupportedHybridKEXAlgorithm::ECDHNistP384Kyber768r3Sha384D00OQS),
            )),
            "ecdh-nistp521-kyber-1024r3-sha512-d00@openquantumsafe.org" => Ok(Self::HybridKEX(
                SshHybridKEX::new(SupportedHybridKEXAlgorithm::ECDHNistP521Kyber1024r3Sha512D00OQS),
            )),
            _ => Err(SshKEXError::UnknownProtocol),
        }
        .map(|kex| (kex, negociated_alg))
    }

    /// Parses a new message according to the selected KEX method.
    /// If the parsed message is not related to the KEX protocol, SshKEXError::UnexpectedMessage
    /// is returned.
    pub fn parse_ssh_packet<'c>(
        &mut self,
        unparsed_ssh_packet: &'c SshPacketUnparsed<'c>,
    ) -> Result<(), SshKEXError<'a>>
    where
        'c: 'a,
    {
        let payload = unparsed_ssh_packet.payload;
        match self {
            Self::DiffieHellman(dh) => match unparsed_ssh_packet.message_code {
                SSH_MSG_KEXDH_INIT => {
                    parse_match_and_assign!(dh, init, SshPacketDHKEXInit, payload)
                }
                SSH_MSG_KEXDH_REPLY => {
                    parse_match_and_assign!(dh, reply, SshPacketDHKEXReply, payload)
                }
                _ => Err(SshKEXError::UnexpectedMessage),
            },
            Self::ECDiffieHellman(dh) => match unparsed_ssh_packet.message_code {
                SSH_MSG_KEXECDH_INIT => {
                    parse_match_and_assign!(dh, init, SshPacketECDHKEXInit, payload)
                }
                SSH_MSG_KEXECDH_REPLY => {
                    parse_match_and_assign!(dh, reply, SshPacketECDHKEXReply, payload)
                }
                _ => Err(SshKEXError::UnexpectedMessage),
            },
            Self::DiffieHellmanKEXGEX(dh) => match unparsed_ssh_packet.message_code {
                SSH_MSG_KEX_DH_GEX_REQUEST => {
                    parse_match_and_assign!(dh, request, SshPacketDhKEXGEXRequest, payload)
                }
                SSH_MSG_KEX_DH_GEX_REQUEST_OLD => {
                    parse_match_and_assign!(dh, request_old, SshPacketDhKEXGEXRequestOld, payload)
                }
                SSH_MSG_KEX_DH_GEX_GROUP => {
                    parse_match_and_assign!(dh, group, SshPacketDhKEXGEXGroup, payload)
                }
                SSH_MSG_KEX_DH_GEX_INIT => {
                    parse_match_and_assign!(dh, init, SshPacketDhKEXGEXInit, payload)
                }
                SSH_MSG_KEX_DH_GEX_REPLY => {
                    parse_match_and_assign!(dh, reply, SshPacketDhKEXGEXReply, payload)
                }
                _ => Err(SshKEXError::UnexpectedMessage),
            },
            Self::HybridKEX(hk) => match unparsed_ssh_packet.message_code {
                SSH_MSG_KEX_HYBRID_INIT => {
                    parse_match_and_assign_hybrid!(hk, init, SshPacketHybridKEXInit, payload)
                }
                SSH_MSG_KEX_HYBRID_REPLY => {
                    parse_match_and_assign_hybrid!(hk, reply, SshPacketHybridKEXReply, payload)
                }
                _ => Err(SshKEXError::UnexpectedMessage),
            },
        }
    }
}

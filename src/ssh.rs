//! # SSH parser
//!
//! This module contains parsing functions for the SSH 2.0 protocol. It is also
//! compatible with obsolete version negotiation.
use std::str;

use nom::{IResult,IError,ErrorKind,crlf,not_line_ending,line_ending,be_u8,be_u32};

use enum_primitive::FromPrimitive;


/// SSH Protocol Version Exchange
///
/// Defined in [RFC4253 section 4.2](https://tools.ietf.org/html/rfc4253#section-4.2).
///
/// Unparsed proto and software fields must contain US-ASCII printable
/// characters only (without space and minus sign). There is no constraint on
/// the comment field except it must not contain the null byte.
#[derive(Debug,PartialEq)]
pub struct SshVersion<'a> {
    pub proto: &'a [u8],
    pub software: &'a [u8],
    pub comments: Option<&'a[u8]>,
}


// Version exchange terminates with CRLF for SSH 2.0 or LF for compatibility
// with older versions.
named!(parse_version<SshVersion>, do_parse!(
    proto: take_until_and_consume_s!("-") >>
    software: is_not_s!(" \r\n") >>
    comments: opt!(do_parse!(
            tag!(" ") >>
            comments: not_line_ending >>
            ( comments ))
    ) >>
    ( SshVersion { proto: proto, software: software, comments: comments } )
));


/// Parse the SSH identification phase.
///
/// In version 2.0, the SSH server is allowed to send an arbitrary number of
/// UTF-8 lines before the final identification line containing the server
/// version. This function allocates a vector to store these line slices in
/// addition of the advertised version of the SSH implementation.
pub fn parse_ssh_identification(i: &[u8]) -> IResult<&[u8], (Vec<&[u8]>, SshVersion)> {
    many_till!(i,
        terminated!(take_until_s!("\r\n"), crlf),
        delimited!(tag!("SSH-"), parse_version, line_ending)
    )
}


named!(parse_string<&[u8]>, do_parse!(
    len: be_u32 >>
    string: take!(len) >>
    ( string )
));

// US-ASCII printable characters without comma
#[inline]
fn is_us_ascii(c: u8) -> bool {
    c >= 0x20 && c <= 0x7e && c != 0x2c
}

named!(parse_name<&[u8]>, take_while!(is_us_ascii));

fn parse_name_list(i: &[u8]) -> IResult<&[u8], Vec<&str>> {
    separated_list_complete!(i, tag!(","), map_res!(parse_name, str::from_utf8))
}


/// SSH Algorithm Negotiation 
///
/// Defined in [RFC4253 section 7.1](https://tools.ietf.org/html/rfc4253#section-7.1).
///
/// This packet contains all information necessary to prepare the key exchange.
/// The algorithms are UTF-8 strings in name lists. The order is significant
/// with most preferred algorithms first. Parsing of lists is done only when
/// the field are accessed though accessors (note that lists can
/// be successfully extracted at the packet level but accessing them later can
/// fail with a UTF-8 conversion error).
#[derive(Debug,PartialEq)]
pub struct SshPacketKeyExchange<'a> {
    pub cookie: &'a[u8],
    pub kex_algs: &'a [u8],
    pub server_host_key_algs: &'a [u8],
    pub encr_algs_client_to_server: &'a [u8],
    pub encr_algs_server_to_client: &'a [u8],
    pub mac_algs_client_to_server: &'a [u8],
    pub mac_algs_server_to_client: &'a [u8],
    pub comp_algs_client_to_server: &'a [u8],
    pub comp_algs_server_to_client: &'a [u8],
    pub langs_client_to_server: &'a [u8],
    pub langs_server_to_client: &'a [u8],
    pub first_kex_packet_follows: bool,
}

named!(parse_packet_key_exchange<SshPacket>, do_parse!(
    cookie: take!(16) >>
    kex_algs: parse_string >>
    server_host_key_algs: parse_string >>
    encr_algs_client_to_server: parse_string >>
    encr_algs_server_to_client: parse_string >>
    mac_algs_client_to_server: parse_string >>
    mac_algs_server_to_client: parse_string >>
    comp_algs_client_to_server: parse_string >>
    comp_algs_server_to_client: parse_string >>
    langs_client_to_server: parse_string >>
    langs_server_to_client: parse_string >>
    first_kex_packet_follows: be_u8 >>
    be_u32 >>
    ( SshPacket::KeyExchange(SshPacketKeyExchange {
        cookie: cookie,
        kex_algs: kex_algs,
        server_host_key_algs: server_host_key_algs,
        encr_algs_client_to_server: encr_algs_client_to_server,
        encr_algs_server_to_client: encr_algs_server_to_client,
        mac_algs_client_to_server: mac_algs_client_to_server,
        mac_algs_server_to_client: mac_algs_server_to_client,
        comp_algs_client_to_server: comp_algs_client_to_server,
        comp_algs_server_to_client: comp_algs_server_to_client,
        langs_client_to_server: langs_client_to_server,
        langs_server_to_client: langs_server_to_client,
        first_kex_packet_follows: first_kex_packet_follows > 0,
    }) )
));


impl<'a> SshPacketKeyExchange<'a> {

    pub fn get_kex_algs(&self) -> Result<Vec<&str>, IError<&'a [u8]>> {
        parse_name_list(self.kex_algs).to_full_result()
    }

    pub fn get_server_host_key_algs(&self) -> Result<Vec<&str>, IError<&'a [u8]>> {
        parse_name_list(self.server_host_key_algs).to_full_result()
    }

    pub fn get_encr_algs_client_to_server(&self) -> Result<Vec<&str>, IError<&'a [u8]>> {
        parse_name_list(self.encr_algs_client_to_server).to_full_result()
    }

    pub fn get_encr_algs_server_to_client(&self) -> Result<Vec<&str>, IError<&'a [u8]>> {
        parse_name_list(self.encr_algs_server_to_client).to_full_result()
    }

    pub fn get_mac_algs_client_to_server(&self) -> Result<Vec<&str>, IError<&'a [u8]>> {
        parse_name_list(self.mac_algs_client_to_server).to_full_result()
    }

    pub fn get_mac_algs_server_to_client(&self) -> Result<Vec<&str>, IError<&'a [u8]>> {
        parse_name_list(self.mac_algs_server_to_client).to_full_result()
    }

    pub fn get_comp_algs_client_to_server(&self) -> Result<Vec<&str>, IError<&'a [u8]>> {
        parse_name_list(self.comp_algs_client_to_server).to_full_result()
    }

    pub fn get_comp_algs_server_to_client(&self) -> Result<Vec<&str>, IError<&'a [u8]>> {
        parse_name_list(self.comp_algs_server_to_client).to_full_result()
    }

    pub fn get_langs_client_to_server(&self) -> Result<Vec<&str>, IError<&'a [u8]>> {
        parse_name_list(self.langs_client_to_server).to_full_result()
    }

    pub fn get_langs_server_to_client(&self) -> Result<Vec<&str>, IError<&'a [u8]>> {
        parse_name_list(self.langs_server_to_client).to_full_result()
    }

}


/// SSH Key Exchange Client Packet
///
/// Defined in [RFC4253 section 8](https://tools.ietf.org/html/rfc4253#section-8) and [errata](https://www.rfc-editor.org/errata_search.php?rfc=4253).
///
/// The single field e is left unparsed because its representation depends on
/// the negotiated key exchange algorithm:
/// 
/// - with a diffie hellman exchange on multiplicative group of integers modulo
///   p, such as defined in [RFC4253](https://tools.ietf.org/html/rfc4253), the
///   field is a multiple precision integer (defined in [RFC4251 section 5](https://tools.ietf.org/html/rfc4251#section-5)).
/// - with a DH on elliptic curves, such as defined in [RFC6239](https://tools.ietf.org/html/rfc6239), the field is an octet string.
///
/// TODO: add accessors for the different representations
#[derive(Debug,PartialEq)]
pub struct SshPacketDhInit<'a> {
    pub e: &'a [u8],
}

named!(parse_packet_dh_init<SshPacket>, map!(
   call!(parse_string),
   |x| SshPacket::DiffieHellmanInit(SshPacketDhInit { e: x })
));


/// SSH Key Exchange Server Packet
/// 
/// Defined in [RFC4253 section 8](https://tools.ietf.org/html/rfc4253#section-8) and [errata](https://www.rfc-editor.org/errata_search.php?rfc=4253).
///
/// Like the client packet, the fields depend on the algorithm negotiated during
/// the previous packet exchange.
#[derive(Debug,PartialEq)]
pub struct SshPacketDhReply<'a> {
    pub pubkey_and_cert: &'a [u8],
    pub f: &'a [u8],
    pub signature: &'a [u8],
}

named!(parse_packet_dh_reply<SshPacket>, do_parse!(
    pubkey: parse_string >>
    f: parse_string >>
    signature: parse_string >>
    ( SshPacket::DiffieHellmanReply(SshPacketDhReply { pubkey_and_cert: pubkey, f: f, signature: signature }) )
));

impl<'a> SshPacketDhReply<'a> {

    /// Parse the ECDSA server signature.
    ///
    /// Defined in [RFC5656 Section 3.1.2](https://tools.ietf.org/html/rfc5656#section-3.1.2).
    pub fn get_ecdsa_signature(&self) -> Result<(&str, Vec<u8>), IError<&'a [u8]>> {
        let (identifier, blob) = try!(do_parse!(self.signature,
            identifier: map_res!(parse_string, str::from_utf8) >>
            blob: flat_map!(call!(parse_string), pair!(parse_string, parse_string)) >>
            ( (identifier, blob) )
        ).to_full_result());

        let mut rs = Vec::new();

        rs.extend_from_slice(blob.0);
        rs.extend_from_slice(blob.1);

        Ok((identifier, rs))
    }

}


/// SSH Disconnection Message
///
/// Defined in [RFC4253 Section 11.1](https://tools.ietf.org/html/rfc4253#section-11.1).
#[derive(Debug,PartialEq)]
pub struct SshPacketDisconnect<'a> {
    pub reason_code: u32,
    pub description: &'a [u8],
    pub lang: &'a [u8],
}

enum_from_primitive! {
/// SSH Disconnection Message Reason Code
///
/// Defined in [IANA SSH Protocol Parameters](http://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-3).
#[repr(u32)]
pub enum SshDisconnectReason {
    HostNotAllowedToConnect          =   1,
    ProtocolError                    =   2,
    KeyExchangeFailed                =   3,
    Reserved                         =   4,
    MacError                         =   5,
    CompressionError                 =   6,
    ServiceNotAvailable              =   7,
    ProtocolVersionNotSupported      =   8,
    HostKeyNotVerifiable             =   9,
    ConnectionLost                   =  10,
    ByApplication                    =  11,
    TooManyConnections               =  12,
    AuthCancelledByUser              =  13,
    NoMoreAuthMethodsAvailable       =  14,
    IllegalUserName                  =  15,
}
}

named!(parse_packet_disconnect<SshPacket>, do_parse!(
    reason_code: be_u32 >>
    description: parse_string >>
    lang: parse_string >>
    ( SshPacket::Disconnect(SshPacketDisconnect { reason_code: reason_code, description: description, lang: lang}) )
));

impl<'a> SshPacketDisconnect<'a> {

    /// Parse Disconnection Description
    pub fn get_description(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(self.description)
    }

    /// Parse Disconnection Reason Code
    pub fn get_reason(&self) -> Option<SshDisconnectReason> {
        SshDisconnectReason::from_u32(self.reason_code)
    }

}


/// SSH Debug Message
///
/// Defined in [RFC4253 Section 11.3](https://tools.ietf.org/html/rfc4253#section-11.3).
#[derive(Debug,PartialEq)]
pub struct SshPacketDebug<'a> {
    pub always_display: bool,
    pub message: &'a [u8],
    pub lang: &'a [u8],
}

named!(parse_packet_debug<SshPacket>, do_parse!(
    display: be_u8 >>
    message: parse_string >>
    lang: parse_string >>
    ( SshPacket::Debug(SshPacketDebug { always_display: display > 0, message: message, lang: lang}) )
));

impl<'a> SshPacketDebug<'a> {

    /// Parse Debug Message
    pub fn get_message(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(self.message)
    }

}


/// SSH Packet Enumeration
#[derive(Debug,PartialEq)]
pub enum SshPacket<'a> {
    Disconnect(SshPacketDisconnect<'a>),
    Ignore(&'a [u8]),
    Unimplemented(u32),
    Debug(SshPacketDebug<'a>),
    ServiceRequest(&'a [u8]),
    ServiceAccept(&'a [u8]),
    KeyExchange(SshPacketKeyExchange<'a>),
    NewKeys,
    DiffieHellmanInit(SshPacketDhInit<'a>),
    DiffieHellmanReply(SshPacketDhReply<'a>),
}


/// Parse a plaintext SSH packet with its padding.
///
/// Packet structure is defined in [RFC4253 Section 6](https://tools.ietf.org/html/rfc4253#section-6) and
/// message codes are defined in [RFC4253 Section 12](https://tools.ietf.org/html/rfc4253#section-12).
pub fn parse_ssh_packet(i: &[u8]) -> IResult<&[u8], (SshPacket, &[u8])> {
    do_parse!(i,
        packet_length: be_u32 >>
        padding_length: be_u8 >>
        error_if!(padding_length as u32 + 1 > packet_length, ErrorKind::Custom(128)) >>
        payload: flat_map!(
            take!(packet_length - padding_length as u32 - 1),
            switch!(be_u8,
                /* SSH_MSG_DISCONNECT       */  1 => call!(parse_packet_disconnect) |
                /* SSH_MSG_IGNORE           */  2 => map!(parse_string, |x| SshPacket::Ignore(x)) |
                /* SSH_MSG_UNIMPLEMENTED    */  3 => map!(be_u32, |x| SshPacket::Unimplemented(x)) |
                /* SSH_MSG_DEBUG            */  4 => call!(parse_packet_debug) |
                /* SSH_MSG_SERVICE_REQUEST  */  5 => map!(parse_string, |x| SshPacket::ServiceRequest(x)) |
                /* SSH_MSG_SERVICE_ACCEPT   */  6 => map!(parse_string, |x| SshPacket::ServiceAccept(x)) |
                /* SSH_MSG_KEXINIT          */ 20 => call!(parse_packet_key_exchange) |
                /* SSH_MSG_NEWKEYS          */ 21 => value!(SshPacket::NewKeys) |
                /* SSH_MSG_KEXDH_INIT       */ 30 => call!(parse_packet_dh_init) |
                /* SSH_MSG_KEXDH_REPLY      */ 31 => call!(parse_packet_dh_reply)
            )
        ) >>
        padding: take!(padding_length) >>
        ( (payload, padding) )
    )
}


#[cfg(test)]
mod tests {

    use super::*;
    use nom::{ErrorKind,Err};

    #[test]
    fn test_name() {
        let res = parse_name(b"ssh-rsa");
        let expected = IResult::Done(&b""[..],&b"ssh-rsa"[..]);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_empty_name_list() {
        let res = parse_name_list(b"");
        let expected = IResult::Error(Err::Position(ErrorKind::SeparatedList, &b""[..]));
        assert_eq!(res, expected);
    }

    #[test]
    fn test_one_name_list() {
        let res = parse_name_list(b"ssh-rsa");
        let expected = IResult::Done(&b""[..],vec!["ssh-rsa"]);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_two_names_list() {
        let res = parse_name_list(b"ssh-rsa,ssh-ecdsa");
        let expected = IResult::Done(&b""[..],vec!["ssh-rsa","ssh-ecdsa"]);
        assert_eq!(res, expected);
    }

}

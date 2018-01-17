// Public API tests
use nom::{IResult,ErrorKind,Err};

use super::ssh::*;

static CLIENT_KEY_EXCHANGE: &'static [u8] = include_bytes!("../assets/client_init.raw");
static CLIENT_DH_INIT: &'static [u8] = include_bytes!("../assets/dh_init.raw");
static SERVER_DH_REPLY: &'static [u8] = include_bytes!("../assets/dh_reply.raw");
static SERVER_NEW_KEYS: &'static [u8] = include_bytes!("../assets/new_keys.raw");
static SERVER_COMPAT: &'static [u8] = include_bytes!("../assets/server_compat.raw");


#[test]
fn test_identification() {
    let empty: Vec<&[u8]> = vec![];
    let version = SshVersion { proto: b"2.0", software: b"OpenSSH_7.3", comments: None };

    let expected = IResult::Done(b"" as &[u8], (empty, version));
    let res = parse_ssh_identification(&CLIENT_KEY_EXCHANGE[..21]);
    assert_eq!(res, expected);
}


#[test]
fn test_compatibility() {
    let empty: Vec<&[u8]> = vec![];
    let version = SshVersion { proto: b"1.99", software: b"OpenSSH_3.1p1", comments: None };

    let expected = IResult::Done(b"" as &[u8], (empty, version));
    let res = parse_ssh_identification(&SERVER_COMPAT[..23]);
    assert_eq!(res, expected);
}


#[test]
fn test_version_with_comments() {
    let empty: Vec<&[u8]> = vec![];
    let version = SshVersion { proto: b"2.0", software: b"OpenSSH_7.3", comments: Some(b"toto") };
    let expected = IResult::Done(b"" as &[u8], (empty, version));
    let res = parse_ssh_identification(b"SSH-2.0-OpenSSH_7.3 toto\r\n");
    assert_eq!(res, expected);
}


#[test]
fn test_client_key_exchange() {
    let cookie = [0xca, 0x98, 0x42, 0x14, 0xd6, 0xa5, 0xa7, 0xfd, 0x6c, 0xe8, 0xd4, 0x7c, 0x0b, 0xc0, 0x96, 0xcc];
    let key_exchange = SshPacket::KeyExchange(SshPacketKeyExchange {
        cookie: &cookie,
        kex_algs: b"curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c",
        server_host_key_algs: b"ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
        encr_algs_client_to_server: b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc",
        encr_algs_server_to_client: b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc",
        mac_algs_client_to_server: b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        mac_algs_server_to_client: b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        comp_algs_client_to_server: b"none,zlib@openssh.com,zlib",
        comp_algs_server_to_client: b"none,zlib@openssh.com,zlib",
        langs_client_to_server: b"",
        langs_server_to_client: b"",
        first_kex_packet_follows: false,
    });
    let padding: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let expected = IResult::Done(b"" as &[u8], (key_exchange, padding));
    let res = parse_ssh_packet(&CLIENT_KEY_EXCHANGE[21..]);
    assert_eq!(res, expected);
}


#[test]
fn test_dh_init() {
    let e = [
        0x04, 0xe7, 0x59, 0x2a, 0xe1, 0xb9, 0xb6, 0xbe, 0x7c, 0x81, 0x5f, 0xc8,
        0x3d, 0x55, 0x7b, 0x8f, 0xc7, 0x09, 0x1d, 0x71, 0x6c, 0xed, 0x68, 0x45,
        0x6c, 0x31, 0xc7, 0xf3, 0x65, 0x98, 0xa5, 0x44, 0x7d, 0xa4, 0x28, 0xdd,
        0xe7, 0x3a, 0xd9, 0xa1, 0x0e, 0x4b, 0x75, 0x3a, 0xde, 0x33, 0x99, 0x6e,
        0x41, 0x7d, 0xea, 0x88, 0xe9, 0x90, 0xe3, 0x5a, 0x27, 0xf8, 0x38, 0x09,
        0x01, 0x66, 0x46, 0xd4, 0xdc
    ];
    let dh = SshPacket::DiffieHellmanInit(SshPacketDhInit { e: &e });
    let padding: &[u8] = &[0, 0, 0, 0, 0];
    let expected = IResult::Done(b"" as &[u8], (dh, padding));
    let res = parse_ssh_packet(CLIENT_DH_INIT);
    assert_eq!(res, expected);
}


#[test]
fn test_dh_reply() {
    let pubkey = [
        0x00, 0x00, 0x00, 0x13, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x73, 0x68,
        0x61, 0x32, 0x2d, 0x6e, 0x69, 0x73, 0x74, 0x70, 0x32, 0x35, 0x36, 0x00,
        0x00, 0x00, 0x08, 0x6e, 0x69, 0x73, 0x74, 0x70, 0x32, 0x35, 0x36, 0x00,
        0x00, 0x00, 0x41, 0x04, 0x55, 0xa1, 0xb5, 0x65, 0xde, 0xf5, 0x6a, 0xac,
        0xcb, 0xa9, 0x60, 0xd1, 0x49, 0xf8, 0x8c, 0x46, 0x42, 0x1c, 0xe2, 0x92,
        0x59, 0xe4, 0x5d, 0x85, 0xdf, 0xb9, 0x27, 0x84, 0xa2, 0x6a, 0x28, 0x83,
        0xe8, 0x49, 0xf6, 0x23, 0x78, 0xc9, 0x60, 0x71, 0x73, 0xc7, 0x78, 0xf5,
        0x83, 0x85, 0xdd, 0xcf, 0x74, 0x63, 0x0e, 0xbd, 0xcf, 0x78, 0x33, 0xeb,
        0x5e, 0xfa, 0xfe, 0x2f, 0xd8, 0x1c, 0x65, 0xbc
    ];
    let f = [
        0x04, 0x99, 0x2c, 0x48, 0xfd, 0xeb, 0x2d, 0x58, 0xdf, 0x37, 0xfd, 0x74,
        0xf0, 0x60, 0xe9, 0x9c, 0x73, 0x40, 0x42, 0x8f, 0x73, 0x28, 0x3f, 0x05,
        0x1a, 0x44, 0x6b, 0xdb, 0xb1, 0x87, 0x4c, 0xe8, 0xe8, 0x96, 0x4a, 0x36,
        0x98, 0x6e, 0x5e, 0x91, 0x87, 0xd3, 0x04, 0x86, 0x43, 0x83, 0x5f, 0x04,
        0xdd, 0x6e, 0x27, 0x22, 0x2b, 0x3f, 0xb8, 0x00, 0x82, 0x3f, 0x76, 0x0d,
        0xbd, 0x40, 0xc1, 0xd6, 0x2a
    ];
    let signature = [
        0x00, 0x00, 0x00, 0x13, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x73, 0x68,
        0x61, 0x32, 0x2d, 0x6e, 0x69, 0x73, 0x74, 0x70, 0x32, 0x35, 0x36, 0x00,
        0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x20, 0x0b, 0xca, 0x56, 0x33, 0xaf,
        0xe5, 0xd6, 0x72, 0xaf, 0x3f, 0x8c, 0x1a, 0x8c, 0x28, 0x50, 0x6d, 0x3f,
        0x5a, 0xa4, 0x55, 0xba, 0x80, 0x4d, 0x98, 0x16, 0x56, 0x9b, 0x6b, 0x1f,
        0x79, 0x21, 0xc8, 0x00, 0x00, 0x00, 0x20, 0x0c, 0xa5, 0x7a, 0xce, 0x69,
        0xcf, 0x38, 0x28, 0xb4, 0xb4, 0xf8, 0xf0, 0x4e, 0xa9, 0x67, 0x8f, 0xd2,
        0x62, 0x3c, 0x94, 0x63, 0x6f, 0x5d, 0x08, 0x25, 0xad, 0xfc, 0x2d, 0x95,
        0x25, 0x73, 0xbc
    ];
    let dh = SshPacket::DiffieHellmanReply(SshPacketDhReply { pubkey_and_cert: &pubkey, f: &f, signature: &signature });
    let padding: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let expected = IResult::Done(b"" as &[u8], (dh, padding));
    let res = parse_ssh_packet(SERVER_DH_REPLY);
    assert_eq!(res, expected);
}


#[test]
fn test_new_keys() {
    let keys = SshPacket::NewKeys;
    let padding: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let expected = IResult::Done(b"" as &[u8], (keys, padding));
    let res = parse_ssh_packet(&SERVER_NEW_KEYS);
    assert_eq!(res, expected);
}

#[test]
fn test_invalid_packet0() {
    let data = b"\x00\x00\x00\x00\x00\x00\x00\x00";
    let expected = IResult::Error(Err::Position(ErrorKind::Custom(128), &data[5..]));
    let res = parse_ssh_packet(data);
    assert_eq!(res, expected);
}

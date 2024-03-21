// Public API tests
extern crate ssh_parser;

use ssh_parser::*;

static CLIENT_KEY_EXCHANGE: &[u8] = include_bytes!("../assets/client_init.raw");
static SERVER_COMPAT: &[u8] = include_bytes!("../assets/server_compat.raw");

#[test]
fn test_identification() {
    let empty: Vec<&[u8]> = vec![];
    let version = SshVersion {
        proto: b"2.0",
        software: b"OpenSSH_7.3",
        comments: None,
    };

    let expected = Ok((b"" as &[u8], (empty, version)));
    let res = parse_ssh_identification(&CLIENT_KEY_EXCHANGE[..21]);
    assert_eq!(res, expected);
}

#[test]
fn test_compatibility() {
    let empty: Vec<&[u8]> = vec![];
    let version = SshVersion {
        proto: b"1.99",
        software: b"OpenSSH_3.1p1",
        comments: None,
    };

    let expected = Ok((b"" as &[u8], (empty, version)));
    let res = parse_ssh_identification(&SERVER_COMPAT[..23]);
    assert_eq!(res, expected);
}

#[test]
fn test_version_with_comments() {
    let empty: Vec<&[u8]> = vec![];
    let version = SshVersion {
        proto: b"2.0",
        software: b"OpenSSH_7.3",
        comments: Some(b"toto"),
    };
    let expected = Ok((b"" as &[u8], (empty, version)));
    let res = parse_ssh_identification(b"SSH-2.0-OpenSSH_7.3 toto\r\n");
    assert_eq!(res, expected);
}

#[test]
fn test_client_key_exchange() {
    let cookie = [
        0xca, 0x98, 0x42, 0x14, 0xd6, 0xa5, 0xa7, 0xfd, 0x6c, 0xe8, 0xd4, 0x7c, 0x0b, 0xc0, 0x96,
        0xcc,
    ];
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

    let expected = Ok((b"" as &[u8], (key_exchange, padding)));
    let res = parse_ssh_packet(&CLIENT_KEY_EXCHANGE[21..]);
    assert_eq!(res, expected);
}

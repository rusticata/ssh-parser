// Public API tests for KEX.
extern crate ssh_parser;

use ssh_parser::*;

fn load_client_server_key_exchange_init(
    client: &'static [u8],
    server: &'static [u8],
) -> (SshPacketKeyExchange<'static>, SshPacketKeyExchange<'static>) {
    let client = parse_ssh_packet(client).unwrap().1 .0;
    let server = parse_ssh_packet(server).unwrap().1 .0;
    assert!(matches!(
        (&client, &server),
        (SshPacket::KeyExchange(_), SshPacket::KeyExchange(_))
    ));
    match (client, server) {
        (SshPacket::KeyExchange(client), SshPacket::KeyExchange(server)) => (client, server),
        _ => unreachable!(),
    }
}

fn load_kex_packet(packet: &[u8]) -> SshPacketUnparsed<'_> {
    let kex_packet = parse_ssh_packet(packet).unwrap().1 .0;
    assert!(matches!(&kex_packet, SshPacket::DiffieHellmanKEX(_)));
    match kex_packet {
        SshPacket::DiffieHellmanKEX(kex) => kex.0,
        _ => unreachable!(),
    }
}

mod ecdh {
    use super::*;

    static CLIENT_KEY_EXCHANGE_INIT: &[u8] =
        include_bytes!("../assets/kex/ecdh/client_kex_init.raw");
    static SERVER_KEY_EXCHANGE_INIT: &[u8] =
        include_bytes!("../assets/kex/ecdh/server_kex_init.raw");
    static INIT: &[u8] = include_bytes!("../assets/kex/ecdh/init.raw");
    static REPLY: &[u8] = include_bytes!("../assets/kex/ecdh/reply.raw");

    #[test]
    fn test_kex() {
        let (client_kex, server_kex) = load_client_server_key_exchange_init(
            CLIENT_KEY_EXCHANGE_INIT,
            SERVER_KEY_EXCHANGE_INIT,
        );
        let (mut kex, negociated_alg) = SshKEX::init(&client_kex, &server_kex).unwrap();
        assert_eq!(negociated_alg, "curve25519-sha256");
        assert!(matches!(kex, SshKEX::ECDiffieHellman(_)));

        let init_packet = load_kex_packet(INIT);
        assert!(matches!(kex.parse_ssh_packet(&init_packet), Ok(())));
        assert!(matches!(
            kex.parse_ssh_packet(&init_packet),
            Err(SshKEXError::DuplicatedMessage)
        ));

        let reply_packet = load_kex_packet(REPLY);
        assert!(matches!(kex.parse_ssh_packet(&reply_packet), Ok(())));
        assert!(matches!(
            kex.parse_ssh_packet(&reply_packet),
            Err(SshKEXError::DuplicatedMessage)
        ));

        let kex = match kex {
            SshKEX::ECDiffieHellman(kex) => kex,
            _ => unreachable!(),
        };

        assert!(kex.init.is_some());
        assert!(kex.reply.is_some());
    }
}

mod dh {
    use super::*;

    static CLIENT_KEY_EXCHANGE_INIT: &[u8] = include_bytes!("../assets/kex/dh/client_kex_init.raw");
    static SERVER_KEY_EXCHANGE_INIT: &[u8] = include_bytes!("../assets/kex/dh/server_kex_init.raw");
    static INIT: &[u8] = include_bytes!("../assets/kex/dh/init.raw");
    static REPLY: &[u8] = include_bytes!("../assets/kex/dh/reply.raw");

    #[test]
    fn test_kex() {
        let (client_kex, server_kex) = load_client_server_key_exchange_init(
            CLIENT_KEY_EXCHANGE_INIT,
            SERVER_KEY_EXCHANGE_INIT,
        );
        let (mut kex, negociated_alg) = SshKEX::init(&client_kex, &server_kex).unwrap();
        assert_eq!(negociated_alg, "diffie-hellman-group18-sha512");
        assert!(matches!(kex, SshKEX::DiffieHellman(_)));

        let init_packet = load_kex_packet(INIT);
        assert!(matches!(kex.parse_ssh_packet(&init_packet), Ok(())));
        assert!(matches!(
            kex.parse_ssh_packet(&init_packet),
            Err(SshKEXError::DuplicatedMessage)
        ));

        let reply_packet = load_kex_packet(REPLY);
        assert!(matches!(kex.parse_ssh_packet(&reply_packet), Ok(())));
        assert!(matches!(
            kex.parse_ssh_packet(&reply_packet),
            Err(SshKEXError::DuplicatedMessage)
        ));

        let kex = match kex {
            SshKEX::DiffieHellman(kex) => kex,
            _ => unreachable!(),
        };

        assert!(kex.init.is_some());
        assert!(kex.reply.is_some());

        let ecdsa_signature = kex.reply.as_ref().unwrap().get_ecdsa_signature().unwrap();
        assert_eq!(ecdsa_signature.identifier, "ssh-ed25519");
    }
}

mod dh_kex_gex {
    use super::*;

    static CLIENT_KEY_EXCHANGE_INIT: &[u8] =
        include_bytes!("../assets/kex/dh-kex-gex/client_kex_init.raw");
    static SERVER_KEY_EXCHANGE_INIT: &[u8] =
        include_bytes!("../assets/kex/dh-kex-gex/server_kex_init.raw");
    static REQUEST: &[u8] = include_bytes!("../assets/kex/dh-kex-gex/request.raw");
    static GROUP: &[u8] = include_bytes!("../assets/kex/dh-kex-gex/group.raw");
    static INIT: &[u8] = include_bytes!("../assets/kex/dh-kex-gex/init.raw");
    static REPLY: &[u8] = include_bytes!("../assets/kex/dh-kex-gex/reply.raw");

    #[test]
    fn test_kex() {
        let (client_kex, server_kex) = load_client_server_key_exchange_init(
            CLIENT_KEY_EXCHANGE_INIT,
            SERVER_KEY_EXCHANGE_INIT,
        );
        let (mut kex, negociated_alg) = SshKEX::init(&client_kex, &server_kex).unwrap();
        assert_eq!(negociated_alg, "diffie-hellman-group-exchange-sha256");
        assert!(matches!(kex, SshKEX::DiffieHellmanKEXGEX(_)));

        let request_packet = load_kex_packet(REQUEST);
        assert!(matches!(kex.parse_ssh_packet(&request_packet), Ok(())));
        assert!(matches!(
            kex.parse_ssh_packet(&request_packet),
            Err(SshKEXError::DuplicatedMessage)
        ));

        let group_packet = load_kex_packet(GROUP);
        assert!(matches!(kex.parse_ssh_packet(&group_packet), Ok(())));
        assert!(matches!(
            kex.parse_ssh_packet(&group_packet),
            Err(SshKEXError::DuplicatedMessage)
        ));

        let init_packet = load_kex_packet(INIT);
        assert!(matches!(kex.parse_ssh_packet(&init_packet), Ok(())));
        assert!(matches!(
            kex.parse_ssh_packet(&init_packet),
            Err(SshKEXError::DuplicatedMessage)
        ));

        let reply_packet = load_kex_packet(REPLY);
        assert!(matches!(kex.parse_ssh_packet(&reply_packet), Ok(())));
        assert!(matches!(
            kex.parse_ssh_packet(&reply_packet),
            Err(SshKEXError::DuplicatedMessage)
        ));

        let kex = match kex {
            SshKEX::DiffieHellmanKEXGEX(kex) => kex,
            _ => unreachable!(),
        };

        assert!(kex.request.is_some());
        assert!(kex.group.is_some());
        assert!(kex.init.is_some());
        assert!(kex.reply.is_some());
    }
}

mod kex_hybrid_oqs {
    use std::fs;
    use std::path::Path;

    use super::*;

    /// Path to assets.
    const ASSETS_PATH: &str = "assets/kex/kex-hybrid";

    fn read_test_file(directory: &Path, filename: &str) -> &'static [u8] {
        let data = Box::new(fs::read(directory.join(filename)).unwrap());
        Box::leak(data)
    }

    /// Tests an hybrid algorithm with a directory containing its assets.
    fn test_alg_with_directory(directory: impl AsRef<Path>, expected_algorithm: impl AsRef<str>) {
        let directory = Path::new(ASSETS_PATH).join(directory);
        println!("dir={}", directory.display());
        let client_kex_init = read_test_file(&directory, "client_kex_init.raw");
        let server_kex_init = read_test_file(&directory, "server_kex_init.raw");

        let init_msg = fs::read(directory.join("init.raw")).unwrap();
        let reply_msg = fs::read(directory.join("reply.raw")).unwrap();

        let (client_kex, server_kex) =
            load_client_server_key_exchange_init(client_kex_init, server_kex_init);

        let (mut kex, negotiated_alg) = SshKEX::init(&client_kex, &server_kex).unwrap();
        assert_eq!(negotiated_alg, expected_algorithm.as_ref());
        assert!(matches!(kex, SshKEX::HybridKEX(_)));

        let init_packet = load_kex_packet(&init_msg);
        assert!(matches!(kex.parse_ssh_packet(&init_packet), Ok(())));
        assert!(matches!(
            kex.parse_ssh_packet(&init_packet),
            Err(SshKEXError::DuplicatedMessage)
        ));

        let reply_packet = load_kex_packet(&reply_msg);
        assert!(matches!(kex.parse_ssh_packet(&reply_packet), Ok(())));
        assert!(matches!(
            kex.parse_ssh_packet(&reply_packet),
            Err(SshKEXError::DuplicatedMessage)
        ));

        let kex = match kex {
            SshKEX::HybridKEX(kex) => kex,
            _ => unreachable!(),
        };

        assert!(kex.init.is_some());
        assert!(kex.reply.is_some());
    }

    #[test]
    fn ecdh_nistp256_kyber_512r3_sha256_d00_openquantumsafe_org_test() {
        test_alg_with_directory(
            "ecdh-nistp256-kyber-512r3-sha256-d00",
            "ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org",
        );
    }

    #[test]
    fn ecdh_nistp384_kyber_768r3_sha384_d00_openquantumsafe_org_test() {
        test_alg_with_directory(
            "ecdh-nistp384-kyber-768r3-sha384-d00",
            "ecdh-nistp384-kyber-768r3-sha384-d00@openquantumsafe.org",
        );
    }

    #[test]
    fn ecdh_nistp521_kyber_1024r3_sha512_d00_openquantumsafe_org_test() {
        test_alg_with_directory(
            "ecdh-nistp521-kyber-1024r3-sha512-d00",
            "ecdh-nistp521-kyber-1024r3-sha512-d00@openquantumsafe.org",
        );
    }
}

mod kex_algorithm_negociation {
    use super::ssh_kex_negociate_algorithm;

    #[test]
    fn test_negociation() {
        assert_eq!(
            ssh_kex_negociate_algorithm(["a", "b", "c"], ["a", "b", "c"]),
            Some("a")
        );
        assert_eq!(
            ssh_kex_negociate_algorithm(["a", "b", "c"], ["b", "a", "c"]),
            Some("a")
        );
        assert_eq!(
            ssh_kex_negociate_algorithm(["a", "b", "c"], ["b", "d", "c"]),
            Some("b")
        );
        assert_eq!(
            ssh_kex_negociate_algorithm(["a", "b", "c"], ["d", "c", "e"]),
            Some("c")
        );
        assert_eq!(
            ssh_kex_negociate_algorithm(["a", "b", "c"], ["c", "b", "a"]),
            Some("a")
        );
        assert_eq!(
            ssh_kex_negociate_algorithm(["a", "b", "c"], ["d", "e", "f"]),
            None
        );
    }
}

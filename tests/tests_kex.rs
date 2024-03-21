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

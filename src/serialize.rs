use super::{SshPacket, SshPacketDebug, SshPacketDisconnect, SshPacketKeyExchange};
use cookie_factory::gen::{set_be_u32, set_be_u8};
use cookie_factory::*;
use std::iter::repeat;

fn gen_string<'a>(x: (&'a mut [u8], usize), s: &[u8]) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(x, gen_be_u32!(s.len() as u32) >> gen_slice!(s))
}

fn gen_packet_key_exchange<'a>(
    x: (&'a mut [u8], usize),
    p: &SshPacketKeyExchange,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        x,
        gen_copy!(p.cookie, 16)
            >> gen_string(p.kex_algs)
            >> gen_string(p.server_host_key_algs)
            >> gen_string(p.encr_algs_client_to_server)
            >> gen_string(p.encr_algs_server_to_client)
            >> gen_string(p.mac_algs_client_to_server)
            >> gen_string(p.mac_algs_server_to_client)
            >> gen_string(p.comp_algs_client_to_server)
            >> gen_string(p.comp_algs_server_to_client)
            >> gen_string(p.langs_client_to_server)
            >> gen_string(p.langs_server_to_client)
            >> gen_be_u8!(if p.first_kex_packet_follows { 1 } else { 0 })
            >> gen_be_u32!(0)
    )
}

fn gen_packet_disconnect<'a>(
    x: (&'a mut [u8], usize),
    p: &SshPacketDisconnect,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        x,
        gen_be_u32!(p.reason_code) >> gen_string(p.description) >> gen_string(p.lang)
    )
}

fn gen_packet_debug<'a>(
    x: (&'a mut [u8], usize),
    p: &SshPacketDebug,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        x,
        gen_be_u8!(if p.always_display { 1 } else { 0 })
            >> gen_string(p.message)
            >> gen_string(p.lang)
    )
}

fn packet_payload_type(p: &SshPacket) -> u8 {
    match *p {
        SshPacket::Disconnect(_) => 1,
        SshPacket::Ignore(_) => 2,
        SshPacket::Unimplemented(_) => 3,
        SshPacket::Debug(_) => 4,
        SshPacket::ServiceRequest(_) => 5,
        SshPacket::ServiceAccept(_) => 6,
        SshPacket::KeyExchange(_) => 20,
        SshPacket::NewKeys => 21,
        SshPacket::DiffieHellmanKEX(ref p) => p.0.message_code,
    }
}

fn gen_packet_payload<'a>(
    x: (&'a mut [u8], usize),
    p: &SshPacket,
) -> Result<(&'a mut [u8], usize), GenError> {
    match *p {
        SshPacket::Disconnect(ref p) => gen_packet_disconnect(x, p),
        SshPacket::Ignore(p) => gen_string(x, p),
        SshPacket::Unimplemented(n) => set_be_u32(x, n),
        SshPacket::Debug(ref p) => gen_packet_debug(x, p),
        SshPacket::ServiceRequest(p) => gen_string(x, p),
        SshPacket::ServiceAccept(p) => gen_string(x, p),
        SshPacket::KeyExchange(ref p) => gen_packet_key_exchange(x, p),
        SshPacket::NewKeys => Ok(x),
        SshPacket::DiffieHellmanKEX(ref p) => gen_string(x, p.0.payload),
    }
}

fn padding_len(payload: usize) -> usize {
    let len = 8 - (payload % 8);

    if len < 4 {
        len + 8
    } else {
        len
    }
}

/// Serialize an SSH packet from its intermediate representation.
pub fn gen_ssh_packet<'a>(
    x: (&'a mut [u8], usize),
    p: &SshPacket,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        x,
        len: gen_skip!(4)
            >> padlen: gen_skip!(1)
            >> gen_be_u8!(packet_payload_type(p))
            >> gen_packet_payload(p)
            >> pad: gen_many!(repeat(0).take(padding_len(pad - len)), set_be_u8)
            >> end: gen_at_offset!(padlen, gen_be_u8!((end - pad) as u8))
            >> gen_at_offset!(len, gen_be_u32!((end - padlen) as u32))
    )
}

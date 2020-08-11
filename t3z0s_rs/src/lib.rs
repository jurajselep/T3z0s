extern crate libc;

use libc::{c_char, c_int, c_uint, c_void};
use std::{
    boxed::Box,
    collections::HashMap,
    convert::TryFrom,
    ffi::CString,
    net::IpAddr,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    option::Option,
};

use failure::Error;

use crypto::{
    crypto_box::precompute,
    hash::HashType,
    nonce::{generate_nonces, NoncePair},
};
use std::fmt;
use tezos_messages::p2p::binary_message::{cache::CachedData, BinaryChunk};

mod network;
use network::{
    connection_message::ConnectionMessage,
    msg_decoder::{EncryptedMessage, EncryptedMessageDecoder},
    raw_packet_msg::{RawMessageDirection, RawPacketMessage},
};

mod dissector;
use dissector::configuration::{get_configuration, Config};
use dissector::conversation::Conversation;
use dissector::dissector_info::T3zosDissectorInfo;
use dissector::error::{
    NotT3z0sStreamError, PeerNotUpgradedError, T3z0sNodeIdentityNotLoadedError,
    UnknownDecrypterError,
};
use dissector::logger::msg;

mod wireshark;
use wireshark::packet::packet_info;
use wireshark::{get_data, proto_tree, proto_tree_add_string, tcp_analysis, tvbuff_t};

pub(crate) fn get_ref<'a, T>(p: *const T) -> &'a T {
    unsafe { &*p }
}

#[no_mangle]
pub extern "C" fn t3z03s_free_conv_data(p_data: *mut c_void) {
    Conversation::remove(p_data as *const tcp_analysis);
}

#[no_mangle]
pub extern "C" fn t3z03s_dissect_packet(
    p_info: *const T3zosDissectorInfo,
    tvb: *mut tvbuff_t,
    proto_tree: *mut proto_tree,
    p_pinfo: *const packet_info,
    tcpd: *const tcp_analysis,
) -> c_int {
    let info = get_ref(p_info);
    let pinfo = get_ref(p_pinfo);

    let conv = Conversation::get_or_create(tcpd);

    match conv.process_packet(info, pinfo, tvb, proto_tree, tcpd) {
        Err(e) => {
            msg(format!("E: Cannot process packet: {}", e));
            proto_tree_add_string(proto_tree, info.hf_error, tvb, 0, 0, format!("{}", e));
            0 as c_int
        }
        Ok(size) => size as c_int,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

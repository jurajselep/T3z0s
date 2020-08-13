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
    NotTezosStreamError, PeerNotUpgradedError, TezosNodeIdentityNotLoadedError,
    UnknownDecrypterError,
};
use dissector::logger::msg;

mod wireshark;
use wireshark::packet::packet_info;
use wireshark::{get_data, proto_tree, proto_tree_add_string, tcp_analysis, tvbuff_t};

/// Convert a C pointer into a Rust reference
pub(crate) fn get_ref<'a, T>(p: *const T) -> &'a T {
    unsafe { &*p }
}

#[no_mangle]
/// This function is called on C side when data related to some Tezos connection
/// (== Conversation from Wireshark point of view) needs to be releases.
pub extern "C" fn t3z03s_free_conv_data(p_data: *mut c_void) {
    Conversation::remove(p_data as *const tcp_analysis);
}

#[no_mangle]
/// Entry point that is called on C side when one frame needs to be dissected
pub extern "C" fn t3z03s_dissect_packet(
    p_dissector_info: *const T3zosDissectorInfo,
    tvb: *mut tvbuff_t, // Wireshark packet buffer, `tvb` is a name used within Wireshark
    proto_tree: *mut proto_tree,
    p_packet_info: *const packet_info,
    tcpd: *const tcp_analysis, // Data from TCP dissector, `tcpd` is a name used within Wireshark
) -> c_int {
    let dissector_info = get_ref(p_dissector_info);
    let packet_info = get_ref(p_packet_info);

    // Obtain a conversation for this TCP connection
    let conversation = Conversation::get_or_create(tcpd);

    // Process one concrete packet from the TCP connection.
    // Conversation stores all data necessary to decrypt Tezos connection
    // and it also caches intermediate results for case when packets are exposed
    // in order that is different from their appearance within TCP stream.
    match conversation.process_packet(dissector_info, packet_info, tvb, proto_tree, tcpd) {
        Err(e) => {
            msg(format!("E: Cannot process packet: {}", e));
            proto_tree_add_string(
                proto_tree,
                dissector_info.hf_error,
                tvb,
                0,
                0,
                format!("{}", e),
            );
            0 as c_int
        }
        Ok(size) => size as c_int,
    }
}

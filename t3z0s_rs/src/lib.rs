extern crate libc;

use libc::{c_char, c_int, c_uint, c_void};
use std::{
    boxed::Box,
    collections::HashMap,
    ffi::CString,
    net::IpAddr,
    option::Option,
    net::{SocketAddr, SocketAddrV4, Ipv4Addr},
    convert::TryFrom,
};

use failure::Error;

use crypto::{
    hash::HashType,
    crypto_box::precompute,
    nonce::{NoncePair, generate_nonces},
};
use tezos_messages::p2p::{
    binary_message::{
        BinaryChunk,
        cache::CachedData,
    }
};
use std::fmt;

// TODO: DRF: Move ConnectionMessage from tezedge-debugger to some library or turn tezedge-debugger to a mod?
//mod connection_message;
//use connection_message::ConnectionMessage;
mod network;
use network::{
    connection_message::ConnectionMessage,
    msg_decoder::{EncryptedMessage, EncryptedMessageDecoder},
    raw_packet_msg::{RawPacketMessage, RawMessageDirection},
};

mod logger;
use logger::msg;

mod wireshark;
use wireshark::packet::packet_info;
use wireshark::ws::{
    tvbuff_t,
    tcp_analysis,
    proto_tree,
    get_data_safe,
    proto_tree_add_string_safe,
};

mod error;
use error::{NotT3z0sStreamError, T3z0sNodeIdentityNotLoadedError, UnknownDecrypterError, PeerNotUpgradedError};

mod configuration;
use configuration::{get_configuration, Config};

mod conversation;
use conversation::Conversation;

mod dissector_info;
use dissector_info::T3zosDissectorInfo;

pub(crate) fn get_ref<'a, T>(p: *const T) ->&'a T {
    unsafe {&*p}
}

#[no_mangle]
pub extern "C" fn t3z03s_free_conv_data(p_data: *mut c_void) {
    Conversation::remove(p_data as *const tcp_analysis);
}

#[no_mangle]
pub extern "C" fn t3z03s_dissect_packet(
        p_info: *const T3zosDissectorInfo,
        tvb: *mut tvbuff_t, proto_tree: *mut proto_tree,
        p_pinfo: *const packet_info, tcpd: *const tcp_analysis
) -> c_int {
    let info = get_ref(p_info);
    let pinfo = get_ref(p_pinfo);

    let conv = Conversation::get_or_create(tcpd);

    match conv.process_packet(info, pinfo, tvb, proto_tree, tcpd) {
        Err(e) => {
            msg(format!("E: Cannot process packet: {}", e));
        proto_tree_add_string_safe(proto_tree, info.hf_error, tvb, 0, 0, format!("{}", e));
            0 as c_int
        },
        Ok(size) => size as c_int
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

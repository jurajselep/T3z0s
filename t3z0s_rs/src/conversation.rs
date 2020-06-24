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
use crate::network::{
    connection_message::ConnectionMessage,
    msg_decoder::{EncryptedMessage, EncryptedMessageDecoder},
    raw_packet_msg::{RawPacketMessage, RawMessageDirection},
};

use crate::logger::msg;

use crate::wireshark::packet::packet_info;
use crate::wireshark::ws::{
    tvbuff_t,
    tcp_analysis,
    proto_tree,
    get_data_safe,
    proto_tree_add_string_safe,
};

use crate::error::{NotT3z0sStreamError, T3z0sNodeIdentityNotLoadedError, UnknownDecrypterError, PeerNotUpgradedError};

use crate::configuration::{get_configuration, Config};

use crate::dissector_info::T3zosDissectorInfo;
use crate::get_ref;

type ConversationKey = u64;

#[derive(Debug, Clone)]
struct ConversationItem {
    counter: u64,
    srcaddr: Option<SocketAddr>,
    dstaddr: Option<SocketAddr>,
    conn_msg: Option<String>,
    decrypted_msg: Option<String>,
    direction: Option<RawMessageDirection>,
    dbg: String,
}

// Data stored for every T3z0s stream
pub(crate) struct Conversation {
    counter: u64,
    /* *** PeerProcessor from Tezedge-Debugger *** */
    // addr: SocketAddr,
    conn_msgs: Vec<(ConnectionMessage, SocketAddr)>,
    is_initialized: bool,
    is_incoming: bool,
    is_dead: bool,
    waiting: bool,
    //handshake: u8,
    peer_id: String,
    public_key: Vec<u8>,
    incoming_decrypter: Option<EncryptedMessageDecoder>,
    outgoing_decrypter: Option<EncryptedMessageDecoder>,
    frames: HashMap<ConversationKey, Result<ConversationItem, Error>>,
}
impl Conversation {
    pub fn new() -> Self {
        Conversation {
            counter: 0,
            /* PeerProcessor */
            conn_msgs: Vec::<(ConnectionMessage, SocketAddr)>::with_capacity(2),
            is_initialized: false,
            is_incoming: false,
            is_dead: false,
            waiting: false,
            peer_id: Default::default(),
            public_key: Default::default(),
            incoming_decrypter: None,
            outgoing_decrypter: None,
            frames: HashMap::new(),
        }
    }

    fn is_ok(&self) -> bool {
        match self.counter {
            0 => true,
            1 => self.conn_msgs.len() == 1,
            _ => self.conn_msgs.len() == 2,
        }
    }

    fn local_addr(&self) -> SocketAddr {
        assert!(self.conn_msgs.len() == 2);

        if self.is_incoming {
            self.conn_msgs[1].1
        } else {
            self.conn_msgs[0].1
        }
    }

    /*
    fn remote_addr(&self) -> SocketAddr {
        assert!(self.conn_msgs.len() == 2);

        if self.is_incoming {
            self.conn_msgs[0].1
        } else {
            self.conn_msgs[1].1
        }
    }

    fn local_conn_msg(&self) -> &ConnectionMessage {
        assert!(self.conn_msgs.len() == 2);

        if self.is_incoming {
            &self.conn_msgs[1].0
        } else {
            &self.conn_msgs[0].0
        }
    }

    fn remote_conn_msg(&self) -> &ConnectionMessage {
        assert!(self.conn_msgs.len() == 2);

        if self.is_incoming {
            &self.conn_msgs[0].0
        } else {
            &self.conn_msgs[1].0
        }
    }
    */

    fn inc_counter(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    pub fn process_connection_msg(payload: Vec<u8>) -> Result<ConnectionMessage, Error> {
        let chunk = BinaryChunk::try_from(payload)?;
        let conn_msg = ConnectionMessage::try_from(chunk)?;
        Ok(conn_msg)
    }

    fn upgrade(&mut self, configuration: &Config) -> Result<(), Error> {
        let ((first, _), (second, _)) = (&self.conn_msgs[0], &self.conn_msgs[1]);
        let first_pk = HashType::CryptoboxPublicKeyHash.bytes_to_string(&first.public_key);
        // FIXME: DRF: Use the same deserialization as in debugger.
        msg(format!("keys: first:{}; {:?}; second:{}; {:?}; configuration:{}; {}; secret-key:{}",
            HashType::CryptoboxPublicKeyHash.bytes_to_string(&first.public_key),
            first.public_key,
            HashType::CryptoboxPublicKeyHash.bytes_to_string(&second.public_key),
            second.public_key,
            HashType::CryptoboxPublicKeyHash.bytes_to_string(configuration.identity.public_key.as_bytes()),
            configuration.identity.public_key,
            configuration.identity.secret_key));
        let is_incoming = first_pk != configuration.identity.public_key;
        msg(format!("upgrade pks cmp: {} != {}", first_pk, configuration.identity.public_key));
        // FIXME: Kyras: Otocil jsem to, zda se mi, ze takto je spravne, v Debugerru je to naopak.
        let (received, sent) = if is_incoming {
            (first, second)
        } else {
            (second, first)
        };

        let sent_data = BinaryChunk::from_content(&sent.cache_reader().get().unwrap())?;
        let recv_data = BinaryChunk::from_content(&received.cache_reader().get().unwrap())?;
        msg(format!("sent_data:{:?}; recv_data:{:?}", sent_data.raw(), recv_data.raw()));

        let NoncePair { remote, local } = generate_nonces(
            &sent_data.raw(),
            &recv_data.raw(),
            is_incoming,
        );
        msg(format!("noncences: {:?};{:?}", remote, local));

        let remote_pk = HashType::CryptoboxPublicKeyHash.bytes_to_string(&received.public_key);
        msg(format!("remote_pk:{:?}", remote_pk));

        let precomputed_key = precompute(
            &hex::encode(&received.public_key),
            &configuration.identity.secret_key,
        )?;
        msg(format!("precomputed-key: received.public_key:{:?}; configuration.identity.secret_key:{:?}",
            &hex::encode(&received.public_key),
            &configuration.identity.secret_key));

        self.incoming_decrypter = Some(EncryptedMessageDecoder::new(precomputed_key.clone(), remote, remote_pk.clone()));
        self.outgoing_decrypter = Some(EncryptedMessageDecoder::new(precomputed_key, local, remote_pk.clone()));
        self.public_key = received.public_key.clone();
        self.peer_id = remote_pk;
        self.is_incoming = is_incoming;
        self.is_initialized = true;
        Ok(())
    }

    fn process_encrypted_msg(&mut self, msg: &mut RawPacketMessage) -> Result<Option<EncryptedMessage>, Error> {
        let decrypter = if msg.is_incoming() {
            &mut self.incoming_decrypter
        } else {
            &mut self.outgoing_decrypter
        };

        if let Some(ref mut decrypter) = decrypter {
            Ok(decrypter.recv_msg(msg))
        } else {
            Err(UnknownDecrypterError)?
        }
    }

    fn process_unvisited_packet(
        self: &mut Self,
        info: &T3zosDissectorInfo, pinfo: &packet_info,
        tvb: *mut tvbuff_t, proto_tree: *mut proto_tree,
        tcpd: *const tcp_analysis
    ) -> Result<ConversationItem, Error> {
        if !self.is_ok() { Err(NotT3z0sStreamError)?; }

        let counter = self.inc_counter();
        let mut dbg_direction = None;
        let mut dbg_srcaddr = None;
        let mut dbg_dstaddr = None;
        let payload = get_data_safe(tvb);
        if counter <= 2 {
            assert!(counter >= 1);
            let conn_msg = Conversation::process_connection_msg(payload.to_vec())?;
           // proto_tree_add_string_safe(proto_tree, info.hf_connection_msg, tvb, 0, 0, format!("{:?};", conn_msg));

            let ip_addr = IpAddr::try_from(pinfo.src)?;
            let sock_addr = SocketAddr::new(ip_addr, pinfo.srcport as u16);
            // FIXME: Can duplicate message happen? We use TCP stream, not raw packets stream.
            self.conn_msgs.push((conn_msg.clone(), sock_addr));
            if self.conn_msgs.len() == 2 {
                let configuration = get_configuration().ok_or(T3z0sNodeIdentityNotLoadedError)?;
                self.upgrade(&configuration)?;
                msg(format!("Upgraded peer! {}", self))
            }
Ok(ConversationItem {
    counter: counter,
    srcaddr: None,
    dstaddr: None,
    conn_msg: Some(format!("{:?};", conn_msg)),
    decrypted_msg: None,
    direction: None,
    dbg: format!("Self {}", self),
})
        } else {
            let srcaddr = SocketAddr::new(IpAddr::try_from(pinfo.src)?, pinfo.srcport as u16);
            dbg_srcaddr = Some(srcaddr);
            dbg_dstaddr = Some(SocketAddr::new(IpAddr::try_from(pinfo.dst)?, pinfo.destport as u16));
            if self.is_initialized {
                msg(format!("local-addr:{}", self.local_addr()));
                let direction = if self.local_addr() == srcaddr {
                    RawMessageDirection::OUTGOING
                } else {
                    RawMessageDirection::INCOMING
                };
                dbg_direction = Some(direction);

                let mut raw = RawPacketMessage::new(
                    direction, payload
                );

                let decrypted_msg = self.process_encrypted_msg(&mut raw)?;
                msg(format!("decrypted-msg: {:?}; src-addr:{:?}; dst-addr:{:?}; counter:{};", decrypted_msg, dbg_srcaddr, dbg_dstaddr, counter));
                //proto_tree_add_string_safe(proto_tree, info.hf_decrypted_msg, tvb, 0, 0, format!("{:?};", decrypted_msg));
Ok(
ConversationItem {
    counter: counter,
    srcaddr: dbg_srcaddr,
    dstaddr: dbg_dstaddr,
    conn_msg: None,
    decrypted_msg: Some(format!("{:?};", decrypted_msg)),
    direction: dbg_direction,
    dbg: format!("Self {}", self),
})
            } else {
                Err(PeerNotUpgradedError)?
            }
        }
    }

    pub fn process_packet(
        self: &mut Self,
        info: &T3zosDissectorInfo, pinfo: &packet_info,
        tvb: *mut tvbuff_t, proto_tree: *mut proto_tree,
        tcpd: *const tcp_analysis
    ) -> Result<usize, Error> {

        let is_visited = get_ref(pinfo.fd).visited() != 0;
        let frame_num = get_ref(pinfo.fd).num as u64;

        if !is_visited {
            let res = self.process_unvisited_packet(info, pinfo, tvb, proto_tree, tcpd);
            self.frames.insert(frame_num, res);
        }

        let res_item = self.frames.get(&frame_num).unwrap();
        let item = match res_item {
            Err(ref e) => {
                msg(format!("E: Cannot process packet: {}", e));
                proto_tree_add_string_safe(proto_tree, info.hf_error, tvb, 0, 0, format!("{}", e));
            },
            Ok(item) => {
                proto_tree_add_string_safe(proto_tree, info.hf_debug, tvb, 0, 0, format!("count:{:?}", item.counter));
                proto_tree_add_string_safe(proto_tree, info.hf_debug, tvb, 0, 0, format!("direction:{:?}", item.direction));
                proto_tree_add_string_safe(proto_tree, info.hf_debug, tvb, 0, 0, format!("srcaddr:{:?}", item.srcaddr));
                proto_tree_add_string_safe(proto_tree, info.hf_debug, tvb, 0, 0, format!("dstaddr:{:?}", item.dstaddr));
                proto_tree_add_string_safe(proto_tree, info.hf_debug, tvb, 0, 0, format!("dbg:{}", item.dbg));
                proto_tree_add_string_safe(proto_tree, info.hf_connection_msg, tvb, 0, 0, format!("{:?}", item.conn_msg));
                proto_tree_add_string_safe(proto_tree, info.hf_decrypted_msg, tvb, 0, 0, format!("{:?}", item.decrypted_msg));
            }
        };
        //msg(format!("Conversation: {}; direction:{:?}; src-addr:{:?}; dst-addr:{:?};", self, dbg_direction, dbg_srcaddr, dbg_dstaddr));
        //proto_tree_add_string_safe(proto_tree, info.hf_debug, tvb, 0, 0, format!("payload: {}; {:?};", payload.len(), payload));

        let payload = get_data_safe(tvb);
        Ok(payload.len())
    }


    pub fn get_or_create<'a>(key: *const tcp_analysis) -> &'a mut Self {
        get_conv(key)
    }

    pub fn remove<'a>(key: *const tcp_analysis) {
        get_conv_map().remove(&key);
    }
}
impl fmt::Display for Conversation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "counter:{}; is_initialised:{}; is_incoming:{}; is_dead:{}; conn_msgs:{:?};", self.counter, self.is_initialized, self.is_incoming, self.is_dead,  self.conn_msgs)
    }
}

static mut conversations_map: Option<HashMap<*const tcp_analysis, Conversation>> = None;

fn get_conv_map() -> &'static mut HashMap<*const tcp_analysis, Conversation> {
    unsafe { conversations_map.get_or_insert(HashMap::new()) }
}

fn get_conv<'a>(key: *const tcp_analysis) -> &'a mut Conversation {
    get_conv_map().entry(key).or_insert_with(|| Conversation::new())
}

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

use crate::network::{
    connection_message::ConnectionMessage,
    msg_decoder::{EncryptedMessage, EncryptedMessageDecoder},
    raw_packet_msg::{RawMessageDirection, RawPacketMessage},
};

use crate::wireshark::packet::packet_info;
use crate::wireshark::{get_data, proto_tree, proto_tree_add_string, tcp_analysis, tvbuff_t};

use crate::dissector::configuration::{get_configuration, Config};
use crate::dissector::dissector_info::T3zosDissectorInfo;
use crate::dissector::error::{
    NotT3z0sStreamError, PeerNotUpgradedError, T3z0sNodeIdentityNotLoadedError,
    UnknownDecrypterError,
};
use crate::dissector::logger::msg;
use crate::get_ref;

type ConversationKey = u64;

#[derive(Debug, Clone)]
enum ConversationItem {
    Nothing,
    ConnMsg {
        counter: u64,
        msg: ConnectionMessage,
    },
    DecryptedMsg {
        counter: u64,
        msg: String,
    },
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
        msg(format!(
            "keys: first:{}; {:?}; second:{}; {:?}; configuration:{}; {}; secret-key:{}",
            HashType::CryptoboxPublicKeyHash.bytes_to_string(&first.public_key),
            first.public_key,
            HashType::CryptoboxPublicKeyHash.bytes_to_string(&second.public_key),
            second.public_key,
            HashType::CryptoboxPublicKeyHash
                .bytes_to_string(configuration.identity.public_key.as_bytes()),
            configuration.identity.public_key,
            configuration.identity.secret_key
        ));
        let is_incoming = first_pk != configuration.identity.public_key;
        msg(format!(
            "upgrade pks cmp: {} != {}",
            first_pk, configuration.identity.public_key
        ));
        let (received, sent) = if is_incoming {
            (first, second)
        } else {
            (second, first)
        };

        let sent_data = BinaryChunk::from_content(&sent.cache_reader().get().unwrap())?;
        let recv_data = BinaryChunk::from_content(&received.cache_reader().get().unwrap())?;
        msg(format!(
            "sent_data:{:?}; recv_data:{:?}",
            sent_data.raw(),
            recv_data.raw()
        ));

        let NoncePair { remote, local } =
            generate_nonces(&sent_data.raw(), &recv_data.raw(), is_incoming);
        msg(format!("noncences: {:?};{:?}", remote, local));

        let remote_pk = HashType::CryptoboxPublicKeyHash.bytes_to_string(&received.public_key);
        msg(format!("remote_pk:{:?}", remote_pk));

        let precomputed_key = precompute(
            &hex::encode(&received.public_key),
            &configuration.identity.secret_key,
        )?;
        msg(format!(
            "precomputed-key: received.public_key:{:?}; configuration.identity.secret_key:{:?}",
            &hex::encode(&received.public_key),
            &configuration.identity.secret_key
        ));

        self.incoming_decrypter = Some(EncryptedMessageDecoder::new(
            precomputed_key.clone(),
            remote,
            remote_pk.clone(),
        ));
        self.outgoing_decrypter = Some(EncryptedMessageDecoder::new(
            precomputed_key,
            local,
            remote_pk.clone(),
        ));
        self.public_key = received.public_key.clone();
        self.peer_id = remote_pk;
        self.is_incoming = is_incoming;
        self.is_initialized = true;
        Ok(())
    }

    fn process_encrypted_msg(
        &mut self,
        msg: &mut RawPacketMessage,
    ) -> Result<Option<EncryptedMessage>, Error> {
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
        info: &T3zosDissectorInfo,
        pinfo: &packet_info,
        tvb: *mut tvbuff_t,
        proto_tree: *mut proto_tree,
        tcpd: *const tcp_analysis,
        srcaddr: &SocketAddr,
        dstaddr: &SocketAddr,
    ) -> Result<ConversationItem, Error> {
        if !self.is_ok() {
            Err(NotT3z0sStreamError)?;
        }

        let counter = self.inc_counter();
        let payload = get_data(tvb);
        if counter <= 2 {
            assert!(counter >= 1);
            let conn_msg = Conversation::process_connection_msg(payload.to_vec())?;

            let ip_addr = IpAddr::try_from(pinfo.src)?;
            let sock_addr = SocketAddr::new(ip_addr, pinfo.srcport as u16);
            // NOTE: Duplicate message should not happen? We use TCP stream, not raw packets stream.
            self.conn_msgs.push((conn_msg.clone(), sock_addr));
            if self.conn_msgs.len() == 2 {
                let configuration = get_configuration().ok_or(T3z0sNodeIdentityNotLoadedError)?;
                self.upgrade(&configuration)?;
                msg(format!("Upgraded peer! {}", self))
            }
            Ok(ConversationItem::ConnMsg {
                counter: counter,
                msg: conn_msg,
            })
        } else {
            if self.is_initialized {
                msg(format!("local-addr:{}", self.local_addr()));
                let direction = if self.local_addr() == *srcaddr {
                    RawMessageDirection::OUTGOING
                } else {
                    RawMessageDirection::INCOMING
                };

                let mut raw = RawPacketMessage::new(direction, payload);

                let decrypted_msg = self.process_encrypted_msg(&mut raw)?;
                msg(format!(
                    "decrypted-msg: {:?}; src-addr:{:?}; dst-addr:{:?}; counter:{};",
                    decrypted_msg, srcaddr, dstaddr, counter
                ));
                Ok(decrypted_msg.map_or(ConversationItem::Nothing, |m| {
                    ConversationItem::DecryptedMsg {
                        counter: counter,
                        msg: format!("{:?}", m),
                    }
                }))
            } else {
                Err(PeerNotUpgradedError)?
            }
        }
    }

    pub fn process_packet(
        self: &mut Self,
        info: &T3zosDissectorInfo,
        pinfo: &packet_info,
        tvb: *mut tvbuff_t,
        proto_tree: *mut proto_tree,
        tcpd: *const tcp_analysis,
    ) -> Result<usize, Error> {
        let is_visited = get_ref(pinfo.fd).visited() != 0;
        let frame_num = get_ref(pinfo.fd).num as u64;

        let srcaddr = SocketAddr::new(IpAddr::try_from(pinfo.src)?, pinfo.srcport as u16);
        let dstaddr = SocketAddr::new(IpAddr::try_from(pinfo.dst)?, pinfo.destport as u16);

        if !is_visited {
            let res = self
                .process_unvisited_packet(info, pinfo, tvb, proto_tree, tcpd, &srcaddr, &dstaddr);
            self.frames.insert(frame_num, res);
        }

        proto_tree_add_string(
            proto_tree,
            info.hf_debug,
            tvb,
            0,
            0,
            format!("srcaddr:{:?}", srcaddr),
        );
        proto_tree_add_string(
            proto_tree,
            info.hf_debug,
            tvb,
            0,
            0,
            format!("dstaddr:{:?}", dstaddr),
        );

        let res_item = self.frames.get(&frame_num).unwrap();
        let item = match res_item {
            Err(ref e) => {
                proto_tree_add_string(proto_tree, info.hf_error, tvb, 0, 0, format!("{}", e));
            }
            Ok(ref item) => match item {
                ConversationItem::Nothing => {
                    proto_tree_add_string(
                        proto_tree,
                        info.hf_debug,
                        tvb,
                        0,
                        0,
                        format!("No message"),
                    );
                }
                ConversationItem::ConnMsg { counter, ref msg } => {
                    proto_tree_add_string(
                        proto_tree,
                        info.hf_debug,
                        tvb,
                        0,
                        0,
                        format!("counter:{:?}", counter),
                    );
                    proto_tree_add_string(
                        proto_tree,
                        info.hf_connection_msg,
                        tvb,
                        0,
                        0,
                        format!("{:?}", msg),
                    );
                }
                ConversationItem::DecryptedMsg { counter, ref msg } => {
                    proto_tree_add_string(
                        proto_tree,
                        info.hf_debug,
                        tvb,
                        0,
                        0,
                        format!("counter:{:?}", counter),
                    );
                    proto_tree_add_string(
                        proto_tree,
                        info.hf_decrypted_msg,
                        tvb,
                        0,
                        0,
                        format!("{:?}", msg),
                    );
                }
            },
        };

        let payload = get_data(tvb);
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
        write!(
            f,
            "counter:{}; is_initialised:{}; is_incoming:{}; is_dead:{}; conn_msgs:{:?};",
            self.counter, self.is_initialized, self.is_incoming, self.is_dead, self.conn_msgs
        )
    }
}

static mut CONVERSATIONS_MAP: Option<HashMap<*const tcp_analysis, Conversation>> = None;

fn get_conv_map() -> &'static mut HashMap<*const tcp_analysis, Conversation> {
    unsafe { CONVERSATIONS_MAP.get_or_insert(HashMap::new()) }
}

fn get_conv<'a>(key: *const tcp_analysis) -> &'a mut Conversation {
    get_conv_map()
        .entry(key)
        .or_insert_with(|| Conversation::new())
}

extern crate regex;

mod errors;
use errors::{
    CannotFindMessagesError
};

use failure::Error;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::default::Default;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddr::V4, SocketAddr::V6, SocketAddrV4};
use std::option::Option;
use std::path::Path;
use std::result::Result;
use std::vec::Vec;

#[derive(Debug, Clone)]
struct ConnectionFromRpc {
    peer_id: String,
    addr: SocketAddr,
}

#[derive(Debug, Clone)]
struct ConnectionMsg {
    conversation: String,
    msg: String,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
}

#[derive(Debug, Clone)]
struct DecryptedMsg {
    conversation: String,
    msg: String,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
}

#[derive(Debug, Clone, Default)]
struct TsharkData {
    connection_msgs: Vec<ConnectionMsg>,
    decrypted_msgs: Vec<DecryptedMsg>,
}

fn unify_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        V4(_) => addr,
        V6(ref a) => {
            if let Some(a4) = a.ip().to_ipv4() {
                V4(SocketAddrV4::new(a4, a.port()))
            } else {
                addr
            }
        }
    }
}

fn parse_json(file_path: &str) -> Result<Value, Error> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(file_path)?)?;
    return Ok(v);
}

fn process_connections(file_path: &str) -> Result<HashMap<String, ConnectionFromRpc>, Error> {
    let mut m = HashMap::new();

    let res = parse_json(file_path);
    res.map(|r| {
        r.as_array().map(|arr| {
            for v in arr {
                let conn_opt = || -> Option<ConnectionFromRpc> {
                    //println!("v:{:?}", v);
                    let peer_id = v
                        .pointer("/peer_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())?;
                    //println!("peer_id:{:?}", peer_id);
                    let addr = v
                        .pointer("/id_point/addr")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<IpAddr>().ok())?;
                    //println!("addr::{:?}", addr);
                    let port = v
                        .pointer("/id_point/port")
                        .and_then(|v| v.as_u64())
                        .and_then(|u| {
                            if (u as u16) as u64 == u {
                                Some(u as u16)
                            } else {
                                None
                            }
                        })?;
                    //println!("port:{:?}", port);
                    //let chain_name = v.pointer("/announced_version/chain_name");
                    //println!("\tpeer_id:{:?}; addr:{:?}; port:{:?}; chain_name:{:?}", peer_id, addr, port, chain_name);
                    Some(ConnectionFromRpc {
                        peer_id,
                        addr: unify_addr(SocketAddr::new(addr, port)),
                    })
                }();
                if let Some(conn) = conn_opt {
                    let peer_id = conn.peer_id.clone();
                    m.insert(peer_id, conn);
                }
            }
        })
    })?;

    Ok(m)
}

fn process_peers(
    file_path: &str,
    conns_from_rpc: &HashMap<String, ConnectionFromRpc>,
    tshark_data: &TsharkData,
) -> Result<(), Error> {
    let res = parse_json(file_path);

    //println!("conn_from_rpc:{:?}", conns_from_rpc);
    //println!("conn_msgs:{:?}", conn_msgs);

    let mut unmatched_messages_num = 0;

    res.map(|r| {
        r.as_array().map(|arr| {
            for v in arr {
                //println!("v:{:?}", v);
                let peer_id = v
                    .pointer("/0")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let total_sent = v
                    .pointer("/1/stat/total_sent")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                let total_received = v
                    .pointer("/1/stat/total_recv")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                //println!("\tpeer_id:{:?}; total_sent:{:?}; total_received:{:?}", peer_id, total_sent, total_received);

                if total_sent > 0 || total_received > 0 {
                    let msg_from_rpc = conns_from_rpc.get(&peer_id).unwrap();
                    let item = tshark_data.connection_msgs.iter().find(|msg| {
                        msg.src_addr == msg_from_rpc.addr || msg.dst_addr == msg_from_rpc.addr
                    });
                    if item.is_none() {
                        eprintln!(
                            "Cannot find connection for peer_id:{}, addr:{} :-(",
                            peer_id, msg_from_rpc.addr
                        );
                        unmatched_messages_num += 1;
                    } else {
                        eprintln!("Found connection for peer_id:{}, addr:{} :-)", peer_id, msg_from_rpc.addr);
                    }
                    let item_decr = tshark_data.decrypted_msgs.iter().find(|msg| {
                        msg.src_addr == msg_from_rpc.addr || msg.dst_addr == msg_from_rpc.addr
                    });
                    if item_decr.is_none() {
                        eprintln!(
                            "Cannot find decrypted msg for peer_id:{}, addr:{} :-(",
                            peer_id, msg_from_rpc.addr
                        );
                        unmatched_messages_num += 1;
                    } else {
                        eprintln!("Found decrypted msg for peer_id:{}, addr:{} :-)", peer_id, msg_from_rpc.addr);
                    }
                }
            }
        })
    })?;

    if unmatched_messages_num > 0 {
        Err(CannotFindMessagesError{})?;
    }
    Ok(())
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn parse_tshark(file_path: &str) -> Result<TsharkData, Error> {
    let lines = read_lines(file_path)?;

    let mut conn_msg_opt: Option<String> = None;
    let mut decrypted_msg_opt: Option<String> = None;
    let mut conversation_opt: Option<String> = None;
    let mut src_addr_opt: Option<SocketAddr> = None;
    let mut dst_addr_opt: Option<SocketAddr> = None;

    let re_empty_line = Regex::new(r"^\s*$")?;
    let re_conversation = Regex::new(r"Tezos conversation: (0x[a-zA-Z0-9]+)")?;
    let re_conn_msg = Regex::new(r"Tezos Connection Msg: (.+)$")?;
    let re_decrypted_msg = Regex::new(r"Tezos Decrypted Msg: (.+)$")?;
    let re_src_ip = Regex::new(r"Tezos Debug: srcaddr:V[46][(]([^)]+)[)]")?;
    let re_dst_ip = Regex::new(r"Tezos Debug: dstaddr:V[46][(]([^)]+)[)]")?;

    let mut ret = TsharkData::default();

    for line_res in lines {
        let line = line_res?;
        if re_empty_line.is_match(&line) {
            let conversation = conversation_opt.unwrap_or("0x0".to_string());
            let src_addr =
                src_addr_opt.unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0));
            let dst_addr =
                dst_addr_opt.unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0));
            if let Some(msg) = conn_msg_opt {
                ret.connection_msgs.push(ConnectionMsg {
                    conversation: conversation,
                    msg: msg,
                    src_addr: unify_addr(src_addr),
                    dst_addr: unify_addr(dst_addr),
                });
            } else if let Some(msg) = decrypted_msg_opt {
                ret.decrypted_msgs.push(DecryptedMsg {
                    conversation: conversation,
                    msg: msg,
                    src_addr: unify_addr(src_addr),
                    dst_addr: unify_addr(dst_addr),
                });
            }

            conn_msg_opt = None;
            decrypted_msg_opt = None;
            conversation_opt = None;
            src_addr_opt = None;
            dst_addr_opt = None;
        } else if let Some(captures) = re_conversation.captures(&line) {
            conversation_opt = Some(captures.get(1).unwrap().as_str().to_owned());
        } else if let Some(captures) = re_conn_msg.captures(&line) {
            conn_msg_opt = Some(captures.get(1).unwrap().as_str().to_owned());
        } else if let Some(captures) = re_decrypted_msg.captures(&line) {
            decrypted_msg_opt = Some(captures.get(1).unwrap().as_str().to_owned());
        } else if let Some(captures) = re_src_ip.captures(&line) {
            src_addr_opt = captures.get(1).unwrap().as_str().parse::<SocketAddr>().ok();
        } else if let Some(captures) = re_dst_ip.captures(&line) {
            dst_addr_opt = captures.get(1).unwrap().as_str().parse::<SocketAddr>().ok();
        }
    }

    Ok(ret)
}

fn main() {
    let err = || -> Result<(), Error> {
        let tshark_data = parse_tshark("/tmp/tshark.out")?;
        let conns_from_rpc = process_connections("/tmp/connections.json")?;
        process_peers("/tmp/peers.json", &conns_from_rpc, &tshark_data)?;

        Ok(())
    }();

    std::process::exit(
        if let Err(err) = err {
            eprintln!("Cannot match every message: {}", err);
            1
        } else {
            eprintln!("Every non-empty peer matched at least one connection and one encrypted message");
            0
        });
}

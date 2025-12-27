use std::net::Ipv4Addr;
use std::vec;
use serde::Serialize;
use std::path::{Path, PathBuf};
use pcap::{Capture, Packet};

use crate::ip::{self, ipv4::*, ipv6::*, port::*};
use crate::l4::{tcp::*, udp::*, icmp::*};
use crate::gtp::{gtp::*, gtp_ie::*, gtpv2_types::*};
use crate::types::*;

#[derive(Serialize, Debug)]
pub struct CallFlow{
    pub src_addr: String,
    pub dst_addr: String,
    pub message: String,
    pub timestamp: String,
    pub id: usize,
}
impl CallFlow{
    pub fn new() -> Self {
        CallFlow {
            src_addr: String::new(),
            dst_addr: String::new(),
            message: String::new(),
            timestamp: String::new(),
            id: 0,
        }
    }
}


#[derive(Serialize, Debug, Clone)]
pub struct ip5tuple {
    pub protocol: u8,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}
impl ip5tuple{
    pub fn new() -> Self {
        ip5tuple {
            protocol: 0,
            src_addr: Ipv4Addr::new(0, 0, 0, 0),
            dst_addr: Ipv4Addr::new(0, 0, 0, 0),
            src_port: 0,
            dst_port: 0,
        }
    }
}

#[derive(Serialize, Debug)]
struct OwnedPacket {
    idx: i32,
    data: Vec<u8>,
}

#[derive(Serialize, Debug)]
struct SessCtxInfo {
    imsi: String,
    my_s11_teid: u32,
    my_s5s8_teid: u32,
    peer_s11_teid: u32,
    peer_s5s8_teid: u32,
}
impl SessCtxInfo {
    pub fn new() -> Self {
        SessCtxInfo {
            imsi: String::new(),
            my_s11_teid: 0,
            my_s5s8_teid: 0,
            peer_s11_teid: 0,
            peer_s5s8_teid: 0,
        }
    }
}

#[derive(Serialize, Debug)]
struct NodeInfo {
    addr: Ipv4Addr,
    port: u16,
    s11_seq: u32,
    s5s8_seq: u32,
    msg_type: u8,
    status: u8,
    session: SessCtxInfo,
}
impl NodeInfo {
    pub fn new() -> Self {
        NodeInfo {
            addr: Ipv4Addr::new(0, 0, 0, 0),
            port: 0,
            s11_seq: 0,
            s5s8_seq: 0,
            msg_type: 0,
            status: 0,
            session: SessCtxInfo::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct TargetInfo {
    tuple: ip5tuple,
    teid: u32,
    imsi: String,
}

fn load_pcap(path: &PathBuf) -> Result<Vec<OwnedPacket>, String> {
    let mut cap = Capture::from_file(path)
        .map_err(|e| e.to_string())?;

    let mut idx: i32 = 1;
    let mut packets = Vec::new();

    while let Ok(pkt) = cap.next_packet() {
        packets.push(
            OwnedPacket { idx, data: pkt.data.to_vec() }
        );
        idx += 1;
    }

    Ok(packets)
}


async
fn senario_analysis(target:TargetInfo, vecPackets: Vec<OwnedPacket>, nodes: &mut Vec<NodeInfo>)
->Result<Vec<OwnedPacket>, String>
{
    let mut filtered_packets = Vec::new();

    let mut init_node = NodeInfo::new();
    let mut resp_node = NodeInfo::new();
    let mut third_node = NodeInfo::new();
    // let tuple = target.tuple;

    for pkt in vecPackets.into_iter() {
        //IP & UDP Layer

        let msg_type = get_msg_type_from_header(&pkt);
        let seq = get_seq_from_header(&pkt);
        let teid = get_teid_from_header(&pkt);
        let tuple = extract_5tuple(&pkt).await;
        // println!("Current TEID: {}", teid);
        // println!("#{} - Msg type: {}",pkt.idx, GTPV2_MSG_TYPES[msg_type as usize]);

        match msg_type {
            GTPV2C_CREATE_SESSION_REQ => {
                let fteid_teid = extract_fteid(&pkt).await;
                let imsi = extract_imsi(&pkt).await;

                if imsi != target.imsi {
                    // println!("{} -- {}", imsi, target.imsi);
                    continue;
                }
                //First Create Session Request Packet
                //[mme] -> [sgw]  [pgw]
                if init_node.status == 0 {

                    println!(" [mme] -> [sgw]  [pgw] ");
                    //First Node
                    init_node_info(&mut init_node, tuple.src_addr, tuple.src_port, msg_type,
                        seq, 0, &imsi);
                    init_fteid_info(&mut init_node, fteid_teid, 0, 0, 0);
                    // println!("INIT NODE - S11 TEID: {}", init_node.session.my_s11_teid);

                    //Second Node
                    init_node_info(&mut resp_node, tuple.dst_addr, tuple.dst_port, msg_type,
                            0, 0, &imsi);
                    init_fteid_info(&mut resp_node, 0, 0, fteid_teid, 0);
                    // println!("RESP NODE - PEER S11 TEID: {} addr:{}", resp_node.session.peer_s11_teid, resp_node.addr);
                    filtered_packets.push(pkt);
                    continue;
                }
                //[mme]  [sgw] -> [pgw]
                //If Second Create Session Request Packet
                else if init_node.status == 1 && resp_node.status == 1 {

                    // println!("Second CSR?!!!??!?! {}-{}   {}-{}", resp_node.addr, tuple.src_addr, tuple.dst_addr, init_node.addr);
                    if resp_node.addr == tuple.src_addr &&
                       tuple.dst_addr != init_node.addr {

                        println!(" [mme]  [sgw] -> [pgw] ");
                        //Third Node check
                        init_node_info(&mut third_node, tuple.dst_addr, tuple.dst_port, msg_type,
                            0, seq, &imsi);
                        init_fteid_info(&mut third_node, 0, 0,
                            0, fteid_teid);
                        // println!("THIRD NODE - PEER S5S8 TEID: {}", third_node.session.peer_s5s8_teid);

                        //Second Node Update
                        update_node_info(&mut resp_node, 0, seq,
                            0, fteid_teid,
                            0, 0);
                        // println!("RESP NODE - MY S5S8 TEID: {}", resp_node.session.my_s5s8_teid);

                        filtered_packets.push(pkt);
                    }
                }   
            },

            GTPV2C_CREATE_SESSION_RSP => {
                let fteid_teid = extract_fteid(&pkt).await;
                if init_node.status == 0 {
                    continue;
                }
                //Third Node
                //[mme]  [sgw] <- [pgw]
                if third_node.status == 1 {
                    // println!("Third node check");
                    if is_match_node(&third_node, &tuple) &&
                       is_match_node(&resp_node, &tuple) {

                        // println!("5tuple check : expect seq:{}, curseq:{}", resp_node.s5s8_seq, seq);
                        if is_s5s8_seq_match(&resp_node, seq) { //if sequence numaber is match what respond node is expecting.
                            // println!("Sequence check ok expect teid: {}, cur teid:{}", resp_node.session.my_s5s8_teid, teid);
                            if is_s5s8_teid_match(&resp_node, teid) {

                                println!(" [mme]  [sgw] <- [pgw] ");
                                update_node_info(&mut third_node, 0, seq,
                                    0, fteid_teid, 0, 0);
                                update_node_info(&mut resp_node, 0, 0,
                                    0, 0, 0, fteid_teid);
                                filtered_packets.push(pkt);
                                continue;
                            }
                        }
                    }
                }
                //Second Node
                //[mme] <- [sgw]  [pgw]
                else if init_node.status == 1 {
                    // println!("Init Node check");
                    if is_match_node(&resp_node, &tuple) &&
                       is_match_node(&init_node, &tuple) {

                        if is_s11_seq_match(&init_node, seq) &&
                           is_s11_teid_match(&init_node, teid) {

                            println!(" [mme] <- [sgw]  [pgw] ");
                            update_node_info(&mut resp_node, seq, 0,
                                fteid_teid, 0,
                                0, 0);
                            update_node_info(&mut init_node, 0, 0,
                                0, 0,
                                fteid_teid, 0);

                            filtered_packets.push(pkt);
                                continue;
                        }
                    }
                }
            }
            GTPV2C_MODIFY_BEARER_REQ |
            GTPV2C_RELEASE_ACCESS_BEARERS_REQ
            => {
                if init_node.status <= 1 {
                    //Unexpected Case
                    continue;
                }
                // [mme] -> [sgw or spgw]
                if check_node(&init_node, tuple.src_addr, tuple.src_port) {
                    //Intiator Node check
                    if is_s11_teid_match(&resp_node, teid) {
                        println!(" [mme] -> [sgw or spgw] ");
                        update_node_info(&mut init_node, seq, 0,
                            0, 0, 0, 0);
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
                // [mme]  [sgw] -> [pgw] or [mme] <- [sgw or s/pgw]
                else if check_node(&resp_node, tuple.src_addr, tuple.src_port) {
                    //Response Node check
                    // [mme]  [sgw] -> [pgw]
                    if third_node.status > 0 &&
                       check_node(&third_node, tuple.dst_addr, tuple.dst_port) {
                        if is_s5s8_teid_match(&third_node, teid) {
                            println!(" [mme]  [sgw] -> [pgw] ");
                            update_node_info(&mut resp_node, 0, seq,
                            0, 0, 0, 0);
                            filtered_packets.push(pkt);
                            continue;
                        }
                    }
                    else
                    // [mme] <- [sgw]  [pgw]
                    if check_node(&init_node, tuple.dst_addr, tuple.dst_port) {
                        if is_s11_teid_match(&init_node, teid) {
                            println!(" [mme] <- [sgw]  [pgw] ");
                            update_node_info(&mut resp_node, seq, 0,
                                0, 0, 0, 0);
                            filtered_packets.push(pkt);
                            continue;
                        }
                    }
                }
                // [mme]    [sgw] <- [pgw]
                else if third_node.status > 0 && check_node(&third_node, tuple.src_addr, tuple.src_port) {
                    if is_s5s8_teid_match(&resp_node, teid) {
                        println!(" [mme]    [sgw] <- [pgw] ");
                        //Third Node check
                        update_node_info(&mut third_node, 0, seq,
                            0, 0, 0, 0);
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
            }

            GTPV2C_MODIFY_BEARER_RSP |
            GTPV2C_RELEASE_ACCESS_BEARERS_RSP 
            => {
                if init_node.status <= 1 {
                    //Unexpected Case
                    continue;
                }

                // [mme] <- [sgw or spgw]
                if check_node(&init_node, tuple.dst_addr, tuple.dst_port) {
                    if init_node.s11_seq == seq {
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
                // [mme]  [sgw] <- [pgw]
                else if is_match_node(&resp_node, &tuple) {
                    //Response Node check
                    // [mme]  [sgw] <- [pgw]
                    if third_node.status > 0 && check_node(&third_node, tuple.src_addr, tuple.src_port) {
                        if resp_node.s5s8_seq == seq {
                            filtered_packets.push(pkt);
                            continue;
                        }
                    }
                }
                // [mme] -> [sgw or s/pgw]
                else if check_node(&init_node, tuple.src_addr, tuple.src_port) {
                    if resp_node.s11_seq == seq {
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
            },

            GTPV2C_DOWNLINK_DATA_NOTIFICATION => {
                if init_node.status <= 1 {
                    //Unexpected Case
                    continue;
                }
                // [mme] <- [sgw]
                if check_node(&init_node, tuple.dst_addr, tuple.dst_port) &&
                   check_node(&resp_node, tuple.src_addr, tuple.src_port) 
                {
                    if is_s11_teid_match(&init_node, teid) {
                        update_node_info(&mut resp_node, seq, 0,
                            0, 0, 0, 0);
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
            },
            GTPV2C_DOWNLINK_DATA_NOTIFICATION_ACK => {
                if init_node.status == 0 {
                    //Unexpected Case
                    continue;
                }
                // [mme] -> [sgw]
                if check_node(&init_node, tuple.src_addr, tuple.src_port) &&
                    check_node(&resp_node, tuple.dst_addr, tuple.dst_port)  {
                    if is_s11_teid_match(&resp_node, teid) &&
                       is_s11_seq_match(&resp_node, seq) {
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
            },

            GTPV2C_DELETE_SESSION_REQ => {
                if init_node.status <= 1 {
                    //Unexpected Case
                    continue;
                }
                //[mme] -> [sgw or spgw]
                if check_node(&init_node, tuple.src_addr, tuple.src_port) {
                    if is_s11_teid_match(&resp_node, teid) {
                        println!(" [mme] -> [sgw or spgw] ");
                        update_node_info(&mut init_node, seq, 0, 0, 0, 0, 0);
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
                //[mme]  [sgw] -> [pgw]
                else if check_node(&resp_node, tuple.src_addr, tuple.src_port) {
                    if is_s5s8_teid_match(&third_node, teid) {
                        println!(" [mme]  [sgw] -> [pgw] ");
                        update_node_info(&mut resp_node, 0, seq, 0, 0, 0, 0);

                        filtered_packets.push(pkt);
                        continue;
                    }
                }
            },

            GTPV2C_DELETE_SESSION_RSP => {
                // println!("Msg type: {}", GTPV2_MSG_TYPES[msg_type as usize]);
                if init_node.status == 0 {
                    //Unexpected Case
                    continue;
                }
                //[mme]  [sgw] <- [pgw]
                if third_node.status > 0 &&
                   check_node(&resp_node, tuple.dst_addr, tuple.dst_port) &&
                   check_node(&third_node, tuple.src_addr, tuple.src_port) {
                    if is_s5s8_teid_match(&resp_node, teid) &&
                       is_s5s8_seq_match(&resp_node, seq) {

                        println!(" [mme]  [sgw] <- [pgw] ");
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
                //[mme] <- [sgw]  [pgw]
                else if check_node(&init_node, tuple.dst_addr, tuple.dst_port) &&
                    check_node(&resp_node, tuple.src_addr, tuple.src_port) 
                {
                    if is_s11_teid_match(&init_node, teid) &&
                       is_s11_seq_match(&init_node, seq) {
                        println!(" [mme] <- [sgw]  [pgw] ");
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
            },

            _ => {}
        }
    }

    if filtered_packets.is_empty() {
        return Err("No packets matched the 5-tuple".to_string());
    }

    //First Node create
    nodes.push(init_node);
    //Second Node create
    nodes.push(resp_node);
    //Third Node create
    if third_node.status > 0 {
        nodes.push(third_node);
    }

    Ok(filtered_packets)

}


fn get_seq_from_header (packet: &OwnedPacket) -> u32
{

    let offset: usize = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    let (_, hdr) = get_gtp_header(&packet.data[offset..]).map_err(|e| {
        eprintln!("GTP Header parse error: {:?}", e);
        e
    }).unwrap();


    hdr.seq
}

fn get_teid_from_header (packet: &OwnedPacket) -> u32
{

    let offset: usize = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    let (_, hdr) = get_gtp_header(&packet.data[offset..]).map_err(|e| {
        eprintln!("GTP Message Type parse error: {:?}", e);
        e
    }).unwrap();

    match hdr.teid {
        None => {
            println!("No TEID in GTP Header");
            return 0;
        },
        Some(teid) => teid,
    }
}

fn get_msg_type_from_header (packet: &OwnedPacket) -> u8
{

    let offset: usize = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    let (_, hdr) = get_gtp_header(&packet.data[offset..]).map_err(|e| {
        eprintln!("GTP Message Type parse error: {:?}", e);
        e
    }).unwrap();

    // println!("GTP Message Type: {}", hdr.msg_type);

    hdr.msg_type
}



async fn
extract_imsi(packet: &OwnedPacket)
// -> Result<GtpIeVal, String>
-> String
{
    let mut offset: usize = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    let imsi = String::new();
    let hdr_size = get_gtp_hdr_len(&packet.data[offset..]);

    offset += hdr_size;

    let ies = parse_all_ies(&packet.data[offset..]);

    let imsi = match ies {
        Ok(ies) => {
            let t = find_ie_imsi(&ies);
            match t {
                Ok(imsi_value) => {
                    imsi_value
                },
                Err(e) => {
                    return imsi;
                }
            }
        },

        Err(e) => {
            return imsi;
        },
    };

    return imsi;
}

async fn extract_fteid(packet: &OwnedPacket) -> u32
{
    let mut offset: usize = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    offset += get_gtp_hdr_len(&packet.data[offset..]);
    
    let ies = parse_all_ies(&packet.data[offset..]);

    let fteid = match ies {
        Ok(ies) => {
            let t = find_ie_fteid(&ies);
            match t {
                Ok(fteid_value) => {
                    fteid_value
                },
                Err(e) => {
                    return 0;
                }
            }
        },
        Err(e) => {
            return 0;
        },
    };

    fteid.teid
}

async fn
extract_5tuple(packet: &OwnedPacket)
-> ip5tuple
{
    let mut offset: usize = 0;
    let mut tuple = ip5tuple::new();

    offset += MIN_ETH_HDR_LEN;

    (tuple.src_addr, tuple.dst_addr) = get_ip_addr(&packet.data[offset..]);

    let proto = get_next_proto(
                &packet.data[offset..]);

    tuple.protocol = proto as u8;

    if PROTO_TYPE_UDP != proto as usize {
        return ip5tuple::new();
    }

    offset += IP_HDR_LEN;

    (tuple.src_port, tuple.dst_port) = get_udp_port(&packet.data[offset..]);

    tuple
}

fn filter_by_imsi(target_imsi: &str, packets: Vec<OwnedPacket>)
->Vec<OwnedPacket>
{
    let mut imsi_filtered_packets = Vec::new();

    for pkt in packets.into_iter() {
        let mut offset: usize = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
        let hdr_size = get_gtp_hdr_len(&pkt.data[offset..]);
        offset += hdr_size;
        let ies = parse_all_ies(&pkt.data[offset..]);

        let imsi = match ies {
            Ok(ies) => {
                let t = find_ie_imsi(&ies);
                match t {
                    Ok(imsi_value) => {
                        imsi_value
                    },
                    Err(e) => String::new(),
                }
            },

            Err(e) => String::new(),
        };

        // println!("Extracted IMSI: {}", imsi);
        if imsi == target_imsi {
            imsi_filtered_packets.push(pkt);
        }

    }

    imsi_filtered_packets
}

async fn filter_by_teid(orig_teid:u32, filtered_packets: Vec<OwnedPacket>)
->Vec<OwnedPacket>
{
    let offset: usize = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    filtered_packets.into_iter().filter(|pkt| {
        match get_gtp_teid(&pkt.data[offset..]) {
            Ok ((_, teid)) => teid == orig_teid,
            Err(_) => false,
        }
    }).collect()

}

fn checked_by_5tuple(tuple: &ip5tuple, packet: &OwnedPacket)
-> bool
{
    let mut offset: usize = MIN_ETH_HDR_LEN;

    let (src_addr, dst_addr) = get_ip_addr(&packet.data[offset..]);
    let proto = get_next_proto(&packet.data[offset..]);

    if (tuple.src_addr == src_addr || tuple.src_addr == dst_addr) &&
       (tuple.dst_addr == src_addr || tuple.dst_addr == dst_addr) &&
       tuple.protocol as usize == proto {
        
        offset += IP_HDR_LEN;

        let (src_port, dst_port) = get_udp_port(&packet.data[offset..]);

        if ( tuple.src_port == src_port || tuple.src_port == dst_port ) &&
           ( tuple.dst_port == src_port || tuple.dst_port == dst_port ) {
            return true;   
        }
    }

    false
}

async fn filter_by_5tuple(tuple:ip5tuple, vecPackets: Vec<OwnedPacket>)
->Result<Vec<OwnedPacket>, String>
{
    let mut filtered_packets = Vec::new();

    for pkt in vecPackets.into_iter() {

		if checked_by_5tuple(&tuple, &pkt) {
            filtered_packets.push(pkt);
        }

    }
    if filtered_packets.is_empty() {
        return Err("No packets matched the 5-tuple".to_string());
    }

    Ok(filtered_packets)
}


fn init_fteid_info(node: &mut NodeInfo,
    my_s11_teid:u32, my_s5s8_teid:u32, peer_s11_teid:u32, peer_s5s8_teid:u32)
{
    if my_s11_teid > 0 {
        node.session.my_s11_teid = my_s11_teid;
    }
    if my_s5s8_teid > 0 {
        node.session.my_s5s8_teid = my_s5s8_teid;
    }
    if peer_s11_teid > 0 {
        node.session.peer_s11_teid = peer_s11_teid;
    }
    if peer_s5s8_teid > 0 {
        node.session.peer_s5s8_teid = peer_s5s8_teid;
    }

}

fn init_node_info(node: &mut NodeInfo,
    addr: Ipv4Addr, port: u16,
    msg_type:u8,
    s11_seq:u32, s5s8_seq:u32,
    imsi:&str)
{
    node.status = 1; //Start with Create Session Request Sent
    node.addr = addr;
    node.port = port;
    node.msg_type = msg_type;

    if s11_seq > 0 {
        node.s11_seq = s11_seq;
    }
    if s5s8_seq > 0 {
        node.s5s8_seq = s5s8_seq;
    }

    node.session.imsi = imsi.to_string();
}

fn update_node_info(node: &mut NodeInfo,
    s11_seq: u32, s5s8_seq: u32,
    my_s11_teid:u32, my_s5s8_teid:u32,
    peer_s11_teid:u32, peer_s5s8_teid:u32)
{
    node.status += 1;

    if s11_seq > 0 {
        node.s11_seq = s11_seq;
    }
    if s5s8_seq > 0 {
        node.s5s8_seq = s5s8_seq;
    }

    if my_s11_teid > 0 {
        node.session.my_s11_teid = my_s11_teid;
    }

    if my_s5s8_teid > 0 {
        node.session.my_s5s8_teid = my_s5s8_teid;
    }

    if peer_s11_teid > 0 {
        node.session.peer_s11_teid = peer_s11_teid;
    }

    if peer_s5s8_teid > 0 {
        node.session.peer_s5s8_teid = peer_s5s8_teid;
    }
}

fn is_s5s8_teid_match( node: &NodeInfo, teid:u32)
-> bool
{
    if node.session.my_s5s8_teid == teid {
       return true;
    }
    false
}

fn is_s11_teid_match( node: &NodeInfo, teid:u32)
-> bool
{
    if node.session.my_s11_teid == teid {
       return true;
    }
    false
}

fn is_s5s8_seq_match( node: &NodeInfo, seq:u32)
-> bool
{
    if node.s5s8_seq == seq {
       return true;
    }
    false
}

fn is_s11_seq_match( node: &NodeInfo, seq:u32)
-> bool
{
    if node.s11_seq == seq {
       return true;
    }
    false
}

fn
check_node ( node: &NodeInfo, addr: Ipv4Addr, port: u16 )
-> bool
{
    if node.addr == addr && node.port == port {
        return true;
    }

    false
}


fn
is_match_node( node: &NodeInfo, tuple: &ip5tuple )
-> bool
{
    if ( node.addr == tuple.src_addr || node.addr == tuple.dst_addr) &&
       ( node.port == tuple.src_port || node.port == tuple.dst_port)
       {
           return true;
    }

    false
}

fn
make_data( tuple_filtered_packets: Vec<OwnedPacket>)
-> Result<Vec<CallFlow>, String>
{
    let mut call_flow= Vec::new();

    for pkt in tuple_filtered_packets {
        let mut offset: usize = 0;
        let mut cf = CallFlow::new();

        // cf.timestamp = print_timestamp(idx, &packet);

        cf.id = pkt.idx as usize;

        offset += MIN_ETH_HDR_LEN;

        let (src_addr, dst_addr) = get_ip_addr(&pkt.data[offset..]);

        cf.src_addr.push_str(&src_addr.to_string());
        cf.dst_addr.push_str(&dst_addr.to_string());

        offset += IP_HDR_LEN+UDP_HDR_LEN;

        let (input, message) = get_msg_type_from_gtpc (&pkt.data[offset..]).map_err(|e| format!("Error: {:?}", e))?;

        cf.message.push_str(&message);

        call_flow.push(cf);
    }

    return Ok(call_flow);
}

pub async fn
make_call_flow (path: &PathBuf, id: usize)
-> Result<Vec<CallFlow>, String>
{
    let mut offset: usize = 0;

    // println!("Target Packet ID: {}", id);
    //1. convert whole pcap to vec
    let vecPackets = load_pcap(path)?;

    //2. find the packet by id
    let packet = vecPackets.get(id-1).ok_or("Packet not found".to_string())?;
    println!("Target Packet idx: {}", packet.idx);

    //3. extract 5-tuple from previous found packet
    let tuple = extract_5tuple(&packet).await;
    println!("Extracted 5-tuple: {:?}", tuple);

    offset += MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    //4. extract TEID from previous found packet
    let (rest,  teid) = get_gtp_teid(&packet.data[offset..]).map_err(|e| format!("GTP-C parse error: {:?}", e))?;
    // println!("Extracted TEID: {}", teid);

    //4.1 extract IMSI from previous found packet
    let target_imsi = extract_imsi(&packet).await;
    println!("Extracted IMSI: {}", target_imsi);


    //4.2 extract SEQ from previous found packet
    // let seq = get_seq_from_header(&packet);
    // println!("Extracted SEQ: {}", seq);

    // let msg_type = get_msg_type_from_header(&packet);
    // println!("Extracted Message Type: {}", msg_type);

    let target = TargetInfo {
        tuple : tuple.clone(),
        teid,
        imsi: target_imsi.clone(),
    };



    /****************************************/

    /*
    //5. Filter by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol_type) of found previous packet
    let tuple_filtered_packets = filter_by_5tuple(tuple, vecPackets).await;

    //5.1 Handle error from filtering by 5-tuple
    let filtered_packets = match tuple_filtered_packets {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error filtering by 5-tuple: {}", e);
            return Err("Error filtering by 5-tuple".to_string());
        }
    };
    // println!("Filtered packets count: {}", tuple_filtered_packets.len());

    */
    let mut nodes = vec![];

    let packets = senario_analysis(target, vecPackets, &mut nodes).await;
    let packets = match packets {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error filtering by 5-tuple: {}", e);
            return Err("Error filtering by 5-tuple".to_string());
        }
    };

    println!("Nodes constructed: {:?}", nodes);

    // //6. Filter by TEID of found previous packet
    // let teid_filtered_packets = filter_by_teid(teid, tuple_filtered_packets).await;
    // println!("TEID Filtered packets count: {}", teid_filtered_packets.len());

    // //7. Filter by IMSI of found previous packet
    // let imsi_filtered_packets = filter_by_imsi(&target_imsi, teid_filtered_packets);
    // println!("IMSI Filtered packets count: {}", imsi_filtered_packets.len());

    // //7. Make Call Flow raw data

    let call_flow = make_data( packets);

    println!("Call Flow constructed with\n{:?}", call_flow);
    return call_flow;
}
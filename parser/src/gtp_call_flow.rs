use std::net::Ipv4Addr;
use std::vec;
use serde::Serialize;
use std::path::PathBuf;
use pcap::Capture;

use crate::ip::{ipv4::*, port::*};
use crate::l4::udp::*;
use crate::gtp::{gtp::*, gtp_ie::*, gtpv2_types::*};
use crate::types::*;
use crate::parse_pcap::*;

#[derive(Serialize, Debug)]
pub struct Bearer{
    pub lbi: u8,
    pub ebi: Vec<u8>,
    pub ip: String,
}
impl Bearer {
    pub fn new() -> Self {
        Bearer {
            lbi: 0,
            ebi: Vec::new(),
            ip: String::new(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct CallFlow{
    pub id: usize,
    pub timestamp: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub message: String,
    pub bearer: Bearer,
}
impl CallFlow{
    pub fn new() -> Self {
        CallFlow {
            id: 0,
            timestamp: String::new(),
            src_addr: String::new(),
            dst_addr: String::new(),
            message: String::new(),
            bearer: Bearer::new(),
        }
    }
}


#[derive(Serialize, Debug, Clone)]
pub struct Ip5Tuple {
    pub protocol: u8,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}
impl Ip5Tuple{
    pub fn new() -> Self {
        Ip5Tuple {
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
    ies: Vec<GtpIe>,
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
    // msg_type: u8,
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
            status: 0,
            session: SessCtxInfo::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct TargetInfo {
    tuple: Ip5Tuple,
    teid: u32,
    imsi: String,
}

fn load_pcap(path: &PathBuf) -> Result<Vec<OwnedPacket>, String> {
    let mut cap = Capture::from_file(path)
        .map_err(|e| e.to_string())?;

    let mut idx: i32 = 1;
    let mut packets = Vec::new();

    while let Ok(pkt) = cap.next_packet() {
        packets.push (
            OwnedPacket {
                idx,
                data: pkt.data.to_vec(),
                ies: Vec::new()
            }
        );

        idx += 1;
    }

    Ok(packets)
}


async fn
senario_analysis(target:TargetInfo, vec_packets: Vec<OwnedPacket>, nodes: &mut Vec<NodeInfo>)
->Result<Vec<OwnedPacket>, String>
{
    let mut filtered_packets = Vec::new();

    let mut init_node = NodeInfo::new();
    let mut resp_node = NodeInfo::new();
    let mut third_node = NodeInfo::new();

    for mut pkt in vec_packets.into_iter() {

        let mut offset = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

        let (_, hdr) = get_gtp_header(&pkt.data[offset..]).map_err(|e| {
            eprintln!("GTP Message Type parse error: {:?}", e);
            e
        }).unwrap();

        let msg_type = hdr.msg_type;
        let seq = hdr.seq;
        let teid = hdr.teid.unwrap();

        let tuple = extract_5tuple(&pkt).await;

        offset += get_gtp_hdr_len(&pkt.data[offset..]);
        let ies = parse_all_ies(&pkt.data[offset..]).unwrap_or_default();

        pkt.ies = ies.clone();

        match msg_type {
            GTPV2C_CREATE_SESSION_REQ => {
                let fteid_teid = extract_fteid(ies.clone()).await;
                let imsi = extract_imsi(ies.clone()).await;

                if imsi != target.imsi {
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

                    //Second Node
                    init_node_info(&mut resp_node, tuple.dst_addr, tuple.dst_port, msg_type,
                            0, 0, &imsi);
                    init_fteid_info(&mut resp_node, 0, 0, fteid_teid, 0);

                    filtered_packets.push(pkt);
                    continue;
                }
                //[mme]  [sgw] -> [pgw]
                //If Second Create Session Request Packet
                else if init_node.status == 1 && resp_node.status == 1 {

                    if resp_node.addr == tuple.src_addr &&
                       tuple.dst_addr != init_node.addr {

                        println!(" [mme]  [sgw] -> [pgw] ");
                        //Third Node check
                        init_node_info(&mut third_node, tuple.dst_addr, tuple.dst_port, msg_type,
                            0, seq, &imsi);
                        init_fteid_info(&mut third_node, 0, 0,
                            0, fteid_teid);

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
                let fteid_teid = extract_fteid(ies).await;
                if init_node.status == 0 {
                    continue;
                }
                //Third Node
                //[mme]  [sgw] <- [pgw]
                if third_node.status == 1 {
                    // println!("Third node check");
                    if is_match_node(&third_node, &tuple) &&
                       is_match_node(&resp_node, &tuple) {

                        if is_s5s8_seq_match(&resp_node, seq) { //if sequence numaber is match what respond node is expecting.
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

            GTPV2C_MODIFY_BEARER_CMD |
            GTPV2C_DELETE_BEARER_CMD |
            GTPV2C_BEARER_RESOURCE_CMD |
            GTPV2C_MODIFY_BEARER_REQ |
            GTPV2C_RELEASE_ACCESS_BEARERS_REQ => {
                if init_node.status <= 1 {
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
            GTPV2C_RELEASE_ACCESS_BEARERS_RSP => {
                if init_node.status <= 1 {
                    continue;
                }

                // [mme] <- [sgw or spgw]
                if check_node(&init_node, tuple.dst_addr, tuple.dst_port) {
                    if is_s11_seq_match(&init_node, seq){
                        println!(" [mme] <- [sgw or spgw]");
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
                // [mme]  [sgw] <- [pgw]
                else if is_match_node(&resp_node, &tuple) {
                    //Response Node check
                    // [mme]  [sgw] <- [pgw]
                    if third_node.status > 0 && check_node(&third_node, tuple.src_addr, tuple.src_port) {
                        if is_s5s8_seq_match(&resp_node, seq) {
                            println!(" [mme]  [sgw] <- [pgw]");
                            filtered_packets.push(pkt);
                            continue;
                        }
                    }
                }
                // [mme] -> [sgw or s/pgw]
                else if check_node(&init_node, tuple.src_addr, tuple.src_port) {
                    if is_s11_seq_match(&resp_node, seq) {
                        println!(" [mme] -> [sgw or s/pgw]");
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
            },

            GTPV2C_DOWNLINK_DATA_NOTIFICATION => {
                if init_node.status <= 1 {
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

            GTPV2C_CREATE_BEARER_REQ |
            GTPV2C_UPDATE_BEARER_REQ |
            GTPV2C_DELETE_BEARER_REQ => {
                if init_node.status <= 1 {
                    continue;
                }
                // [mme]  [sgw] <- [pgw]
                if check_node(&resp_node, tuple.dst_addr, tuple.dst_port) &&
                   check_node(&third_node, tuple.src_addr, tuple.src_port) {

                    if is_s5s8_teid_match(&third_node, teid) {
                        update_node_info(&mut init_node, seq, 0,
                            0, 0, 0, 0);

                        filtered_packets.push(pkt);
                        continue;
                    }
                }
                // [mme] <- [sgw]  [pgw]
                else if check_node(&init_node, tuple.dst_addr, tuple.dst_port) &&
                    check_node(&resp_node, tuple.src_addr, tuple.src_port)  {

                    if is_s11_teid_match(&resp_node, teid) {
                        update_node_info(&mut resp_node, 0, seq,
                            0, 0, 0, 0);

                        filtered_packets.push(pkt);
                        continue;
                    }
                }
            },

            GTPV2C_CREATE_BEARER_RSP |
            GTPV2C_UPDATE_BEARER_RSP |
            GTPV2C_DELETE_BEARER_RSP => {
                if init_node.status <= 1 {
                    continue;
                }
                // [mme] -> [sgw]  [pgw]
                if check_node(&resp_node, tuple.dst_addr, tuple.dst_port) {
                    if is_s11_seq_match(&resp_node, seq) &&
                       is_s11_teid_match(&resp_node, teid) {

                        println!(" [mme] -> [sgw]  [pgw] ");
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
                // [mme]  [sgw] -> [pgw]
                else if third_node.status > 0 && check_node(&third_node, tuple.dst_addr, tuple.dst_port) {
                    if is_s5s8_seq_match(&third_node, seq) &&
                       is_s5s8_teid_match(&third_node, teid) {

                        println!(" [mme]  [sgw] -> [pgw] ");
                        filtered_packets.push(pkt);
                        continue;
                    }
                }
            },

            GTPV2C_DELETE_SESSION_REQ => {
                if init_node.status <= 1 {
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
                if init_node.status == 0 {
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
                    check_node(&resp_node, tuple.src_addr, tuple.src_port) {

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

    //Add First Node
    nodes.push(init_node);

    //Add Second Node
    nodes.push(resp_node);

    //Add Third Node
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
extract_imsi( ies: Vec<GtpIe>)
-> String
{
    let t = find_ie_imsi(&ies);
    let imsi = match t {
        Ok(imsi_value) => {
            imsi_value
        },
        Err(e) => {
            return "".to_string();
        }
    };

    return imsi;
}

async fn extract_fteid( ies: Vec<GtpIe>)
-> u32
{
    let t = find_ie_fteid(&ies);
    let fteid = match t {
        Ok(fteid_value) => {
            fteid_value
        },
        Err(_) => {
            return 0;
        }
    };

    fteid.teid
}

async fn add_ebi(bearer: &mut Bearer, ebi: u8)
{
    bearer.ebi.push(ebi);
}

async fn extract_bearer_ctx(ies: Vec<GtpIe>)
-> Bearer
{
    let subie = find_ie_bearer_ctx(&ies.clone()).unwrap_or_default();

    let fteid = match find_ie_fteid(&subie.clone()) {
        Ok(v) => v,
        Err (e) => {
            FTeidValue{
                v4: false,
                v6: false,
                iface_type: 0,
                teid: 0,
                ipv4: None,
                ipv6: None,
            }
        },
    };

    let ebi = find_ie_ebi(&subie.clone()).unwrap_or_default();

    let ebis = vec![ebi];
    let bearer = Bearer {
        lbi: ebi,
        ebi: ebis,
        ip: fteid.ipv4.unwrap(),
    };

    bearer
}

async fn
extract_5tuple(packet: &OwnedPacket)
-> Ip5Tuple
{
    let mut offset: usize = 0;
    let mut tuple = Ip5Tuple::new();

    offset += MIN_ETH_HDR_LEN;

    (tuple.src_addr, tuple.dst_addr) = get_ip_addr(&packet.data[offset..]);

    let proto = get_next_proto(
                &packet.data[offset..]);

    tuple.protocol = proto as u8;

    if PROTO_TYPE_UDP != proto as usize {
        return Ip5Tuple::new();
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
                    Err(_) => String::new(),
                }
            },

            Err(_) => String::new(),
        };

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

pub fn check_gtp(packet: &OwnedPacket)
-> bool
{
    let mut offset: usize = MIN_ETH_HDR_LEN;
    let mut next_type = 0;

    if packet.data.len() >= MIN_ETH_HDR_LEN {
        next_type = parse_ethernet(&packet.data);
    }
    if next_type != 0x0800 {
        return false
    }

    // --- Parse Layer 3 ---
    let next_proto = get_next_proto(&packet.data[offset..]);
    if next_proto != PROTO_TYPE_UDP {
        return false;
    }

    offset += IP_HDR_LEN;
    let (_, dst_port) = get_udp_port(&packet.data[offset..]);
    if dst_port != WELLKNOWN_PORT_GTPV2 {
        return false;
    }

    true
}



async fn filtered_as_gtp(vec_packets: Vec<OwnedPacket>)
->Result<Vec<OwnedPacket>, String>
{
    let mut filtered_packets = Vec::new();

    for pkt in vec_packets.into_iter() {

        if check_gtp(&pkt) {
            filtered_packets.push(pkt);
        }
    }
    if filtered_packets.is_empty() {
        return Err("No GTP packets in pcap file".to_string());
    }

    Ok(filtered_packets)
}

fn checked_by_5tuple(tuple: &Ip5Tuple, packet: &OwnedPacket)
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

async fn filter_by_5tuple(tuple: Ip5Tuple, vec_packets: Vec<OwnedPacket>)
->Result<Vec<OwnedPacket>, String>
{
    let mut filtered_packets = Vec::new();

    for pkt in vec_packets.into_iter() {

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
is_match_node( node: &NodeInfo, tuple: &Ip5Tuple )
-> bool
{
    if ( node.addr == tuple.src_addr || node.addr == tuple.dst_addr) &&
       ( node.port == tuple.src_port || node.port == tuple.dst_port) {
        return true;
    }

    false
}

async fn
make_data( flow_packets: Vec<OwnedPacket>)
-> Result<Vec<CallFlow>, String>
{
    let mut call_flow= Vec::new();

    for pkt in flow_packets {
        let mut offset: usize = 0;
        let mut cf = CallFlow::new();

        cf.id = pkt.idx as usize;

        offset += MIN_ETH_HDR_LEN;

        let (src_addr, dst_addr) = get_ip_addr(&pkt.data[offset..]);

        cf.src_addr.push_str(&src_addr.to_string());
        cf.dst_addr.push_str(&dst_addr.to_string());

        offset += IP_HDR_LEN+UDP_HDR_LEN;

        let (_, message) = get_msg_type_from_gtpc (&pkt.data[offset..]).map_err(|e| format!("Error: {:?}", e))?;

        cf.message.push_str(&message);
        cf.bearer = extract_bearer_ctx(pkt.ies).await;

        call_flow.push(cf);
    }

    return Ok(call_flow);
}


pub async fn
make_call_flow (path: &PathBuf, id: usize)
-> Result<Vec<CallFlow>, String>
{
    let mut offset = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    //1. convert whole packets of pcap to vec
    let vec_packets = load_pcap(path)?;

    //2. find the packet by id
    let packet = vec_packets.get(id-1).ok_or("Packet not found".to_string())?;

    //2.1 parse all IEs
    offset += get_gtp_hdr_len(&packet.data[offset..]);
    let ies = parse_all_ies(&packet.data[offset..]).unwrap_or_default();

    //3. extract 5-tuple from previous found packet
    let tuple = extract_5tuple(&packet).await;

    offset = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    //4. extract TEID from previous found packet
    let (_, teid) = get_gtp_teid(&packet.data[offset..]).map_err(|e| format!("GTP-C parse error: {:?}", e))?;

    //4.1 extract IMSI from previous found packet
    let target_imsi = extract_imsi(ies).await;

    let target = TargetInfo {
        tuple : tuple.clone(),
        teid,
        imsi: target_imsi.clone(),
    };

    //5. This Callfow Feature can analyze only GTP messages
    let filtered_packets = filtered_as_gtp(vec_packets).await;
    let gtp_packets = match filtered_packets {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error filtering by 5-tuple: {}", e);
            return Err("Error filtering by 5-tuple".to_string());
        }
    };

    let mut nodes = vec![];

    //6. Packets will be filtered by GTP Call procedure.
    let packets = senario_analysis(target, gtp_packets, &mut nodes).await;
    let packets = match packets {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error filtering by 5-tuple: {}", e);
            return Err("Error filtering by 5-tuple".to_string());
        }
    };

    //7. Make Call Flow raw data
    let call_flow = make_data( packets).await;

    return call_flow;
}
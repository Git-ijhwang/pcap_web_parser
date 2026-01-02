use std::{collections::HashMap, path::PathBuf, sync::Arc};
use serde::Serialize;
use tokio::sync::RwLock;
use std::time::Instant;

use crate::gtp::gtp_ie::*;

pub type Cache = Arc<RwLock<HashMap<String, FileInfo>>>;

pub const MIN_ETH_HDR_LEN:usize = 14;
pub const IP_HDR_LEN:usize = 20;
pub const IP6_HDR_LEN:usize = 40;
pub const TCP_HDR_LEN:usize = 20;
pub const UDP_HDR_LEN:usize = 8;
pub const ICMP_HDR_LEN:usize = 8;


#[derive(Clone)]
pub struct FileInfo {
    // pub uuid: String,
    pub path: PathBuf,
    pub original_name: String,
    pub last_used: Instant,
}

#[derive(serde::Deserialize)]
pub struct PacketQuery {
    pub file_id: u64,
    pub id: usize, // 프론트엔드에서 보내는 id
}

#[derive(serde::Serialize)]
pub struct ParsedDetail {
    pub id: usize,
    pub packet: PacketDetail,
}
#[derive(serde::Serialize, Debug, Clone)]
pub struct ParsedResult {
    pub file: String,
    pub total_packets: usize,
    pub packets: Vec<PacketSummary>,
}

#[derive(Debug, Clone, Serialize )]
pub struct PacketSummary {
    pub id: usize,
    pub ts: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: usize,
    pub description: String,
}

impl PacketSummary{
    pub fn new() -> Self {
        PacketSummary {
            id : 0,
            ts : String::new(),
            src_ip : String::new(),
            dst_ip : String::new(),
            src_port : 0,
            dst_port : 0,
            protocol : String::new(),
            length: 0,
            description: String::new(),
        }
    }
}
#[derive(Serialize, Debug)]
pub struct Ip6Info {
    pub version: u8,
    pub tc: u8,
    pub fl: u32,
    pub pl: u16,
    pub next: u8,
    pub hop: u8,
    pub src_addr: String,
    pub dst_addr: String,
    pub raw: Vec<u8>,
}
impl Ip6Info {
    pub fn new() -> Self {
        Ip6Info {
            version: 0,
            tc: 0,
            fl: 0,
            pl: 0,
            next: 0,
            hop: 0,
            src_addr: String::new(),
            dst_addr: String::new(),
            raw: Vec::new(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct IpInfo {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: String,
    pub dst_addr: String,
    pub next: String,
    pub raw: Vec<u8>,
}
impl  IpInfo {
    pub fn new() -> Self {
        IpInfo {
            version: 0,
            ihl: 0,
            dscp: 0,
            ecn: 0,
            total_length: 0,
            id: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 0,
            protocol: 0,
            checksum: 0,
            src_addr: String::new(),
            dst_addr: String::new(),
            next: String::new(),
            raw: Vec::new(),
        }
    }
}

#[derive(Serialize, Debug)]
pub enum Layer3Info {
    IP(IpInfo),
    IP6(Ip6Info),
    None,
}

#[derive(Serialize, Debug)]
pub enum Layer4Info {
    UDP(UdpInfo),
    TCP(TcpInfo),
    ICMP(IcmpInfo),
    None,
}

#[derive(Serialize, Debug)]
pub struct IcmpInfo {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub id: u16,
    pub seq: u16,
    pub raw: Vec<u8>,
}
impl  IcmpInfo {
    pub fn new() -> Self {
        IcmpInfo {
            icmp_type: 0,
            code: 0,
            checksum: 0,
            id: 0,
            seq: 0,
            raw: Vec::new(),
        }
    }
}


#[derive(Serialize, Debug)]
pub struct UdpInfo {
    pub src_port: u16,
    pub str_src_port: String,
    pub dst_port: u16,
    pub str_dst_port: String,
    pub length: u16,
    pub checksum: u16,
    pub raw: Vec<u8>,
}

impl  UdpInfo {
    pub fn new() -> Self {
        UdpInfo {
            src_port: 0,
            dst_port: 0,
            str_src_port: String::new(),
            str_dst_port: String::new(),
            length: 0,
            checksum: 0,
            raw: Vec::new(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct TcpInfo {
    pub src_port: u16,
    pub src_port_str: String,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub header_sz: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent: u16,
    pub raw: Vec<u8>,
}
impl  TcpInfo {
    pub fn new() -> Self {
        TcpInfo {
            src_port: 0,
            src_port_str: String::new(),
            dst_port: 0,
            seq: 0,
            ack: 0,
            header_sz: 0,
            flags: 0,
            window: 0,
            checksum: 0,
            urgent: 0,
            raw: Vec::new(),
        }
    }
}

#[derive(Serialize, Debug)]
pub enum AppLayerInfo {
    GTP(GtpInfo),
    // HTTP(HttpInfo),
    None,
}

#[derive(Serialize, Debug)]
pub struct GtpInfo {
    pub version: u8,
    pub p_flag: bool,
    pub t_flag: bool,
    pub mp_flag: bool,

    pub msg_type: u8,
    pub msg_type_str: String,
    pub msg_len: u16,

    pub teid: Option<u32>,

    pub seq: u32,
    pub mp: Option<u8>,
    pub ies: Vec<GtpIe>,
    pub raw: Vec<u8>,
}
impl GtpInfo {
    pub fn new() -> Self {
        GtpInfo {
            version: 0,
            p_flag: false,
            t_flag: false,
            mp_flag: false,

            msg_type: 0,
            msg_type_str: String::new(),
            msg_len: 0,

            teid: None,
            seq: 0,
            mp: None,
            ies: Vec::new(),
            raw: Vec::new(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct PacketDetail {
    pub id: usize,
    pub l3: Vec<Layer3Info>,
    pub l4: Layer4Info,
    pub app: AppLayerInfo,
}
impl PacketDetail{
    pub fn new() -> Self {
        PacketDetail {
            id: 0,
            l3: Vec::new(),
            l4: Layer4Info::None,
            app: AppLayerInfo::None,
        }
    }
}
use std::{collections::HashMap, path::{Path, PathBuf}, sync::Arc};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::gtp::gtp::*; // 비동기 환경이면 tokio RwLock 권장

pub type Cache = Arc<RwLock<HashMap<String, FileInfo>>>;

pub const IP_HDR_LEN:usize = 20;
pub const MIN_ETH_HDR_LEN:usize = 14;


#[derive(Clone)]
pub struct FileInfo {
    pub path: PathBuf,
    pub original_name: String,
}

#[derive(serde::Deserialize)]
pub struct PacketQuery {
    pub file: String,
    pub id: usize, // 프론트엔드에서 보내는 id
}

#[derive(serde::Serialize)]
pub struct ParsedDetail {
    pub id: usize,
    pub packet: PacketDetail,
}
#[derive(serde::Serialize, Debug)]
pub struct ParsedResult {
    pub file: String,
    pub total_packets: usize,
    pub packets: Vec<PacketSummary>,
}

#[derive(Debug, Serialize)]
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
        }
    }
}

#[derive(Serialize, Debug)]
pub enum Layer4Info {
    UDP(UdpInfo),
    TCP(TcpInfo),
    //ICMP(IcmpInfo),
}
#[derive(Serialize, Debug)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
}
impl  UdpInfo {
    pub fn new() -> Self {
        UdpInfo {
            src_port: 0,
            dst_port: 0
        }
    }
}

#[derive(Serialize, Debug)]
pub struct TcpInfo {
    pub seq: u32,
    pub src_port: u16,
    pub dst_port: u16,
}
impl  TcpInfo {
    pub fn new() -> Self {
        TcpInfo {
            seq: 0,
            src_port: 0,
            dst_port: 0
        }
    }
}

#[derive(Serialize, Debug)]
pub enum AppLayerInfo {
    GTP(GtpInfo),
    // HTTP(HttpInfo),
    //ICMP(IcmpInfo),
}

#[derive(Serialize, Debug)]
pub struct GtpInfo {
    pub msg_type: u8,
    pub msg_type_str: String,
    pub teid: u32,
    pub ies: Vec<GtpIe>,
}
impl GtpInfo {
    pub fn new() -> Self {
        GtpInfo {
            msg_type: 0,
            msg_type_str: String::new(),
            teid: 0,
            ies: Vec::new(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct PacketDetail {
    pub id: usize,
    pub ip: IpInfo,
    pub l4: Layer4Info,
    pub app: AppLayerInfo,
}
impl PacketDetail{
    pub fn new() -> Self {
        PacketDetail {
            id: 0,
            ip: IpInfo::new(),
            l4: Layer4Info::UDP(UdpInfo::new()),
            app: AppLayerInfo::GTP(GtpInfo::new()),
        }
    }
}
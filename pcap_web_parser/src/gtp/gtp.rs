use serde::Serialize;
use nom::{
    IResult,
    number::complete::{be_u8, be_u16, be_u32},
    bytes::complete::take,
};

use crate::types::*;
use crate::gtp::gtp_ie::*;
use crate::gtp::gtpv2_types::*;

#[derive(Debug)]
pub struct GtpHeader {
    pub version: u8,
    pub p_flag: bool,
    pub t_flag: bool,
    pub mp_flag: bool,

    pub msg_type: u8,
    pub msg_len: u16,

    pub teid: Option<u32>,

    pub seq: u32,
    pub mp: Option<u8>,
    // pub payload: &'a [u8],
}
impl GtpHeader {
    pub fn new() -> Self {
        GtpHeader {
            version: 0,
            p_flag: false,
            t_flag: false,
            mp_flag: false,
            msg_type: 0,
            msg_len: 0,
            teid: None,
            seq: 0,
            mp: None,
        }
    }
}


pub fn get_msg_type_from_gtpc<'a>(input: &'a [u8])
-> IResult<&'a [u8], String> {
    let (input, _flags) = be_u8(input)?;
    let (input, msg_type) = be_u8(input)?;

    Ok((input, GTPV2_MSG_TYPES[msg_type as usize].to_string()))
}


pub fn parse_gtpc<'a>(input: &'a [u8], packet: &'a mut PacketSummary)
-> IResult<&'a[u8], GtpHeader>
{
    let (input, flags) = be_u8(input)?;
    let version = (flags >> 5) & 0x07;
    let p_flag = ((flags >> 4) & 0x01) == 1;
    let t_flag = ((flags >> 3) & 0x01) == 1;
    let mp_flag = ((flags >> 2) & 0x01) == 1;

    let (input, msg_type) = be_u8(input)?;
    let (input, msg_len) = be_u16(input)?;

    let (input, teid) = if t_flag {
        let (input, teid) = be_u32(input)?;
        (input, Some(teid))
    }
    else {
        (input, None)
    };

    let (input, seq_bytes) = take(3usize)(input)?;
    let seq = ((seq_bytes[0] as u32) << 16)
                    | ((seq_bytes[1] as u32) << 8)
                    | (seq_bytes[2] as u32);

    let (input, mp) = if mp_flag {
        let (input, m) = be_u8(input)?;
        let m = (m >> 4) & 0x0f;
        (input, Some(m))
    }
    else {
        (input, None)
    };

    let (input, _spare) = be_u8(input)?;

    let mut add = 0;
    if !teid.is_none() {
        add += 4;
    }

    add += 4;
    let (remaining, payload) = take((msg_len-add) as usize)(input)?;

    packet.description = format!("{} [{}]",
        GTPV2_MSG_TYPES[msg_type as usize],
        msg_type).to_string();

    Ok (( remaining, GtpHeader {
        version,
        p_flag,
        t_flag,
        mp_flag,
        msg_type,
        msg_len,
        teid,
        seq,
        mp,
        // payload,
    }))
}

pub fn get_gtp_hdr_len(input: &[u8]) -> usize
{
    // let (input, flags) = be_u8(input)?;
    let flags = input[0];
    let t_flag = ((flags >> 3) & 0x01) == 1;
    let mp_flag = ((flags >> 2) & 0x01) == 1;

    let mut len = 8; // Base header length

    if t_flag {
        len += 4; // TEID field length
    }
    if mp_flag {
        len += 1; // Message Priority field length
    }

    len
}

pub fn find_ie_imsi(ies: &Vec<GtpIe>)
-> Result<String, String>
// -> Result<GtpIeValue, String>
{
    for ie in ies {
        if ie.ie_type == GTPV2C_IE_IMSI {
            match &ie.ie_value {
                GtpIeValue::Utf8String(s) => {
                    return Ok(s.clone());
                }
                _ => {
                    return Err("IMSI IE has unexpected value type".to_string());
                },
            }
        }
    }

    Err("IMSI IE not found".to_string())
}

pub fn get_gtp_teid<'a>(input: &'a [u8])
// -> u16
-> IResult<&'a[u8], u32>
{
    let start = input;
    let (input, flags) = be_u8(input)?;
    let t_flag = ((flags >> 3) & 0x01) == 1;

    let (input, msg_type) = be_u8(input)?;
    let (input, msg_len) = be_u16(input)?;

    let (input, teid) = if t_flag {
        let (input, teid) = be_u32(input)?;
            (input, Some(teid))
    }
    else {
        (input, None)
    };
    Ok (( input, teid.unwrap()))
}

pub fn get_gtp_header(input: & [u8])
// ->GtpHeader
-> IResult<&[u8], GtpHeader>
{
    let (input, flags) = be_u8(input)?;
    let version = (flags >> 5) & 0x07;
    let p_flag = ((flags >> 4) & 0x01) == 1;
    let t_flag = ((flags >> 3) & 0x01) == 1;
    let mp_flag = ((flags >> 2) & 0x01) == 1;

    let (input, msg_type) = be_u8(input)?;
    let (input, msg_len) = be_u16(input)?;

    let (input, teid) = if t_flag {
        let (input, teid) = be_u32(input)?;
        (input, Some(teid))
    }
    else {
        (input, None)
    };

    let (input, seq_bytes) = take(3usize)(input)?;
    let seq = ((seq_bytes[0] as u32) << 16)
                    | ((seq_bytes[1] as u32) << 8)
                    | (seq_bytes[2] as u32);

    let (input, mp) = if mp_flag {
        let (input, m) = be_u8(input)?;
        let m = (m >> 4) & 0x0f;
        (input, Some(m))
    }
    else {
        (input, None)
    };

    let (input, _spare) = be_u8(input)?;

    let mut add = 0;
    if !teid.is_none() {
        add += 4;
    }

    add += 4;
    let (remaining, payload) = take((msg_len-add) as usize)(input)?;

    Ok((remaining, GtpHeader {
        version,
        p_flag, t_flag, mp_flag,
        msg_type, msg_len,
        teid, seq, mp,
    }))
}


pub fn parse_gtpc_detail<'a>(input: &'a [u8])//, packet: &'a mut PacketDetail)
-> IResult<&'a[u8], GtpInfo>
{
    let start = input;
    let (input, flags) = be_u8(input)?;
    let version = (flags >> 5) & 0x07;
    let p_flag = ((flags >> 4) & 0x01) == 1;
    let t_flag = ((flags >> 3) & 0x01) == 1;
    let mp_flag = ((flags >> 2) & 0x01) == 1;

    let (input, msg_type) = be_u8(input)?;
    let (input, msg_len) = be_u16(input)?;

    let (input, teid) = if t_flag {
        let (input, teid) = be_u32(input)?;
        (input, Some(teid))
    }
    else {
        (input, None)
    };

    let (input, seq_bytes) = take(3usize)(input)?;
    let seq = ((seq_bytes[0] as u32) << 16)
                | ((seq_bytes[1] as u32) << 8)
                | (seq_bytes[2] as u32);

    let (input, mp) = if mp_flag {
        let (input, m) = be_u8(input)?;
        let m = (m >> 4) & 0x0f;
        (input, Some(m))
    }
    else {
        (input, None)
    };

    // println!("len {:?}", msg_len);
        // println!("TEID {:?}", teid);
        // println!("Seq {:?}", seq);
    let (input, _spare) = be_u8(input)?;

    let mut add = 0;
    if !teid.is_none() {
        add += 4;
    }
    add += (4);
    // let (remaining, payload) = take((msg_len-add) as usize)(input)?;

    // if let AppLayerInfo::GTP(gtp) = &mut packet.app {
    //     gtp.msg_type = msg_type;
    //     gtp.msg_type_str = GTPV2_MSG_TYPES[msg_type as usize].to_string();
    //     gtp.teid = teid.unwrap();
    // }


    // GTP 메시지 전체 길이 계산
    let header_len = 8 + if t_flag { 4 } else { 0 } + if mp_flag { 1 } else { 0 }; 
    let total_len = header_len + msg_len as usize;

    let raw = start[..total_len.min(start.len())].to_vec(); // 안전하게 슬라이스

    let info=    GtpInfo {
        version,
        p_flag,
        t_flag,
        mp_flag,
        msg_type,
        msg_type_str:GTPV2_MSG_TYPES[msg_type as usize].to_string(),
        msg_len,
        teid: if t_flag {teid}else {None},
        seq,
        mp: if mp_flag {mp}else {None},

        ies: Vec::new(),
        raw,
    };

    Ok (( input, info))
        // GtpHeader { version, p_flag, t_flag, mp_flag, msg_type, msg_len, teid, seq, mp, }
}
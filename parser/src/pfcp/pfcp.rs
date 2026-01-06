use serde::Serialize;
use nom::{
    IResult,
    number::complete::{be_u8, be_u16, be_u32, be_u64},
    bytes::complete::take,
};
use crate::types::*;
use crate::pfcp::types::*;


#[derive(Debug)]
pub struct PfcpHeader {
    pub version: u8,
    pub fo_flag: bool,
    pub mp_flag: bool,
    pub s_flag: bool,

    pub msg_type: u8,
    pub msg_len: u16,

    pub seid: Option<u64>,

    pub seq: u32,
    pub mp: Option<u8>,
    // pub payload: &'a [u8],
}
impl PfcpHeader {
    pub fn new() -> Self {
        PfcpHeader {
            version: 0,
            fo_flag: false,
            mp_flag: false,
            s_flag: false,

            msg_type: 0,
            msg_len: 0,
            seid: None,
            seq: 0,
            mp: None,
        }
    }
}

pub fn parse_pfcp<'a>(input: &'a[u8], packet: &mut PacketSummary)
    -> IResult<&'a[u8], PfcpHeader>
{
    let (input, flags) = be_u8(input)?;
    let version = (flags >> 5) & 0x07;
    let fo_flag = ((flags >> 2) & 0x01) == 1;
    let mp_flag = ((flags >> 1) & 0x01) == 1;
    let s_flag = (flags & 0x01) == 1;

    let (input, msg_type) = be_u8(input)?;
    let (input, msg_len) = be_u16(input)?;

    let (input, seid) = if s_flag {
        let (input, seid) = be_u64(input)?;
        (input, Some(seid))
    }
    else {
        (input, None)
    };

    let (input, seq_bytes) = take(3usize)(input)?;
    let seq = ((seq_bytes[0] as u32) << 16) |
                    ((seq_bytes[1] as u32) << 8) |
                    (seq_bytes[2] as u32);

    let (input, mp) = if mp_flag {
        let (input, m) = be_u8(input)?;
        let m = (m >> 4) & 0x0f;
        (input, Some(m))
    }
    else {
        (input, None)
    };

    let (input, _spare) = be_u8(input)?;

    packet.description = format!("{} [{}]",
        PFCP_MSG_TYPES[msg_type as usize], msg_type).to_string();


    let header = PfcpHeader {
        version,
        fo_flag,
        mp_flag,
        s_flag,
        msg_type,
        msg_len,
        seid,
        seq,
        mp
    };

    Ok((input, header))
}


// pub fn parse_pfcp_detail<'a>(input: &'a[u8])
//     -> IResult<&'a[u8]>, PfcpHeader>
// {
// }
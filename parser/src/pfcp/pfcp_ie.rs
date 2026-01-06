use std::net::{Ipv4Addr, Ipv6Addr};
use serde::Serialize;
use nom::{
    IResult,
    number::complete::{be_u8, be_u16, be_u32, be_u64},
    bytes::complete::take,
};
use std::convert::TryInto;

use crate::pfcp::types::*;
use crate::gtp::gtp_ie::*;

#[derive(Debug, Clone, Serialize)]
pub struct PfcpIe {
    pub ie_type: u16,
    pub type_str: String,
    pub length: u16,
    pub ie_value: GtpIeValue,
    pub raw: Vec<u8>,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4ProtocolType {
    PROTO_TYPE_ICMP = 1,
    PROTO_TYPE_IPINIP = 4,
    PROTO_TYPE_TCP = 6,
    PROTO_TYPE_UDP = 17,
    PROTO_TYPE_ICMPV6 = 58,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum wellknown_port {
    WELLKNOWN_PORT_FTP_DATA = 20,
    WELLKNOWN_PORT_FTP_CTRL = 21,
    WELLKNOWN_PORT_DNS      = 53,
    WELLKNOWN_PORT_DHCP_SVR      = 67,
    WELLKNOWN_PORT_DHCP_CLI      = 68,
    WELLKNOWN_PORT_HTTP      = 80,
    WELLKNOWN_PORT_GTPV2      = 2123,
    WELLKNOWN_PORT_PFCP      = 8805,
}
pub fn v6_ext_hdr_to_str(ext_hdr: usize) -> Option<String>
{
    match ext_hdr {
        0	=> Some("Hop-by-Hop Extension Header".to_string()),
        43	=> Some("Routing Extension Header".to_string()),
        44	=> Some("Fragment Extension Header".to_string()),
        51	=> Some("Authentication Header (AH) Extension Header".to_string()),
        50	=> Some("Encapsulating Security Payload (ESP) Extension Header".to_string()),
        60	=> Some("Destination Extension Header".to_string()),
        135	=> Some("Mobility Extension Header".to_string()),
        139	=> Some("Host Identity Protocol Extension Header".to_string()),
        140	=> Some("Shim6 Protocol Extension Header".to_string()),
        _   => None,
    }

}

pub fn protocol_to_str(next_hdr: usize) -> Option<String>
{
    match next_hdr {
        PROTO_TYPE_ICMP   => Some("ICMP".to_string()),
        PROTO_TYPE_IPINIP   => Some("IP in IP".to_string()),
        PROTO_TYPE_TCP   => Some("TCP".to_string()),
        PROTO_TYPE_UDP  => Some("UDP".to_string()),
        PROTO_TYPE_ICMPV6  => Some("ICMPv6".to_string()),
        _   => None,
    }

}

pub fn port_to_str(port: u16) -> Option<String>
{
    match port {
        WELLKNOWN_PORT_FTP_DATA   => Some("FTP-Data".to_string()),
        WELLKNOWN_PORT_FTP_CTRL   => Some("FTP-Control".to_string()),
        WELLKNOWN_PORT_DNS        => Some("DNS".to_string()),
        WELLKNOWN_PORT_DHCP_SVR        => Some("DHCP-Server".to_string()),
        WELLKNOWN_PORT_DHCP_CLI        => Some("DHCP-Client".to_string()),
        WELLKNOWN_PORT_HTTP        => Some("HTTP".to_string()),
        WELLKNOWN_PORT_GTPV2       => Some("GTPv2-C".to_string()),
        // 5G
        WELLKNOWN_PORT_PFCP       => Some("PFCP".to_string()),
        _       => None,
    }
}
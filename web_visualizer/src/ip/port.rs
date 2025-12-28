pub const PROTO_TYPE_ICMP: usize    = 1;
pub const PROTO_TYPE_IPINIP: usize  = 4;
pub const PROTO_TYPE_TCP: usize     = 6;
pub const PROTO_TYPE_UDP: usize     = 17;
pub const PROTO_TYPE_ICMPV6: usize  = 58;

pub const WELLKNOWN_PORT_FTP_DATA: u16     = 20;
pub const WELLKNOWN_PORT_FTP_CTRL: u16     = 21;
pub const WELLKNOWN_PORT_DNS: u16          = 53;
pub const WELLKNOWN_PORT_DHCP_SVR: u16     = 67;
pub const WELLKNOWN_PORT_DHCP_CLI: u16     = 68;
pub const WELLKNOWN_PORT_HTTP: u16         = 80;
pub const WELLKNOWN_PORT_GTPV2: u16        = 2123;
pub const WELLKNOWN_PORT_PFCP: u16         = 8805;

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
        WELLKNOWN_PORT_DHCP_SVR   => Some("DHCP-Server".to_string()),
        WELLKNOWN_PORT_DHCP_CLI   => Some("DHCP-Client".to_string()),
        WELLKNOWN_PORT_HTTP       => Some("HTTP".to_string()),
        WELLKNOWN_PORT_GTPV2      => Some("GTPv2-C".to_string()),
        // 5G
        WELLKNOWN_PORT_PFCP       => Some("PFCP".to_string()),
        _       => None,
    }
}
#![allow(dead_code)]
/* Node Message */
pub const PFCP_HEARTBEAT_REQUEST: u8                = 1;
pub const PFCP_HEARTBEAT_RESPONSE: u8               = 2;
pub const PFCP_PFD_MANAGEMENT_REQUEST: u8           = 3;
pub const PFCP_PFD_MANAGEMENT_RESPONSE: u8          = 4;
pub const PFCP_ASSOCIATION_SETUP_REQUEST: u8        = 5;
pub const PFCP_ASSOCIATION_SETUP_RESPONSE: u8       = 6;
pub const PFCP_ASSOCIATION_UPDATE_REQUEST: u8       = 7;
pub const PFCP_ASSOCIATION_UPDATE_RESPONSE: u8      = 8;
pub const PFCP_ASSOCIATION_RELEASE_REQUEST: u8      = 9;
pub const PFCP_ASSOCIATION_RELEASE_RESPONSE: u8     = 10;
pub const PFCP_VERSION_NOT_SUPPORTED_RESPONSE: u8   = 11;
pub const PFCP_NODE_REPORT_REQUEST: u8              = 12;
pub const PFCP_NODE_REPORT_RESPONSE: u8             = 13;
pub const PFCP_SESSION_SET_DELETION_REQUEST: u8     = 14;
pub const PFCP_SESSION_SET_DELETION_RESPONSE: u8    = 15;
pub const PFCP_SESSION_SET_MODIFICATION_REQUEST: u8 = 16;
pub const PFCP_SESSION_SET_MODIFCATION_RESPONSE: u8 = 17;

/* Session Message */
pub const PFCP_SESSION_ESTABLISHMENT_REQUEST: u8    = 50;
pub const PFCP_SESSION_ESTABLISHMENT_RESPONSE: u8   = 51;
pub const PFCP_SESSION_MODIFICATION_REQUEST: u8     = 52;
pub const PFCP_SESSION_MODIFICATION_RESPONSE: u8    = 53;
pub const PFCP_SESSION_DELETION_REQUEST: u8         = 54;
pub const PFCP_SESSION_DELETION_RESPONSE: u8        = 55;
pub const PFCP_SESSION_REPORT_REQUEST: u8           = 56;
pub const PFCP_SESSION_REPORT_RESPONSE: u8          = 57;

pub static PFCP_MSG_TYPES: [&str; 57] = [
    "Heartbeat Request",                //1
    "Heartbeat Response",               //2
    "PFD Management Request",           //3
    "PFD Management Response",          //4
    "Association Setup Reuqest",        //5
    "Association Setup Response",       //6
    "Association Update Request",       //7
    "Association Update Response",      //8
    "Association Release Request",      //9
    "Association Release Response",     //10
    "Version Not Suported Response",    //11
    "Node Report Request",              //12
    "Node Report Response",             //13
    "Session Set Deletion Request",     //14
    "Session Set Deletion Response",    //15
    "Session Set Modification Request", //16
    "Session Set Modification Response",//17
    "Unknwon",                          //18
    "Unknwon",                          //19
    "Unknwon",                          //20
    "Unknwon",                          //21
    "Unknwon",                          //22
    "Unknwon",                          //23
    "Unknwon",                          //24
    "Unknwon",                          //25
    "Unknwon",                          //26
    "Unknwon",                          //27
    "Unknwon",                          //28
    "Unknwon",                          //29
    "Unknwon",                          //30
    "Unknwon",                          //31
    "Unknwon",                          //32
    "Unknwon",                          //33
    "Unknwon",                          //34
    "Unknwon",                          //35
    "Unknwon",                          //36
    "Unknwon",                          //37
    "Unknwon",                          //38
    "Unknwon",                          //39
    "Unknwon",                          //40
    "Unknwon",                          //41
    "Unknwon",                          //42
    "Unknwon",                          //43
    "Unknwon",                          //44
    "Unknwon",                          //45
    "Unknwon",                          //46
    "Unknwon",                          //47
    "Unknwon",                          //48
    "Unknwon",                          //49
    "Session Establishment Request",    //50
    "Session Establishment Response",   //51
    "Session Modification Request",     //52
    "Session Modification Response",    //53
    "Session Deletetion Request",       //54
    "Session Deletetion Response",      //55
    "Session Report Request",           //56
    "Session Report Response",          //57
];


// pub const PFCP_IE_RESERVED: u16         = 0;
pub const PFCP_IE_CREATE_PDR: u16         = 1;
pub const PFCP_IE_PDI: u16         = 2;
pub const PFCP_IE_CREATE_FAR: u16         = 3;
pub const PFCP_IE_FORWARDING_PARAMETERS: u16         = 4;
pub const PFCP_IE_DUPLICATING_PARAMETERS: u16         = 5;
pub const PFCP_IE_CREATE_URR: u16         = 6;
pub const PFCP_IE_CREATE_QER: u16         = 7;
pub const PFCP_IE_CREATED_PDR: u16         = 8;
pub const PFCP_IE_UPDATE_PDR: u16         = 9;
pub const PFCP_IE_UPDATE_FAR: u16         = 10;
pub const PFCP_IE_UPDATE_FORWARDING_PARAMETERS: u16         = 11;
pub const PFCP_IE_UPDATE_BAR_PFCP_SESSION_REPORT_RESPONSE: u16         = 12;
pub const PFCP_IE_UPDATE_URR: u16         = 13;
pub const PFCP_IE_UPDATE_QER: u16         = 14;
pub const PFCP_IE_REMOVE_PDR: u16         = 15;
pub const PFCP_IE_REMOVE_FAR: u16			= 16;
pub const PFCP_IE_REMOVE_URR: u16			= 17;
pub const PFCP_IE_REMOVE_QER: u16			= 18;
pub const PFCP_IE_CAUSE: u16			= 19;
pub const PFCP_IE_SOURCE_INTERFACE: u16			= 20;
pub const PFCP_IE_F_TEID: u16			= 21;
pub const PFCP_IE_NETWORK_INSTANCE: u16			= 22;
pub const PFCP_IE_SDF_FILTER: u16			= 23;
pub const PFCP_IE_APPLICATION_ID: u16			= 24;
pub const PFCP_IE_GATE_STATUS: u16			= 25;
pub const PFCP_IE_MBR: u16			= 26;
pub const PFCP_IE_GBR: u16			= 27;
pub const PFCP_IE_QER_CORRELATION_ID: u16			= 28;
pub const PFCP_IE_PRECEDENCE: u16			= 29;
pub const PFCP_IE_TRANSPORT_LEVEL_MARKING: u16			= 30;
pub const PFCP_IE_VOLUME_THRESHOLD: u16			= 31;
pub const PFCP_IE_TIME_THRESHOLD: u16			= 32;
pub const PFCP_IE_MONITORING_TIME: u16			= 33;
pub const PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD: u16			= 34;
pub const PFCP_IE_SUBSEQUENT_TIME_THRESHOLD: u16			= 35;
pub const PFCP_IE_INACTIVITY_DETECTION_TIME: u16			= 36;
pub const PFCP_IE_REPORTING_TRIGGERS: u16			= 37;
pub const PFCP_IE_REDIRECT_INFORMATION: u16			= 38;
pub const PFCP_IE_REPORT_TYPE: u16			= 39;
pub const PFCP_IE_OFFENDING_IE: u16			= 40;
pub const PFCP_IE_FORWARDING_POLICY: u16			= 41;
pub const PFCP_IE_DESTINATION_INTERFACE: u16			= 42;
pub const PFCP_IE_UP_FUNCTION_FEATURES: u16			= 43;
pub const PFCP_IE_APPLY_ACTION: u16			= 44;
pub const PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION: u16			= 45;
pub const PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY: u16			= 46;
pub const PFCP_IE_DL_BUFFERING_DURATION: u16			= 47;
pub const PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT: u16			= 48;
pub const PFCP_IE_PFCPSMREQ_FLAGS: u16			= 49;
pub const PFCP_IE_PFCPSRRSP_FLAGS: u16			= 50;
pub const PFCP_IE_LOAD_CONTROL_INFORMATION: u16			= 51;
pub const PFCP_IE_SEQUENCE_NUMBER: u16			= 52;
pub const PFCP_IE_METRIC: u16			= 53;
pub const PFCP_IE_OVERLOAD_CONTROL_INFORMATION: u16			= 54;
pub const PFCP_IE_TIMER: u16			= 55;
pub const PFCP_IE_PDR_ID: u16			= 56;
pub const PFCP_IE_F_SEID: u16			= 57;
pub const PFCP_IE_APPLICATION_ID_PFDS: u16			= 58;
pub const PFCP_IE_PFD_CONTEXT: u16			= 59;
pub const PFCP_IE_NODE_ID: u16			= 60;
pub const PFCP_IE_PFD_CONTENTS: u16			= 61;
pub const PFCP_IE_MEASUREMENT_METHOD: u16			= 62;
pub const PFCP_IE_USAGE_REPORT_TRIGGER: u16			= 63;
pub const PFCP_IE_MEASUREMENT_PERIOD: u16			= 64;
pub const PFCP_IE_FQ_CSID: u16			= 65;
pub const PFCP_IE_VOLUME_MEASUREMENT: u16			= 66;
pub const PFCP_IE_DURATION_MEASUREMENT: u16			= 67;
pub const PFCP_IE_APPLICATION_DETECTION_INFORMATION: u16			= 68;
pub const PFCP_IE_TIME_OF_FIRST_PACKET: u16			= 69;
pub const PFCP_IE_TIME_OF_LAST_PACKET: u16			= 70;
pub const PFCP_IE_QUOTA_HOLDING_TIME: u16			= 71;
pub const PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD: u16			= 72;
pub const PFCP_IE_VOLUME_QUOTA: u16			= 73;
pub const PFCP_IE_TIME_QUOTA: u16			= 74;
pub const PFCP_IE_START_TIME: u16			= 75;
pub const PFCP_IE_END_TIME: u16			= 76;
pub const PFCP_IE_QUERY_URR: u16			= 77;
pub const PFCP_IE_USAGE_REPORT_SESSION_MODIFICATION_RESPONSE: u16			= 78;
pub const PFCP_IE_USAGE_REPORT_SESSION_DELETION_RESPONSE: u16			= 79;
pub const PFCP_IE_USAGE_REPORT_SESSION_REPORT_REQUEST: u16			= 80;
pub const PFCP_IE_URR_ID: u16			= 81;
pub const PFCP_IE_LINKED_URR_ID: u16			= 82;
pub const PFCP_IE_DOWNLINK_DATA_REPORT: u16			= 83;
pub const PFCP_IE_OUTER_HEADER_CREATION: u16			= 84;
pub const PFCP_IE_CREATE_BAR: u16			= 85;
pub const PFCP_IE_UPDATE_BAR_SESSION_MODIFICATION_REQUEST: u16			= 86;
pub const PFCP_IE_REMOVE_BAR: u16			= 87;
pub const PFCP_IE_BAR_ID: u16			= 88;
pub const PFCP_IE_CP_FUNCTION_FEATURES: u16			= 89;
pub const PFCP_IE_USAGE_INFORMATION: u16			= 90;
pub const PFCP_IE_APPLICATION_INSTANCE_ID: u16			= 91;
pub const PFCP_IE_FLOW_INFORMATION: u16			= 92;
pub const PFCP_IE_UE_IP_ADDRESS: u16			= 93;
pub const PFCP_IE_PACKET_RATE: u16			= 94;
pub const PFCP_IE_OUTER_HEADER_REMOVAL: u16			= 95;
pub const PFCP_IE_RECOVERY_TIME_STAMP: u16			= 96;
pub const PFCP_IE_DL_FLOW_LEVEL_MARKING: u16			= 97;
pub const PFCP_IE_HEADER_ENRICHMENT: u16			= 98;
pub const PFCP_IE_ERROR_INDICATION_REPORT: u16			= 99;
pub const PFCP_IE_MEASUREMENT_INFORMATION: u16			= 100;
pub const PFCP_IE_NODE_REPORT_TYPE: u16			= 101;
pub const PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT: u16			= 102;
pub const PFCP_IE_REMOTE_GTP_U_PEER: u16			= 103;
pub const PFCP_IE_UR_SEQN: u16			= 104;
pub const PFCP_IE_UPDATE_DUPLICATING_PARAMETERS: u16			= 105;
pub const PFCP_IE_ACTIVATE_PREDEFINED_RULES: u16			= 106;
pub const PFCP_IE_DEACTIVATE_PREDEFINED_RULES: u16			= 107;
pub const PFCP_IE_FAR_ID: u16			= 108;
pub const PFCP_IE_QER_ID: u16			= 109;
pub const PFCP_IE_OCI_FLAGS: u16			= 110;
pub const PFCP_IE_PFCP_ASSOCIATION_RELEASE_REQUEST: u16			= 111;
pub const PFCP_IE_GRACEFUL_RELEASE_PERIOD: u16			= 112;
pub const PFCP_IE_PDN_TYPE: u16			= 113;
pub const PFCP_IE_FAILED_RULE_ID: u16			= 114;
pub const PFCP_IE_TIME_QUOTA_MECHANISM: u16			= 115;
// pub const PFCP_IE_RESERVED: u16			= 116;
pub const PFCP_IE_USER_PLANE_INACTIVITY_TIMER: u16			= 117;
pub const PFCP_IE_AGGREGATED_URRS: u16			= 118;
pub const PFCP_IE_MULTIPLIER: u16			= 119;
pub const PFCP_IE_AGGREGATED_URR_ID: u16			= 120;
pub const PFCP_IE_SUBSEQUENT_VOLUME_QUOTA: u16			= 121;
pub const PFCP_IE_SUBSEQUENT_TIME_QUOTA: u16			= 122;
pub const PFCP_IE_RQI: u16			= 123;
pub const PFCP_IE_QFI: u16			= 124;
pub const PFCP_IE_QUERY_URR_REFERENCE: u16			= 125;
pub const PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION: u16			= 126;
pub const PFCP_IE_CREATE_TRAFFIC_ENDPOINT: u16			= 127;
pub const PFCP_IE_CREATED_TRAFFIC_ENDPOINT: u16			= 128;
pub const PFCP_IE_UPDATE_TRAFFIC_ENDPOINT: u16			= 129;
pub const PFCP_IE_REMOVE_TRAFFIC_ENDPOINT: u16			= 130;
pub const PFCP_IE_TRAFFIC_ENDPOINT_ID: u16			= 131;
pub const PFCP_IE_ETHERNET_PACKET_FILTER: u16			= 132;
pub const PFCP_IE_MAC_ADDRESS: u16			= 133;
pub const PFCP_IE_C_TAG: u16			= 134;
pub const PFCP_IE_S_TAG: u16			= 135;
pub const PFCP_IE_ETHERTYPE: u16			= 136;
pub const PFCP_IE_PROXYING: u16			= 137;
pub const PFCP_IE_ETHERNET_FILTER_ID: u16			= 138;
pub const PFCP_IE_ETHERNET_FILTER_PROPERTIES: u16			= 139;
pub const PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT: u16			= 140;
pub const PFCP_IE_USER_ID: u16			= 141;
pub const PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION: u16			= 142;
pub const PFCP_IE_ETHERNET_TRAFFIC_INFORMATION: u16			= 143;
pub const PFCP_IE_MAC_ADDRESSES_DETECTED: u16			= 144;
pub const PFCP_IE_MAC_ADDRESSES_REMOVED: u16			= 145;
pub const PFCP_IE_ETHERNET_INACTIVITY_TIMER: u16			= 146;
pub const PFCP_IE_ADDITIONAL_MONITORING_TIME: u16			= 147;
pub const PFCP_IE_EVENT_QUOTA: u16			= 148;
pub const PFCP_IE_EVENT_THRESHOLD: u16			= 149;
pub const PFCP_IE_SUBSEQUENT_EVENT_QUOTA: u16			= 150;
pub const PFCP_IE_SUBSEQUENT_EVENT_THRESHOLD: u16			= 151;
pub const PFCP_IE_TRACE_INFORMATION: u16			= 152;
pub const PFCP_IE_FRAMED_ROUTE: u16			= 153;
pub const PFCP_IE_FRAMED_ROUTING: u16			= 154;
pub const PFCP_IE_FRAMED_IPV6_ROUTE: u16			= 155;
pub const PFCP_IE_TIME_STAMP: u16			= 156;
pub const PFCP_IE_AVERAGING_WINDOW: u16			= 157;
pub const PFCP_IE_PAGING_POLICY_INDICATOR: u16			= 158;
pub const PFCP_IE_APN_DNN: u16			= 159;
pub const PFCP_IE_3GPP_INTERFACE_TYPE: u16			= 160;
pub const PFCP_IE_PFCPSRREQ_FLAGS: u16			= 161;
pub const PFCP_IE_PFCPAUREQ_FLAGS: u16			= 162;
pub const PFCP_IE_ACTIVATION_TIME: u16			= 163;
pub const PFCP_IE_DEACTIVATION_TIME: u16			= 164;
pub const PFCP_IE_CREATE_MAR: u16			= 165;
pub const PFCP_IE_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION: u16			= 166;
pub const PFCP_IE_NON_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION: u16			= 167;
pub const PFCP_IE_REMOVE_MAR: u16			= 168;
pub const PFCP_IE_UPDATE_MAR: u16			= 169;
pub const PFCP_IE_MAR_ID: u16			= 170;
pub const PFCP_IE_STEERING_FUNCTIONALITY: u16			= 171;
pub const PFCP_IE_STEERING_MODE: u16			= 172;
pub const PFCP_IE_WEIGHT: u16			= 173;
pub const PFCP_IE_PRIORITY: u16			= 174;
pub const PFCP_IE_UPDATE_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION: u16			= 175;
pub const PFCP_IE_UPDATE_NON_3GPP_ACCESS_FORWARDING_ACTION_INFORMATION: u16			= 176;
pub const PFCP_IE_UE_IP_ADDRESS_POOL_IDENTITY: u16			= 177;
pub const PFCP_IE_ALTERNATIVE_SMF_IP_ADDRESS: u16			= 178;
pub const PFCP_IE_PACKET_REPLICATION_AND_DETECTION_CARRY_ON_INFORMATION: u16			= 179;
pub const PFCP_IE_SMF_SET_ID: u16			= 180;
pub const PFCP_IE_QUOTA_VALIDITY_TIME: u16			= 181;
pub const PFCP_IE_NUMBER_OF_REPORTS: u16			= 182;
pub const PFCP_IE_PFCP_SESSION_RETENTION_INFORMATION_WITHIN_PFCP_ASSOCIATION_SETUP_REQUEST: u16			= 183;
pub const PFCP_IE_PFCPASRSP_FLAGS: u16			= 184;
pub const PFCP_IE_CP_PFCP_ENTITY_IP_ADDRESS: u16			= 185;
pub const PFCP_IE_PFCPSEREQ_FLAGS: u16			= 186;
pub const PFCP_IE_USER_PLANE_PATH_RECOVERY_REPORT: u16			= 187;
pub const PFCP_IE_IP_MULTICAST_ADDRESSING_INFO_WITHIN_PFCP_SESSION_ESTABLISHMENT_REQUEST: u16			= 188;
pub const PFCP_IE_JOIN_IP_MULTICAST_INFORMATION_IE_WITHIN_USAGE_REPORT: u16			= 189;
pub const PFCP_IE_LEAVE_IP_MULTICAST_INFORMATION_IE_WITHIN_USAGE_REPORT: u16			= 190;
pub const PFCP_IE_IP_MULTICAST_ADDRESS: u16			= 191;
pub const PFCP_IE_SOURCE_IP_ADDRESS: u16			= 192;
pub const PFCP_IE_PACKET_RATE_STATUS: u16			= 193;
pub const PFCP_IE_CREATE_BRIDGE_ROUTER_INFO: u16			= 194;
pub const PFCP_IE_CREATED_BRIDGE_ROUTER_INFO: u16			= 195;
pub const PFCP_IE_PORT_NUMBER: u16			= 196;
pub const PFCP_IE_NW_TT_PORT_NUMBER: u16			= 197;
pub const PFCP_IE_5GS_USER_PLANE_NODE_ID: u16			= 198;
pub const PFCP_IE_TSC_MANAGEMENT_INFORMATION_IE_WITHIN_PFCP_SESSION_MODIFICATION_REQUEST: u16			= 199;
pub const PFCP_IE_TSC_MANAGEMENT_INFORMATION_IE_WITHIN_PFCP_SESSION_MODIFICATION_RESPONSE: u16			= 200;
pub const PFCP_IE_TSC_MANAGEMENT_INFORMATION_IE_WITHIN_PFCP_SESSION_REPORT_REQUEST: u16			= 201;
pub const PFCP_IE_PORT_MANAGEMENT_INFORMATION_CONTAINER: u16			= 202;
pub const PFCP_IE_CLOCK_DRIFT_CONTROL_INFORMATION: u16			= 203;
pub const PFCP_IE_REQUESTED_CLOCK_DRIFT_INFORMATION: u16			= 204;
pub const PFCP_IE_CLOCK_DRIFT_REPORT: u16			= 205;
pub const PFCP_IE_TIME_DOMAIN_NUMBER: u16			= 206;
pub const PFCP_IE_TIME_OFFSET_THRESHOLD: u16			= 207;
pub const PFCP_IE_CUMULATIVE_RATERATIO_THRESHOLD: u16			= 208;
pub const PFCP_IE_TIME_OFFSET_MEASUREMENT: u16			= 209;
pub const PFCP_IE_CUMULATIVE_RATERATIO_MEASUREMENT: u16			= 210;
pub const PFCP_IE_REMOVE_SRR: u16			= 211;
pub const PFCP_IE_CREATE_SRR: u16			= 212;
pub const PFCP_IE_UPDATE_SRR: u16			= 213;
pub const PFCP_IE_SESSION_REPORT: u16			= 214;
pub const PFCP_IE_SRR_ID: u16			= 215;
pub const PFCP_IE_ACCESS_AVAILABILITY_CONTROL_INFORMATION: u16			= 216;
pub const PFCP_IE_REQUESTED_ACCESS_AVAILABILITY_INFORMATION: u16			= 217;
pub const PFCP_IE_ACCESS_AVAILABILITY_REPORT: u16			= 218;
pub const PFCP_IE_ACCESS_AVAILABILITY_INFORMATION: u16			= 219;
pub const PFCP_IE_PROVIDE_ATSSS_CONTROL_INFORMATION: u16			= 220;
pub const PFCP_IE_ATSSS_CONTROL_PARAMETERS: u16			= 221;
pub const PFCP_IE_MPTCP_CONTROL_INFORMATION: u16			= 222;
pub const PFCP_IE_ATSSS_LL_CONTROL_INFORMATION: u16			= 223;
pub const PFCP_IE_PMF_CONTROL_INFORMATION: u16			= 224;
pub const PFCP_IE_MPTCP_PARAMETERS: u16			= 225;
pub const PFCP_IE_ATSSS_LL_PARAMETERS: u16			= 226;
pub const PFCP_IE_PMF_PARAMETERS: u16			= 227;
pub const PFCP_IE_MPTCP_ADDRESS_INFORMATION: u16			= 228;
pub const PFCP_IE_LINK_SPECIFIC_MULTIPATH_IP_ADDRESS: u16			= 229;
pub const PFCP_IE_PMF_ADDRESS_INFORMATION: u16			= 230;
pub const PFCP_IE_ATSSS_LL_INFORMATION: u16			= 231;
pub const PFCP_IE_DATA_NETWORK_ACCESS_IDENTIFIER: u16			= 232;
pub const PFCP_IE_UE_IP_ADDRESS_POOL_INFORMATION: u16			= 233;
pub const PFCP_IE_AVERAGE_PACKET_DELAY: u16			= 234;
pub const PFCP_IE_MINIMUM_PACKET_DELAY: u16			= 235;
pub const PFCP_IE_MAXIMUM_PACKET_DELAY: u16			= 236;
pub const PFCP_IE_QOS_REPORT_TRIGGER: u16			= 237;
pub const PFCP_IE_GTP_U_PATH_QOS_CONTROL_INFORMATION: u16			= 238;
pub const PFCP_IE_GTP_U_PATH_QOS_REPORT_PFCP_NODE_REPORT_REQUEST: u16			= 239;
pub const PFCP_IE_QOS_INFORMATION_IN_GTP_U_PATH_QOS_REPORT: u16			= 240;
pub const PFCP_IE_GTP_U_PATH_INTERFACE_TYPE: u16			= 241;
pub const PFCP_IE_QOS_MONITORING_PER_QOS_FLOW_CONTROL_INFORMATION: u16			= 242;
pub const PFCP_IE_REQUESTED_QOS_MONITORING: u16			= 243;
pub const PFCP_IE_REPORTING_FREQUENCY: u16			= 244;
pub const PFCP_IE_PACKET_DELAY_THRESHOLDS: u16			= 245;
pub const PFCP_IE_MINIMUM_WAIT_TIME: u16			= 246;
pub const PFCP_IE_QOS_MONITORING_REPORT: u16			= 247;
pub const PFCP_IE_QOS_MONITORING_MEASUREMENT: u16			= 248;
pub const PFCP_IE_MT_EDT_CONTROL_INFORMATION: u16			= 249;
pub const PFCP_IE_DL_DATA_PACKETS_SIZE: u16			= 250;
pub const PFCP_IE_QER_CONTROL_INDICATIONS: u16			= 251;
pub const PFCP_IE_PACKET_RATE_STATUS_REPORT: u16			= 252;
pub const PFCP_IE_NF_INSTANCE_ID: u16			= 253;
pub const PFCP_IE_ETHERNET_CONTEXT_INFORMATION: u16			= 254;
pub const PFCP_IE_REDUNDANT_TRANSMISSION_PARAMETERS: u16			= 255;
pub const PFCP_IE_UPDATED_PDR: u16			= 256;
pub const PFCP_IE_S_NSSAI: u16			= 257;
pub const PFCP_IE_IP_VERSION: u16			= 258;
pub const PFCP_IE_PFCPASREQ_FLAGS: u16			= 259;
pub const PFCP_IE_DATA_STATUS: u16			= 260;
pub const PFCP_IE_PROVIDE_RDS_CONFIGURATION_INFORMATION: u16			= 261;
pub const PFCP_IE_RDS_CONFIGURATION_INFORMATION: u16			= 262;
pub const PFCP_IE_QUERY_PACKET_RATE_STATUS_IE_WITHIN_PFCP_SESSION_MODIFICATION_REQUEST: u16			= 263;
pub const PFCP_IE_PACKET_RATE_STATUS_REPORT_IE_WITHIN_PFCP_SESSION_MODIFICATION_RESPONSE: u16			= 264;
pub const PFCP_IE_MULTIPATH_APPLICABLE_INDICATION: u16			= 265;
pub const PFCP_IE_USER_PLANE_NODE_MANAGEMENT_INFORMATION_CONTAINER: u16			= 266;
pub const PFCP_IE_UE_IP_ADDRESS_USAGE_INFORMATION: u16			= 267;
pub const PFCP_IE_NUMBER_OF_UE_IP_ADDRESSES: u16			= 268;
pub const PFCP_IE_VALIDITY_TIMER: u16			= 269;
pub const PFCP_IE_REDUNDANT_TRANSMISSION_FORWARDING_PARAMETERS: u16			= 270;
pub const PFCP_IE_TRANSPORT_DELAY_REPORTING: u16			= 271;
pub const PFCP_IE_PARTIAL_FAILURE_INFORMATION: u16			= 272;
pub const PFCP_IE_SPARE: u16			= 273;
pub const PFCP_IE_OFFENDING_IE_INFORMATION: u16			= 274;
pub const PFCP_IE_RAT_TYPE: u16			= 275;
pub const PFCP_IE_L2TP_TUNNEL_INFORMATION: u16			= 276;
pub const PFCP_IE_L2TP_SESSION_INFORMATION: u16			= 277;
pub const PFCP_IE_L2TP_USER_AUTHENTICATION: u16			= 278;
pub const PFCP_IE_CREATED_L2TP_SESSION: u16			= 279;
pub const PFCP_IE_LNS_ADDRESS: u16			= 280;
pub const PFCP_IE_TUNNEL_PREFERENCE: u16			= 281;
pub const PFCP_IE_CALLING_NUMBER: u16			= 282;
pub const PFCP_IE_CALLED_NUMBER: u16			= 283;
pub const PFCP_IE_L2TP_SESSION_INDICATIONS: u16			= 284;
pub const PFCP_IE_DNS_SERVER_ADDRESS: u16			= 285;
pub const PFCP_IE_NBNS_SERVER_ADDRESS: u16			= 286;
pub const PFCP_IE_MAXIMUM_RECEIVE_UNIT: u16			= 287;
pub const PFCP_IE_THRESHOLDS: u16			= 288;
pub const PFCP_IE_STEERING_MODE_INDICATOR: u16			= 289;
pub const PFCP_IE_PFCP_SESSION_CHANGE_INFO: u16			= 290;
pub const PFCP_IE_GROUP_ID: u16			= 291;
pub const PFCP_IE_CP_IP_ADDRESS: u16			= 292;
pub const PFCP_IE_IP_ADDRESS_AND_PORT_NUMBER_REPLACEMENT: u16			= 293;
pub const PFCP_IE_DNS_QUERY_RESPONSE_FILTER: u16			= 294;
pub const PFCP_IE_DIRECT_REPORTING_INFORMATION: u16			= 295;
pub const PFCP_IE_EVENT_NOTIFICATION_URI: u16			= 296;
pub const PFCP_IE_NOTIFICATION_CORRELATION_ID: u16			= 297;
pub const PFCP_IE_REPORTING_FLAGS: u16			= 298;
pub const PFCP_IE_PREDEFINED_RULES_NAME: u16			= 299;
pub const PFCP_IE_MBS_SESSION_N4MB_CONTROL_INFORMATION: u16			= 300;
pub const PFCP_IE_MBS_MULTICAST_PARAMETERS: u16			= 301;
pub const PFCP_IE_ADD_MBS_UNICAST_PARAMETERS: u16			= 302;
pub const PFCP_IE_MBS_SESSION_N4MB_INFORMATION: u16			= 303;
pub const PFCP_IE_REMOVE_MBS_UNICAST_PARAMETERS: u16			= 304;
pub const PFCP_IE_MBS_SESSION_IDENTIFIER: u16			= 305;
pub const PFCP_IE_MULTICAST_TRANSPORT_INFORMATION: u16			= 306;
pub const PFCP_IE_MBSN4MBREQ_FLAGS: u16			= 307;
pub const PFCP_IE_LOCAL_INGRESS_TUNNEL: u16			= 308;
pub const PFCP_IE_MBS_UNICAST_PARAMETERS_ID: u16			= 309;
pub const PFCP_IE_MBS_SESSION_N4_CONTROL_INFORMATION: u16			= 310;
pub const PFCP_IE_MBS_SESSION_N4_INFORMATION: u16			= 311;
pub const PFCP_IE_MBSN4RESP_FLAGS: u16			= 312;
pub const PFCP_IE_TUNNEL_PASSWORD: u16			= 313;
pub const PFCP_IE_AREA_SESSION_ID: u16			= 314;
pub const PFCP_IE_PEER_UP_RESTART_REPORT: u16			= 315;
pub const PFCP_IE_DSCP_TO_PPI_CONTROL_INFORMATION: u16			= 316;
pub const PFCP_IE_DSCP_TO_PPI_MAPPING_INFORMATION: u16			= 317;
pub const PFCP_IE_PFCPSDRSP_FLAGS: u16			= 318;
pub const PFCP_IE_QER_INDICATIONS: u16			= 319;
pub const PFCP_IE_VENDOR_SPECIFIC_NODE_REPORT_TYPE: u16			= 320;
pub const PFCP_IE_CONFIGURED_TIME_DOMAIN: u16			= 321;
pub const PFCP_IE_METADATA: u16			= 322;
pub const PFCP_IE_TRAFFIC_PARAMETER_MEASUREMENT_CONTROL_INFORMATION: u16			= 323;
pub const PFCP_IE_TRAFFIC_PARAMETER_MEASUREMENT_REPORT: u16			= 324;
pub const PFCP_IE_TRAFFIC_PARAMETER_THRESHOLD: u16			= 325;
pub const PFCP_IE_DL_PERIODICITY: u16			= 326;
pub const PFCP_IE_N6_JITTER_MEASUREMENT: u16			= 327;
pub const PFCP_IE_TRAFFIC_PARAMETER_MEASUREMENT_INDICATION: u16			= 328;
pub const PFCP_IE_UL_PERIODICITY: u16			= 329;
pub const PFCP_IE_MPQUIC_CONTROL_INFORMATION: u16			= 330;
pub const PFCP_IE_MPQUIC_PARAMETERS: u16			= 331;
pub const PFCP_IE_MPQUIC_ADDRESS_INFORMATION: u16			= 332;
pub const PFCP_IE_TRANSPORT_MODE: u16			= 333;
pub const PFCP_IE_PROTOCOL_DESCRIPTION: u16			= 334;
pub const PFCP_IE_REPORTING_SUGGESTION_INFO: u16			= 335;
pub const PFCP_IE_TL_CONTAINER: u16			= 336;
pub const PFCP_IE_MEASUREMENT_INDICATION: u16			= 337;
pub const PFCP_IE_HPLMN_S_NSSAI: u16			= 338;
pub const PFCP_IE_MEDIA_TRANSPORT_PROTOCOL: u16			= 339;
pub const PFCP_IE_RTP_HEADER_EXTENSION_INFORMATION: u16			= 340;
pub const PFCP_IE_RTP_PAYLOAD_INFORMATION: u16			= 341;
pub const PFCP_IE_RTP_HEADER_EXTENSION_TYPE: u16			= 342;
pub const PFCP_IE_RTP_HEADER_EXTENSION_ID: u16			= 343;
pub const PFCP_IE_RTP_PAYLOAD_TYPE: u16			= 344;
pub const PFCP_IE_RTP_PAYLOAD_FORMAT: u16			= 345;
pub const PFCP_IE_EXTENDED_DL_BUFFERING_NOTIFICATION_POLICY: u16			= 346;
pub const PFCP_IE_MT_SDT_CONTROL_INFORMATION: u16			= 347;
pub const PFCP_IE_REPORTING_THRESHOLDS: u16			= 348;
pub const PFCP_IE_RTP_HEADER_EXTENSION_ADDITIONAL_INFORMATION: u16			= 349;
pub const PFCP_IE_MAPPED_N6_IP_ADDRESS: u16			= 350;
pub const PFCP_IE_N6_ROUTING_INFORMATION: u16			= 351;


pub static PFCP_IE_TYPES: [(&str, bool);352] = [
("Reserved", false),
("Create PDR",false),
("PDI",false),
("Create FAR",false),
("Forwarding Parameters",false),
("Duplicating Parameters",false),
("Create URR",false),
("Create QER",false),
("Created PDR",false),
("Update PDR",false),
("Update FAR",false),
("Update Forwarding Parameters",false),
("Update BAR (PFCP Session Report Response)",false),
("Update URR",false),
("Update QER",false),
("Remove PDR",false),
("Remove FAR",false),
("Remove URR",false),
("Remove QER",false),
("Cause",false),
("Source Interface",false),
("F-TEID",false),
("Network Instance",false),
("SDF Filter",false),
("Application ID",false),
("Gate Status",false),
("MBR",false),
("GBR",false),
("QER Correlation ID",false),
("Precedence",false),
("Transport Level Marking",false),
("Volume Threshold",false),
("Time Threshold",false),
("Monitoring Time",false),
("Subsequent Volume Threshold",false),
("Subsequent Time Threshold",false),
("Inactivity Detection Time",false),
("Reporting Triggers",false),
("Redirect Information",false),
("Report Type",false),
("Offending IE",false),
("Forwarding Policy",false),
("Destination Interface",false),
("UP Function Features",false),
("Apply Action",false),
("Downlink Data Service Information",false),
("Downlink Data Notification Delay",false),
("DL Buffering Duration",false),
("DL Buffering Suggested Packet Count",false),
("PFCPSMReq-Flags",false),
("PFCPSRRsp-Flags",false),
("Load Control Information",false),
("Sequence Number",false),
("Metric",false),
("Overload Control Information",false),
("Timer",false),
("PDR ID",false),
("F-SEID",false),
("Application ID's PFDs",false),
("PFD context",false),
("Node ID",false),
("PFD contents",false),
("Measurement Method",false),
("Usage Report Trigger",false),
("Measurement Period",false),
("FQ-CSID",false),
("Volume Measurement",false),
("Duration Measurement",false),
("Application Detection Information",false),
("Time of First Packet",false),
("Time of Last Packet",false),
("Quota Holding Time",false),
("Dropped DL Traffic Threshold",false),
("Volume Quota",false),
("Time Quota",false),
("Start Time",false),
("End Time",false),
("Query URR",false),
("Usage Report (Session Modification Response)",false),
("Usage Report (Session Deletion Response)",false),
("Usage Report (Session Report Request)",false),
("URR ID",false),
("Linked URR ID",false),
("Downlink Data Report",false),
("Outer Header Creation",false),
("Create BAR",false),
("Update BAR (Session Modification Request)",false),
("Remove BAR",false),
("BAR ID",false),
("CP Function Features",false),
("Usage Information",false),
("Application Instance ID",false),
("Flow Information",false),
("UE IP Address",false),
("Packet Rate",false),
("Outer Header Removal",false),
("Recovery Time Stamp",false),
("DL Flow Level Marking",false),
("Header Enrichment",false),
("Error Indication Report",false),
("Measurement Information",false),
("Node Report Type",false),
("User Plane Path Failure Report",false),
("Remote GTP-U Peer",false),
("UR-SEQN",false),
("Update Duplicating Parameters",false),
("Activate Predefined Rules",false),
("Deactivate Predefined Rules",false),
("FAR ID",false),
("QER ID",false),
("OCI Flags",false),
("PFCP Association Release Request",false),
("Graceful Release Period",false),
("PDN Type",false),
("Failed Rule ID",false),
("Time Quota Mechanism",false),
("Reserved",false),
("User Plane Inactivity Timer",false),
("Aggregated URRs",false),
("Multiplier",false),
("Aggregated URR ID",false),
("Subsequent Volume Quota",false),
("Subsequent Time Quota",false),
("RQI",false),
("QFI",false),
("Query URR Reference",false),
("Additional Usage Reports Information",false),
("Create Traffic Endpoint",false),
("Created Traffic Endpoint",false),
("Update Traffic Endpoint",false),
("Remove Traffic Endpoint",false),
("Traffic Endpoint ID",false),
("Ethernet Packet Filter",false),
("MAC address",false),
("C-TAG",false),
("S-TAG",false),
("Ethertype",false),
("Proxying",false),
("Ethernet Filter ID",false),
("Ethernet Filter Properties",false),
("Suggested Buffering Packets Count",false),
("User ID",false),
("Ethernet PDU Session Information",false),
("Ethernet Traffic Information",false),
("MAC Addresses Detected",false),
("MAC Addresses Removed",false),
("Ethernet Inactivity Timer",false),
("Additional Monitoring Time",false),
("Event Quota",false),
("Event Threshold",false),
("Subsequent Event Quota",false),
("Subsequent Event Threshold",false),
("Trace Information",false),
("Framed-Route",false),
("Framed-Routing",false),
("Framed-IPv6-Route",false),
("Time Stamp",false),
("Averaging Window",false),
("Paging Policy Indicator",false),
("APN/DNN",false),
("3GPP Interface Type",false),
("PFCPSRReq-Flags",false),
("PFCPAUReq-Flags",false),
("Activation Time",false),
("Deactivation Time",false),
("Create MAR",false),
("3GPP Access Forwarding Action Information",false),
("Non-3GPP Access Forwarding Action Information",false),
("Remove MAR",false),
("Update MAR",false),
("MAR ID",false),
("Steering Functionality",false),
("Steering Mode",false),
("Weight",false),
("Priority",false),
("Update 3GPP Access Forwarding Action Information",false),
("Update Non 3GPP Access Forwarding Action Information",false),
("UE IP address Pool Identity",false),
("Alternative SMF IP Address",false),
("Packet Replication and Detection Carry-On Information",false),
("SMF Set ID",false),
("Quota Validity Time",false),
("Number of Reports",false),
("PFCP Session Retention Information (within PFCP Association Setup Request)",false),
("PFCPASRsp-Flags",false),
("CP PFCP Entity IP Address",false),
("PFCPSEReq-Flags",false),
("User Plane Path Recovery Report",false),
("IP Multicast Addressing Info within PFCP Session Establishment Request",false),
("Join IP Multicast Information IE within Usage Report",false),
("Leave IP Multicast Information IE within Usage Report",false),
("IP Multicast Address",false),
("Source IP Address",false),
("Packet Rate Status",false),
("Create Bridge/Router Info",false),
("Created Bridge/Router Info",false),
(" Port Number",false),
("NW-TT Port Number",false),
("5GS User Plane Node ID",false),
("TSC Management Information IE within PFCP Session Modification Request",false),
("TSC Management Information IE within PFCP Session Modification Response",false),
("TSC Management Information IE within PFCP Session Report Request",false),
("Port Management Information Container",false),
("Clock Drift Control Information",false),
("Requested Clock Drift Information",false),
("Clock Drift Report",false),
("Time Domain Number",false),
("Time Offset Threshold",false),
("Cumulative rateRatio Threshold",false),
("Time Offset Measurement",false),
("Cumulative rateRatio Measurement",false),
("Remove SRR",false),
("Create SRR",false),
("Update SRR",false),
("Session Report",false),
("SRR ID",false),
("Access Availability Control Information",false),
("Requested Access Availability Information",false),
("Access Availability Report",false),
("Access Availability Information",false),
("Provide ATSSS Control Information",false),
("ATSSS Control Parameters",false),
("MPTCP Control Information",false),
("ATSSS-LL Control Information",false),
("PMF Control Information",false),
("MPTCP Parameters",false),
("ATSSS-LL Parameters",false),
("PMF Parameters",false),
("MPTCP Address Information",false),
("Link-Specific Multipath IP Address",false),
("PMF Address Information",false),
("ATSSS-LL Information",false),
("Data Network Access Identifier",false),
("UE IP address Pool Information",false),
("Average Packet Delay",false),
("Minimum Packet Delay",false),
("Maximum Packet Delay",false),
("QoS Report Trigger",false),
("GTP-U Path QoS Control Information",false),
("GTP-U Path QoS Report (PFCP Node Report Request)",false),
("QoS Information in GTP-U Path QoS Report",false),
("GTP-U Path Interface Type",false),
("QoS Monitoring per QoS flow Control Information",false),
("Requested QoS Monitoring",false),
("Reporting Frequency",false),
("Packet Delay Thresholds",false),
("Minimum Wait Time",false),
("QoS Monitoring Report",false),
("QoS Monitoring Measurement",false),
("MT-EDT Control Information",false),
("DL Data Packets Size",false),
("QER Control Indications",false),
("Packet Rate Status Report",false),
("NF Instance ID",false),
("Ethernet Context Information",false),
("Redundant Transmission Parameters",false),
("Updated PDR",false),
("S-NSSAI",false),
("IP version",false),
("PFCPASReq-Flags",false),
("Data Status",false),
("Provide RDS configuration information",false),
("RDS configuration information",false),
("Query Packet Rate Status IE within PFCP Session Modification Request",false),
("Packet Rate Status Report IE within PFCP Session Modification Response",false),
("Multipath Applicable Indication",false),
("User Plane Node Management Information Container",false),
("UE IP Address Usage Information",false),
("Number of UE IP Addresses",false),
("Validity Timer",false),
("Redundant Transmission Forwarding Parameters",false),
("Transport Delay Reporting",false),
("Partial Failure Information",false),
("Spare",false),
("Offending IE Information",false),
("RAT Type",false),
("L2TP Tunnel Information",false),
("L2TP Session Information",false),
("L2TP User Authentication",false),
("Created L2TP Session",false),
("LNS Address",false),
("Tunnel Preference",false),
("Calling Number",false),
("Called Number",false),
("L2TP Session Indications",false),
("DNS Server Address",false),
("NBNS Server Address",false),
("Maximum Receive Unit",false),
("Thresholds",false),
("Steering Mode Indicator",false),
("PFCP Session Change Info",false),
("Group ID",false),
("CP IP Address",false),
("IP Address and Port number Replacement",false),
("DNS Query/Response Filter",false),
("Direct Reporting Information",false),
("Event Notification URI",false),
("Notification Correlation ID",false),
("Reporting Flags",false),
("Predefined Rules Name",false),
("MBS Session N4mb Control Information",false),
("MBS Multicast Parameters",false),
("Add MBS Unicast Parameters",false),
("MBS Session N4mb Information",false),
("Remove MBS Unicast Parameters",false),
("MBS Session Identifier",false),
("Multicast Transport Information",false),
("MBSN4mbReq-Flags",false),
("Local Ingress Tunnel",false),
("MBS Unicast Parameters ID",false),
("MBS Session N4 Control Information",false),
("MBS Session N4 Information",false),
("MBSN4Resp-Flags",false),
("Tunnel Password",false),
("Area Session ID",false),
("Peer UP Restart Report",false),
("DSCP to PPI Control Information",false),
("DSCP to PPI Mapping Information",false),
("PFCPSDRsp-Flags",false),
("QER Indications",false),
("Vendor-Specific Node Report Type",false),
("Configured Time Domain",false),
("Metadata",false),
("Traffic Parameter Measurement Control Information",false),
("Traffic Parameter Measurement Report",false),
("Traffic Parameter Threshold",false),
("DL Periodicity",false),
("N6 Jitter Measurement",false),
("Traffic Parameter Measurement Indication",false),
("UL Periodicity",false),
("MPQUIC Control Information",false),
("MPQUIC Parameters",false),
("MPQUIC Address Information",false),
("Transport Mode",false),
("Protocol Description",false),
("Reporting Suggestion Info",false),
("TL-Container",false),
("Measurement Indication",false),
("HPLMN S-NSSAI",false),
("Media Transport Protocol",false),
("RTP Header Extension Information",false),
("RTP Payload Information",false),
("RTP Header Extension Type",false),
("RTP Header Extension ID",false),
("RTP Payload Type",false),
("RTP Payload Format",false),
("Extended DL Buffering Notification Policy",false),
("MT-SDT Control Information",false),
("Reporting Thresholds",false),
("RTP Header Extension Additional Information",false),
("Mapped N6 IP Address",false),
("N6 Routing Information",false),
];
use std::fmt::Display;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::gtp::gtp_ie::*;
// use super::gtp_call_flow::*;

#[cfg(feature = "mock")]
use super::call_flow_test::*;

#[derive(Serialize, Debug, Clone)]
pub struct Bearer{
    pub ebi: u8,
    pub fteid_list: Option<Vec<FTeidValue>>,
}

impl Bearer {
    pub fn new() -> Self {
        Bearer {
            ebi: 0,
            fteid_list: None,
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct CallFlow{
    pub id: usize,
    pub timestamp: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub message: String,
    pub ebi: Option<u8>,
    pub bearer: Option<Vec<Bearer>>,

    // Key: Node IP (e.g., "10.10.1.71")
    pub snapshot: HashMap<String, NodeState>,
}

impl CallFlow{
    pub fn new() -> Self {
        CallFlow {
            id: 0,
            timestamp: String::new(),
            src_addr: String::new(),
            dst_addr: String::new(),
            message: String::new(),
            ebi: None,
            bearer: None,

            snapshot: HashMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeState {
    pub ip: String,
    pub role: String,

    // LBI를 키로 하여 해당 세션에 속한 EBI 리스트를 관리
    // Key: LBI
    pub sessions: HashMap<u8, Vec<EbiDetail>>,
}

impl NodeState {
    pub fn new(ip: &str) -> Self {
        NodeState {
            ip: ip.to_string(),
            role: String::new(),
            sessions: HashMap::new(),
        }
    }
}


#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct EbiDetail {
    pub ebi: u8,
    pub active: bool,
    pub pending: bool,
    pub is_local: bool,
    pub delete_pending: bool,
    pub tunnels: TunnelInfo,
}

impl EbiDetail {

    pub fn create_dummy_bearer( bearers: &Bearer, msg: &str, ip: &str) -> Option<Self>
    {
        let mut detail = EbiDetail {
            ebi: bearers.ebi,
            ..Default::default()
        };

        return Some(detail);
    }

    pub fn create_bearer( bearers: &Bearer, msg: &str, ip: &str) -> Option<Self>
    {
        let mut detail = EbiDetail {
            ebi: bearers.ebi,
            ..Default::default()
        };

        if detail.update_ebi(bearers, msg, ip ) {
            return Some(detail);
        }
        return None;
    }

    pub fn update_ebi( &mut self, bearers: &Bearer, msg: &str, node_ip: &str)
    -> bool
    {
        let mut update_flag = false;
        if let Some(fteid_list) = &bearers.fteid_list {
            for fteid_value in fteid_list {
                let tunnel_ip = fteid_value.ipv4.as_deref().unwrap_or("0.0.0.0");

                if tunnel_ip != node_ip {
                    continue; 
                }

                let endpoint = Some(TunnelEndpoint {
                    teid: fteid_value.teid,
                    ip: tunnel_ip.to_string(),
                });

                match fteid_value.iface_type {
                    0 => self.tunnels.s1u_enb = endpoint,
                    1 => self.tunnels.s1u_sgw = endpoint,
                    4 => self.tunnels.s5s8_sgw = endpoint,
                    5 => self.tunnels.s5s8_pgw = endpoint,
                    _ => println!("Unknown Interface type"),
                }
                update_flag = true;
            }
        }

        set_status(self, msg);

        return update_flag;
    }


    fn contains_teid(&self, teid: u32) -> bool
    {
        // let tunnel = self.tunnels.clone();

        self.tunnels.s1u_enb.as_ref().map_or(false, |f| f.teid == teid) ||
        self.tunnels.s1u_sgw.as_ref().map_or(false, |f| f.teid == teid) ||
        self.tunnels.s5s8_sgw.as_ref().map_or(false, |f| f.teid == teid) ||
        self.tunnels.s5s8_pgw.as_ref().map_or(false, |f| f.teid == teid)
    }

    fn has_teid_match(&self, bearer: &Bearer) -> bool {
        if let Some(fteid) = &bearer.fteid_list {
            fteid.iter().any(|f| self.contains_teid(f.teid))
        }
        else {
            false
        }
    }

}


pub fn
set_status( detail: &mut EbiDetail, msg: &str)
{
	let is_request = msg.contains("Request");
    let is_response = msg.contains("Response");

    if msg.contains("Delete") {
        detail.delete_pending = true;
    }
    else if is_request {
        detail.pending = true;
    }
    else if is_response {
        detail.pending = false;
        detail.active = true;
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TunnelInfo {
    pub s1u_enb: Option<TunnelEndpoint>,
    pub s1u_sgw: Option<TunnelEndpoint>,
    pub s5s8_sgw: Option<TunnelEndpoint>,
    pub s5s8_pgw: Option<TunnelEndpoint>,
}

impl TunnelInfo {
    pub fn has_teid(&self, teid:u32) -> bool {
        let check = |endpoint: &Option<TunnelEndpoint>| {
            endpoint.as_ref().map_or(false, |e| e.teid == teid)
        };

        check(&self.s1u_enb) || check(&self.s1u_sgw)
        || check(&self.s5s8_sgw) || check(&self.s5s8_pgw)
    }

    fn contains_teid(&self, teid: u32) -> bool
    {
        // let tunnel = self.tunnels.clone();

        self.s1u_enb.as_ref().map_or(false, |f| f.teid == teid) ||
        self.s1u_sgw.as_ref().map_or(false, |f| f.teid == teid) ||
        self.s5s8_sgw.as_ref().map_or(false, |f| f.teid == teid) ||
        self.s5s8_pgw.as_ref().map_or(false, |f| f.teid == teid)
    }

    pub fn has_teid_match(&self, bearer: &Bearer) -> bool {
        if let Some(fteid) = &bearer.fteid_list {
            fteid.iter().any(|f| self.contains_teid(f.teid))
        }
        else {
            false
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TunnelEndpoint {
    pub teid: u32,
    pub ip: String,
}


// fn
// find_session(sess: &Vec<EbiDetail>, ebi:u8) -> bool
// {
//     for session in sess {
//         if session.ebi == ebi {
//             return true;
//         }
//     }
//     false
// }


fn identify_role(ebi_list: &mut Vec<EbiDetail>) -> String
{
    let mut has_s1u: bool = false;
    let mut has_s5s8: bool = false;
    let mut local: bool = false;

    for detail in ebi_list {
        if detail.tunnels.s1u_enb.is_some() ||
            detail.tunnels.s1u_sgw.is_some() {
                has_s1u = true;
        }
        if detail.tunnels.s5s8_pgw.is_some() ||
            detail.tunnels.s5s8_sgw.is_some() {
                has_s5s8 = true;
        }
    }

    if has_s1u && has_s5s8 {
        return "RELAY".to_string();
    }
    else if !has_s1u && has_s5s8 {
        return "Core".to_string();
    }
    else if has_s1u && !has_s5s8 {
        return "Access".to_string();
    }

    "Unknown".to_string()

}

fn handle_create_session_req_rsp( cf: &CallFlow,
    state: &mut HashMap<String, NodeState> )
{
    let cf_bearers = match &cf.bearer {
        Some(b) if !b.is_empty() => b,
        _ => return,
    };

    let src = &cf.src_addr;
    let dst = &cf.dst_addr;

    // 1. 노드 존재 확인 (없으면 생성)
    for ip in &[src, dst] {
        let node = state.entry(ip.to_string()).or_insert_with(|| NodeState::new(ip));
    }

    for cf_b in cf_bearers {
        //Get Info from CallFlow(cf)
        let b_ebi = cf_b.ebi;

        for ip in &[src, dst] {
            if let Some(node) = state.get_mut(*ip)  {

                let session_list = node.sessions.entry(b_ebi).or_insert_with(||Vec::new());

                let exists = session_list.iter().any(|e|e.ebi==b_ebi);

                if !exists {
                    if let Some(ebi) = EbiDetail::create_bearer(&cf_b, &cf.message, ip) {
                        session_list.push(ebi);
                    }
                }
                else {
                    if let Some(target_sess) = session_list.iter_mut().find(|e| e.ebi == b_ebi) {

                        target_sess.update_ebi(&cf_b, &cf.message, ip);
                    }
                }

                if node.role == "Unknown" || node.role.len() == 0 {
                    node.role = identify_role(session_list );
                }

            }
        }
    }
}


fn handle_create_bearer_request( cf: &CallFlow,
    state: &mut HashMap<String, NodeState> )
{
    let cf_bearers = match &cf.bearer {
        Some(b) if !b.is_empty() => b,
        _ => return,
    };

    let lbi = match cf.ebi {
        Some(e) => e,
        None => return,
    };
    
    for ip in [&cf.src_addr, &cf.dst_addr] {
        if let Some(node) = state.get_mut(ip) {

            if let Some(session_list) = node.sessions.get_mut(&lbi) {
                for cf_b in cf_bearers {
                    let is_duplicate = session_list.iter().any(|existing| {
                        existing.ebi == 0 && existing.has_teid_match(cf_b)
                    });

                    if !is_duplicate {
                        if let Some(ebi) = EbiDetail::create_bearer(&cf_b, &cf.message, ip) {
                            session_list.push(ebi);
                        }
                    }

                    if node.role == "Access" {
                        if let Some(ebi) = EbiDetail::create_dummy_bearer(&cf_b, &cf.message, ip) {
                            session_list.push(ebi);
                        }
                    }
                }
                node.role = identify_role(session_list );
            }
        }
    }
}


fn handle_create_bearer_response( cf: &CallFlow,
    state: &mut HashMap<String, NodeState>)
{
    let cf_bearers = match &cf.bearer {
        Some(b) if !b.is_empty() => b,
        _ => return,
    };

    let src = &cf.src_addr;
    let dst = &cf.dst_addr;

    for ip in &[src, dst] {
        if let Some(node) = state.get_mut(*ip) {
            for cf_b in cf_bearers {
                let assigned_ebi = cf_b.ebi; // 새로 할당된 EBI (9, 10, 11)
                
                // 1. 현재 메시지에서 이 노드(ip)에 해당하는 TEID를 찾습니다.
                let target_teid = cf_b.fteid_list.as_ref()
                    .and_then(|list| list.iter().find(|f| f.ipv4.as_ref() == Some(*ip)))
                    .map(|f| f.teid);

                let mut found = false;

                // 2. 모든 세션 리스트를 순회하며 매칭되는 베어러를 찾습니다.
                for session_list in node.sessions.values_mut() {
                    // 조건: EBI가 이미 할당되었거나, 아직 0인 베어러 중 TEID가 일치하는 것
                    if let Some(sess) = session_list.iter_mut().find(|e| {
                        e.ebi == assigned_ebi ||
                        ( e.ebi == 0 && e.tunnels.has_teid_match(cf_b) ) ||
                        ( e.ebi == 0 && node.role == "Access" )
                    }) {
                        sess.ebi = assigned_ebi;
                        sess.update_ebi(cf_b, &cf.message, ip.as_str());
                        found = true;
                        break;
                    }
                    node.role = identify_role(session_list );
                }

                if !found {
                    println!("Warning: No matching pending bearer for EBI {} on node {}", assigned_ebi, ip);
                    // if node.role == "Access" {
                    //     if let Some(ebi) = EbiDetail::create_bearer(&cf_b, &cf.message, ip, true) {
                    //         session_list.push(ebi);
                    //     }

                    // }
                }
            }
        }
    }
}


fn handle_modify_bearer_request( cf: &CallFlow,
    state: &mut HashMap<String, NodeState> )
{
    let cf_bearers = match &cf.bearer {
        Some(b) if !b.is_empty() => b,
        _ => return,
    };

    for ip in [&cf.src_addr, &cf.dst_addr] {
        if let Some(node) = state.get_mut(ip) {

            for cf_b in cf_bearers {
                let ebi = cf_b.ebi;
                let mut found = false;

                for session_list in node.sessions.values_mut()
                {
                    if let Some(sess) = session_list.iter_mut().find(|e| e.ebi == ebi) {

                        sess.update_ebi( &cf_b, &cf.message, ip.as_str());
                        node.role = identify_role(session_list );

                        found = true;
                        break;
                    }
                }

                if !found {
                    if node.role == "Unknown" || node.role == "Access" {
                        let vec_ebi_entry = node.sessions.entry(ebi as u8).or_insert_with(||Vec::new());

                        if let Some(ebi_detail) = EbiDetail::create_bearer(&cf_b, &cf.message, ip) {

                            vec_ebi_entry.push(ebi_detail);

                            if let Some(new_list) = node.sessions.get_mut(& (ebi as u8)) {
                                node.role = identify_role(new_list );
                            }
                        }
                    }
                }
            }
        }
    }
}


fn handle_modify_bearer_response( cf: &CallFlow,
    state: &mut HashMap<String, NodeState> )
{
    let cf_bearers = match &cf.bearer {
        Some(b) if !b.is_empty() => b,
        _ => return,
    };

    for ip in [&cf.src_addr, &cf.dst_addr] {
        if let Some(node) = state.get_mut(ip) {
            // let session_list = node.sessions.entry(lbi);

            for cf_b in cf_bearers {
                let target_ebi = cf_b.ebi;
                for session_list in node.sessions.values_mut() {
                    if let Some(sess) = session_list.iter_mut().find(|e| e.ebi == target_ebi) {
                        sess.update_ebi( &cf_b, &cf.message, ip.as_str());
                        break;
                    }
                    node.role = identify_role(session_list );
                }
            }
        }
    }
}


fn handle_delete_bearer_request( cf: &CallFlow,
    state: &mut HashMap<String, NodeState>)
{
    // Request의 ebi 필드에서 삭제할 대상을 가져옵니다.
    let target_ebi = match cf.ebi {
        Some(e) => e,
        None => return,
    };

    let addrs = [&cf.src_addr, &cf.dst_addr];

    for ip in addrs {
        if let Some(node) = state.get_mut(ip) {
            // 모든 세션 리스트를 순회하며 해당 EBI를 찾습니다.
            for session_list in node.sessions.values_mut() {
                if let Some(sess) = session_list.iter_mut().find(|b| b.ebi == target_ebi) {
                    // set_status가 "Delete" 문구를 인식해 delete_pending = true로 만듭니다.
                    set_status(sess, &cf.message);
                    break;
                }
                    node.role = identify_role(session_list );
            }
        }
    }
}

fn handle_delete_bearer_response( cf: &CallFlow,
    state: &mut HashMap<String, NodeState>)
{
    // Response에서는 bearer 리스트 안에 삭제된 EBI들이 들어옵니다.
    let cf_bearers = match &cf.bearer {
        Some(b) if !b.is_empty() => b,
        _ => return,
    };

    let addrs = [&cf.src_addr, &cf.dst_addr];

    for ip in addrs {
        if let Some(node) = state.get_mut(ip) {
            for cf_b in cf_bearers {
                let target_ebi = cf_b.ebi;

                // 세션 리스트를 순회하며 해당 EBI를 리스트에서 완전히 제거(retain)합니다.
                for session_list in node.sessions.values_mut() {
                    session_list.retain(|b| b.ebi != target_ebi);
                    node.role = identify_role(session_list );
                }
            }
            // 베어러 삭제 후 노드 역할 재계산 (필요 시)
            // node.update_role();
        }
    }
}

fn handle_delete_session_request( cf: &CallFlow,
    state: &mut HashMap<String, NodeState> )
{
    let src = &cf.src_addr;
    let dst = &cf.dst_addr;

    for ip in &[src, dst] {
        if let Some(node) = state.get_mut(*ip) {
            // 해당 노드가 관리하는 모든 세션(LBI)을 순회
            for session_list in node.sessions.values_mut() {
                // 세션 리스트 안의 모든 베어러(EbiDetail)를 삭제 대기 상태로 전환
                for detail in session_list.iter_mut() {
                    // 이전에 만든 set_status를 활용합니다.
                    // msg에 "Delete"가 포함되어 있으므로 delete_pending = true가 됩니다.
                    set_status(detail, &cf.message);
                }
                    node.role = identify_role(session_list );
            }
            
            // 삭제 시작 시점에 노드의 역할이나 상태를 갱신할 수 있습니다.
            // node.update_role(); 
        }
    }

}


fn handle_delete_session_response( cf: &CallFlow,
    state: &mut HashMap<String, NodeState>)
{
    // Delete Session Response 역시 bearer 리스트가 비어있는 경우가 많습니다.
    let src = &cf.src_addr;
    let dst = &cf.dst_addr;

    for ip in &[src, dst] {
        if let Some(node) = state.get_mut(*ip) {
            // 1. 해당 노드의 모든 세션을 완전히 삭제합니다.
            // 만약 특정 세션만 삭제해야 한다면 cf.ebi(LBI)를 사용하여 
            // node.sessions.remove(&lbi)를 호출하면 됩니다.
            
            if let Some(lbi) = cf.ebi {
                // 특정 LBI가 명시된 경우 해당 세션만 삭제
                node.sessions.remove(&lbi);
            } else {
                // LBI가 명시되지 않은 경우, 관례적으로 해당 노드의 모든 세션 정리
                node.sessions.clear();
            }

            // 2. 세션이 사라졌으므로 노드의 역할(Role)을 초기화하거나 재계산합니다.
            // 베어러가 하나도 없다면 보통 "Unknown"이나 기본 상태로 돌아갑니다.
            if node.sessions.is_empty() {
                node.role = "IDLE".to_string();
            } else {
                // 남아있는 세션이 있다면 역할 재계산
                // node.update_role();
            }
        }
    }
}


pub fn
update_global_state( cf: &CallFlow,
    state: &mut HashMap<String, NodeState>)
{
    match cf.message.as_str() {
        "Create Session Request"    => handle_create_session_req_rsp(cf, state),
        "Create Session Response"   => handle_create_session_req_rsp(cf, state),

        "Create Bearer Request"     => handle_create_bearer_request(cf, state),
        "Create Bearer Response"    => handle_create_bearer_response(cf, state),

        "Modify Bearer Request"     => handle_modify_bearer_request(cf, state),
        "Modify Bearer Response"    => handle_modify_bearer_response(cf, state),
        
        "Delete Bearer Request"     => handle_delete_bearer_request(cf, state),
        "Delete Bearer Response"    => handle_delete_bearer_response(cf, state),

        "Delete Session Request"    => handle_delete_session_request(cf, state),
        "Delete Session Response"   => handle_delete_session_response(cf, state),

        _ => println!("Unknown Message"),
    }
}
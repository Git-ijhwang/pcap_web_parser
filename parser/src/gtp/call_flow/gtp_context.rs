use std::collections::HashMap;
use super::gtp_call_flow::*;

fn
find_session(sess: &Vec<EbiDetail>, ebi:u8) -> bool
{
    for session in sess {
        if session.ebi == ebi {
            return true;
        }
    }
    false
}

fn
handle_create_session_req_rsp( cf: &CallFlow,
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
        state.entry(ip.to_string()).or_insert_with(|| NodeState::new(ip));
    }

    for cf_b in cf_bearers {
        //Get Info from CallFlow(cf)
        let b_ebi = cf_b.ebi;

        for ip in &[src, dst] {
            if let Some(node) = state.get_mut(*ip)  {
                let session_list = node.sessions.entry(b_ebi).or_insert_with(||Vec::new());

                let exists = session_list.iter().any(|e|e.ebi==b_ebi);

                if !exists {
                    session_list.push(EbiDetail::create_bearer(&cf_b, &cf.message, ip));
                    //Check if  Original message(Call flow) has Fteid.
                    //if Fteid exist ,Create EbiDetail and push fteid info
                    //if not Fteid exist, create Ebi detail with only Ebi info
                }
                else {
                    //update fteid
                    if let Some(target_sess) = session_list.iter_mut().find(|e| e.ebi == b_ebi) {
                        target_sess.update_ebi(&cf_b, &cf.message, ip);
                    }
                }
            }
        }
    }
}


fn
handle_create_bearer_request(
    cf: &CallFlow,
    state: &mut HashMap<String, NodeState> )
{
    let cf_bearers = match &cf.bearer {
        Some(b) if !b.is_empty() => b,
        _ => return,
    };

    let lbi = cf.ebi.unwrap();

    for ip in [&cf.src_addr, &cf.dst_addr] {
        if let Some(node) = state.get_mut(ip) {
            let session_list = node.sessions.entry(lbi).or_insert_with(||Vec::new());

            for cf_b in cf_bearers {
                session_list.push(EbiDetail::create_bearer(&cf_b, &cf.message, ip));
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

                for session_list in node.sessions.values_mut() {
                    if let Some(sess) = session_list.iter_mut().find(|e| e.ebi == ebi) {

                        sess.update_ebi( &cf_b, &cf.message, ip.as_str());
                        break;

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
                }
            }
        }
    }
}


pub fn
new_update_global_state( cf: &CallFlow,
    state: &mut HashMap<String, NodeState> )
{
    let msg = &cf.message;

    match cf.message.as_str() {
        "Create Session Request"    => handle_create_session_req_rsp(cf, state),
        "Create Session Response"   => handle_create_session_req_rsp(cf, state),
        "Create Bearer Request"     => handle_create_bearer_request(cf, state),
        // "Create Bearer Response"     => handle_create_bearer_response(cf, state),
        "Modify Bearer Request"     => handle_modify_bearer_request(cf, state),
        "Modify Bearer Response"    => handle_modify_bearer_response(cf, state),
        
        // "Delete Bearer Request"    => handle_delete_bearer_request(cf, state),
        // "Delete Bearer Response"    => handle_delete_bearer_response(cf, state),
        // "Delete Session Request"    => handle_delete_session_request(cf, state),
        // "Delete Session Response"    => handle_delete_session_response(cf, state),
        _ => println!("Unknown Message"),
    }
    // 2. 메시지 타입별 분기 처리 (JS의 if-else if 구조와 동일)
    // if msg.contains("Create Session Request") {
    //     handle_create_session_req_rsp(cf, state);
    // } else if msg.contains("Create Session Response") {
    //     handle_create_session_req_rsp(cf, state);
    // } else if msg.contains("") {
    //     handle_create_bearer_request(cf, state);
    // } else if msg.contains("Create Bearer Response") {
    // //     handle_create_bearer_response(cf, state);
    //     println!("handle_create_bearer_response");
    // } else if msg.contains("Modify Bearer Request") {
    //     handle_modify_bearer_request(cf, state);
    // } else if msg.contains("Modify Bearer Response") {
    //     handle_modify_bearer_response(cf, state);
    // }
}

// pub fn
// update_global_state(cf: &mut CallFlow,
//     state: &mut HashMap<String, NodeState>
// ) {
//     let src = &cf.src_addr;
//     let dst = &cf.dst_addr;

//     // 1. IP노드 존재여부 검사.
//     //    노드가 존재하지 않으면 새로 생성 (src_ip, dst_ip 둘 다)
//     for ip in &[src, dst] {
//         state.entry(ip.to_string()).or_insert_with(|| NodeState::new(&ip));
//     }

//     println!(" ##{} [{} -> {}] ",
//         cf.message, src.to_string(), dst.to_string());
//     println!("\tCurrent Message EBI: {:?}", cf.ebi);

//     // 2. 메시지 타입에 따른 Bearer 상태 업데이트 로직
//     if let Some(bearers) = &cf.bearer {
//         for b in bearers {
//             let b_ebi = b.ebi;
            
//             // 각 노드(src, dst)의 세션 정보 업데이트
//             for ip in &[src, dst] {

//                 if let Some(node) = state.get_mut(*ip) {
                    
//                     let session = node.sessions.entry(cf.ebi.unwrap_or(5)).or_insert(Vec::new());
                    
//                     // 기존 동일 EBI가 있으면 찾아서 업데이트, 없으면 추가
//                     if let Some(target) =
//                         session.iter_mut().find(|e| e.ebi == b_ebi) {
//                         // 터널 및 상태 업데이트 로직 (is_local 체크 등)
//                         if *ip == src {
//                             update_bearer_detail(target, b, Some(ip), &cf.message);
//                         }
//                         else {
//                             update_bearer_detail(target, b, None, &cf.message);
//                         }
//                         println!("target Delete pending flag: {}", target.delete_pending);
//                         println!("target active  flag: {}", target.active);
//                         println!("target pendingl  flag: {}", target.pending);

//                     } else {
//                         // 새로운 Bearer 추가
//                         session.push(EbiDetail::from_bearer(b, ip, &cf.message));
//                     }
                    
//                     // 3. 역할 판별 (RELAY/CORE/ACCESS)
//                     node.role = identify_role(session );
//                 }
//             }
//         }
//     }

//     println!("$$$$#### ===> {:?}", state);
// }


// fn
// update_bearer_detail(target: &mut EbiDetail, b: &Bearer, ip: Option<&str>, msg: &str)
// {
//     update_ebi(target, b, ip, msg);

//     if let Some(ref fteids) = b.fteid_list {

//         for f in fteids {
//             let tunnel_ip = f.ipv4.as_deref().unwrap_or("");

//             if let  Some(ip)= ip {
//                 if tunnel_ip == ip {
//                     target.is_local = true;
//                 }
//             }
//         }
//     }
// }

fn
identify_role(ebi_list: &mut Vec<EbiDetail>)
// -> String
{
    let mut has_s1u: bool = false;
    let mut has_s5s8: bool = false;
    let mut local: bool = false;

    // for detail in ebi_list {
    //     if detail.tunnels.s1u_enb.is_some() ||
    //         detail.tunnels.s1u_sgw.i




    
}

fn update_global_state(
    state: &mut HashMap<String, NodeState>,
    src: &str,
    dst: &str,
    msg: &str,
    msg_ebi: Option<u8>,
    bearers: &Option<Vec<Bearer>>
) {
    // 1. 노드가 존재하지 않으면 새로 생성 (src_ip, dst_ip 둘 다)
    state.entry(src.to_string()).or_insert_with(|| NodeState::new(src));
    state.entry(dst.to_string()).or_insert_with(|| NodeState::new(dst));

    // 2. 메시지 타입에 따른 Bearer 상태 업데이트 로직
    if let Some(bearer_list) = bearers {
        for b in bearer_list {
            // let ebi = b.ebi.unwrap_or(0);
            let ebi = b.ebi;
            
            // 각 노드(src, dst)의 세션 정보 업데이트
            for ip in &[src, dst] {
                if let Some(node) = state.get_mut(*ip) {
                    let session = node.sessions.entry(msg_ebi.unwrap_or(5)).or_insert(Vec::new());
                    
                    // 기존 동일 EBI가 있으면 찾아서 업데이트, 없으면 추가
                    if let Some(target) =
                        session.iter_mut().find(|e| e.ebi == ebi) {
                        // 터널 및 상태 업데이트 로직 (is_local 체크 등)
                        update_bearer_detail(target, b, *ip, msg);
                    } else {
                        // 새로운 Bearer 추가
                        session.push(BearerDetail::from_bearer(b, *ip, msg));
                    }
                    
                    // 3. 역할 판별 (RELAY/CORE/ACCESS)
                    node.role = identify_role(session, *ip);
                }
            }
        }
    }
}
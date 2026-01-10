import React,{ useMemo }  from "react";
import LBIBox from "./BearerView"


export function useBearerState(callFlows, nodeState) {
  return useMemo(() => {
    let state = {};
    const history = [];

    callFlows.forEach((cf, idx) => {
      state = applyCallFlowToBearerState(state, cf);
      history[idx] = structuredClone(state); // 가능하면 이게 더 안전
    });

    return history;
  }, [callFlows]);
}

function
applyCallFlowToBearerState(state, cf)
{
  const next = JSON.parse(JSON.stringify(state));
  const { src_addr,dst_addr, message, bearer, ebi, id} = cf;
  const src = cf.src_addr;
  const dst = cf.dst_addr;

  if (!next[src_addr]) next[src_addr] = {};
  if (!next[dst_addr]) next[dst_addr] = {};


  // ============ Create Session Request ============ 
if (cf.message.includes("Create Session Request") && Array.isArray(cf.bearer)) {
  const lbi = cf.bearer[0]?.ebi ? Number(cf.bearer[0].ebi) : 5;

  [src_addr, dst_addr].forEach(nodeAddr => {
    if (!next[nodeAddr]) next[nodeAddr] = {};
    if (!next[nodeAddr][lbi]) {
      next[nodeAddr][lbi] = { lbi, ip: nodeAddr, ebiList: [] };
    }

    const currentEbiList = next[nodeAddr][lbi].ebiList;

    cf.bearer.forEach(b => {
      const ebiNum = b.ebi ? Number(b.ebi) : lbi;
      const fteid_list = b.fteid_list || [];
      
      // 1. 기존에 같은 EBI가 있는지 확인
      let targetBearer = currentEbiList.find(e => e.ebi === ebiNum);

      // 2. 없다면 새로 생성 (첫 번째 메시지 MME -> SGW 상황)
      if (!targetBearer) {
        targetBearer = {
          ebi: ebiNum,
          pending: true,
          active: false,
          matchKey: { ebi: ebiNum, iface_type: null, teid: null },
          tunnels: { s1u_enb: null, s1u_sgw: null, s5s8_sgw: null, s5s8_pgw: null }
        };
        currentEbiList.push(targetBearer);
      }

      // 3. ★ 핵심: 메시지에 fteid_list가 있다면 기존 베어러 정보 업데이트
      // (두 번째 메시지 SGW -> PGW 상황에서 SGW 터널 정보가 저장됨)
      fteid_list.forEach(f => {
        const ip = f.ipv4 || f.ipv6 || null;
        const isLocal = ip === nodeAddr; // 가드 로직: 내 IP일 때만 저장

        if (f.iface_type === 4 && isLocal) {
          targetBearer.tunnels.s5s8_sgw = { teid: f.teid, ip };
          // 매칭을 위해 matchKey도 최신화
          targetBearer.matchKey.iface_type = 4;
          targetBearer.matchKey.teid = f.teid;
        }
        // PGW 입장(dst_addr)에서도 상대방(SGW)의 정보를 미리 알고 싶다면 
        // else if (!isLocal) { ... peer 정보 저장 ... } 로직 추가 가능
      });
    });
  });
}
  // ============ Create Session Response (Confirm) ============ 
  else if (cf.message.includes("Create Session Response") && Array.isArray(cf.bearer)) {
    [src_addr, dst_addr].forEach(nodeAddr => {
      const nodeState = next[nodeAddr];
      if (!nodeState) return;

      Object.keys(nodeState).forEach(lbiKey => {
        const lbiState = nodeState[lbiKey];
        const pendingItems = lbiState.ebiList.filter(e => e.pending);

        lbiState.ebiList = lbiState.ebiList.map((item, idx) => {
          if (!item.pending) return item;

          // 1. TEID 기반 매칭
          let matched_bearer = cf.bearer.find(b => 
            (b.fteid_list || []).some(f => 
              f.iface_type === item.matchKey.iface_type &&
              f.teid === item.matchKey.teid
            )
          );

          // 2. MME/SGW 비대칭 TEID 대응 (순서 기반 매칭)
          if (!matched_bearer && nodeAddr === src_addr) {
            const pIdx = pendingItems.findIndex(p => p.matchKey.teid === item.matchKey.teid);
            if (pIdx !== -1 && cf.bearer[pIdx]) {
              matched_bearer = cf.bearer[pIdx];
            }
          }

          if (matched_bearer) {
            const updatedTunnels = { ...item.tunnels };
            (matched_bearer.fteid_list || []).forEach(f => {

              const ip = f.ipv4 || f.ipv6 || null;

              if (f.iface_type === 0)
                updatedTunnels.s1u_enb = { teid: f.teid, ip };

              if (f.iface_type === 1)
                updatedTunnels.s1u_sgw = { teid: f.teid, ip };

              if (f.iface_type === 4)
                updatedTunnels.s5s8_sgw = { teid: f.teid, ip };

              if (f.iface_type === 5)
                updatedTunnels.s5s8_pgw = { teid: f.teid, ip };
            });

            return {
              ...item,
              ebi: Number(matched_bearer.ebi),
              pending: false,
              active: true,
              tunnels: updatedTunnels
            };
          }
          return item;
        });
      });
    });
  }
  // ============ Create Bearer Request ============ 
  else if (cf.message.includes("Create Bearer Request") && bearer)
  {
    const lbi = Number(ebi); 

    [src_addr, dst_addr].forEach(nodeAddr => {
      // 1. 노드 공간 및 LBI 공간 확보
      if (!next[nodeAddr]) next[nodeAddr] = {};
      if (!next[nodeAddr][lbi]) {
        next[nodeAddr][lbi] = { lbi, ip: nodeAddr, ebiList: [] };
      }

      const currentEbiList = next[nodeAddr][lbi].ebiList;

      bearer.forEach(b => {
        // 2. 해당 Bearer의 matchKey(TEID) 추출
        const fteid_list = b.fteid_list || [];
        const firstF = fteid_list[0] || {};

        // 1. 기존에 동일한 matchKey를 가진 Bearer가 있는지 검색
        let targetBearer = currentEbiList.find(e => 
          e.matchKey?.teid === firstF.teid &&
          e.matchKey?.iface_type === firstF.iface_type
        );

        // 2. 없다면 새로 생성 (최초 수신 시)
        if (!targetBearer) {
          targetBearer = {
            ebi: b.ebi ? Number(b.ebi) : null,
            pending: true,
            active: false,
            matchKey: { teid: firstF.teid, iface_type: firstF.iface_type },
            tunnels: { s1u_enb: null, s1u_sgw: null, s5s8_sgw: null, s5s8_pgw: null }
          };
          currentEbiList.push(targetBearer);
        }

        fteid_list.forEach(f => {
          const ip = f.ipv4 || f.ipv6 || null;
          const isLocal = ip === nodeAddr;

          // SGW가 보낸 메시지에서 자기가 생성한 S1-U SGW(1) 혹은 S5/S8 SGW(4) 저장
          if (isLocal) {
            if (f.iface_type === 1) targetBearer.tunnels.s1u_sgw = { teid: f.teid, ip };
            if (f.iface_type === 4) targetBearer.tunnels.s5s8_sgw = { teid: f.teid, ip };
            if (f.iface_type === 5) targetBearer.tunnels.s5s8_pgw = { teid: f.teid, ip };
            
            // 자신의 최신 TEID를 matchKey로 동기화 (나중에 Response와 매칭하기 위함)
            targetBearer.matchKey.teid = f.teid;
            targetBearer.matchKey.iface_type = f.iface_type;
          }
          else {
            if (f.iface_type === 1) targetBearer.tunnels.s1u_sgw = { teid: f.teid, ip };
            if (f.iface_type === 5) targetBearer.tunnels.s5s8_pgw = { teid: f.teid, ip };
          }
        });
      });
    });
  }
  // ============ Create Bearer Response ============ 
  else if (cf.message.includes("Create Bearer Response") && bearer)
  {
    [src_addr, dst_addr].forEach(nodeAddr => {
      const nodeState = next[nodeAddr];
      if (!nodeState) return;

      Object.keys(nodeState).forEach(lbi => {
        const lbiState = nodeState[lbi];
        const pendingItems = lbiState.ebiList.filter(e => e.pending);

        lbiState.ebiList = lbiState.ebiList.map((item, idx) => {
          let matched = bearer.find(b =>  {
            const isEbiMatch = item.ebi && b.ebi && Number(item.ebi) === Number(b.ebi);
            const fList = b.fteid_list || [];

            const isTeidMatch = fList.some(f => 
              (f.iface_type === item.matchKey.iface_type &&
                f.teid === item.matchKey.teid) ||
              (item.tunnels.s1u_sgw?.teid === f.teid) ||
              (item.tunnels.s5s8_sgw?.teid === f.teid)
            );

            return b.ebi ? isEbiMatch : isTeidMatch;
          });

          if (!matched ) {
            const pIdx = pendingItems.findIndex(p => p.matchKey.teid === item.matchKey.teid);
            if (pIdx !== -1 && bearer[pIdx]) {
              matched = bearer[pIdx];
            }
          }

          if (matched) {
            const updatedTunnels = { ...item.tunnels };
            let hasUpdate = false;

            (matched.fteid_list || []).forEach(f => {
              const ip = f.ipv4 || f.ipv6 || null;
              const isLocal = ip === nodeAddr;

              if (f.iface_type === 0 && isLocal) {
                updatedTunnels.s1u_enb = { teid: f.teid, ip };
                hasUpdate = true;
              }

              if (f.iface_type === 1 && isLocal) {
                updatedTunnels.s1u_sgw = { teid: f.teid, ip };
                hasUpdate = true;
              }

              if (f.iface_type === 4 && isLocal) {
                updatedTunnels.s5s8_sgw = { teid: f.teid, ip };
                hasUpdate = true;
              }

              if (f.iface_type === 5 && isLocal) {
                updatedTunnels.s5s8_pgw = { teid: f.teid, ip };
                hasUpdate = true;
              }
            });

            return { 
              ...item, 
              ebi: Number(matched.ebi)||item.ebi, 
              pending: false, 
              active: true,
              tunnels: hasUpdate? updatedTunnels : item.tunnels,
            };
          }
          return item;
        });
      });
    });
  }

  // ============ Modify Bearer Request ============ 
  else if (cf.message.includes("Modify Bearer Request") && Array.isArray(cf.bearer)) {
    [src_addr, dst_addr].forEach(nodeAddr => {
      const nodeState = next[nodeAddr];
      if (!nodeState) return;

      cf.bearer.forEach(b => {
        const targetEbi = Number(b.ebi);
        
        // 모든 LBI를 뒤져서 해당 EBI(5번)를 찾음
        Object.keys(nodeState).forEach(lbi => {
          const targetBearer = nodeState[lbi].ebiList.find(e => e.ebi === targetEbi);
          
          if (targetBearer) {
            const updatedTunnels = { ...targetBearer.tunnels };
            
            (b.fteid_list || []).forEach(f => {
              const ip = f.ipv4 || f.ipv6 || null;
              // Interface Type 0: S1-U eNB F-TEID가 여기서 업데이트됨
              if (f.iface_type === 0)
                updatedTunnels.s1u_enb = { teid: f.teid, ip };
              if (f.iface_type === 1)
                updatedTunnels.s1u_sgw = { teid: f.teid, ip };
            });

            // 데이터 갱신 및 활성화 상태로 변경
            targetBearer.tunnels = updatedTunnels;
            targetBearer.active = false;//true;
            targetBearer.pending = true;//false;
          }
        });
      });
    });
  }
  // ============ Modify Bearer Response ============ 
  else if (cf.message.includes("Modify Bearer Response") && Array.isArray(cf.bearer)) {
    [src_addr, dst_addr].forEach(nodeAddr => {
      const nodeState = next[nodeAddr];
      if (!nodeState) return;

      cf.bearer.forEach(b => {
        const targetEbi = Number(b.ebi);
        
        // 모든 LBI 세션을 순회하며 해당 EBI를 찾음
        Object.keys(nodeState).forEach(lbi => {
          const ebiList = nodeState[lbi].ebiList;
          const targetBearer = ebiList.find(e => e.ebi === targetEbi);
          
          if (targetBearer) {
            const updatedTunnels = { ...targetBearer.tunnels };
            
            // SGW 측에서 제공하는 터널 정보 업데이트 (보통 S1-U SGW TEID)
            (b.fteid_list || []).forEach(f => {
              const ip = f.ipv4 || f.ipv6 || null;
              // Interface Type 1: S1-U SGW F-TEID
              if (f.iface_type === 1) updatedTunnels.s1u_sgw = { teid: f.teid, ip };
            });

            // 최종 확정 상태로 변경
            targetBearer.tunnels = updatedTunnels;
            targetBearer.pending = false; // 모든 절차 완료
            targetBearer.active = true;   // 통신 준비 완료
            
          }
        });
      });
    });
  }
  // ============ Delete Bearer Request ============ 
  else if (cf.message.includes("Delete Bearer Request")){
    [src_addr, dst_addr].forEach(nodeAddr => {
      const nodeState = next[nodeAddr];
      if (!nodeState) return;

      const targetEbi = Number(cf.ebi);

      Object.keys(nodeState).forEach(lbi => {
        const targetBearer = nodeState[lbi].ebiList.find(e => e.ebi === targetEbi);
        
        if (targetBearer) {
          targetBearer.deletePending = true;
          targetBearer.active = false; // 더 이상 활성 상태가 아님을 표시
        }
      });
    });
  }
  // ============ Delete Bearer Response ============ 
  else if (cf.message.includes("Delete Bearer Response") && Array.isArray(cf.bearer)) {
    [src_addr, dst_addr].forEach(nodeAddr => {
      const nodeState = next[nodeAddr];
      if (!nodeState) return;

      cf.bearer.forEach(b => {
        const targetEbi = Number(b.ebi);

        Object.keys(nodeState).forEach(lbi => {
          // 해당 EBI를 리스트에서 제외 (실제 데이터 삭제)
          const initialCount = nodeState[lbi].ebiList.length;
          nodeState[lbi].ebiList = nodeState[lbi].ebiList.filter(e => e.ebi !== targetEbi);
          
          if (nodeState[lbi].ebiList.length < initialCount) {
            console.log(`[Delete Bearer Response] Ebi ${targetEbi} removed from ${nodeAddr}`);
          }

          if (nodeState[lbi].ebiList.length === 0) {
            delete nodeState[lbi];
          }
        });
      });
    });
  }
  // ============ Delete Session Request ============ 
  else if (cf.message.includes("Delete Session Request")){
    [src_addr, dst_addr].forEach(nodeAddr => {
      const nodeState = next[nodeAddr];

      if (!nodeState) return;

      Object.keys(nodeState).forEach(lbi => {
        nodeState[lbi] = {
          ...nodeState[lbi],
          pending: true,
        }
        nodeState[lbi].ebiList =
          nodeState[lbi].ebiList.map(item => ({
            ...item,
            pending:true,
            active: false,
        }))

      });
    });
  }
  // ============ Delete Session Response ============ 
  else if (cf.message.includes("Delete Session Response")){
    delete next[src_addr];
    delete next[dst_addr];
  }

  return next;
}


function CallFlowGraph({ data, step }) {
  // 1. 기본 설정 (필요에 따라 조정)
  const width = 1100;
  const rowHeight = 50;
  const headerHeight = 100;
  const padding = 120;
  // 데이터 길이에 따라 동적으로 높이 계산
  const messageAreaHeight = data.length * (rowHeight);
  const height = headerHeight + (messageAreaHeight ) + 200;

  // 2. 노드(IP) 추출 및 X 좌표 계산
  const nodes = [...new Set(data.flatMap(p => [p.src_addr, p.dst_addr]))];
  const nodeX = {};
  const span = nodes.length > 1 ? (width - 2 * padding) / (nodes.length - 1) : 0;
  nodes.forEach((node, idx) => {
    nodeX[node] = padding + idx * span;
  });

  const visibleFlows = data.slice(0, step);
  const bearerHistory = useBearerState(data); // 전체 히스토리 미리 계산
  const currentNodeState = bearerHistory[step - 1] || {};

  return (
    <svg width="100%" height={height+500} viewBox={`0 0 ${width} ${height}`} >
      {/* 1. 노드 수직선 및 헤더 */}
      {nodes.map(node => (
        <g key={node}>
          <line x1={nodeX[node]} y1={70} x2={nodeX[node]} y2={height - 200} stroke="#aaa" />
          <text x={nodeX[node]} y={50} textAnchor="middle" fontWeight="bold">{node}</text>
        </g>
      ))}

      {/* 2. 메시지 화살표 (Step까지만) */}
      {visibleFlows.map((pkt, idx) => {
        const y = headerHeight + idx * rowHeight;

        const sourceX = nodeX[pkt.src_addr];
        const targetX = nodeX[pkt.dst_addr];

        return (
          <g key={pkt.id}>

            {/* Horizontal Line */}
            <line
              x1={sourceX} y1={y} // Start Point
              x2={targetX> sourceX ? targetX - 2 : targetX + 2} y2={y} //End Point
              stroke="black"
              strokeWidth={1}
              markerEnd="url(#arrowhead)"
            />

            {/* Message Name */}
            <text
              x={(sourceX + targetX) / 2}
              y={y - 8}
              textAnchor="middle"
              fontSize={14}>
              #{pkt.id} {pkt.message}
            </text>
          </g>
        );
      })}

      {/* SVG 하단이나 상단에 정의할 Marker (화살표 촉) */}
      <defs>
        <marker
          id="arrowhead"
          markerWidth="10"
          markerHeight="7"
          refX="10" // 화살표 끝점이 선의 끝과 만나는 지점
          refY="3.5"
          orient="auto" // 선의 방향에 따라 자동으로 회전
        >
          <polygon points="0 0, 10 3.5, 0 7" fill="black" />
        </marker>
      </defs>

      {/* 3. Bearer 정보 (최종 Step의 상태만 노드 하단에 렌더링) */}
      {Object.entries(currentNodeState).map(([nodeIp, lbiMap]) => {
        const x = nodeX[nodeIp];
        if (!x) return null;
        
        return Object.values(lbiMap).map((lbiObj, lbiIdx) => (
          <LBIBox 
            key={`${nodeIp}-${lbiObj.lbi}`}
            x={x - 110}
            y={height - 220 + (lbiIdx * 190)} // LBI가 여러개일 경우 아래로 나열
            lbiObj={lbiObj}
            nodeAddr={nodeIp}
          />
        ));
      })}
    </svg>
  );
}

export default CallFlowGraph;

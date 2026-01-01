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

  // bearer 정보가 없는 메시지는 상태 변경 없음
  if (!cf.bearer && cf.ebi === undefined) return next;

  const src = cf.src_addr;
  const dst = cf.dst_addr;

  // 노드 공간 확보
  if (!next[src_addr]) next[src_addr] = {};
  if (!next[dst_addr]) next[dst_addr] = {};

  console.log("Call FLow #",cf.id, " Message: ", cf.message);

  // ============ Create Session ============ 
  if (cf.message.includes("Create Session")
      && Array.isArray(cf.bearer)
      && cf.bearer.length > 0
  )
    {
    const lbi = Number(cf.bearer[0]?.ebi);

    [src_addr, dst_addr].forEach(node => {

      if (!next[node][lbi]) {
        next[node][lbi] = { lbi, ip: node, ebiList: [] };
      }

      cf.bearer.forEach(b => {
        const exists = next[node][lbi].ebiList.some(e=>e.ebi === b.ebi);
        if (!exists) {
          next[node][lbi].ebiList.push({
              ebi: b.ebi,
              active: true,
              fteid: b.fteid_list || []
            });
        }
      });
    });
  }

  // ============ Create Bearer Request ============ 
  if (cf.message.includes("Create Bearer Request")
    && bearer)
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
      const matchFteid = (b.fteid_list || []).find(f =>
        [0, 1, 4, 5].includes(f.iface_type)) || b.fteid_list?.[0];
        // f.iface_type === 5 || f.iface_type === 1
      // );
      
      if (matchFteid) {
        // 3. 중복 체크: 동일한 matchKey를 가진 Bearer가 이미 존재하는지 확인
        const isDuplicate = currentEbiList.some(e => 
          e.pending && 
          e.matchKey?.teid === matchFteid.teid && 
          e.matchKey?.iface_type === matchFteid.iface_type
        );

        // 4. 중복이 아닐 때만 추가
        if (!isDuplicate) {
          currentEbiList.push({
            ebi: null,
            pending: true,
            matchKey: { teid: matchFteid.teid, iface_type: matchFteid.iface_type },
            tunnels: {
              s1u_enb: null,
              s1u_sgw: null,
              s5s8_sgw: null,
              s5s8_pgw: null
            },
            active: false,
          });
          console.log(`[Request] Pending bearer created for ${nodeAddr} (TEID: ${matchFteid.teid})`);
          console.log(`[Flow #${cf.id}] Added pending bearer to ${nodeAddr}`);
        } else {
          console.log(`[Flow #${cf.id}] Duplicate bearer skipped for ${nodeAddr}`);
        }
      }
    });
  });

  }
  // ============ Create Bearer Response ============ 
  if (cf.message.includes("Create Bearer Response") && bearer)
  {
    [src_addr, dst_addr].forEach(nodeAddr => {
      const nodeState = next[nodeAddr];
      if (!nodeState) return;

      // 해당 노드가 가진 모든 LBI 세션을 순회하며 pending 중인 EBI 찾기
    Object.keys(nodeState).forEach(lbi => {
      const lbiState = nodeState[lbi];

      // if (!lbiState.ebiList) return;
      const pendingItems = lbiState.ebiList.filter(e => e.pending);
      lbiState.ebiList = lbiState.ebiList.map((item, idx) => {
        // 이미 확정된(pending이 아닌) EBI는 그대로 유지
        if (!item.pending) return item;

        // matchKey(TEID)가 일치하는 bearer 정보 찾기
        let matched = bearer.find(b => 
          (b.fteid_list || []).some(f => 
             f.iface_type === item.matchKey.iface_type && f.teid === item.matchKey.teid
          )
        );

        if (!matched && nodeAddr === src_addr) {
          const pIdx = pendingItems.findIndex(p => p.matchKey.teid === item.matchKey.teid);
          if (pIdx !== -1 && bearer[pIdx]) {
            matched = bearer[pIdx];
            console.log(`[MME Match] Flow #${cf.id}: Pending Index ${pIdx} -> EBI ${matched.ebi}`);
          }
          // matched = bearer[idx];
        }

        if (matched) {
          // 일치하는 정보를 찾으면 pending을 풀고 EBI 번호 할당
          console.log(`[Flow #${cf.id}] Updating Node ${nodeAddr}: EBI ${matched.ebi} confirmed.`);

          const updatedTunnels = { ...item.tunnels };

          (matched.fteid_list || []).forEach(f => {
            const ip = f.ipv4 || f.ipv6 || null;
            // 각 인터페이스 타입별로 터널 정보 업데이트
            if (f.iface_type === 0 || f.iface_type === 1) {
              if (f.iface_type === 0) updatedTunnels.s1u_enb = { teid: f.teid, ip };
              if (f.iface_type === 1) updatedTunnels.s1u_sgw = { teid: f.teid, ip };
            }
            if (f.iface_type === 4 || f.iface_type === 5) {
              if (f.iface_type === 4) updatedTunnels.s5s8_sgw = { teid: f.teid, ip };
              if (f.iface_type === 5) updatedTunnels.s5s8_pgw = { teid: f.teid, ip };
            }

          });

          return { 
            ...item, 
            ebi: Number(matched.ebi), 
            pending: false, 
            active: true,
            // fteid: matched.fteid_list || [], // 터널 정보 업데이트
            // 추가적인 터널 정보(S1-U eNB 등)를 구조화해서 저장
            tunnels: updatedTunnels,
            // matched.fteid_list?.reduce((acc, f) => {
            //   const ip = f.ipv4 || f.ipv6 || null;
            //   if (f.iface_type === 0) acc.s1u_enb = { teid: f.teid, ip };
            //   if (f.iface_type === 1) acc.s1u_sgw = { teid: f.teid, ip };
            //   return acc;
            // }, { ...item.tunnels })
          };
        }
        return item;
      });
    });
  });

  }

  // ============ Modify Bearer  ============ 
  if (cf.message.includes("Modify Bearer") && bearer ) {
    [src_addr, dst_addr].forEach(nodeAddr => {
    const nodeState = next[nodeAddr];
    if (!nodeState) return;

    bearer.forEach(b => {
      const targetEbi = Number(b.ebi);
      
      // 해당 노드에서 targetEbi를 가지고 있는 LBI 찾기
      const lbiKey = Object.keys(nodeState).find(lbi =>
        nodeState[lbi].ebiList.some(e => e.ebi === targetEbi)
      );

      if (lbiKey) {
        const ebiObj = nodeState[lbiKey].ebiList.find(e => e.ebi === targetEbi);
        
        // FTEID 업데이트 (S1-U eNB 주소 등)
        if (b.fteid_list) {
          ebiObj.fteid = b.fteid_list;
          
          // 터널 상세 정보 업데이트 로직 (S1-U 인터페이스 예시)
          b.fteid_list.forEach(f => {
            const ip = f.ipv4 || f.ipv6 || null;
            if (f.iface_type === 0) { // S1-U eNodeB Side
              ebiObj.s1u_enb = { teid: f.teid, ip };
            }
            if (f.iface_type === 1) { // S1-U SGW Side
              ebiObj.s1u_sgw = { teid: f.teid, ip };
            }
          });
        }
        ebiObj.active = true;
      }
    });
  });
  }

  // ============ Delete Bearer  ============ 
  if (cf.message.includes("Delete Bearer") && cf.ebi !== undefined) {
    let delEbi = cf.ebi !== undefined ? Number(cf.ebi) : (bearer?.[0]?.ebi ? Number(bearer[0].ebi) : null);

    if (delEbi !== null) {
      [src_addr, dst_addr].forEach(nodeAddr => {
        const nodeState = next[nodeAddr];
        if (!nodeState) return;

        Object.keys(nodeState).forEach(lbi => {
          // 1. EBI 필터링
          nodeState[lbi].ebiList = nodeState[lbi].ebiList.filter(e => e.ebi !== delEbi);
          
          // 2. LBI 자체가 삭제 대상인 경우 (LBI == EBI) 혹은 하위 EBI가 하나도 없는 경우 세션 삭제 고려
          if (Number(lbi) === delEbi || nodeState[lbi].ebiList.length === 0) {
            delete nodeState[lbi];
          }
        });
      });
    }
  }

  /* Delete Session */
  if (cf.message.includes("Delete Session")) {
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
  const messageAreaHeight = data.length * rowHeight;
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
    <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} >
      {/* 1. 노드 수직선 및 헤더 */}
      {nodes.map(node => (
        <g key={node}>
          <line x1={nodeX[node]} y1={70} x2={nodeX[node]} y2={height - 250} stroke="#aaa" />
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
            <line
              x1={sourceX}
              // x1={nodeX[pkt.src_addr]}
              y1={y}
              x2={targetX> sourceX ? targetX - 2 : targetX + 2}
              // x2={nodeX[pkt.dst_addr]}
              y2={y}
              
              stroke="black"
              strokeWidth={1}
              markerEnd="url(#arrowhead)"
            />

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
            y={height - 220 + (lbiIdx * 100)} // LBI가 여러개일 경우 아래로 나열
            lbiObj={lbiObj}
          />
        ));
      })}
    </svg>




  );
}

export default CallFlowGraph;

import React,{ useMemo }  from "react";

const NODE_ROLES = {
  ACCESS: "ACCESS", // eNB, gNB
  RELAY: "RELAY",   // SGW, UPF
  CORE: "CORE"      // PGW, SMF
};

function AidentifyNodeRole(lbiObj, nodeIp) {
  // lbiObj가 단일 세션 객체이므로 바로 ebiList를 순회
  const ebiList = lbiObj.ebiList || [];
  
  let hasS1U = false;
  let hasS5S8 = false;

  ebiList.forEach(ebiItem => {
    const t = ebiItem.tunnels;
    if (!t){

      console.log("t is not exist");
    return;
    }
    console.log("tunnel of ebiItem ", t);

    // 1. IP 기반 체크 (가장 정확함)
    const isS1U_SGW = t.s1u_sgw?.ip === nodeIp;
    const isS5S8_SGW = t.s5s8_sgw?.ip === nodeIp;
    
    // 2. 만약 IP가 없는 단계라면, 구조적 특징으로 보완 (SGW는 보통 두 터널 키를 동시에 가짐)
    if (isS1U_SGW || (t.s1u_sgw && !nodeIp)) hasS1U = true;
    if (isS5S8_SGW || (t.s5s8_sgw && !nodeIp)) hasS5S8 = true;
    
    // PGW나 eNB인데 데이터 오염으로 SGW 정보가 들어온 경우를 위해 
    // 본인 IP가 확실히 맞을 때만 우선권을 줌
    if (nodeIp) {
        if (t.s5s8_pgw?.ip === nodeIp) { hasS5S8 = true; hasS1U = false; } // PGW 확정
        if (t.s1u_enb?.ip === nodeIp) { hasS1U = true; hasS5S8 = false; }  // eNB 확정
    }
  });

  if (hasS1U && hasS5S8) return "RELAY";
  if (hasS5S8) return "CORE";
  return "ACCESS";
}
function identifyNodeRole(nodeState, nodeIp) {
  /*
  // 1. 해당 노드가 관리하는 모든 베어러 세션을 확인
  const sessions = Object.values(nodeState || {});
  
  let hasS1U = false;
  let hasS5S8 = false;

  sessions.forEach(s => {
    console.log("Is Array? ", Array.isArray(s.ebiList));
    console.log("TYpe: ", typeof s[0]);
    if ( s[0])
      {
      
      const firstEbi = s[0];
      
      // 2. tunnels 객체 존재 여부 확인
      if (firstEbi.tunnels) {
        const t = firstEbi.tunnels;
        
        // S1U 인터페이스 판별
        if (t.s1u_enb || t.s1u_sgw) {
          hasS1U = true;
        }
        
        // S5S8 인터페이스 판별
        if (t.s5s8_sgw || t.s5s8_pgw) {
          hasS5S8 = true;
        }
      }
    }
  });
  */
// nodeState가 null이거나 객체가 아니면 바로 탈출
  if (!nodeState || typeof nodeState !== 'object') return NODE_ROLES.ACCESS;

  let hasS1U_Local = false;
  let hasS5S8_Local = false;

  /*
  // 1. 객체의 키-값 쌍을 모두 확인합니다.
  Object.entries(nodeState).forEach(([key, value]) => {
    
    if (key === 'ebiList' && Array.isArray(value)) {
      console.log("Found ebiList array!");
      
      value.forEach(ebiItem => {
        if (ebiItem.tunnels) {
          const t = ebiItem.tunnels;
          // S1U 판별 (enb 혹은 sgw 터널 정보가 있을 때)
          if (t.s1u_enb || t.s1u_sgw) hasS1U = true;
          // S5S8 판별 (sgw 혹은 pgw 터널 정보가 있을 때)
          if (t.s5s8_sgw || t.s5s8_pgw) hasS5S8 = true;
        }
      });
    }
  });
  */
  Object.values(nodeState).forEach(session => {
    if (session && Array.isArray(session.ebiList)) {
      session.ebiList.forEach(ebiItem => {
        const t = ebiItem.Tunnels;
        if (!t) return;

        if (
          (t.s1u_sgw && t.s1u_sgw.ip === nodeIp) ||
          (t.s1u_enb && t.s1u_enb.ip === nodeIp)
        ) {
          hasS1U_Local = true;
        }

        if (
          (t.s5s8_sgw && t.s5s8_sgw.ip === nodeIp) ||
          (t.s5s8_pgw && t.s5s8_pgw.ip === nodeIp)
        ) {
          hasS1U_Local = true;
        }
      });
    }
  });

  // 2. 판단 로직
  if (hasS1U_Local && hasS5S8_Local) return NODE_ROLES.RELAY; // 두 인터페이스가 다 있으면 SGW(Relay)
  if (hasS5S8_Local ) return NODE_ROLES.CORE;  // PGW 방향만 있으면 Core
  if (hasS1U_Local ) return NODE_ROLES.ACCESS; // eNB 방향만 있으면 Access

  return NODE_ROLES.ACCESS; // 기본값
 
}

function
EBIBox({ x, y, width, height, ebiObj, nodeRole, ifaceType }) {
  const tunnels = ebiObj.tunnels || {};
  const isPending = ebiObj.pending === true;
  const isDelPending = ebiObj.deletePending === true;

  console.log("NodeRole: ", nodeRole, "Interface Type: ", ifaceType);
  console.log("Tunnel Info: ", tunnels);
  const targetTunnel = ifaceType === "S1U"
   ? {
      local: nodeRole === "SGW" ?  tunnels.s1u_sgw : tunnels.s1u_enb,
      // peer: tunnels.s1u_enb,
      label: "S1-U",
      color: "#228be6",
   }
   : {
      local: nodeRole === "SGW" ?  tunnels.s5s8_sgw : tunnels.s5s8_pgw, 
      // peer: tunnels.s5s8_pgw,
      label: "S5/S8",
      color: "#e64980",
   };

  return (
    <g>
      <rect
        x={x} y={y}
        width={width} height={height+6}
        rx={6} ry={6}
        fill={isPending ? "#fff9db" : isDelPending? "#fa7f7fff":"#ffffff"} // 대기 중일 땐 연한 노란색
        stroke={isPending||isDelPending ? "#fcc419" : "#666"}
        strokeDasharray={isPending||isDelPending ? "3,2" : "none"} // 대기 중일 땐 점선
      />

      <text x={x + 5} y={y + 12} fontSize={9} fontWeight="bold" fill={targetTunnel.color}>
        {targetTunnel.label} [EBI: {ebiObj.ebi || "!"}]
      </text>

      <text x={x + 5} y={y + 26} fontSize={10} fill="#333">
        {/* local이나 peer 중 하나라도 있으면 TEID 표시 */}
        {(targetTunnel.local || targetTunnel.peer) ? (
          <>
            <tspan fontWeight="bold">Teid: </tspan>
            <tspan fill={targetTunnel.color}>
              {targetTunnel.local ? `0x${targetTunnel.local.teid.toString(16).toUpperCase()}` : "-"}
            </tspan>

            <tspan fontWeight="bold">  IP: </tspan>
            <tspan fill={targetTunnel.color}>
              {targetTunnel.local ? `0x${targetTunnel.local.ip}` : "-"}
            </tspan>
            {/* <tspan dx={4} fill="#888" fontSize={8}>
              (P:{targetTunnel.peer ? `0x${targetTunnel.peer.toString(16).toUpperCase()}` : "-"})
            </tspan> */}
          </>
        ) : (
          <tspan fill="#ccc" fontStyle="italic">No Tunnel Info</tspan>
        )}
      </text>

      {/* 상태 표시 (삭제 중일 때) */}
      {isDelPending && (
        <text x={x + width - 5} y={y + 12} textAnchor="end" fontSize={8} fill="#ffffff" fontWeight="bold">
          DELETE
        </text>
      )}
      {/* <text x={x + 10} y={y + 18} fontSize={12}>
        EBI: {ebiObj.ebi || "Pending"}
        </text> */}

{/* 
      <text x={x + 65} y={y + 15} fontSize={10} fill="#444">
        {tunnels.s1u_enb && (
          <tspan x={x + 65} dy="0">eNB:{tunnels.s1u_enb.teid}</tspan>
        )}
        {tunnels.s1u_sgw && (
          <tspan dx={5} fill="#007bff">SGW:{tunnels.s1u_sgw.teid}</tspan>
        )}
        
        {(tunnels.s5s8_pgw || tunnels.s5s8_sgw) && (
          <>
            <tspan x={x + 65} dy="12" fill="#444">S5/8:</tspan>
            <tspan dx={3} fill="#e64980">PGW:{tunnels.s5s8_pgw?.teid || "-"}</tspan>
            <tspan dx={5} fill="#228be6">SGW:{tunnels.s5s8_sgw?.teid || "-"}</tspan>
          </>
        )}
        </text>
          */}
    </g>
  );
}

/**
 * SGW 전용 분할 렌더링 컴포넌트
 */
function SGWBearerBox({ x, y, lbiObj, ebiList, ebiHeight, headerHeight }) {
  const relayWidth = 340; // SGW는 좌우 분할을 위해 더 넓게
  const sideWidth = (relayWidth / 2) - 15;
  const relayHeight = headerHeight + ebiList.length * (ebiHeight + 6) + 10;

  return (
    <g>
      {/* SGW 전체 배경 */}
      <rect
        x={x - relayWidth / 2}
        y={y}
        width={relayWidth}
        height={relayHeight}
        rx={8} ry={8}
        fill="#f8f9fa"
        stroke="#228be6"
        strokeWidth="1.5"
      />
      <text x={x} y={y + 18} textAnchor="middle" fontSize={13} fontWeight="bold" fill="#1971c2">
        SGW Relay (LBI:{lbiObj.lbi})
      </text>

      {ebiList.map((ebiObj, idx) => {
        const ebiY = y + headerHeight + idx * (ebiHeight + 6);
        return (
          <g key={ebiObj.ebi}>
            {/* 왼쪽 S1-U 칸 */}
            <EBIBox
              x={x - relayWidth / 2 + 10}
              y={ebiY}
              width={sideWidth}
              height={ebiHeight}
              ebiObj={ebiObj}
              nodeRole = "SGW"
              ifaceType="S1U"
            />
            
            {/* 중앙 연결 브릿지 */}
            {/* <line 
              x1={x - 5} y1={ebiY + ebiHeight / 2} 
              x2={x + 5} y2={ebiY + ebiHeight / 2} 
              stroke="#40c057" strokeWidth="2" strokeDasharray="2,1"
            /> */}

            {/* 오른쪽 S5/S8 칸 */}
            <EBIBox
              x={x + 5}
              y={ebiY}
              width={sideWidth}
              height={ebiHeight}
              ebiObj={ebiObj}
              nodeRole = "SGW"
              ifaceType="S5S8"
            />
          </g>
        );
      })}
    </g>
  );
}

function
LBIBox({ x, y, lbiObj, nodeAddr }) {

  let nodeRole = AidentifyNodeRole(lbiObj, nodeAddr);

  console.log(nodeRole);
  const ebiList = lbiObj.ebiList || [];

  const isRelay = nodeRole === "RELAY";
  const isPending = lbiObj.pending === true;
  console.log("IS Relay??? >", isRelay);

  const headerHeight = 28;
  const ebiHeight = 26;
  const padding = 10;

  // const standardWidth = 220;
  const standardWidth = isRelay ? 340 : 220;
  const standardHeight =
    headerHeight + ebiList.length * (ebiHeight + 6) + padding;

  return (
    <g>
      {isRelay ? (
        <SGWBearerBox 
          x={x+(standardWidth/2)} y={y} 
          lbiObj={lbiObj} 
          ebiList={ebiList} 
          ebiHeight={ebiHeight}
          headerHeight={headerHeight}
          nodeAddr={nodeAddr}
        />
      ):(
    <g>
      <rect
        // x={x - standardWidth / 2} y={y}
          x={x} y={y} 
        width={standardWidth} height={standardHeight}
        rx={8} ry={8}
        fill={isPending ? "#fff9db" : "#f1f3f5"}
        stroke="#333"
      />

      <text
        // x={x - standardWidth / 2 + 10}
        x={x+10}
        y={y + 18} fontSize={13} fontWeight="bold">
        LBI : {lbiObj.lbi}
      </text>

      <text
      // x={x - standardWidth / 2 + 100 }
      x={x + 100 }
      y={y + 18} fontSize={11} fill="#555">
        {lbiObj.ip || ""}({nodeRole})
      </text>

      {ebiList.map((ebiObj, idx) => (
        <EBIBox
          key={ebiObj.ebi}
          // x={x -standardWidth / 2+ 10}
          x={x+10}
          y={y + headerHeight + idx * (ebiHeight + 6)}
          width={standardWidth - 20}
          height={ebiHeight}
          ebiObj={ebiObj}
          nodeRole = {nodeRole}
          ifaceType={nodeRole === "CORE" ? "S5S8" : "S1U"}
        />
      ))}
    </g>
      )}
    </g>
  );
}
export default LBIBox;
import React,{ useMemo }  from "react";

const NODE_ROLES = {
  ACCESS: "eNB",//"ACCESS", // eNB, gNB
  RELAY: "SGW", //"RELAY",   // SGW, UPF
  CORE: "PGW",//"CORE"      // PGW, SMF
};

function
identifyNodeRole(lbiObj, nodeIp)
{
  // lbiObj가 단일 세션 객체이므로 바로 ebiList를 순회
  const ebiList = lbiObj.ebiList || [];
  
  let hasS1U = false;
  let hasS5S8 = false;

  ebiList.forEach(ebiItem => {
    const t = ebiItem.tunnels;
    if (!t) return;

    const isS1U_SGW = t.s1u_sgw?.ip === nodeIp;
    const isS5S8_SGW = t.s5s8_sgw?.ip === nodeIp;
    
    if (isS1U_SGW || (t.s1u_sgw && !nodeIp)) hasS1U = true;
    if (isS5S8_SGW || (t.s5s8_sgw && !nodeIp)) hasS5S8 = true;
    
    if (nodeIp) {
        if (t.s5s8_pgw?.ip === nodeIp) { hasS5S8 = true; hasS1U = false; }
        if (t.s1u_enb?.ip === nodeIp) { hasS1U = true; hasS5S8 = false; }
    }
  });

  if (hasS1U && hasS5S8) return "RELAY";
  if (hasS5S8) return "CORE";
  return "ACCESS";
}

function
EBIBox({ x, y, width, height, ebiObj, nodeRole, ifaceType })
{
  const tunnels = ebiObj.tunnels || {};
  const isPending = ebiObj.pending === true;
  const isDelPending = ebiObj.deletePending === true;
  let displayIp = "-";

  if (ifaceType === "S1U") {
    const info = nodeRole === "ACCESS" ? tunnels.s1u_enb : tunnels.s1u_sgw;
    displayIp = info?.ip || "-";
  } else if (ifaceType === "S5S8") {
    const info = nodeRole === "CORE" ? tunnels.s5s8_pgw : tunnels.s5s8_sgw;
    displayIp = info?.ip || "-";
  }

  const targetTunnel = ifaceType === "S1U" ? {
    local: nodeRole === "SGW" ?  tunnels.s1u_sgw : tunnels.s1u_enb,
    label: "S1-U",
    color: "#228be6",
   } : {
    local: nodeRole === "SGW" ?  tunnels.s5s8_sgw : tunnels.s5s8_pgw, 
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
              {targetTunnel.local ? `${displayIp}` : "-"}
            </tspan>
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
    </g>
  );
}

/**
 * SGW 전용 분할 렌더링 컴포넌트
 */
function
SGWBearerBox({ x, y, lbiObj, ebiList, ebiHeight, headerHeight })
{
  const relayWidth = 400; // SGW는 좌우 분할을 위해 더 넓게
  const sideWidth = (relayWidth / 2) - 15;
  const relayHeight = headerHeight + ebiList.length * (ebiHeight + 6) + 10;

  return (
    <g>
      {/* SGW 전체 배경 */}
      <rect
        x={x - relayWidth / 2}
        y={y}
        width={relayWidth}
        height={relayHeight+20}
        rx={8} ry={8}
        fill="#f8f9fa"
        stroke="#228be6"
        strokeWidth="1.5"
      />

      <text x={x} y={y + 18} textAnchor="middle" fontSize={13} fontWeight="bold" fill="#1971c2">
          LBI:{lbiObj.lbi}
      </text>

      {ebiList.map((ebiObj, idx) => {
        const ebiY = y + headerHeight + idx * (ebiHeight + 10);
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

  let nodeRole = identifyNodeRole(lbiObj, nodeAddr);
  const ebiList = lbiObj.ebiList || [];
  const isRelay = nodeRole === "RELAY";
  const isPending = lbiObj.pending === true;

  const headerHeight = 28;
  const ebiHeight = 26;
  const padding = 10;

  const standardWidth = isRelay ? 240 : 220;
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
            x={x} y={y} 
            width={standardWidth} height={standardHeight+20}
            rx={8} ry={8}
            fill={isPending ? "#fff9db" : "#f1f3f5"}
            stroke="#333"
          />

          <text
            x={x+10}
            y={y + 18} fontSize={13} fontWeight="bold">
            LBI : {lbiObj.lbi}
          </text>

          {ebiList.map((ebiObj, idx) => (
            <EBIBox
              key={ebiObj.ebi}
              x={x+10}
              y={y + headerHeight + idx * (ebiHeight + 10)}
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
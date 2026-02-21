import React,{ useMemo }  from "react";

function
EBIBox({ x, y, width, height, ebiObj, nodeRole, ifaceType })
{
  const tunnels = ebiObj.tunnels || {};
  const isPending = ebiObj.pending === true;
  const isDelPending = ebiObj.delete_pending === true;

  let localInfo = null;
  let label = ifaceType;
  let color = "#228be6"

  console.log("ebiObj: ", ebiObj);
  // let displayIp = "-";

  // if (ifaceType === "S1U") {
  //   const info = nodeRole === "ACCESS" ? tunnels.s1u_enb : tunnels.s1u_sgw;
  //   displayIp = info?.ip || "-";
  // } else if (ifaceType === "S5S8") {
  //   const info = nodeRole === "CORE" ? tunnels.s5s8_pgw : tunnels.s5s8_sgw;
  //   displayIp = info?.ip || "-";
  // }
  if (ifaceType === "S1U") {
    label = "S1-U";
    color = "#228be6";
    // Access(eNB)면 enb 정보를, Relay(SGW)면 sgw 정보를 보여줌
    localInfo = nodeRole === "Access" ? tunnels.s1u_enb : tunnels.s1u_sgw;
  } else if (ifaceType === "S5S8") {
    label = "S5/S8";
    color = "#e64980"; // S5S8 기본 핑크
    // Core(PGW)면 pgw 정보를, Relay(SGW)면 sgw 정보를 보여줌
    localInfo = nodeRole === "Core" ? tunnels.s5s8_pgw : tunnels.s5s8_sgw;
  }

  console.log("label: ", label)
  console.log("localInfo: ", localInfo)

  // const targetTunnel = ifaceType === "S1U" ? {
  //   local: nodeRole === "SGW" ?  tunnels.s1u_sgw : tunnels.s1u_enb,
  //   label: "S1-U",
  //   color: "#228be6",
  //  } : {
  //   local: nodeRole === "SGW" ?  tunnels.s5s8_sgw : tunnels.s5s8_pgw, 
  //   label: "S5/S8",
  //   color: "#e64980",
  //  };

  // return (
  //   <g>
  //     <rect
  //       x={x} y={y}
  //       width={width} height={height+6}
  //       rx={6} ry={6}
  //       fill={isPending ? "#fff9db" : isDelPending? "#fa7f7fff":"#ffffff"} // 대기 중일 땐 연한 노란색
  //       stroke={isPending||isDelPending ? "#fcc419" : "#666"}
  //       strokeWidth={isPending || isDelPending ? 1.5 : 1}
  //       strokeDasharray={isPending||isDelPending ? "3,2" : "none"} // 대기 중일 땐 점선
  //     />

  //     <text x={x + 5} y={y + 12} fontSize={9} fontWeight="bold" fill={targetTunnel.color}>
  //       {targetTunnel.label} [EBI: {ebiObj.ebi || "!"}]
  //     </text>

  //     <text x={x + 5} y={y + 26} fontSize={10} fill="#333">
  //       {/* local이나 peer 중 하나라도 있으면 TEID 표시 */}
  //       {(targetTunnel.local || targetTunnel.peer) ? (
  //         <>
  //           <tspan fontWeight="bold">Teid: </tspan>
  //           <tspan fill={targetTunnel.color}>
  //             {targetTunnel.local ? `0x${targetTunnel.local.teid.toString(16).toUpperCase()}` : "-"}
  //           </tspan>

  //           <tspan fontWeight="bold">  IP: </tspan>
  //           <tspan fill={targetTunnel.color}>
  //             {targetTunnel.local ? `${displayIp}` : "-"}
  //           </tspan>
  //         </>
  //       ) : (
  //         <tspan fill="#ccc" fontStyle="italic">No Tunnel Info</tspan>
  //       )}
  //     </text>

  //     {/* 상태 표시 (삭제 중일 때) */}
  //     {isDelPending && (
  //       <text x={x + width - 5} y={y + 12} textAnchor="end" fontSize={8} fill="#ffffff" fontWeight="bold">
  //         DELETE
  //       </text>
  //     )}
  //   </g>
  // );
  return (
    <g>
      {/* 배경 박스: 상태에 따라 색상과 테두리 변경 */}
      <rect
        x={x} y={y}
        width={width} height={height + 6}
        rx={6} ry={6}
        fill={isDelPending ? "#fff5f5" : (isPending ? "#fff9db" : "#ffffff")}
        stroke={isDelPending ? "#ff8787" : (isPending ? "#fcc419" : "#adb5bd")}
        strokeWidth={isPending || isDelPending ? 1.5 : 1}
        strokeDasharray={isPending || isDelPending ? "3,2" : "none"}
      />

      {/* 상단 라벨 및 EBI 번호 */}
      <text x={x + 5} y={y + 12} fontSize={9} fontWeight="bold" fill={color}>
        {label} [EBI: {ebiObj.ebi}]
      </text>

      {/* 터널 상세 정보 (TEID, IP) */}
      <text x={x + 5} y={y + 26} fontSize={10} fill="#333">
        {localInfo ? (
          <>
            <tspan fontWeight="bold">Teid: </tspan>
            <tspan fill={color} fontWeight="500">
              {`0x${localInfo.teid.toString(16).toUpperCase()}`}
            </tspan>
            <tspan fontWeight="bold">  IP: </tspan>
            <tspan fill="#495057">
              {localInfo.ip}
            </tspan>
          </>
        ) : (
          <tspan fill="#adb5bd" fontStyle="italic">No Tunnel Info</tspan>
        )}
      </text>

      {/* 삭제 상태 표시 배지 */}
      {isDelPending && (
        <g>
          <rect x={x + width - 40} y={y + 3} width={35} height={10} rx={3} fill="#ff8787" />
          <text x={x + width - 22.5} y={y + 11} textAnchor="middle" fontSize={7} fill="#fff" fontWeight="bold">
            DELETE
          </text>
        </g>
      )}
    </g>
  );
}

/**
 * SGW 전용 분할 렌더링 컴포넌트
 */
function
SGWBearerBox({ x, y, lbi, ebiList, ebiHeight, headerHeight, nodeRole })
{
  const relayWidth = 400; // SGW는 좌우 분할을 위해 더 넓게
  const sideWidth = (relayWidth / 2) - 15;
  const relayHeight = headerHeight + (ebiList?.length||0) * (ebiHeight + 10) + 10;
  const isPending = ebiList.pending === true;

  return (
    <g>
      {/* SGW 전체 배경 */}
      <rect
        x={x - relayWidth / 2}
        y={y}
        width={relayWidth} height={relayHeight+10}
        rx={8} ry={8}
        // fill="#f8f9fa"
        fill={isPending ? "#fff9db" : "#f1f3f5"}
        stroke="#228be6"
        strokeWidth="1.5"
      />

      <text x={x} y={y + 18}
        textAnchor="middle"
        fill="#1971c2"
        fontSize={13} fontWeight="bold"
        >
          LBI : {lbi}
      </text>


      {ebiList.map((ebiObj, idx) => {
        const ebiY = y + headerHeight + idx * (ebiHeight + 10) ;
        return (
          <g key={ebiObj.ebi}>
            {/* 왼쪽 S1-U 칸 */}
            <EBIBox
              x={x - relayWidth / 2 + 10}
              y={ebiY}
              width={sideWidth}
              height={ebiHeight}
              ebiObj={ebiObj}
              nodeRole = {nodeRole}
              ifaceType="S1U"
            />
            
            {/* 오른쪽 S5/S8 칸 */}
            <EBIBox
              x={x + 5}
              y={ebiY}
              width={sideWidth}
              height={ebiHeight}
              ebiObj={ebiObj}
              nodeRole = {nodeRole}
              ifaceType="S5S8"
            />
          </g>
        );
      })}
    </g>
  );
}

function
// LBIBox({ x, y, lbiObj, nodeAddr }) {
LBIBox({ x, y, lbi, ebiList, nodeState }) {

  // let nodeRole = identifyNodeRole(lbiObj, nodeAddr);
  const nodeRole = nodeState?.role;
  // let nodeRole = nodeState.role;
  // const ebiList = lbiObj.ebiList || [];
  const isRelay = nodeRole === "RELAY";
  const isPending = ebiList.some(ebi => ebi.pending)

  const headerHeight = 28;
  const ebiHeight = 26;
  const padding = 10;

  // const ebiList = props.ebiList || [];
  const standardWidth = isRelay ? 240 : 220;
  const standardHeight =
    headerHeight + ebiList.length * (ebiHeight + 10) + padding;
    // headerHeight + ebiList.length * (ebiHeight + 6) + padding;

  return (
    <g>
      {isRelay ? (
        <SGWBearerBox 
          x={x +(standardWidth/2) } y={y} 
          lbi={lbi}
          ebiList={ebiList} 
          ebiHeight={ebiHeight}
          headerHeight={headerHeight}
          nodeRole={nodeRole}
        />
      ):(
        <g>
          {/* 배경박스 */}
          <rect
            x={x} y={y} 
            width={standardWidth} height={standardHeight+10}
            rx={8} ry={8}
            fill={isPending ? "#fff9db" : "#f1f3f5"}
            // stroke="#333"
            stroke="#228be6"
          />

          <text x={x+10} y={y + 18}
            fill="#1971c2"
            fontSize={13} fontWeight="bold">
            LBI : {lbi}
          </text>

          {ebiList.map((ebiObj, idx) => (
            <EBIBox
              // key={ebiObj.ebi}
              x={x+10}
              y={y + headerHeight + idx * (ebiHeight + 10)}
              width={standardWidth - 20}
              height={ebiHeight}
              ebiObj={ebiObj}
              nodeRole = {nodeRole}
              ifaceType={nodeRole === "Core" ? "S5S8" : "S1U"}
            />
          ))}
        </g>
      )}
    </g>
  );
}
export default LBIBox;
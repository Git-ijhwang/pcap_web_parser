import React,{ useMemo }  from "react";

function
EBIBox({ x, y, width, height, ebiObj }) {
  const tunnels = ebiObj.tunnels || {};
  return (
    <g>
      <rect
        x={x} y={y}
        width={width} height={height}
        rx={6} ry={6}
        // fill="#ffffff" stroke="#666"
        fill={ebiObj.pending ? "#fff9db" : "#ffffff"} // 대기 중일 땐 연한 노란색
        stroke={ebiObj.pending ? "#fcc419" : "#666"}
        strokeDasharray={ebiObj.pending ? "3,2" : "0"} // 대기 중일 땐 점선
      />
      <text x={x + 10} y={y + 18} fontSize={12}>
        EBI: {ebiObj.ebi || "Pending"}
        {/* TeID: {ebiObj.teid} */}
        </text>

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

function
LBIBox({ x, y, lbiObj }) {

  const ebiList = lbiObj.ebiList || [];
  const boxWidth = 220;
  const headerHeight = 28;
  const ebiHeight = 26;
  const padding = 10;

  const boxHeight =
    headerHeight + ebiList.length * (ebiHeight + 6) + padding;

  return (
    <g>
      <rect
        x={x} y={y}
        width={boxWidth} height={boxHeight}
        rx={8} ry={8}
        fill="#f1f3f5" stroke="#333"
      />

      <text x={x + 10} y={y + 18} fontSize={13} fontWeight="bold">
        LBI : {lbiObj.lbi}
      </text>

      <text x={x + 120} y={y + 18} fontSize={11} fill="#555">
        {lbiObj.ip || ""}
      </text>

      {ebiList.map((ebiObj, idx) => (
        <EBIBox
          key={ebiObj.ebi}
          x={x + 10}
          y={y + headerHeight + idx * (ebiHeight + 6)}
          width={boxWidth - 20}
          height={ebiHeight}
          ebiObj={ebiObj}
        />
      ))}
    </g>
  );
}
export default LBIBox;
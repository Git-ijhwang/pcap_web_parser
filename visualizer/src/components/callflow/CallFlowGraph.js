import LBIBox from "./BearerView"

function CallFlowGraph({ data, step }) {
  // 1. 기본 설정 (필요에 따라 조정)
  const width = 1100;
  const rowHeight = 50;
  const headerHeight = 100;
  const padding = 120;

  // 데이터 길이에 따라 동적으로 높이 계산
  const messageAreaHeight = data.length * (rowHeight);
  const height = headerHeight + (messageAreaHeight ) + 200; //하단 박스 공간 확보

  // 2. 노드(IP) 추출 및 X 좌표 계산
  const nodes = [...new Set(data.flatMap(p => [p.src_addr, p.dst_addr]))];
  const nodeX = {};
  const span = nodes.length > 1 ? (width - 2 * padding) / (nodes.length - 1) : 0;
  nodes.forEach((node, idx) => {
    nodeX[node] = padding + idx * span;
  });

  const visibleFlows = data.slice(0, step);
  const currentPacket = data && step > 0 ? data[step - 1] : null;
  // const currentNodeState = bearerHistory[step - 1] || {};
  const currentNodeState = currentPacket?.snapshot || {};

  console.log(data)
  console.log(currentNodeState)

  return (
    <svg width="100%" height={height+20} viewBox={`0 0 ${width} ${height}`} >
      {/* 1. 노드 수직선 및 헤더 */}
      {nodes.map(node => (
        <g key={node}>
          <line x1={nodeX[node]} y1={70}
                x2={nodeX[node]} y2={height - 200}
                stroke="#aaa" />
          <text x={nodeX[node]} y={50}
            textAnchor="middle" fontWeight="bold">IP: {node}</text>
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
              strokeWidth={1.2}
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
      {/* {Object.entries(currentNodeState).map(([nodeIp, lbiMap]) => { */}
      {Object.entries(currentNodeState).map(([nodeIp, nodeState]) => {
        const x = nodeX[nodeIp];
        if (!x) return null;
        
        const sessions = nodeState.sessions || {};

        // return Object.values(lbiMap).map((lbiObj, lbiIdx) => (
        return Object.entries(sessions).
          map(([lbi, ebiList], lbiIdx) => {
            const safeEbiList = Array.isArray(ebiList) ? ebiList : [];

            console.log("EbiList:", safeEbiList);
            console.log("State Map:", currentNodeState);
            return (
              <LBIBox 
                key={`${nodeIp}-${lbi}`}
                x={x - 110}
                y={height - 220 + (lbiIdx * 210)} // LBI가 여러개일 경우 아래로 나열
                lbi={lbi}
                ebiList={safeEbiList}
                nodeState={nodeState}
              />
            );
        });
      })}
    </svg>
  );
}

export default CallFlowGraph;

import React from "react";

function CallFlowGraph({ data }) {

  if (!data || data.length === 0) return <div>No Call Flow</div>

  const width = 1000;
  const padding = 120;
  const rowHeight = 60;
  const headerHeight = 80;
  const height = headerHeight + data.length * rowHeight;


  const nodes = Array.from (
    new Set(data.flatMap(pkt => [pkt.src_addr, pkt.dst_addr]))
  );


  // 🔹 노드 X 좌표 계산 (단 하나만!)
  const nodeX = {};
  const span =
    nodes.length > 1
      ? (width - 2 * padding) / (nodes.length - 1)
      : 0;

  nodes.forEach((node, idx) => {
    nodeX[node] = padding + idx * span;
  });


  return (
    <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} >
      {/* Title */}
      {/* <text x="20" y="30" fontSize="18" fontWeight="bold">
        Call Flow Diagram
      </text> */}

      {nodes.map((node) => {
          const x = nodeX[node];
  const y = 60;

  const paddingX = 10;
  const paddingY = 10;
  const textWidth = node.length * 8; // 간단한 폭 추정
  const textHeight = 18;

        return (
        <g key={node}>
          {/* 테두리박스 */}
          <rect
            x={x - textWidth / 2 - paddingX}
            y={y - textHeight - paddingY}
            width={textWidth + paddingX * 2}
            height={textHeight + paddingY+10}
            rx={6}
            ry={6}
            fill="#f8f9fa"
            // fill="#ffffff"
            stroke="#333"
            strokeWidth={1}
          />
          <text
              key={node}
              x={nodeX[node]}
              y={60}
              fontSize={16} // 노드 이름 크기
              fontWeight="bold"
              textAnchor="middle"
            >
            {node}
          </text>
          </g>
      );
      })}

      {/* 세로줄 */}
      {nodes.map((node, idx) => (
        <line
                key={node}
                x1={nodeX[node]}
                y1={70} //세로줄 시작 점
                x2={nodeX[node]}
                y2={headerHeight + data.length * rowHeight}
                stroke="gray"
                // strokeDasharray="4,4"
                strokeWidth={2}
        />
      ))}

      {data.map((pkt,idx) => {
        const y = 100 + idx * 30;
        return (
          <g key={idx}>
            <line
              x1={nodeX[pkt.src_addr]}
              y1={y}
              x2={nodeX[pkt.dst_addr]}
              y2={y}
              stroke="black"
              strokeWidth={2}
              markerEnd="url(#arrow)"
            />

            {/* 메시지 이름 */}
            <text
              x={(nodeX[pkt.src_addr] + nodeX[pkt.dst_addr]) / 2}
              y={y - 5}
              textAnchor="middle"
              fontSize="12"
            >
              #{pkt.id}. {pkt.message}
            </text>
          </g>
        );
      })}


      {/* 화살표 마커 정의 */}
      <defs>
        <marker
          id="arrow"
          markerWidth="10"
          markerHeight="10"
          refX="10"
          refY="3"
          orient="auto"
        >
          <path d="M0,0 L0,6 L9,3 z" fill="black" />
        </marker>
      </defs>

    </svg>
  );
}

export default CallFlowGraph;

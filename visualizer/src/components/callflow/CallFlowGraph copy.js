import React,{ useMemo }  from "react";


function useBearerState(callFlows) {
  return useMemo(() => {
    let state = {};
    const history = [];

    callFlows.forEach(cf => {
      state = applyCallFlowToBearerState(state, cf);
      history.push({ ...state });
    });

    return history;
  }, [callFlows]);
}

function
applyCallFlowToBearerState(state, cf) {
  const next = { ...state };

  // bearer 정보가 없는 메시지는 상태 변경 없음
  if (!cf.bearer) return next;

  const { lbi, ebi, ip } = cf.bearer;

  // Create / Modify Bearer
  if (cf.message.includes("Create") || cf.message.includes("Modify")) {
    next[lbi] = {
      lbi,
      ebis: [...ebi],
      ip,
      active: true,
    };
  }

  // Delete Session
  if (cf.message.includes("Delete")) {
    if (next[lbi]) {
      next[lbi] = {
        ...next[lbi],
        active: false,
      };
    }
  }

  return next;
}


function BearerBox({ x, y, bearer }) {
  if (!bearer || bearer.lbi === 0 || bearer.ebi.length === 0) return null;

  const boxWidth = 220;
  const headerHeight = 28;
  const ebiHeight = 26;
  const padding = 10;

  const boxHeight =
    headerHeight + bearer.ebi.length * (ebiHeight + 6) + padding;

  return (
    <g>
      {/* LBI Outer Box */}
      <rect
        x={x}
        y={y}
        width={boxWidth}
        height={boxHeight}
        rx={8}
        ry={8}
        fill="#f1f3f5"
        stroke="#333"
      />

      {/* LBI Header */}
      <text
        x={x + 10}
        y={y + 18}
        fontSize={13}
        fontWeight="bold"
      >
        LBI : {bearer.lbi}
      </text>

      {/* IP */}
      <text
        x={x + 120}
        y={y + 18}
        fontSize={11}
        fill="#555"
      >
        {bearer.ip}
      </text>

      {/* EBI Boxes */}
      {bearer.ebi.map((ebi, idx) => {
        const ebiY =
          y + headerHeight + idx * (ebiHeight + 6);

        return (
          <g key={ebi}>
            <rect
              x={x + 10}
              y={ebiY}
              width={boxWidth - 20}
              height={ebiHeight}
              rx={6}
              ry={6}
              fill="#ffffff"
              stroke="#666"
            />
            <text
              x={x + 20}
              y={ebiY + 18}
              fontSize={12}
            >
              EBI : {ebi}
            </text>
          </g>
        );
      })}
    </g>
  );
}

function CallFlowGraph({ data }) {
  if (!data || data.length === 0) return <div>No Call Flow</div>;

  const width = 1100;
  const padding = 120;
  const rowHeight = 50;
  const headerHeight = 90;
  const height = headerHeight + data.length * rowHeight + 300;

  /* 노드 추출 */
  const nodes = Array.from(
    new Set(data.flatMap(pkt => [pkt.src_addr, pkt.dst_addr]))
  );

  /* 노드 X 좌표 */
  const nodeX = {};
  const span =
    nodes.length > 1
      ? (width - 2 * padding) / (nodes.length - 1)
      : 0;

  nodes.forEach((node, idx) => {
    nodeX[node] = padding + idx * span;
  });


  return (
    <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`}>


      {/* Node Header */}
      {nodes.map(node => {
        const x = nodeX[node];
        const y = 60;
        const textWidth = node.length * 8;

        return (
          <g key={node}>
            <rect
              x={x - textWidth / 2 - 10}
              y={y - 24}
              width={textWidth + 20}
              height={30}
              rx={6}
              ry={6}
              fill="#f8f9fa"
              stroke="#333"
            />
            <text
              x={x}
              y={y - 4}
              fontSize={14}
              fontWeight="bold"
              textAnchor="middle"
            >
              {node}
            </text>
          </g>
        );
      })}

      {/* Vertical Lines */}
      {nodes.map(node => (
        <line
          key={node}
          x1={nodeX[node]}
          y1={70}
          x2={nodeX[node]}
          y2={height - 200}
          stroke="#aaa"
          strokeWidth={2}
        />
      ))}

      {/* Call Flow Messages */}
      {data.map((pkt, idx) => {
        const y = headerHeight + idx * rowHeight;

        return (
          <g key={idx}>
            <line
              x1={nodeX[pkt.src_addr]}
              y1={y}
              x2={nodeX[pkt.dst_addr]}
              y2={y}
              stroke="#000"
              strokeWidth={2}
              markerEnd="url(#arrow)"
            />

            <text
              x={(nodeX[pkt.src_addr] + nodeX[pkt.dst_addr]) / 2}
              y={y - 6}
              textAnchor="middle"
              fontSize={12}
            >
              #{pkt.id} {pkt.message}
            </text>
          </g>
        );
      })}

      {/* Bearer Visualization (LBI / EBI) */}
      {data.map((pkt, idx) => {
        if (!pkt.bearer || pkt.bearer.lbi === 0) return null;

        return (
          <BearerBox
            key={`bearer-${idx}`}
            x={nodeX[pkt.dst_addr] - 110}
            y={height - 180}
            bearer={pkt.bearer}
          />
        );
      })}

      {/* Arrow */}
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

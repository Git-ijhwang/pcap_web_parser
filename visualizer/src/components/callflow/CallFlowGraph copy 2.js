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
  const next = { ...state };

  if (!cf.bearer && cf.ebi === undefined) return next;

  const node = cf.src_addr;

  if (!next[node]) {
    next[node] = {ebiList: []};
  }

  const nodeData = next[node];

  console.log("Call FLow #",cf.id, " Message: ", cf.message);

  // ============ Create Session ============ 
  if (cf.message.includes("Create Session")
      && Array.isArray(cf.bearer)
      && cf.bearer.length > 0
  )
    {
  
    const lbi = Number(cf.bearer[0]?.ebi);
    if (Number.isNaN(lbi)) return;

    if (!nodeData[lbi]) {
      nodeData[lbi] = {
        lbi,
        ip: cf.src_addr,
        ebiList: [], // 배열로 관리 (여러 개의 EBI가 묶일 수 있음)
      };
    }

    cf.bearer.forEach(b => {
      const ebi = Number(b.ebi);
      if (Number.isNaN(ebi)) return;

      const exists = nodeData[lbi].ebiList.some(e => e.ebi === b.ebi);
      if (!exists) {
        nodeData[lbi].ebiList.push({
          ebi,
          fteid: b.fteid_list || [],
          active: true,
        });
        console.log("-========> Ebilist Created", nodeData[lbi]);
      }
    });
  }

  // ============ Create Bearer Request ============ 
  if (cf.message.includes("Create Bearer Request")
      && cf.bearer && cf.ebi !== null)
  {
    const lbi = Number(cf.ebi);
    const nodes = [cf.src_addr, cf.dst_addr];
    nodes.forEach(nodeAddr => {
      if (!nodeData[nodeAddr]) nodeData[nodeAddr] = {};

      if (!nodeData[nodeAddr][lbi]) {
        nodeData[nodeAddr][lbi] = {
          lbi,
          ip: nodeAddr,
          ebiList: [],
          // pending: true,
        };
      }

      const nodeLbiData = nodeData[nodeAddr][lbi];
      console.log("Node============= ", nodeLbiData);

      cf.bearer.forEach( b => {
        //Request에 매핑 key는 '상대에게 전달되는 TEID'
        const matchFteid = (b.fteid_list || []).find(f =>
          f.iface_type === 5 || f.iface_type === 1
        );
        if (!matchFteid) {
          console.log("Cannot find matched FTEID");
          return;
        }
        console.log("MATCH TEID: ", matchFteid);

        //같은 matchKey가 있으면 skip
        const exists = nodeLbiData.ebiList.some(e =>
          e.matchKey?.teid === matchFteid.teid &&
          e.matchKey?.iface_type === matchFteid.iface_type
        );

        if (exists) return;

        nodeLbiData.ebiList.push( {
          ebi: null,
          pending: true,
          matchKey: {
            iface_type: matchFteid.iface_type,
            teid: matchFteid.teid
          },
          tunnels: {
            s5_pgw: null,
            s5_sgw: null,
            s1_sgw: null,
            s1_enb: null,
          },
        });
      console.log("Node-------------------- ", nodeLbiData);
      });
    });
  }
  // ============ Create Bearer Response ============ 
  if (cf.message.includes("Create Bearer Response") && cf.bearer)
  {

    [cf.src_addr, cf.dst_addr].forEach(nodeAddr => {
      const nodeState = next[nodeAddr];
      if (!nodeState) return;

      Object.values(nodeState).forEach(lbiState => {
        if (!Array.isArray(lbiState.ebiList)) return;

        lbiState.ebiList = lbiState.ebiList.map(pendingBearer => {
          if (!pendingBearer.pending) return pendingBearer;

          const matched = cf.bearer.find( b =>
            (b.fteid_list || []).some(f=>
              f.iface_type === pendingBearer.matchKey.iface_type &&
              f.teid === pendingBearer.matchKey.teid
            )
          );

          if (!matched) return pendingBearer;
          
          const tunnels = { ...pendingBearer.tunnels };

          (matched.fteid_list || []).forEach( f => {
            const ip = f.ipv4 || null;

            if (f.iface_type === 0) tunnels.s1_enb = {teid: f.teid, ip};
            if (f.iface_type === 1) tunnels.s1_sgw = {teid: f.teid, ip};
            if (f.iface_type === 4) tunnels.s5_sgw = {teid: f.teid, ip};
            if (f.iface_type === 5) tunnels.s5_pgw = {teid: f.teid, ip};
          });

          return {
            ...pendingBearer,
            ebi: matched.ebi,
            pending: false,
            tunnels,
          };

        });
      });
    
    })
    [cf.src_addr, cf.dst_addr].forEach(node => {
      if (!nodeData[node]) nodeData[node] = {};

      cf.bearer.forEach( b => {
        const ebi = b.ebi;

        let lbiKey = Object.keys(nodeData[node]).find(lbi =>
          nodeData[node][lbi]?.ebiList?.some(e => e.ebi === ebi ) )
          ;

        if (!lbiKey) {
          console.warn("No match LBI for EBI", ebi, "on node", node);
          return;
        }

        const lbiState = nodeData[node][lbiKey];

        const exists = lbiState.ebiList.some(e => e.ebi === ebi);
        if (exists) return;

        // nodeData[node][ebi] =
        lbiState.ebiList.push({
            ebi,
            fteid: b.fteid_list || [],
            active: true,
            pending: false,
            tunnels: {}
        });
      });
    });

  }

  // ============ Modify Bearer  ============ 
  if (cf.message.includes("Modify Bearer") && cf.bearer ) {

    const lbi = Number(cf.bearer[0]?.ebi);
    if (Number.isNaN(lbi)) return next;;

    // console.log("LBI: ", lbi);
    if (lbi === undefined || lbi === null) return;
    if (!nodeData[lbi]) nodeData[lbi] = { lbi, ip: cf.src_addr, ebiList: [] };

    cf.bearer.forEach(b => {
      const ebi = Number(b.ebi);
      if (Number.isNaN(ebi)) return;

      // console.log("EBI: ", ebi);
      // console.log("Bearer :", b);
      let ebiObj = nodeData[lbi].ebiList.find(e => e.ebi === ebi);
      if (!ebiObj) {
        ebiObj = { ebi, fteid: b.fteid_list || [], active: true, };
        nodeData[lbi].ebiList.push(ebiObj);
      }

      console.log("Node Data :", nodeData[lbi]);
      (b.fteid_list || []).forEach(f => {
        const ip = f.ipv4 || f.ipv6||null;

        if (f.iface_type === 0 || f.face_type === 1) {
          //S1-U
          if (!ebiObj.s1u)
            ebiObj.s1u = {};

          ebiObj.s1u[cf.src_addr] = { teid: f.teid, ip }
        }

        if ( f.iface_type === 4 || f.iface_type === 5) {
          //S5/S8
          ebiObj.s5s8 = {teid: f.teid, ip};
        }
      });
    });
  }

  // ============ Delete Bearer  ============ 
  if (cf.message.includes("Delete Bearer") && cf.ebi !== undefined) {

    //1. 삭제 대상 EBI추출(REQ/Resp 모두 처리)
    let delEbi = cf.ebi ?? (cf.bearer?.[0]?.ebi)??null;
    // if (delEbi === null) return next;

    if (cf.ebi !== undefined && cf.ebi !== null) {
      delEbi = Number(cf.ebi);
    } else if (cf.bearer && cf.bearer.length > 0) {
      delEbi = cf.bearer[0].ebi;
    }
    if (delEbi === null) return next;

    // const lbi = cf.bearer?.lbi;
    // const lbiKey = Object.keys(nodeData).find( lbi =>
    //   nodeData[lbi].ebiList.some(e => e.ebi === delEbi)
    // );
    const lbiKey = Object.keys(nodeData).find(lbi =>
      Array.isArray(nodeData[lbi]?.ebiList) &&
      nodeData[lbi].ebiList.some(e => e.ebi === delEbi)
    );
    
    if (!lbiKey) return next;


    nodeData[lbiKey].ebiList = nodeData[lbiKey].ebiList.filter(e => e.ebi !== delEbi);
  }

  /* Delete Session */
  if (cf.message.includes("Delete Session")) {
    // const { lbi } = cf.bearer;
    delete next[node];
  }

  next[node] = nodeData;

  return next;
}




function CallFlowGraph({ data, step }) {

  const visibleFlows = data.slice(0, step);
  const bearerHistory = useBearerState(visibleFlows);

  const currentNodeState = bearerHistory[step - 1] || {};

  const width = 1100;
  const padding = 120;
  const rowHeight = 50;
  const headerHeight = 90;
  const height = headerHeight + data.length * rowHeight + 300;

  if (!data || data.length === 0) {
    return <div>No Call Flow</div>;
  }

  /* 노드 추출 */
  const nodes = [...new Set(
    data.flatMap( p =>
      [ p.src_addr, p.dst_addr ]
    )
  )]

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
            <rect x={x - textWidth / 2 - 12} y={y - 26} width={textWidth + 25} height={34} rx={6} ry={6} fill="#f8f9fa" stroke="#333" />
            <text x={x} y={y - 4} fontSize={18} fontWeight="bold" textAnchor="middle" >
              {node}
            </text>
          </g>
        );
      })}


      {/* Vertical Lines */}
      {nodes.map(node => (
        <line key={`line-${node}`} x1={nodeX[node]} y1={70} x2={nodeX[node]} y2={height - 200} stroke="#aaa" strokeWidth={2} />
      ))}

      {/* Call Flow Messages */}
      {visibleFlows.map((pkt, idx) => {
        const y = headerHeight + idx * rowHeight;
        const nodeBearers =
        bearerHistory[step-1]?.[pkt.src_addr] ||
        bearerHistory[step-1]?.[pkt.dst_addr] ||
        {};

        return (
          <g key={`cf-${pkt.id}`} >

            <line
              x1={nodeX[pkt.src_addr]} y1={y}
              x2={nodeX[pkt.dst_addr]} y2={y}
              stroke="#000" strokeWidth={2}
              markerEnd="url(#arrow)" />

            <text
              x={(nodeX[pkt.src_addr] + nodeX[pkt.dst_addr]) / 2}
              y={y - 6}
              textAnchor="middle" fontSize={18} >
              #{pkt.id} {pkt.message}
            </text>

              {
                Object.entries(currentNodeState).flatMap(([nodeAddr, lbiMap]) =>
                  Object.values(lbiMap).flatMap(lbiObj => {
                    console.log(lbiObj);
                    if (!Array.isArray(lbiObj.ebiList) || lbiObj.ebiList.length === 0) return [];

                    console.log("└─", lbiObj.ebiList)
                    return lbiObj.ebiList.map((bearer, idx) => (

                      <LBIBox
                        key={`bearer-${lbiObj.lbi}-${bearer.ebi}-${idx}`}
                        x={nodeX[lbiObj.ip] - 110}
                        y={height - 180}

                        lbiObj={lbiObj}
                        // bearer={{
                        //   ...bearer,
                        //   lbi: lbiObj.lbi,
                        //   ip: lbiObj.ip,
                        // }}
                      />
                    ));
                  })
                )
            }

          </g>
        );
      })}


      {/* Arrow */}
      <defs>
        <marker id="arrow" markerWidth="10" markerHeight="10" refX="10" refY="3" orient="auto" >
          <path d="M0,0 L0,6 L9,3 z" fill="black" />
        </marker>
      </defs>

    </svg>
  );
}

export default CallFlowGraph;

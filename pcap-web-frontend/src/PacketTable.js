// src/PacketTable.js
import React, { useState } from "react";

/**
 * PacketTable
 * props:
 *   packets: [{ id, ts, src_ip, dst_ip, src_port, dst_port, protocol, length, description }, ...]
 *   fetchPacketDetail: async function(id) => returns detail object (optional)
 */
export default function PacketTable({ packets = [], fetchPacketDetail }) {
  const [expanded, setExpanded] = useState({}); // { id: {loading, detail, open} }

  // 컬럼 정의(확장성: 여기에 항목 추가하면 자동 적용)
  const columns = [
    { key: "id", label: "ID", width: "50px" },
    { key: "ts", label: "Timestamp", width: "220px" },
    { key: "flow", label: "Flow", width: "auto" },
    { key: "protocol", label: "Proto", width: "80px" },
    { key: "description", label: "Description", width: "360px" },
    { key: "action", label: "", width: "60px" }
  ];

  const onToggle = async (id) => {
    const state = expanded[id] || {};
    // toggle close if open
    if (state.open) {
      setExpanded(prev => ({ ...prev, [id]: { ...state, open: false } }));
      return;
    }

    // if we have detail already, just open
    if (state.detail) {
      setExpanded(prev => ({ ...prev, [id]: { ...state, open: true } }));
      return;
    }

    // otherwise fetch detail
    setExpanded(prev => ({ ...prev, [id]: { loading: true, open: true } }));
    try {
      if (!fetchPacketDetail) {
        // no backend fetch function supplied
        setExpanded(prev => ({ ...prev, [id]: { loading: false, open: true, detail: null } }));
        return;
      }
      const detail = await fetchPacketDetail(id);
      setExpanded(prev => ({ ...prev, [id]: { loading: false, open: true, detail } }));
    } catch (err) {
      setExpanded(prev => ({ ...prev, [id]: { loading: false, open: true, error: String(err) } }));
    }
  };

  const rows = packets.map(pkt => ({
    id: pkt.id,
    ts: pkt.ts,
    flow: `${pkt.src_ip}:${pkt.src_port} → ${pkt.dst_ip}:${pkt.dst_port}`,
    protocol: pkt.protocol,
    description: pkt.description,
  }));

  return (
    <div>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            {columns.map(col => (
              <th key={col.key} style={{ textAlign: "left", padding: "8px", borderBottom: "1px solid #ddd", width: col.width }}>
                {col.label}
              </th>
            ))}
          </tr>
        </thead>

        <tbody>
          {rows.map(row => (
            <React.Fragment key={row.id}>
              <tr style={{ cursor: "pointer" }}>
                <td style={{ padding: "8px", borderBottom: "1px solid #f2f2f2" }}>{row.id}</td>
                <td style={{ padding: "8px", borderBottom: "1px solid #f2f2f2" }}>{row.ts}</td>
                <td style={{ padding: "8px", borderBottom: "1px solid #f2f2f2" }}>{row.flow}</td>
                <td style={{ padding: "8px", borderBottom: "1px solid #f2f2f2" }}>{row.protocol}</td>
                <td style={{ padding: "8px", borderBottom: "1px solid #f2f2f2" }}>{row.description}</td>
                <td style={{ padding: "8px", borderBottom: "1px solid #f2f2f2" }}>
                  <button onClick={() => onToggle(row.id)} style={{ padding: "4px 8px" }}>
                    {expanded[row.id] && expanded[row.id].open ? "−" : "+"}
                  </button>
                </td>
              </tr>

              {/* 확장 영역 */}
              {expanded[row.id] && expanded[row.id].open && (
                <tr>
                  <td colSpan={columns.length} style={{ background: "#fbfbfb", padding: 12 }}>
                    {expanded[row.id].loading && <div>Loading detail...</div>}

                    {expanded[row.id].error && (
                      <div style={{ color: "red" }}>Error: {expanded[row.id].error}</div>
                    )}

                    {expanded[row.id].detail && (
                      <div style={{ fontFamily: "monospace", fontSize: 13 }}>
                        <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>
                          {JSON.stringify(expanded[row.id].detail, null, 2)}
                        </pre>
                      </div>
                    )}

                    {!expanded[row.id].loading && !expanded[row.id].detail && !expanded[row.id].error && (
                      <div style={{ color: "#666" }}>No detail available</div>
                    )}
                  </td>
                </tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

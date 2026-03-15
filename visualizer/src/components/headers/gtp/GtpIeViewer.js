import React, { useState } from "react";
import IeDecoder from "./IeDecoder";

function GtpIeSimpleTable({ ies, level = 0,onHoverRaw= () => {} })
{
  const bgColor=[ "#F5BABB", "#f8dfd7ff", "#245050ff" ];
  const [expanded, setExpanded] = useState({});
  const toggle = (idx) => {
    setExpanded((prev) => ({
      ...performance,
      [idx]: !prev[idx]
    }));
  };

  return (
    <>
    {ies.map((ie, idx) => {
      const subIes = ie.ie_value?.SubIeList;
      const isGrouped = Array.isArray(subIes) && subIes.length > 0;

      const isOpen = expanded[idx] || false;

      return (
        <div key={`ie-wrap-${idx}`}
            onMouseEnter={() => onHoverRaw(ie.raw)}   // ★★ Hover 시 raw 표시
            onMouseLeave={() => onHoverRaw(null)}  // ★★ Hover 벗어나면 clear
        >
          <table className="table table-bordered table-sm ie-table"
                key={`ie-${ie.ie_type}-${ie.instance}-${idx}`}  // ✅ 고유 key
                style={{ fontSize: "14px", backgroundColor:bgColor[level]||"#010101" }}
                >
            <tbody>

              {!isOpen && (
                <tr style={{
                          cursor: "pointer",
                          userSelect: "none",
                          background: isOpen? (bgColor[level] || "#010101"): "#a9e9b7ff",
                        }}
                  onClick={() => toggle(idx)}
                >
                  <th style={{colSpan:"2",
                          backgroundColor:bgColor[level]||"#010101", }}>
                    {isOpen ?  "▼" : "▶"} {ie.type_str}
                  </th>
                </tr>
              )}

                {isOpen && (
                  <>
                  <tr style={{
                            cursor: "pointer",
                            userSelect: "none",
                            fontSize: "14px",
                            backgroundColor:bgColor[level]||"#010101", }}
                      onClick={() => toggle(idx)}
                  >

                    <th style={{ fontSize: "14px", backgroundColor:bgColor[level]||"#010101" }} >
                      {isOpen ? "▼" : "▶"} Type 
                    </th>
                    <td style={{ fontSize: "14px", backgroundColor:bgColor[level]||"#010101" }} >
                      {ie.type_str} [{ie.ie_type}]
                    </td>
                  </tr>

                  <tr >
                    <th> Len </th>
                    <td> {ie.length} <i>bytes</i></td>
                  </tr>
                  <tr >
                    <th> Instance </th>
                    <td> {ie.instance} </td>
                  </tr>

                  {!isGrouped && (
                    <tr >
                      <th> Value </th>
                      <td> 
                        {IeDecoder(ie.ie_value, ie.ie_type)}
                      </td>
                    </tr>
                  )}


                  {isGrouped && (
                    <tr >
                      <td className="ie-group" colSpan="2"
                        style={{ paddingLeft: "10px", paddingRight: "10px", background:"#a4b1fa" }}>
                        <b>Grouped IE Contents</b>
                        <GtpIeSimpleTable ies={subIes} level={level + 1}
                                            onHoverRaw={onHoverRaw} />
                      </td>
                    </tr>
                  )}

                  </>
                )}
            </tbody>
          </table>
        </div>
      );

    })}
    </>
  );
}


function GtpIeViewer({ ies, onHoverRaw = () => {} }) {
  return (   // <- 최종 return
    <div>
      {ies.map((ie, idx) => {
        const subIes = ie.ie_value?.SubIeList;
        const isGrouped = Array.isArray(subIes) && subIes.length > 0;

        return (  // <- map 안에서 JSX를 반환
          <div
            key={`ie-${ie.ie_type}-${ie.instance}-${idx}`}
            onMouseEnter={() => onHoverRaw(ie.raw)}
            onMouseLeave={() => onHoverRaw(null)}
          >
            <GtpIeSimpleTable ies={[ie]} level={0} onHoverRaw={onHoverRaw} />
          </div>
        );
      })}
    </div>
  );
}
export default GtpIeViewer;
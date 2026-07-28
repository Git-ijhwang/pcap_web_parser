import "../gtp/GtpTable.css";

function ComponentRenderer({ comp })
{
  if (!comp) return <div>None</div>;
   // comp가 string ("None")일 수도 있음

  if (typeof comp === "string") {
    return <div>{comp}</div>;
  }

  const type = Object.keys(comp)[0];   // "Ipv4Addr", "Protocol", ...
  const data = comp[type];

  switch (type) {

    case "Ipv4Addr":
      return (
        <div>
          <div>  <strong> IPv4 Addr: </strong>
          {data.addr}</div>
          <div>  <strong>Mask: </strong>{data.mask}</div>
        </div>
      );

    case "Ipv6Addr":
      return (
        <div>
          <div>  <strong>IPv6 Addr: </strong>{data.addr}</div>
          <div> <strong> Mask: </strong>{data.mask}</div>
        </div>
      );

    case "Protocol":
      return <div>  <strong>Protocol: </strong>{data.proto}</div>;

    case "SinglePort":
      return <div>  <strong>Port: </strong>{data.port}</div>;

    case "PortRange":
      return (
        <div>  <strong>Port Range: </strong>{data.start} - {data.end}
        </div>
      );

    case "SecParamIdx":
      return <div>  SPI: {data.spi}</div>;

    case "TypeOfService":
      return (
        <div>  ToS Value: {data.value}, Mask: {data.mask} </div>
      );

    case "FlowLabel":
      return <div>  low Label: {data.label}</div>;

    case "Unknown":
      return (
        <div>
          <i>Unknown data</i>: type {data.t}, raw = [{data.data.join(", ")}]
        </div>
      );

    default:
      return <div>None</div>;
  }
}

function IeDecoder(value, ietype, numrow=1, ieLength=0 ) {
  if (!value) return null;

  const type = Object.keys(value)[0];
  const data = value[type];
  const numDataRows = numrow - 1; // 실제 데이터가 차지하는 행 수
  const lastRowBytes = ieLength % 4 || 4; // 마지막 줄이 차지하는 바이트 수 (1, 2, 3, 4)

  switch (type) {

    case "Uint8":
      if (ietype == 73) {
        return (
          <>
            <td colSpan="4"><span> Spare </span> </td>
            <td colSpan="4"> <span>{data}</span> </td>
          </>
        );
      } else {
        return (
          <>
            <td colSpan="8"> <span>{data}</span> </td>
          </>
        );
      }
    case "Uint16":
      return (
        <td colSpan="16"> <span>{data}</span> </td>
      );

    case "Uint32":
      return (
        <td colSpan="32"> <span>{data}</span> </td>
      );
    case "Ipv4":
      return( <td colSpan="32"> <span>{data}</span>; </td>);

    case "Ambr":
      return (
        <>
        {Array.from({ length: numDataRows }).map((_, index) => {
          const isFirst = index === 0;
          const isLast = index === numDataRows - 1;

          const rowClassName = `value-row ${isLast ? 'ie-last-row' : ''}`;

          return (
            <tr key={index} className={rowClassName}>
              {isFirst ? (
                /* 1. 첫 번째 줄: 모든 데이터를 출력 */
                isLast && lastRowBytes < 4 ? (
                  /* 만약 데이터가 딱 한 줄인데 4바이트가 안 되는 경우 */
                  <>
                    <td colSpan={lastRowBytes * 8}
                      className="text-center font-mono font-bold text-blue-700 bg-white">
                        <div><strong>UL: </strong>{data.ul}</div>
                        <div><strong>DL: </strong>{data.dl}</div>
                    </td>
                    <td colSpan={(4 - lastRowBytes) * 8} className="bg-gray-100 text-gray-400 italic text-[9px] text-center">
                      Spare
                    </td>
                  </>
                ) : (
                  /* 일반적인 첫 번째 줄 (전체 너비 사용) */
                  <td colSpan="32" className="p-2 text-center font-mono font-bold text-blue-700 bg-white">
                    {typeof data === 'object' ?(
                    // JSON.stringify(data)
                    <>
                      <div><strong>UL: </strong>{data.ul}</div>
                      <div><strong>DL: </strong>{data.dl}</div>
                    </>
                    )
                    : data}
                  </td>
                )
              ) : isLast && lastRowBytes < 4 ? (
                /* 2. 마지막 줄: 데이터가 남은 만큼만 Continuation을 그리고 나머지는 Spare */
                <>
                  <td colSpan={lastRowBytes * 8} className="text-center text-[10px] text-gray-400  italic">
                    Continuation
                  </td>
                  <td colSpan={(4 - lastRowBytes) * 8} className="bg-gray-100 text-gray-400 italic text-[9px] text-center">
                  </td>
                </>
              ) : (
                /* 3. 중간 줄 혹은 딱 떨어지는 마지막 줄: 전체 너비 Continuation */
                <td colSpan="32" className="text-center text-[10px] text-gray-400  italic">
                  Continuation
                </td>
              )}
            </tr>
          );
        })}
        </>
      );

    case "Utf8String":
    case "Apn":
      return(
        <>
        {Array.from({ length: numDataRows }).map((_, index) => {
        const isFirst = index === 0;
        const isLast = index === numDataRows - 1;

        const rowClassName = `value-row ${isLast ? 'ie-last-row' : ''}`;

        return (
          <tr key={index} className={rowClassName}>
            {isFirst ? (
              /* 1. 첫 번째 줄: 모든 데이터를 출력 */
              isLast && lastRowBytes < 4 ? (
                /* 만약 데이터가 딱 한 줄인데 4바이트가 안 되는 경우 */
                <>
                  <td colSpan={lastRowBytes * 8}
                    className="text-center font-mono font-bold text-blue-700 bg-white">
                    {JSON.stringify(data)}
                  </td>
                  <td colSpan={(4 - lastRowBytes) * 8} className=" text-gray-900 italic text-[9px] text-center">
                  </td>
                </>
              ) : (
                /* 일반적인 첫 번째 줄 (전체 너비 사용) */
                <td colSpan="32" className="p-2 text-center font-mono font-bold text-blue-700 bg-white">
                  {typeof data === 'object' ? JSON.stringify(data) : data}
                </td>
              )
            ) : isLast && lastRowBytes < 4 ? (
              /* 2. 마지막 줄: 데이터가 남은 만큼만 Continuation을 그리고 나머지는 Spare */
              <>
                <td colSpan={lastRowBytes * 8} className="text-center text-[10px] text-gray-900  italic">
                  Continuation
                </td>
                <td colSpan={(4 - lastRowBytes) * 8} className=" text-gray-400 italic text-[9px] text-center">
                </td>
              </>
            ) : (
              /* 3. 중간 줄 혹은 딱 떨어지는 마지막 줄: 전체 너비 Continuation */
              <td colSpan="32" className="text-center text-[10px] text-gray-900  italic">
                Continuation
              </td>
            )}
          </tr>
        );
      })}
        </>
      );

    case "BearerQoS":
      return (
        <>
          {/* <tr>
            <td colSpan="32">
              <div>
                <div>QCI: {data.qci}</div>
                <div>Max UL: {data.max_ul?  data.max_ul : "-" }</div>
                <div>Max DL: { data.max_dl?  data.max_ul : "-" }</div>
                <div>Guaranteed UL: {data.gbr_ul}</div>
                <div>Guaranteed DL: {data.gbr_dl}</div>
              </div>
            </td>
          </tr>

          {Array.from({ length: numrow -2 }).map((_, index) => (
            <tr key={index}>
              <td colSpan="32"
                  className="text-center bg-gray-50 text-gray-300 italic">
                Continuation
              </td>
            </tr>
          ))} */}
        {Array.from({ length: numDataRows }).map((_, index) => {
          const isFirst = index === 0;
          const isLast = index === numDataRows - 1;

          const rowClassName = `value-row ${isLast ? 'ie-last-row' : ''}`;

          return (
            <tr key={index} className={rowClassName}>
              {isFirst ? (
                /* 1. 첫 번째 줄: 모든 데이터를 출력 */
                isLast && lastRowBytes < 4 ? (
                  /* 만약 데이터가 딱 한 줄인데 4바이트가 안 되는 경우 */
                  <>
                    <td colSpan={lastRowBytes * 8}
                      className="text-center font-mono font-bold text-blue-700 bg-white">
                      {/* {JSON.stringify(data)} */}
                        <div>QCI: {data.qci}</div>
                        <div>Max UL: {data.max_ul?  data.max_ul : "-" }</div>
                        <div>Max DL: { data.max_dl?  data.max_ul : "-" }</div>
                        <div>Guaranteed UL: {data.gbr_ul}</div>
                        <div>Guaranteed DL: {data.gbr_dl}</div>
                    </td>
                    <td colSpan={(4 - lastRowBytes) * 8} className="bg-gray-100 text-gray-400 italic text-[9px] text-center">
                      Spare
                    </td>
                  </>
                ) : (
                  /* 일반적인 첫 번째 줄 (전체 너비 사용) */
                  <td colSpan="32" className="p-2 text-center font-mono font-bold text-blue-700 bg-white">
                    {typeof data === 'object' ?(
                    // JSON.stringify(data)
                    <>
                        <div>QCI: {data.qci}</div>
                        <div>Max UL: {data.max_ul?  data.max_ul : "-" }</div>
                        <div>Max DL: { data.max_dl?  data.max_ul : "-" }</div>
                        <div>Guaranteed UL: {data.gbr_ul}</div>
                        <div>Guaranteed DL: {data.gbr_dl}</div>
                    </>
                    )
                    : data}
                  </td>
                )
              ) : isLast && lastRowBytes < 4 ? (
                /* 2. 마지막 줄: 데이터가 남은 만큼만 Continuation을 그리고 나머지는 Spare */
                <>
                  <td colSpan={lastRowBytes * 8} className="text-center text-[10px] text-gray-400  italic">
                    Continuation
                  </td>
                  <td colSpan={(4 - lastRowBytes) * 8} className="bg-gray-100 text-gray-400 italic text-[9px] text-center">
                  </td>
                </>
              ) : (
                /* 3. 중간 줄 혹은 딱 떨어지는 마지막 줄: 전체 너비 Continuation */
                <td colSpan="32" className="text-center text-[10px] text-gray-400  italic">
                  Continuation
                </td>
              )}
            </tr>
          );
        })}
        </>
      );

    case "BearerTFT":
      // 1. 내부 콘텐츠 렌더링 헬퍼
      const renderTftDetails = () => (
        <div className="tft-wrapper text-left p-2"
            style={{ lineHeight: '1.4' }}>
          <div className="mb-1 border-b border-blue-100 pb-1">
            <strong className="text-blue-800">TFT Op: </strong>
            {data.str_tft_op_code} [{data.tft_op_code}]
            <span className="mx-2 text-gray-300">|</span>
            <strong>Filters: </strong> {data.num_filter}
          </div>

          <div className="pf-scroll-area"
              style={{ maxHeight: '150px', overflowY: 'auto' }}>

            {data.packet_filter_list?.map((pf, pfIdx) => (

              <div key={`pf-${pfIdx}`}
                // className="mb-2 p-1 bg-gray-50 border-l-2 border-blue-400"
                >

                <div className="font-bold text-blue-600">
                  <strong> Packet Filter ID#{pfIdx + 1} </strong> ({pf.pf_dir})
                </div>

                <ul className="ml-2 list-none text-[10px]"
                    style={{ listStyle: 'none', paddingLeft: '5px', margin: 0 }}
                >
                  {pf.packet_filter_component_list?.map((comp, cidx) => (
                     <li key={`comp-${cidx}`} className="truncate">
                      {/* ID: 0x{comp.pf_type_id.toString(16)} | */}
                      <ComponentRenderer comp={comp.components} />
                    </li>
                  ))}

                </ul>
              </div>
            ))}
          </div>
        </div>
      );


  return (
    <>
      {Array.from({ length: numrow - 1 }).map((_, index) => {
        const isFirst = index === 0;
        const isLast = index === (numrow - 2); // numrow-1개 중 마지막
        const rowClassName = `value-row ${isLast ? 'ie-last-row' : ''}`;

        return (
          <tr key={index} className={rowClassName}>
            {isFirst ? (
              /* 첫 번째 줄: TFT 상세 정보 출력 */
              <>
                <td 
                  colSpan={isLast && lastRowBytes < 4 ? lastRowBytes * 8 : 32} 
                  className="bg-white align-top"
                  style={{ height: 'auto' }} // 데이터가 많으면 첫 줄만 늘어남
                >
                  {renderTftDetails()}
                </td>
                {isLast && lastRowBytes < 4 && (
                  <td colSpan={(4 - lastRowBytes) * 8} className="spare-cell">Spare</td>
                )}
              </>
            ) : (
              /* 나머지 줄: Continuation + Spare 처리 */
              <>
                <td 
                  colSpan={isLast && lastRowBytes < 4 ? lastRowBytes * 8 : 32} 
                  className="text-center text-[10px] text-gray-400  italic"
                >
                  Continuation
                </td>
                {isLast && lastRowBytes < 4 && (
                  <td colSpan={(4 - lastRowBytes) * 8} className="spare-cell"></td>
                )}
              </>
            )}
          </tr>
        );
      })}
    </>
  );
/*
    case "BearerTFT":
      return (
        <>
        {Array.from({ length: numDataRows }).map((_, index) => {
          const isFirst = index === 0;
          const isLast = index === numDataRows - 1;

          const rowClassName = `value-row ${isLast ? 'ie-last-row' : ''}`;
          return (
            <tr key={index} className={rowClassName}>
              {isFirst ? (
                isLast && lastRowBytes < 4 ? (
                  <>
                    <td colSpan={lastRowBytes * 8}
                      className="text-center font-mono font-bold text-blue-700 bg-white">

            <div>TFT Operation Code: {data.tft_op_code} ({data.str_tft_op_code})</div>
            <div>Number of Packet Filters: {data.num_filter}</div>

            <hr />

            {data.packet_filter_list?.map((pf, pfIdx) => (
              <div key={`pf-${pfIdx}`} style={{ marginTop: "10px", padding: "10px", border: "1px solid #ccc" }}>
                Packet Filter #{pfIdx + 1}

                <div>Direction: {pf.pf_dir}</div>

                <div style={{ marginTop: "10px" }}>
                  Components:
                  <ul>
                    {pf.packet_filter_component_list?.map((comp, cidx) => (
                      <li key={`comp-${cidx}`} style={{ marginTop: "5px" }}>
                        <div>Type ID: 0x{comp.pf_type_id.toString(16)}</div>

                        <ComponentRenderer comp={comp.components} />
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}
                    </td>
                    <td colSpan={(4 - lastRowBytes) * 8} className="bg-gray-100 text-gray-400 italic text-[9px] text-center">
                      Spare
                    </td>
                  </>
                ):(
                  <td colSpan="32" className="p-2 text-center font-mono font-bold text-blue-700 bg-white">
                    {typeof data === 'object' ?(
                    <>
            <div>TFT Operation Code: {data.tft_op_code} ({data.str_tft_op_code})</div>
            <div>Number of Packet Filters: {data.num_filter}</div>

            <hr />

            {data.packet_filter_list?.map((pf, pfIdx) => (
              <div key={`pf-${pfIdx}`} style={{ marginTop: "10px", padding: "10px", border: "1px solid #ccc" }}>
                Packet Filter #{pfIdx + 1}

                <div>Direction: {pf.pf_dir}</div>

                <div style={{ marginTop: "10px" }}>
                  Components:
                  <ul>
                    {pf.packet_filter_component_list?.map((comp, cidx) => (
                      <li key={`comp-${cidx}`} style={{ marginTop: "5px" }}>
                        <div>Type ID: 0x{comp.pf_type_id.toString(16)}</div>

                        <ComponentRenderer comp={comp.components} />
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}
                    </>
                    )
                    : data}
                  </td>
                )
              ): isLast && lastRowBytes < 4 ? (
                <>
                  <td colSpan={lastRowBytes * 8} className="text-center text-[10px] text-gray-400 bg-gray-50/50 italic">
                    Continuation
                  </td>
                  <td colSpan={(4 - lastRowBytes) * 8} className="bg-gray-100 text-gray-400 italic text-[9px] text-center">
                    Spare
                  </td>
                </>
              ) : (
                <td colSpan="32" className="text-center text-[10px] text-gray-400 bg-gray-50/50 italic">
                  Continuation
                </td>
              )}

            </tr>

          );
        })}
        </>
      );
*/
    case "FTeid":
      // F-TEID도 데이터가 길어질 수 있으므로 행을 분리합니다.
      return (
        <>
          <tr>
            <td colSpan="32">
              <div>
                {/* <div>TEID: 0x{data.teid(16)}</div> */}
                <strong>TEID:</strong> 0x{data?.teid?.toString(16).padStart(8, '0').toUpperCase()}
                {data.v4 &&
                  <div><strong>IPv4 Address: </strong>{data.ipv4}</div>
                }
                {data.v6 &&
                  <div><strong>IPv6 Address:</strong> {data.ipv6}</div>
                }
                <div><strong>Interface Type:</strong> {data.iface_type}</div>
              </div>
            </td>
          </tr>

          {Array.from({ length: numrow -2 }).map((_, index) => (
            <tr key={index}>
              <td colSpan="32"
                  className="text-center  text-gray-300 italic">
                Continuation
              </td>
            </tr>
          ))}
          </>
      );

    default:
      // 기본형 데이터
      // return renderIeGrid(data );
      return(
        <>
          <tr>
            <td colSpan="32" className="text-center font-mono bg-white">
              {typeof data === 'object' ? JSON.stringify(data) : data}
            </td>
          </tr>

          {Array.from({ length: numrow -2 }).map((_, index) => (
            <tr key={index}>
              <td colSpan="32"
                  className="text-center text-gray-300 italic continuation-cell">
                Continuation
              </td>
            </tr>
          ))}
        </>
      );
  }
}
export default IeDecoder;
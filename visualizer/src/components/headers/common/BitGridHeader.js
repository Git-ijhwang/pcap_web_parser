import React from 'react';

/**
 * 모든 프로토콜 헤더 테이블에서 공통으로 사용하는 32비트 그리드 헤더
 */
const BitGridHeader = ({showOctet = true}) => {

  const bitRow = (
    <tr className="bit-indices">
    <th colSpan="2"></th>
      {[...Array(32)].map((_, i) => (
        <th key={i} style={{ textAlign: "center", minWidth: "11px" }}>{i}</th>
      ))}
    </tr>
  );

  if (!showOctet) {
    return bitRow;
  }

  return (
    <thead>
      {/* Octet 행 (0, 1, 2, 3) */}

      <tr className="octet-indices">
    <th colSpan="2"></th>
        {/* <th className="label-cell">Oct</th> */}
        <th colSpan="8">0</th>
        <th colSpan="8">1</th>
        <th colSpan="8">2</th>
        <th colSpan="8">3</th>
      </tr>
      
      {bitRow}
    </thead>
  );
};

export default BitGridHeader;
import React, { useState, useRef } from "react";
import CallFlowGraph from "./CallFlowGraph"

function CallFlowView({ data, loading, onBack }) {

  const [step, setStep] = useState(data?.length || 0);

  if (loading) return <div>Loading call flow...</div>;
  if (!data || data.length === 0) return <div> No Call Flow Data</div>;

  return (
    <div className="callflow-container">
      {onBack && (
      <button
        className="btn btn-sm btn-outline-secondary mb-2"
        onClick={onBack}
      >
        ← Back
      </button>
      )}


      {/* <input
        type="range"
        min={0}
        max={data.length}
        value={step}
        onChange={e => setStep(Number(e.target.value))}
        style={{ width: "100%" }}
      /> */}

{/* 슬라이더 제어 영역: 80% 너비 및 가운데 정렬 */}
    <div style={{ 
      display: "flex", 
      alignItems: "center", 
      justifyContent: "center", 
      gap: "15px", // 버튼과 슬라이더 사이 간격
      width: "80%", 
      margin: "0 auto" // 가로 중앙 정렬
    }}>
      {/* 왼쪽 버튼 */}
      <button 
        className="btn btn-sm btn-secondary"
        onClick={() => setStep(prev => Math.max(0, prev - 1))}
        disabled={step === 0}
      >
        <i class="bi bi-chevron-double-left"></i>
      </button>

      {/* 슬라이더 (Range Input) */}
      <input
        type="range"
        min={0}
        max={data.length}
        value={step}
        onChange={e => setStep(Number(e.target.value))}
        style={{ flex: 1 }} // 남은 공간을 모두 차지하도록 설정
      />

      {/* 오른쪽 버튼 */}
      <button 
        className="btn btn-sm btn-secondary"
        onClick={() => setStep(prev => Math.min(data.length, prev + 1))}
        disabled={step === data.length}
      >
        {/* ▶ */}
        <i class="bi bi-chevron-double-right"></i>
      </button>
    </div>

    {/* 현재 스텝 표시 */}
    <div style={{ textAlign: "center", marginTop: "6px" }}>
      Step {step} / {data.length}
    </div>

      <CallFlowGraph data={data} step={step} />

    </div>
  );
}

export default CallFlowView;

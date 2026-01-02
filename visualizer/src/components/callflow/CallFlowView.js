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
          style={{margin:"10px"}}
          onClick={onBack}
        >
          ← Back
        </button>
      )}

      <div style={{
        width: "80%",
        margin: "20px auto",
        display: "flex", flexDirection: "column", gap: "10px" }}>

        <div style={{
          display: "flex",
          flexDirection: "center",
          alignItems: "center",
          gap: "10px", }}>

          <input
            type="range"
            min={0} max={data.length}
            value={step}
            onChange={e => setStep(Number(e.target.value))}
            style={{ width: "100%", cursor: "pointer" }} />
        </div>

        <div style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "20px", 
        }}>

          <button
            className="btn btn-sm btn-outline-secondary"
            onClick={() => setStep(prev => Math.max(0, prev - 1))}
            disabled={step === 0} >
            <i class="bi bi-chevron-double-left"></i>
          </button>

          <div style={{ fontSize: "14px", fontWeight: "bold",
              minWidth: "100px", textAlign: "center", }}>
            Step {step} / {data.length}
          </div>

          <button 
            className="btn btn-sm btn-outline-secondary"
            onClick={() => setStep(prev => Math.min(data.length, prev + 1))}
            disabled={step === data.length} >
            <i class="bi bi-chevron-double-right"></i>
          </button>

        </div>
      </div>

      <CallFlowGraph data={data} step={step} />

    </div>
  );
}

export default CallFlowView;

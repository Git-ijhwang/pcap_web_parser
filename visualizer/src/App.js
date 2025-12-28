import React, { useState, useRef } from "react";
import {Modal, Button} from "react-bootstrap";
import "./App.css";

import PacketTable from "./PacketTable"
import CallFlowView from "./CallFlowView"


function App() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [collapsed, setCollapsed] = useState(null);
  const [fileId, setFileId] = useState(null);

  const [callFlowData, setCallFlowData] = useState(null);
  const [showCallFlow, setShowCallFlow] = useState(false);
  const [loadingFlow, setLoadingFlow] = useState(false);
  const [flowError, setFlowError] = useState(null);
  // const [onCallFlow, setOnCallFlow] = useState(false);
  // const [callFlow, setCallFlow] = useState(null);


  // 파일 input ref 생성
  const fileInputRef = useRef(null);

  const onFileChange = (e) => {
    setFile(e.target.files?.[0] ?? null);
    setResult(null);
  };

  const resetAll = async () => {
    setFile(null);
    setResult(null);

    // input 파일 초기화
    if (fileInputRef.current) {
      fileInputRef.current.value = null;
    }

    try {
      await fetch("/api/cleanup", {
        method: "POST"
      });
    } catch (err) {
      console.error("Cleanup failed:", err);
    }
  };

  const upload = async () => {
    if (!file) {
      alert("Please choose a file first");
      return;
    }
    setLoading(true);
    setResult(null);

    try {
      const form = new FormData();
      form.append("pcap", file);

      const res = await fetch("/api/parse", {
        method: "POST",
        body: form
      });

      if (!res.ok) {
        const txt = await res.text();
        throw new Error(`Server ${res.status}: ${txt}`);
      }

      const json = await res.json();
      setResult(json.packets);
      setFileId(json.file_id);

    } catch (err) {
      console.error(err);
      setResult({ error: String(err) });

    } finally {
      setLoading(false);
    }
  };


  const fetchCallFlow = async (packetId) => {

    // setLoadingFlow(true);

    try {
      const res = await fetch("/api/gtp/callflow", {
        method: "POST",
        headers: { "Content-Type": "application/json", },
        body: JSON.stringify( {file_id: fileId , packet_id: packetId}),
      });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const data = await res.json();
      console.log("CallFlow data:", data);
      setCallFlowData(data);
      setShowCallFlow(true);
    }
    catch (err) {
        setFlowError("Failed to load call flow");
    }
  };

  // const fetchCallFlow = async (packetId) => {
  //   const res = await fetch(`/api/callflow/${packetId}`);
  //   const data = await res.json();

  //   setCallFlowData(data);
  //   setShowCallFlow(true);
  // };

  // ✅ 여기서 구현
  const handleBackFromCallFlow = () => {
    setShowCallFlow(false);
    setCallFlowData(null);
  };


  return (
    <div className="container mt-4">
      <div className="fileopen-card card shadow p-4 ">

        <button type="button"
            className= "btn btn-sm btn-outline-secondary position-absolute"
          style={{top:"12px", right:"12px", margin:"12px"}}
            onClick={() => setCollapsed(c => !c)}
            aria-label="toggle collapse"
            >
          <i className={`bi ${collapsed ? "bi-chevron-down" : "bi-chevron-up"}`} />
        </button>

        <h1 className={`mb-3 parser-title
          ${collapsed ? "collapsed" : ""}`}>pcap file Parser </h1>

        {/* 🔽 Collapsible Area */}
        <div className={`collapse-wrapper ${collapsed ? "collapsed" : ""}`} >

          <div className="mb-3">
            {/* <label style={{ display: "block", marginBottom: 8 }}> */}
              <input type="file"
                ref={fileInputRef}       // ref 연결
                className="form-control mb-2" onChange={onFileChange} />
            {/* </label> */}
          </div>

          <div>
            <button
                className="btn btn-primary me-3" 
                onClick={upload}
                disabled={loading || !file} >

              {loading ? "Parsing..." : "Upload & Parse"}
            </button>

            <button
              variant="secondary" 
              className="btn btn-secondary " 
              onClick={ resetAll }
            >
              Reset
            </button>

          </div>
        </div>
      </div>

      <div className="packetlist-card card shadow p-4">
        {result?.packets && (

          <div className="viewport">
            <div className={`slider ${showCallFlow ? "shift" : ""}`}>
              {/* Table Panel */}
              <div className="panel table-panel">
                <PacketTable packets={result.packets} fileId={fileId}
                    onCallFlow={fetchCallFlow}
                    showCallFlow={showCallFlow} />
              </div>

              <div className="panel callflow-panel">
                { CallFlowView && (
                  < CallFlowView 
                    data={callFlowData}
                    loading={!callFlowData}
                    onBack={handleBackFromCallFlow}
                  />
                )}
              </div>
            </div>
          </div>
        )}

        <Modal show={selectedPacket !== null} onHide={() => setSelectedPacket(null)} centered size="lg">
          <Modal.Header closeButton>
            <Modal.Title>Packet Detail (ID: {selectedPacket?.id}) </Modal.Title>
          </Modal.Header>
          <Modal.Body>
            {selectedPacket ? (
              <div>
                {Object.entries(selectedPacket).map(([key, value]) => (
                  <p key={key}>
                    <strong>{key}</strong>: {String(value)}
                  </p>
                ))}
              </div>
            ) : null
            }
          </Modal.Body>

          <Modal.Footer>
            <Button variant="secondary"
              onClick={() => setSelectedPacket(null)}>
              Close
            </Button>
          </Modal.Footer>
        </Modal>

      </div>
    </div>
  );
}

export default App;


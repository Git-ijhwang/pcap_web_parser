// src/App.js
import React, { useState } from "react";
import PacketTable from "./PacketTable";

function ResultBlock({ result }) {
  if (!result) return null;
  return (
    <div style={{ marginTop: 16 }}>
      <h3>Parse Result (raw JSON)</h3>
      <div style={{
        background: "#0b1220",
        color: "#dff1c8",
        padding: 12,
        borderRadius: 6,
        maxHeight: "40vh",
        overflow: "auto",
        fontFamily: "monospace",
        fontSize: 13
      }}>
        <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
          {JSON.stringify(result, null, 2)}
        </pre>
      </div>
    </div>
  );
}

function App() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const onFileChange = (e) => {
    setFile(e.target.files?.[0] ?? null);
    setResult(null);
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
      setResult(json);
    } catch (err) {
      console.error(err);
      setResult({ error: String(err) });
    } finally {
      setLoading(false);
    }
  };

  // fetch detail function for PacketTable
  const fetchPacketDetail = async (id) => {
    const res = await fetch(`/api/packet_detail?id=${encodeURIComponent(id)}`);
    if (!res.ok) {
      const txt = await res.text();
      throw new Error(`Server ${res.status}: ${txt}`);
    }
    return res.json();
  };

  return (
    <div style={{ maxWidth: 1100, margin: "24px auto", padding: 12, fontFamily: "Inter, Arial, sans-serif" }}>
      <h1>pcap → GTP / PFCP Parser (frontend)</h1>

      <div style={{
        padding: 12,
        border: "1px solid #ddd",
        borderRadius: 8,
        background: "#fafafa",
        marginBottom: 12
      }}>
        <label style={{ display: "block", marginBottom: 8 }}>
          <input type="file" onChange={onFileChange} />
        </label>

        <div style={{ marginTop: 8 }}>
          <button onClick={upload} disabled={loading || !file} style={{ padding: "6px 12px" }}>
            {loading ? "Parsing..." : "Upload & Parse"}
          </button>
          <button onClick={() => { setFile(null); setResult(null); }} style={{ marginLeft: 8 }}>
            Reset
          </button>
        </div>
      </div>

      {result && result.packets ? (
        <>
          <h3>Total packets: {result.total_packets}</h3>
          <PacketTable packets={result.packets} fetchPacketDetail={fetchPacketDetail} />
        </>
      ) : (
        <ResultBlock result={result} />
      )}
    </div>
  );
}

export default App;

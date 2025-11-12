// src/App.js
import React, { useState } from "react";

/**
 * Simple PCAP/GTP upload & parse UI
 * - Select file
 * - Upload to backend /parse (multipart/form-data)
 * - Show JSON result (pretty) or table view if available
 */

function ResultBlock({ result }) {
  if (!result) return null;

  // If backend returns structured JSON with "packets" or "gtp" etc. adapt here.
  return (
    <div style={{ marginTop: 16 }}>
      <h3>Parse Result</h3>
      <div style={{
        background: "#0b1220",
        color: "#dff1c8",
        padding: 12,
        borderRadius: 6,
        maxHeight: "60vh",
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

      // If you set "proxy" in package.json to http://localhost:3000, this call goes to that address.
      // If not using proxy, change to full URL: http://localhost:3000/parse
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

  // Quick sample: upload a file and also show hex preview (first 256 bytes)
  const hexPreview = file ? (
    <div style={{ marginTop: 8, fontFamily: "monospace", fontSize: 12 }}>
      <strong>Selected:</strong> {file.name} — {file.size} bytes
      <div style={{ marginTop: 6 }}>
        (Hex preview isn't available until file is sent to server)
      </div>
    </div>
  ) : null;

  return (
    <div style={{ maxWidth: 900, margin: "36px auto", padding: 12, fontFamily: "Inter, Arial, sans-serif" }}>
      <h1>pcap → GTP / PFCP Parser (frontend)</h1>

      <div style={{
        padding: 12,
        border: "1px solid #ddd",
        borderRadius: 8,
        background: "#fafafa"
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

        {hexPreview}
      </div>

      <ResultBlock result={result} />
    </div>
  );
}

export default App;

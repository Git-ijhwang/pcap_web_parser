import CallFlowGraph from "./CallFlowGraph"

function CallFlowView({ data, loading, onBack }) {
  if (loading) return <div>Loading call flow...</div>;
  // if (error) return <div>{error}</div>;
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

      <CallFlowGraph data={data} />
    </div>
  );
}

export default CallFlowView;

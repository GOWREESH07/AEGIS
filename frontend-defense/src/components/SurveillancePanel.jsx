import React from 'react';

export function SurveillancePanel({ features }) {
  const reqs      = features?.requests_per_sec       ?? 0;
  const endpoints = features?.distinct_endpoints     ?? 0;
  const cts       = features?.content_type_sequence  ?? [];   // real field name
  const injects   = features?.injection_regex_hits   ?? 0;    // real field name
  const pkts      = features?.packets_per_sec        ?? 0;

  const Row = ({ label, value, warn, crit }) => (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid #1a1a1a' }}>
      <span style={{ fontSize: '0.75rem', color: 'var(--muted)', textTransform: 'uppercase' }}>{label}</span>
      <span className="mono" style={{ 
        fontSize: '0.85rem', 
        color: crit ? 'var(--red)' : (warn ? 'var(--accent)' : 'var(--text)') 
      }}>
        {value}
      </span>
    </div>
  );

  return (
    <div style={{ padding: '16px', height: '100%', display: 'flex', flexDirection: 'column' }}>
      <h3 style={{ fontSize: '0.75rem', marginBottom: '12px' }}>LIVE FEATURE STREAM</h3>
      
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 24px' }}>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <Row label="REQ/S" value={reqs.toFixed(1)} warn={reqs > 3} crit={reqs > 10} />
          <Row label="ENDPOINTS" value={endpoints} warn={endpoints > 4} crit={endpoints > 8} />
          <Row label="WINDOW" value="5s" />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <Row label="INJECT HITS" value={injects} warn={injects > 0} crit={injects > 2} />
          <Row label="PKT/S" value={pkts.toFixed(0)} warn={pkts > 50} crit={pkts > 100} />
          <Row label="CT SEQUENCE" value={`[${cts.slice(0,3).join(',')}]`} warn={cts.length > 2} />
        </div>
      </div>
    </div>
  );
}

import React from 'react';

export function ThreatTable({ blocklist, escalations = [], onResolveEscalation }) {
  const pendingEscalations = (escalations || []).filter(e => e.status === 'pending');

  return (
    <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <h3 style={{ fontSize: '0.75rem', marginBottom: '10px', color: 'var(--muted)', letterSpacing: '0.08em' }}>
        ACTIVE THREAT ISOLATION
      </h3>

      {pendingEscalations.length > 0 && (
        <div style={{
          marginBottom: 8,
          padding: '6px 8px',
          border: '1px solid var(--amber)',
          background: 'rgba(245, 166, 35, 0.08)',
          display: 'flex',
          flexDirection: 'column',
          gap: 4,
        }}>
          <div className="mono" style={{ fontSize: 9, color: 'var(--amber)', fontWeight: 700 }}>
            HUMAN ESCALATION QUEUE ({pendingEscalations.length})
          </div>
          {pendingEscalations.slice(0, 2).map(esc => (
            <div key={esc.escalation_id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 6 }}>
              <span className="mono" style={{ fontSize: 10, color: 'var(--text)' }}>
                {esc.subnet} [S0{esc.stage}] {esc.proposed_action}
              </span>
              <div style={{ display: 'flex', gap: 4 }}>
                <button
                  onClick={() => onResolveEscalation && onResolveEscalation(esc.escalation_id, 'approve')}
                  style={{ padding: '1px 5px', fontSize: 9, borderColor: 'var(--green)', color: 'var(--green)' }}
                >
                  APPROVE
                </button>
                <button
                  onClick={() => onResolveEscalation && onResolveEscalation(esc.escalation_id, 'dismiss')}
                  style={{ padding: '1px 5px', fontSize: 9, borderColor: '#555', color: '#888' }}
                >
                  DISMISS
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      
      <div style={{ flex: 1, overflowY: 'auto', overflowX: 'auto' }}>
        <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', padding: '4px 6px', fontSize: 10, color: '#555' }}>SOURCE IP</th>
              <th style={{ textAlign: 'left', padding: '4px 6px', fontSize: 10, color: '#555' }}>STAGE</th>
              <th style={{ textAlign: 'left', padding: '4px 6px', fontSize: 10, color: '#555' }}>ACTION</th>
              <th style={{ textAlign: 'right', padding: '4px 6px', fontSize: 10, color: '#555' }}>CONF</th>
            </tr>
          </thead>
          <tbody>
            {blocklist.length === 0 ? (
              <tr>
                <td colSpan="4" style={{ textAlign: 'center', color: 'var(--muted)', padding: '32px 0', fontSize: 11 }}>
                  No active threats
                </td>
              </tr>
            ) : (
              blocklist.map((item, idx) => (
                <tr key={idx} style={{ borderBottom: '1px solid #161616' }}>
                  <td className="mono" style={{ padding: '5px 6px', color: 'var(--text)', fontSize: 11 }}>{item.ip}</td>
                  <td className="mono" style={{ padding: '5px 6px', color: 'var(--muted)', fontSize: 11 }}>0{item.stage || 1}</td>
                  <td className="mono" style={{ 
                    padding: '5px 6px',
                    fontSize: 11,
                    color: item.action === 'quarantine' ? '#ef4444' : 'var(--amber)'
                  }}>
                    {item.action.toUpperCase()}
                  </td>
                  <td className="mono" style={{ padding: '5px 6px', color: '#c9c9c9', fontSize: 11, textAlign: 'right' }}>
                    {(item.confidence || 0).toFixed(2)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}


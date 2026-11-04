import React, { useState } from 'react';

export function DetectionLog({ logs }) {
  const [isPaused, setIsPaused] = useState(false);

  const getLogColor = (line) => {
    if (line.includes('BLOCK') || line.includes('QUARANTINE')) return 'var(--red)';
    if (line.includes('DETECT') && !line.includes('ALLOW')) return 'var(--accent)';
    return 'var(--muted)';
  };

  return (
    <div 
      style={{ padding: '16px', height: '100%', display: 'flex', flexDirection: 'column', borderTop: 'var(--border)' }}
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
        <h3 style={{ fontSize: '0.75rem' }}>DETECTION EVENTS</h3>
        <span style={{ fontSize: '0.7rem', color: isPaused ? 'var(--accent)' : 'var(--muted)' }}>
          {logs.length} EVENTS {isPaused ? '[PAUSED]' : '[HOVER TO PAUSE]'}
        </span>
      </div>
      
      <div style={{ 
        flex: 1, 
        backgroundColor: '#0a0a0a', 
        border: 'var(--border)', 
        padding: '8px',
        overflowY: 'auto',
        overflowX: 'hidden',
        fontFamily: 'var(--font-mono)',
        fontSize: '0.75rem',
        lineHeight: '1.4'
      }}>
        {logs.length === 0 ? (
          <div style={{ color: 'var(--muted)' }}>Waiting for events...</div>
        ) : (
          logs.map((log, idx) => (
            <div key={idx} style={{ 
              color: getLogColor(log),
              whiteSpace: 'nowrap',
              marginBottom: '2px'
            }}>
              {log}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

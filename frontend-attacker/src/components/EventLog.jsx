import React, { useRef, useEffect, useState } from 'react';

export default function EventLog({ events }) {
  const [isPaused, setIsPaused] = useState(false);
  const logContainerRef = useRef(null);

  useEffect(() => {
    if (!isPaused && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [events, isPaused]);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      if (e.key.toLowerCase() === 'p') {
        setIsPaused(p => !p);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const getLogStyle = (event) => {
    if (event.type === 'request_sent') return { color: '#a0a0a0' };
    if (event.type === 'response_received') return { color: 'var(--green)' };
    if (event.type === 'blocked' || event.blocked) return { color: 'var(--red)' };
    if (event.type === 'error') return { color: 'var(--amber)' };
    if (event.type === 'stage_complete' || event.type === 'stage_start') return { color: '#ffffff', fontWeight: 'bold' };
    return { color: 'var(--text-dim)' };
  };

  const formatDetail = (event) => {
    if (event.detail) return typeof event.detail === 'object' ? JSON.stringify(event.detail) : event.detail;
    if (event.payload) return JSON.stringify(event.payload);
    if (event.method && event.path) return `${event.method} ${event.path}`;
    return '';
  };

  return (
    <div 
      style={{ height: '220px', borderTop: '1px solid var(--border)', background: 'var(--bg)', display: 'flex', flexDirection: 'column' }}
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
    >
      <div style={{ height: '28px', borderBottom: '1px solid var(--border)', background: 'var(--panel-alt)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 12px' }}>
        <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--muted)', letterSpacing: '0.05em' }}>EVENT LOG</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button 
            style={{ padding: '2px 8px', fontSize: '10px', borderColor: isPaused ? 'var(--amber)' : 'var(--border)', color: isPaused ? 'var(--amber)' : 'var(--text)' }}
            onClick={() => setIsPaused(!isPaused)}
          >
            [P] PAUSE
          </button>
          <div className="mono" style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{events.length} EVTS</div>
        </div>
      </div>
      
      <div ref={logContainerRef} style={{ flex: 1, overflowY: 'auto', padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
        {events.map((evt, idx) => {
          const timeMatch = (evt.timestamp || new Date().toISOString()).match(/T(\d{2}:\d{2}:\d{2}\.\d{3})/);
          const timeStr = timeMatch ? timeMatch[1] : '';
          const stageStr = evt.stage ? `[STAGE-${evt.stage}]` : '[SYSTEM]';
          const actionStr = (evt.action || evt.type || 'UNKNOWN').toUpperCase();
          const detailStr = formatDetail(evt);
          const truncdDetail = detailStr.length > 150 ? detailStr.substring(0, 150) + '...' : detailStr;
          
          return (
            <div key={idx} className="mono" style={{ fontSize: '11px', whiteSpace: 'nowrap', ...getLogStyle(evt) }}>
              <span style={{ color: 'var(--text-dim)', marginRight: '8px' }}>{timeStr}</span>
              <span style={{ color: 'var(--text-dim)', marginRight: '8px' }}>{stageStr}</span>
              <span style={{ marginRight: '8px' }}>{actionStr}</span>
              <span style={{ opacity: 0.8 }}>{truncdDetail}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

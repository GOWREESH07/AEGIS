import React, { useEffect } from 'react';

export function StatusBar({ status, toggleAegis, resetAegis, activeTab = 'live', setActiveTab, onExportIncident }) {
  const [time, setTime] = React.useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const handleKeyPress = (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    if (e.key === 'r' || e.key === 'R') {
      resetAegis();
    }
    if ((e.key === 'e' || e.key === 'E') && onExportIncident) {
      onExportIncident();
    }
  };

  useEffect(() => {
    window.addEventListener('keydown', handleKeyPress);
    return () => window.removeEventListener('keydown', handleKeyPress);
  }, [resetAegis, onExportIncident]);

  return (
    <div style={{
      height: '32px',
      borderBottom: 'var(--border)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 16px',
      backgroundColor: 'var(--panel-bg)'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <span style={{ color: 'var(--accent)', fontWeight: 600, letterSpacing: '1px' }}>AEGIS</span>
        <span style={{ color: 'var(--muted)', fontSize: '0.85rem' }}>// DEFENSE CONSOLE</span>
        {setActiveTab && (
          <div style={{ display: 'flex', gap: '4px', marginLeft: '12px' }}>
            <button
              onClick={() => setActiveTab('live')}
              style={{
                padding: '2px 10px',
                fontSize: '0.72rem',
                borderColor: activeTab === 'live' ? 'var(--accent)' : '#2a2a2a',
                color: activeTab === 'live' ? 'var(--accent)' : 'var(--muted)',
                fontWeight: activeTab === 'live' ? 700 : 400,
              }}
            >
              LIVE DEFENSE
            </button>
            <button
              onClick={() => setActiveTab('reposcan')}
              style={{
                padding: '2px 10px',
                fontSize: '0.72rem',
                borderColor: activeTab === 'reposcan' ? 'var(--accent)' : '#2a2a2a',
                color: activeTab === 'reposcan' ? 'var(--accent)' : 'var(--muted)',
                fontWeight: activeTab === 'reposcan' ? 700 : 400,
              }}
            >
              REPO SCAN
            </button>
          </div>
        )}
      </div>

      <div className="mono" style={{ color: 'var(--text)', fontSize: '0.9rem' }}>
        {time.toISOString().slice(11, 19)} UTC
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <span
          onClick={onExportIncident}
          style={{ color: 'var(--muted)', fontSize: '0.75rem', cursor: onExportIncident ? 'pointer' : 'default' }}
          title="Press R to reset, E to export incident report"
        >
          [R] reset  [E] export
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ color: 'var(--muted)', fontSize: '0.8rem' }}>BLOCKS: {status.blocklist_count}</span>
          <button 
            onClick={toggleAegis}
            style={{ 
              color: status.enabled ? 'var(--green)' : 'var(--red)',
              borderColor: status.enabled ? 'var(--green)' : 'var(--red)',
              fontWeight: 600
            }}
          >
            {status.enabled ? 'ACTIVE' : 'DISABLED'}
          </button>
        </div>
      </div>
    </div>
  );
}

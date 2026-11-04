import React, { useState, useEffect } from 'react';

export default function StatusBar({ wsStatus, runId }) {
  const [time, setTime] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const pad = (n) => n.toString().padStart(2, '0');
      setTime(`${now.getUTCFullYear()}-${pad(now.getUTCMonth()+1)}-${pad(now.getUTCDate())} ${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())} UTC`);
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const isConnected = wsStatus === 'CONNECTED';

  return (
    <div style={{
      height: '32px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 16px',
      borderBottom: '1px solid var(--border)',
      background: 'var(--panel)'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ color: 'var(--amber)', fontWeight: 700, letterSpacing: '0.15em' }}>AEGIS</span>
        <span style={{ color: 'var(--muted)', fontSize: '11px' }}>// ATTACK CONSOLE</span>
      </div>
      
      <div className="mono" style={{ color: 'var(--text-dim)', fontSize: '12px' }}>
        {time}
      </div>
      
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '11px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <div style={{
            width: '8px', height: '8px',
            background: isConnected ? 'var(--green)' : 'var(--red)'
          }}></div>
          <span className="mono" style={{ color: isConnected ? 'var(--green)' : 'var(--red)' }}>
            {wsStatus}
          </span>
        </div>
        {runId && (
          <span className="mono" style={{ color: 'var(--text-dim)' }}>
            RUN: {runId.substring(0,8)}
          </span>
        )}
      </div>
    </div>
  );
}

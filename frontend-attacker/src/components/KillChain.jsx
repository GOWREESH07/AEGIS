import React from 'react';

const STAGE_NAMES = {
  1: 'RECON',
  2: 'ADAPT',
  3: 'AILM',
  4: 'LATERAL',
  5: 'EXEC',
  6: 'MCP_POISON',
  7: 'RAG_INJECT',
  8: 'SLOPSQUAT',
  9: 'CRED_HARVEST',
};

export default function KillChain({ runState, events }) {
  const getStageColor = (status) => {
    switch (status) {
      case 'ACTIVE': return 'var(--amber)';
      case 'COMPLETE': return 'var(--green)';
      case 'BLOCKED': return 'var(--red)';
      default: return 'var(--muted)';
    }
  };

  const getStageStyle = (status) => {
    const color = getStageColor(status);
    const isPulsing = status === 'ACTIVE';
    return {
      border: `1px solid ${color}`,
      boxShadow: isPulsing ? `0 0 8px ${color}40 inset` : 'none',
      color: color === 'var(--muted)' ? 'var(--text-dim)' : 'var(--text)',
      background: 'var(--panel-alt)',
      padding: '12px',
      flex: 1,
      display: 'flex',
      flexDirection: 'column',
      gap: '8px',
      position: 'relative'
    };
  };

  // Bug 9 Fix: Collect the latest event for up to 4 distinct stages rather than 4 duplicate events
  const distinctStageEvents = [];
  const seenStages = new Set();
  for (let i = events.length - 1; i >= 0; i--) {
    const ev = events[i];
    const s = ev.stage;
    if (s && s >= 1 && s <= 9 && !seenStages.has(s)) {
      seenStages.add(s);
      distinctStageEvents.push(ev);
      if (distinctStageEvents.length === 4) break;
    }
  }
  const recentEvents = distinctStageEvents.length >= 2
    ? distinctStageEvents
    : events.slice(-4).reverse();

  const getEventBorderColor = (event) => {
    const action = event.action || event.type;
    if (action === 'blocked' || event.blocked_by) return 'var(--red)';
    if (action === 'response_received' || action === 'stage_complete') return 'var(--green)';
    if (action === 'request_sent' || action === 'stage_start') return 'var(--amber)';
    return 'var(--border)';
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'var(--bg)', overflow: 'hidden' }}>
      
      {/* KILL CHAIN */}
      <div style={{ padding: '24px', display: 'flex', alignItems: 'center', gap: '16px' }}>
        {[1, 2, 3, 4, 5].map((stageNum, index) => {
          const stage = runState.stages[stageNum] || { status: 'PENDING', elapsed_ms: 0, lastAction: '' };
          const ms = stage.elapsed_ms;
          const displayTime = typeof ms === 'number' && ms > 0
            ? (ms < 10 ? ms.toFixed(1) : Math.round(ms).toString())
            : '0';

          return (
            <React.Fragment key={stageNum}>
              <div style={getStageStyle(stage.status)}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '12px', fontWeight: 600, color: getStageColor(stage.status) }}>
                    0{stageNum} / {STAGE_NAMES[stageNum]}
                  </span>
                  <span className="mono" style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                    {stage.status}
                  </span>
                </div>
                <div className="mono" style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                  TIME: {displayTime}ms
                </div>
                <div className="mono" style={{ fontSize: '10px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: 'var(--text-dim)' }}>
                  {stage.lastAction ? `> ${stage.lastAction}` : '> ...'}
                </div>
              </div>
              {index < 4 && (
                <div style={{ color: 'var(--border-bright)', fontSize: '18px', fontWeight: 'bold' }}>
                  →
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>


      {/* SNIPPETS */}
      <div style={{ flex: 1, padding: '0 24px 24px 24px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', overflowY: 'auto' }}>
        {recentEvents.map((evt, idx) => {
          const time = (evt.ts || evt.timestamp || new Date().toISOString()).split('T')[1]?.replace('Z', '').slice(0, 12);
          const detail = evt.detail || {};
          const urlOrMethod = detail.url || detail.method || evt.action;
          
          let preview = '';
          if (typeof detail === 'string') preview = detail;
          else if (detail.error) preview = `ERR: ${detail.error}`;
          else if (detail.url) preview = `${detail.method || 'GET'} ${detail.url} [${detail.status_code || 200}]`;
          else preview = JSON.stringify(detail).substring(0, 90);
          
          return (
            <div key={idx} style={{ 
              border: '1px solid',
              borderColor: getEventBorderColor(evt),
              background: 'var(--panel-alt)',
              padding: '12px',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="mono" style={{ fontSize: '10px', color: 'var(--text-dim)' }}>{time}</span>
                {evt.stage > 0 && <span className="mono" style={{ fontSize: '10px', background: 'var(--panel)', padding: '2px 6px', border: '1px solid var(--border)' }}>[STAGE {evt.stage}]</span>}
              </div>
              
              <div className="mono" style={{ fontSize: '11px', color: 'var(--text)', textTransform: 'uppercase' }}>
                {evt.action || evt.type} {evt.blocked_by && <span style={{ color: 'var(--red)' }}>[BLOCKED BY AEGIS]</span>}
              </div>
              
              {preview && (
                <div className="mono" style={{ fontSize: '10px', color: 'var(--text-dim)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {preview}
                </div>
              )}
            </div>
          );
        })}
      </div>


    </div>
  );
}

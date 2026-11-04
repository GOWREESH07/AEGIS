import React from 'react';

export function KillChainMap({ stageStatus }) {
  const coreStages = [
    { id: 1, name: 'RECON', atlas: 'AML.T0006', asi: 'ASI01' },
    { id: 2, name: 'ADAPT', atlas: 'AML.T0043', asi: 'ASI05' },
    { id: 3, name: 'AILM', atlas: 'AML.T0051', asi: 'ASI01' },
    { id: 4, name: 'LATERAL', atlas: 'AML.T0029', asi: 'ASI02' },
    { id: 5, name: 'EXEC', atlas: 'AML.T0048', asi: 'ASI05' }
  ];
  const aiOptionalStages = [
    { id: 6, name: 'MCP_POISON', atlas: 'AML.T0054', asi: 'ASI02' },
    { id: 7, name: 'RAG_INJECT', atlas: 'AML.T0051.001', asi: 'ASI06' },
    { id: 8, name: 'SLOPSQUAT', atlas: 'AML.T0010', asi: 'ASI04' },
    { id: 9, name: 'CRED_HARVEST', atlas: 'AML.T0055', asi: 'ASI10' },
  ];
  const activeOptional = aiOptionalStages.filter(s => stageStatus[s.id] && stageStatus[s.id].status !== 'clear');
  const stages = [...coreStages, ...activeOptional];

  return (
    <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', height: '100%' }}>
      <h3 style={{ fontSize: '0.75rem', marginBottom: '24px' }}>KILL CHAIN INTERCEPTION MAP</h3>
      
      <div style={{ display: 'flex', alignItems: 'center', flex: 1, padding: '0 16px' }}>
        {stages.map((stage, idx) => {
          const status = stageStatus[stage.id]?.status || 'clear';
          const time = stageStatus[stage.id]?.time_ms;
          
          let borderColor = 'var(--green)';
          let bgColor = 'transparent';
          let textColor = 'var(--green)';
          let label = 'CLEAR';
          
          if (status === 'detecting') {
            borderColor = 'var(--accent)';
            textColor = 'var(--accent)';
            label = 'DETECTING';
          } else if (status === 'intercepted') {
            borderColor = 'var(--red)';
            bgColor = 'rgba(239, 68, 68, 0.1)';
            textColor = 'var(--red)';
            label = 'INTERCEPTED';
          }

          return (
            <React.Fragment key={stage.id}>
              <div style={{
                flex: 1,
                border: `1px solid ${borderColor}`,
                backgroundColor: bgColor,
                padding: '12px',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                position: 'relative',
                transition: 'all 0.3s ease'
              }}>
                <div className="mono" style={{ fontSize: '1.5rem', color: 'var(--muted)', opacity: 0.5, marginBottom: '8px' }}>
                  0{stage.id}
                </div>
                <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text)', marginBottom: '4px', letterSpacing: '1px' }}>
                  {stage.name}
                </div>
                <div className="mono" style={{ fontSize: '0.58rem', color: '#666', marginBottom: '8px' }}>
                  {stage.atlas} · {stage.asi}
                </div>
                
                <div style={{ 
                  color: textColor, 
                  fontSize: '0.7rem', 
                  fontWeight: 600,
                  animation: status === 'detecting' ? 'pulse 1s infinite alternate' : 'none'
                }}>
                  {label}
                </div>
                
                {status === 'intercepted' && time && (
                  <div className="mono" style={{ color: 'var(--red)', fontSize: '0.7rem', marginTop: '4px' }}>
                    {time}ms
                  </div>
                )}
              </div>
              
              {idx < stages.length - 1 && (
                <div style={{ width: '20px', height: '1px', backgroundColor: 'var(--muted)' }} />
              )}
            </React.Fragment>
          );
        })}
      </div>
      
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes pulse {
          0% { opacity: 0.5; }
          100% { opacity: 1; }
        }
      `}} />
    </div>
  );
}

import React, { useState, useEffect } from 'react';

export default function AttackConfig({ runState }) {
  const [proxy, setProxy] = useState('proxy');
  const [speed, setSpeed] = useState(1);
  const [seed, setSeed] = useState(42);
  const [stages, setStages] = useState({ 1: true, 2: true, 3: true, 4: true, 5: true });
  const [mode, setMode] = useState('ONCE');
  const [isRequesting, setIsRequesting] = useState(false);
  const [serverStatus, setServerStatus] = useState('idle');

  // Poll server status every 2s so Stop button stays in sync with backend
  useEffect(() => {
    const poll = async () => {
      try {
        const r = await fetch('http://localhost:8003/api/status');
        const d = await r.json();
        setServerStatus(d.status || 'idle');
      } catch (_) {}
    };
    poll();
    const id = setInterval(poll, 2000);
    return () => clearInterval(id);
  }, []);

  // isRunning: either WS says RUNNING or server poll says running
  const isRunning =
    runState.status === 'RUNNING' ||
    serverStatus === 'running';


  const toggleStage = (stage) => {
    if (isRunning) return;
    setStages(prev => ({ ...prev, [stage]: !prev[stage] }));
  };

  const handleRun = async () => {
    if (isRunning || isRequesting) return;
    setIsRequesting(true);
    try {
      const activeStages = Object.entries(stages)
        .filter(([_, active]) => active)
        .map(([stage]) => parseInt(stage));
      await fetch('http://localhost:8003/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          use_proxy: proxy === 'proxy',
          speed_multiplier: speed,
          mutation_seed: seed,
          stages: activeStages,
          mode: mode.toLowerCase()
        })
      });
    } catch (e) {
      console.error('Failed to start run', e);
    } finally {
      setIsRequesting(false);
    }
  };

  const handleStop = async () => {
    if (!isRunning || isRequesting) return;
    setIsRequesting(true);
    try {
      await fetch('http://localhost:8003/api/stop', { method: 'POST' });
    } catch (e) {
      console.error('Failed to stop run', e);
    } finally {
      setIsRequesting(false);
    }
  };

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      if (e.key.toLowerCase() === 'r') handleRun();
      if (e.key.toLowerCase() === 's') handleStop();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  });

  const getStatusColor = () => {
    switch (runState.status) {
      case 'RUNNING': return 'var(--amber)';
      case 'COMPLETED': return 'var(--green)';
      case 'STOPPED': return 'var(--red)';
      default: return 'var(--muted)';
    }
  };

  return (
    <div style={{ width: '340px', display: 'flex', flexDirection: 'column', background: 'var(--panel)', borderRight: '1px solid var(--border)', overflowY: 'auto' }}>
      
      {/* TARGET SECTION */}
      <div style={{ padding: '16px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: '12px', letterSpacing: '0.05em' }}>TARGET</div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button 
            style={{ flex: 1, borderColor: proxy === 'proxy' ? 'var(--amber)' : 'var(--border)', color: proxy === 'proxy' ? 'var(--amber)' : 'var(--text)' }}
            onClick={() => !isRunning && setProxy('proxy')}
            disabled={isRunning}
          >
            PROXY (AEGIS)
          </button>
          <button 
            style={{ flex: 1, borderColor: proxy === 'direct' ? 'var(--amber)' : 'var(--border)', color: proxy === 'direct' ? 'var(--amber)' : 'var(--text)' }}
            onClick={() => !isRunning && setProxy('direct')}
            disabled={isRunning}
          >
            DIRECT
          </button>
        </div>
      </div>

      {/* PARAMETERS SECTION */}
      <div style={{ padding: '16px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: '12px', letterSpacing: '0.05em' }}>PARAMETERS</div>
        
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <span>SPEED</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <input type="range" min="0.1" max="5" step="0.1" value={speed} onChange={e => setSpeed(parseFloat(e.target.value))} disabled={isRunning} style={{ width: '100px' }}/>
            <span className="mono" style={{ width: '32px', textAlign: 'right' }}>{speed.toFixed(1)}x</span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <span>MUTATION SEED</span>
          <input type="number" value={seed} onChange={e => setSeed(parseInt(e.target.value))} disabled={isRunning} style={{ width: '80px', textAlign: 'right' }} />
        </div>

        <div style={{ marginBottom: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: '8px' }}>STAGES (CORE KILL CHAIN)</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {[
              { id: 1, label: 'RECON' },
              { id: 2, label: 'ADAPT' },
              { id: 3, label: 'AILM' },
              { id: 4, label: 'LATERAL' },
              { id: 5, label: 'EXEC' }
            ].map(stage => (
              <label key={stage.id} style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: isRunning ? 'default' : 'pointer', opacity: isRunning ? 0.6 : 1 }}>
                <input 
                  type="checkbox" 
                  checked={!!stages[stage.id]} 
                  onChange={() => toggleStage(stage.id)}
                  disabled={isRunning}
                  style={{ accentColor: 'var(--amber)' }}
                />
                <span className="mono" style={{ fontSize: '12px' }}>[{stage.id}] {stage.label}</span>
              </label>
            ))}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--muted)', marginTop: '10px', marginBottom: '6px' }}>OPTIONAL AI ATTACK STAGES</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
            {[
              { id: 6, label: 'MCP_POISON (Tool Metadata)' },
              { id: 7, label: 'RAG_INJECT (Indirect Doc)' },
              { id: 8, label: 'SLOPSQUAT (Hallucinated Pkg)' },
              { id: 9, label: 'CRED_HARVEST (~/.claude, .env)' }
            ].map(stage => (
              <label key={stage.id} style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: isRunning ? 'default' : 'pointer', opacity: isRunning ? 0.6 : 1 }}>
                <input 
                  type="checkbox" 
                  checked={!!stages[stage.id]} 
                  onChange={() => toggleStage(stage.id)}
                  disabled={isRunning}
                  style={{ accentColor: 'var(--amber)' }}
                />
                <span className="mono" style={{ fontSize: '11px', color: 'var(--text-dim)' }}>[{stage.id}] {stage.label}</span>
              </label>
            ))}
          </div>
        </div>

        <div>
          <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: '8px' }}>MODE</div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button 
              style={{ flex: 1, borderColor: mode === 'ONCE' ? 'var(--amber)' : 'var(--border)', color: mode === 'ONCE' ? 'var(--amber)' : 'var(--text)' }}
              onClick={() => !isRunning && setMode('ONCE')}
              disabled={isRunning}
            >
              ONCE
            </button>
            <button 
              style={{ flex: 1, borderColor: mode === 'REPEAT' ? 'var(--amber)' : 'var(--border)', color: mode === 'REPEAT' ? 'var(--amber)' : 'var(--text)' }}
              onClick={() => !isRunning && setMode('REPEAT')}
              disabled={isRunning}
            >
              REPEAT
            </button>
          </div>
        </div>
      </div>

      {/* ACTIONS SECTION */}
      <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px', flex: 1, justifyContent: 'flex-end' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
          <div style={{ width: '8px', height: '8px', background: getStatusColor() }}></div>
          <span className="mono" style={{ color: getStatusColor(), fontSize: '12px', fontWeight: 600 }}>{runState.status}</span>
        </div>
        
        <button 
          className="primary" 
          style={{ width: '100%', padding: '12px', fontSize: '14px' }}
          onClick={handleRun}
          disabled={isRunning || isRequesting}
        >
          RUN [R]
        </button>
        <button 
          className="danger" 
          style={{ width: '100%', padding: '12px', fontSize: '14px' }}
          onClick={handleStop}
          disabled={!isRunning || isRequesting}
        >
          STOP [S]
        </button>
      </div>
    </div>
  );
}
